from __future__ import annotations
import os, sys, re, json, time, hashlib, sqlite3, threading, shutil, subprocess, secrets
from pathlib import Path
from datetime import datetime, timedelta
from collections import deque
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / '.env')
except Exception:
    pass

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'data'; DATA.mkdir(exist_ok=True)
BACKUPS = ROOT / 'backups'; BACKUPS.mkdir(exist_ok=True)
REPORTS = ROOT / 'reports'; REPORTS.mkdir(exist_ok=True)
SNAPS = ROOT / 'snapshots'; SNAPS.mkdir(exist_ok=True)
DB = DATA / 'ransomtrap.sqlite3'
APP = Flask(__name__, static_folder=str(ROOT/'frontend'), static_url_path='')
CORS(APP)
LOCK = threading.RLock()
OBSERVERS: dict[str, Observer] = {}
MONITORING = True
EVENTS = deque(maxlen=500)
LAST_RESPONSE_MS = None

# Deliberately conservative: these locations are never accepted as user monitoring roots.
BLOCKED_PARTS = {'windows', 'program files', 'program files (x86)', '$recycle.bin', 'system volume information'}
MAX_SCAN_FILES = 10000
MAX_BACKUP_BYTES = 20 * 1024 * 1024
MASS_THRESHOLD = int(os.getenv('MASS_THRESHOLD', '15'))
AUTO_SNAPSHOT = os.getenv('AUTO_SNAPSHOT', '1') not in ('0', 'false', 'False')
SNAPSHOT_COOLDOWN_S = int(os.getenv('SNAPSHOT_COOLDOWN_S', '120'))
SNAPSHOT_KEEP = int(os.getenv('SNAPSHOT_KEEP', '5'))
MAX_SNAPSHOT_FILES = 5000
MAX_SNAPSHOT_BYTES = 1024 * 1024 * 1024
SNAP_TRIGGERS = {'CANARY_TOUCH', 'RANSOM_EXTENSION', 'RANSOM_NOTE_NAME', 'ML_ALERT'}
SNAP_ID_RE = re.compile(r'^\d{8}_\d{6}_[0-9a-f]{6}$')
_LAST_SNAP = {}
SNAP_LOCK = threading.Lock()
ML_ALERT_CONFIDENCE = float(os.getenv('ML_ALERT_CONFIDENCE', '90'))
# Extensions / note names commonly appended or dropped by file-locking malware (indicators only, heuristic).
SUSPICIOUS_EXT = {'.locked','.encrypted','.crypt','.crypted','.enc','.lock','.crypto','.ryk','.akira','.lockbit','.wncry','.blackcat','.zepto','.cerber'}
RANSOM_NOTE_HINTS = ('how_to_decrypt','how_to_recover','decrypt_instructions','readme_to_restore','restore_files','recover_your_files','ransom')
LIVE = {'ts': deque(), 'renames': deque(), 'ext_changes': deque(), 'entropy': deque(maxlen=200), 'canary': deque()}
_SEEN = {}
def once(key, window):
    """True at most once per `window` seconds for a key (stops alert spam from one rename producing many events)."""
    t = time.time()
    if len(_SEEN) > 5000: _SEEN.clear()
    if t - _SEEN.get(key, 0) < window: return False
    _SEEN[key] = t; return True
_MODEL = {'obj': None, 'mtime': None}


def now(): return datetime.now().astimezone().isoformat(timespec='seconds')
def db():
    con = sqlite3.connect(DB, timeout=10); con.row_factory = sqlite3.Row; return con

def init_db():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS roots(id INTEGER PRIMARY KEY, path TEXT UNIQUE, added_at TEXT);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts TEXT, level TEXT, kind TEXT, path TEXT, detail TEXT, pid INTEGER, process TEXT, outcome TEXT, response_ms REAL);
        CREATE TABLE IF NOT EXISTS baselines(path TEXT PRIMARY KEY, sha256 TEXT, size INTEGER, mtime REAL, backup_path TEXT, scanned_at TEXT);
        CREATE TABLE IF NOT EXISTS decoys(path TEXT PRIMARY KEY, root_id INTEGER, created_at TEXT, sha256 TEXT, status TEXT DEFAULT 'ARMED');
        CREATE TABLE IF NOT EXISTS counters(key TEXT PRIMARY KEY, value INTEGER NOT NULL);
        ''')
        for k in ('detected','contained','modified','deleted','renamed'):
            c.execute('INSERT OR IGNORE INTO counters(key,value) VALUES(?,0)',(k,))

def log(level, kind, path='', detail='', pid=None, process='', outcome='', response_ms=None):
    item={'ts':now(),'level':level,'kind':kind,'path':str(path),'detail':detail,'pid':pid,'process':process,'outcome':outcome,'response_ms':response_ms}
    with LOCK:
        with db() as c:
            c.execute('INSERT INTO events(ts,level,kind,path,detail,pid,process,outcome,response_ms) VALUES(?,?,?,?,?,?,?,?,?)',
                      (item['ts'],level,kind,str(path),detail,pid,process,outcome,response_ms))
            if kind in ('CANARY_TOUCH','MASS_ACTIVITY','SUSPICIOUS_CHANGE','RANSOM_EXTENSION','RANSOM_NOTE_NAME','ML_ALERT'):
                c.execute("UPDATE counters SET value=value+1 WHERE key='detected'")
            if kind == 'CONTAINED': c.execute("UPDATE counters SET value=value+1 WHERE key='contained'")
        EVENTS.appendleft(item)
    if AUTO_SNAPSHOT and kind in SNAP_TRIGGERS:
        threading.Thread(target=auto_snapshot, args=(path, kind), daemon=True).start()
    return item

def sha256_file(path: Path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def entropy(path: Path, limit=1024*1024):
    from math import log2
    with path.open('rb') as fh: data=fh.read(limit)
    if not data: return 0.0
    counts=[0]*256
    for b in data: counts[b]+=1
    n=len(data)
    return round(-sum((x/n)*log2(x/n) for x in counts if x),3)

DEMO_DIR = (ROOT / 'demo_data').resolve()

def safe_root(raw):
    p=Path(raw).expanduser().resolve()
    if not p.exists() or not p.is_dir(): raise ValueError('Folder does not exist or is not a directory.')
    parts={x.casefold() for x in p.parts}
    if parts & BLOCKED_PARTS: raise ValueError('System and program folders cannot be monitored. Choose Documents, Desktop, Pictures or a project folder.')
    if p == Path(p.anchor): raise ValueError('Do not monitor an entire drive. Select a specific user folder.')
    if p == DEMO_DIR: return p  # bundled demo folder is explicitly allowed
    if p == ROOT or ROOT in p.parents: raise ValueError('Choose a folder outside the RansomTrap installation directory.')
    return p

def copy_backup(src: Path, root: Path):
    try:
        if src.stat().st_size > MAX_BACKUP_BYTES: return ''
        rel=src.relative_to(root)
        dest=BACKUPS / hashlib.sha1(str(root).encode()).hexdigest()[:8] / rel
        dest.parent.mkdir(parents=True,exist_ok=True)
        if not dest.exists(): shutil.copy2(src,dest)
        return str(dest)
    except (OSError, ValueError): return ''

def scan_root(root: Path):
    count=0; errors=0
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {'.git','node_modules','venv','.venv','__pycache__','RansomTrap_Archive'}]
        for name in files:
            if count >= MAX_SCAN_FILES: break
            p=Path(base)/name
            try:
                if p.is_symlink() or not p.is_file(): continue
                st=p.stat(); digest=sha256_file(p); backup=copy_backup(p,root)
                with db() as c:
                    previous=c.execute('SELECT sha256,size FROM baselines WHERE path=?',(str(p),)).fetchone()
                    if previous and previous['sha256'] != digest:
                        log('WARNING','INTEGRITY_MISMATCH',p,'SHA-256 differs from the stored baseline. Review the change; this is not proof of ransomware.')
                        c.execute("UPDATE counters SET value=value+1 WHERE key='modified'")
                    elif not previous:
                        c.execute('INSERT INTO baselines(path,sha256,size,mtime,backup_path,scanned_at) VALUES(?,?,?,?,?,?)',
                                  (str(p),digest,st.st_size,st.st_mtime,backup,now()))
                    c.execute('UPDATE baselines SET scanned_at=? WHERE path=?',(now(),str(p)))
                count+=1
            except (OSError, PermissionError): errors+=1
    return count,errors

def deploy_decoys(root: Path, root_id: int):
    # Same-name decoys are placed in a separate, plausible archive folder; originals are never overwritten.
    with db() as c: existing=[r['path'] for r in c.execute('SELECT path FROM decoys WHERE root_id=?',(root_id,))]
    alive=[x for x in existing if Path(x).exists()]
    if alive: return len(alive)   # already armed: never create duplicate canaries
    archive=root/'RansomTrap_Archive'
    archive.mkdir(exist_ok=True)
    candidates=[]
    for base,dirs,files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {'RansomTrap_Archive','.git','node_modules','venv','.venv','__pycache__'}]
        for fn in files:
            p=Path(base)/fn
            if p.is_file() and p.suffix.lower() in {'.txt','.csv','.json','.log'}:
                candidates.append(p)
            if len(candidates)>=5: break
        if len(candidates)>=5: break
    templates=[('Personal_Notes.txt','Synthetic decoy notes. No real personal data.'),('Project_Status.csv','item,status\nprototype,review\n'),('System_Backup.log','RansomTrap synthetic canary. No credentials or personal data.\n'),('Archive_Index.json','{"type":"synthetic-canary","records":[]}')]
    created=0
    for i,(fallback,content) in enumerate(templates):
        name=candidates[i].name if i<len(candidates) else fallback
        target=archive/name
        if target.exists(): target=archive/f'{Path(name).stem}_archive_{i+1}{Path(name).suffix}'
        try:
            target.write_text(content,encoding='utf-8')
            digest=sha256_file(target)
            with db() as c: c.execute('INSERT OR REPLACE INTO decoys(path,root_id,created_at,sha256,status) VALUES(?,?,?,?,?)',(str(target),root_id,now(),digest,'ARMED'))
            created+=1
        except OSError: pass
    log('INFO','DECOYS_DEPLOYED',root, f'{created} synthetic canary files deployed in {archive}')
    return created

FEATURE_KEYS = ('file_events_10s','rename_ratio','entropy_mean','extension_changes','canary_touched')

def _trim(dq, window=10):
    t = time.time()
    while dq and (t - (dq[0][0] if isinstance(dq[0], tuple) else dq[0])) > window: dq.popleft()

def live_features():
    """Feature vector computed from real live telemetry (same 5 features the model trains on)."""
    for k in ('ts','renames','ext_changes','canary','entropy'): _trim(LIVE[k])
    n = len(LIVE['ts'])
    ent = [v for _, v in LIVE['entropy']]
    return {'file_events_10s': float(n),
            'rename_ratio': round(len(LIVE['renames']) / n, 3) if n else 0.0,
            'entropy_mean': round(sum(ent) / len(ent), 3) if ent else 0.0,
            'extension_changes': float(len(LIVE['ext_changes'])),
            'canary_touched': 1.0 if LIVE['canary'] else 0.0}

def get_model():
    if not MODEL_PATH.exists(): return None
    m = MODEL_PATH.stat().st_mtime
    if _MODEL['obj'] is None or _MODEL['mtime'] != m:
        from joblib import load
        _MODEL['obj'] = load(MODEL_PATH); _MODEL['mtime'] = m
    return _MODEL['obj']

def ml_score(features):
    model = get_model()
    if model is None: return None
    row = [[features[k] for k in FEATURE_KEYS]]
    probs = model.predict_proba(row)[0]
    classes = list(model.classes_)
    p_susp = float(probs[classes.index(1)]) if 1 in classes else 0.0
    return round(p_susp * 100, 1)

_LAST_ML_ALERT = [0.0]

class MonitorHandler(FileSystemEventHandler):
    def __init__(self, root): self.root=Path(root); self.recent=deque()
    def _is_decoy(self,p):
        with db() as c: return c.execute('SELECT 1 FROM decoys WHERE path=?',(str(Path(p)),)).fetchone() is not None
    def _record(self, kind, path, dest=''):
        global LAST_RESPONSE_MS
        if not MONITORING: return
        start=time.perf_counter(); p=Path(path)
        LIVE['ts'].append(time.time())
        if kind=='renamed':
            LIVE['renames'].append(time.time())
            if dest and Path(dest).suffix.lower()!=p.suffix.lower(): LIVE['ext_changes'].append(time.time())
        target_name=(Path(dest).name if dest else p.name).lower(); target_ext=(Path(dest).suffix if dest else p.suffix).lower()
        if target_ext in SUSPICIOUS_EXT:
            if once(('ext', str(dest or p)), 30):
                log('CRITICAL','RANSOM_EXTENSION',dest or p,f'File uses an extension often seen with file-locking malware ({target_ext}). Heuristic indicator only.')
        elif any(h in target_name for h in RANSOM_NOTE_HINTS):
            if once(('note', str(dest or p)), 30):
                log('CRITICAL','RANSOM_NOTE_NAME',dest or p,'File name resembles a ransom-note pattern. Heuristic indicator only.')
        if self._is_decoy(p):
            LIVE['canary'].append(time.time())
            log('CRITICAL','CANARY_TOUCH',p,f'Decoy interaction detected ({kind}). No automatic kill was attempted.')
        else:
            self.recent.append(time.time())
            while self.recent and time.time()-self.recent[0]>10: self.recent.popleft()
            if len(self.recent)>=MASS_THRESHOLD and once(('mass', str(self.root)), 10):
                log('WARNING','MASS_ACTIVITY',p,f'{len(self.recent)} file events in 10 seconds; review required.')
            if kind in ('modified','created','renamed'):
                mp = Path(dest) if (kind=='renamed' and dest) else p
                try:
                    e=entropy(mp); LIVE['entropy'].append((time.time(), e))
                    if e>=7.5 and once(('ent', str(mp)), 30): log('WARNING','HIGH_ENTROPY',mp,f'Post-change entropy {e}; entropy alone is not proof of ransomware.')
                except OSError: pass
            log('INFO','FILE_'+kind.upper(),p, f'Filesystem {kind} event'+(f' -> {dest}' if dest else ''))
        try:
            feats=live_features(); score=ml_score(feats)
            if score is not None and score>=ML_ALERT_CONFIDENCE and time.time()-_LAST_ML_ALERT[0]>10:
                _LAST_ML_ALERT[0]=time.time()
                log('WARNING','ML_ALERT',p,f'Live ML model scored recent activity {score}% suspicious. Features: {json.dumps(feats)}. Verify manually.')
        except Exception: pass
        LAST_RESPONSE_MS=round((time.perf_counter()-start)*1000,2)
    def on_modified(self,e):
        if not e.is_directory: self._record('modified',e.src_path)
    def on_created(self,e):
        if not e.is_directory: self._record('created',e.src_path)
    def on_deleted(self,e):
        if not e.is_directory: self._record('deleted',e.src_path)
    def on_moved(self,e):
        if not e.is_directory: self._record('renamed',e.src_path,e.dest_path)

def start_observer(root_id,path):
    key=str(root_id)
    if key in OBSERVERS: return
    ob=Observer(); ob.schedule(MonitorHandler(path),path=path,recursive=True); ob.daemon=True; ob.start(); OBSERVERS[key]=ob
    log('INFO','MONITOR_STARTED',path,'Recursive filesystem monitoring active.')

def stop_all():
    for ob in list(OBSERVERS.values()):
        ob.stop(); ob.join(timeout=2)
    OBSERVERS.clear()

def load_roots():
    with db() as c: return [dict(r) for r in c.execute('SELECT * FROM roots ORDER BY id')]

def add_root(raw):
    p=safe_root(raw)
    with db() as c:
        cur=c.execute('INSERT OR IGNORE INTO roots(path,added_at) VALUES(?,?)',(str(p),now()))
        row=c.execute('SELECT * FROM roots WHERE path=?',(str(p),)).fetchone()
    rid=row['id']; count,errors=scan_root(p); decoys=deploy_decoys(p,rid)
    if MONITORING: start_observer(rid,str(p))
    log('INFO','FOLDER_ADDED',p,f'Baseline indexed: {count} files; {errors} skipped; {decoys} decoys.')
    return {'id':rid,'path':str(p),'files_indexed':count,'decoys_created':decoys,'errors':errors}

@APP.get('/')
def home(): return APP.send_static_file('index.html')
@APP.get('/api/status')
def status():
    roots=load_roots()
    with db() as c:
        counters={r['key']:r['value'] for r in c.execute('SELECT * FROM counters')}
        total=c.execute('SELECT COUNT(*) n FROM baselines').fetchone()['n']
        decoys=c.execute("SELECT COUNT(*) n FROM decoys WHERE status='ARMED'").fetchone()['n']
        events=c.execute('SELECT COUNT(*) n FROM events').fetchone()['n']
    return jsonify({'monitoring':MONITORING,'roots':roots,'counters':counters,'files_indexed':total,'decoys':decoys,'events':events,'last_response_ms':LAST_RESPONSE_MS})
@APP.get('/api/roots')
def roots(): return jsonify(load_roots())
@APP.post('/api/roots')
def roots_add():
    try: return jsonify(add_root(request.json.get('path',''))),201
    except Exception as e: return jsonify({'error':str(e)}),400
@APP.delete('/api/roots/<int:rid>')
def roots_remove(rid):
    with db() as c: row = c.execute('SELECT * FROM roots WHERE id=?', (rid,)).fetchone()
    if not row: return jsonify({'error': 'Folder not found.'}), 404
    root = Path(row['path'])
    ob = OBSERVERS.pop(str(rid), None)
    if ob:
        ob.stop(); ob.join(timeout=2)
    deleted = 0
    failed = []
    with db() as c:
        decoys = c.execute('SELECT path FROM decoys WHERE root_id=?', (rid,)).fetchall()
    archive = (root / 'RansomTrap_Archive').resolve()
    for item in decoys:  # remove only canary paths recorded by this application
        canary = Path(item['path'])
        try:
            resolved = canary.resolve()
            if archive not in resolved.parents:
                failed.append(str(canary))
                continue
            existed = canary.exists()
            canary.unlink(missing_ok=True)
            deleted += int(existed)
        except OSError:
            failed.append(str(canary))
    try:
        archive.rmdir()  # remove the app-created archive directory only when empty
    except OSError:
        pass
    prefix = str(root) + os.sep
    with db() as c:
        # Keep failed cleanup records visible for a later retry; remove successful/missing canary records.
        if failed:
            placeholders = ','.join('?' for _ in failed)
            c.execute(f'DELETE FROM decoys WHERE root_id=? AND path NOT IN ({placeholders})', (rid, *failed))
            c.execute('UPDATE decoys SET status=? WHERE root_id=?', ('CLEANUP_FAILED', rid))
        else:
            c.execute('DELETE FROM decoys WHERE root_id=?', (rid,))
        c.execute('DELETE FROM baselines WHERE path=? OR substr(path,1,?)=?', (str(root), len(prefix), prefix))
        c.execute('DELETE FROM roots WHERE id=?', (rid,))
    _LAST_SNAP.pop(str(root), None)
    detail = f'Folder is no longer monitored. {deleted} canary file(s) removed; your files were not touched.'
    if failed:
        detail += f' {len(failed)} canary file(s) could not be removed (likely locked/permission restricted); close the file and retry cleanup.'
    log('INFO', 'FOLDER_REMOVED', root, detail)
    return jsonify({'removed': True, 'decoys_deleted': deleted, 'cleanup_failed': failed, 'message': detail})

@APP.post('/api/scan')
def scan():
    total=errors=0
    for r in load_roots():
        n,e=scan_root(Path(r['path'])); total+=n; errors+=e
    log('INFO','INTEGRITY_SCAN', '', f'Scan complete. {total} files indexed; {errors} errors.')
    return jsonify({'files_scanned':total,'errors':errors})
@APP.post('/api/monitor/toggle')
def toggle():
    global MONITORING
    MONITORING=not MONITORING
    if MONITORING:
        for r in load_roots(): start_observer(r['id'],r['path'])
    else: stop_all()
    log('INFO','MONITOR_TOGGLE','','Monitoring '+('enabled' if MONITORING else 'paused'))
    return jsonify({'monitoring':MONITORING})
@APP.get('/api/events')
def events():
    with db() as c: rows=[dict(x) for x in c.execute('SELECT * FROM events ORDER BY id DESC LIMIT 200')]
    return jsonify(rows)
@APP.get('/api/decoys')
def decoys():
    with db() as c: rows=[dict(x) for x in c.execute('SELECT * FROM decoys ORDER BY created_at DESC')]
    return jsonify(rows)
@APP.post('/api/demo-attack')
def demo_attack():
    # Harmless simulation: writes a marker to a canary only. It never encrypts user data.
    with db() as c: row=c.execute("SELECT path FROM decoys WHERE status='ARMED' LIMIT 1").fetchone()
    if not row: return jsonify({'error':'Add a folder first so RansomTrap can deploy a canary.'}),400
    target=Path(row['path'])
    def worker():
        try:
            log('WARNING','DEMO_STARTED',target,'Harmless demo writes a marker to one synthetic canary only.')
            time.sleep(.4)
            with target.open('a',encoding='utf-8') as f: f.write('\nRANSOMTRAP_DEMO_MARKER\n')
        except OSError as e: log('ERROR','DEMO_ERROR',target,str(e))
    threading.Thread(target=worker,daemon=True).start()
    return jsonify({'started':True,'message':'Harmless canary interaction simulation started.'})
@APP.post('/api/restore-decoys')
def restore_decoys():
    restored=0
    with db() as c: rows=c.execute('SELECT path,sha256 FROM decoys').fetchall()
    for r in rows:
        p=Path(r['path'])
        if p.exists():
            # Recreate synthetic content instead of trusting modified canary contents.
            try: p.write_text('RansomTrap synthetic canary. Safe test file; no real data.\n',encoding='utf-8'); restored+=1
            except OSError: pass
    log('INFO','DECOYS_RESTORED','',f'{restored} decoys reset to harmless content.')
    return jsonify({'restored':restored})
@APP.get('/api/report')
def report():
    with db() as c:
        ev=[dict(x) for x in c.execute('SELECT * FROM events ORDER BY id DESC LIMIT 500')]
        roots=[dict(x) for x in c.execute('SELECT * FROM roots')]
    p=REPORTS/f'ransomtrap_report_{datetime.now():%Y%m%d_%H%M%S}.json'
    p.write_text(json.dumps({'generated_at':now(),'roots':roots,'events':ev,'note':'Prototype report. Monitoring and heuristic alerts are not a guarantee of malware detection.'},indent=2),encoding='utf-8')
    return send_file(p,as_attachment=True)
@APP.get('/api/export.csv')
def export_csv():
    import csv
    with db() as c: rows=[dict(x) for x in c.execute('SELECT * FROM events ORDER BY id DESC')]
    p=REPORTS/f'ransomtrap_events_{datetime.now():%Y%m%d_%H%M%S}.csv'
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0].keys()) if rows else ['id','ts','level','kind','path','detail','pid','process','outcome','response_ms']); w.writeheader(); w.writerows(rows)
    return send_file(p,as_attachment=True)


# Optional ML lab: trained on a clearly labeled synthetic educational dataset.
ML_DIR = ROOT / 'ml'; ML_DIR.mkdir(exist_ok=True)
MODEL_PATH = ML_DIR / 'ransomtrap_rf.joblib'
METRICS_PATH = ML_DIR / 'training_metrics.json'

@APP.get('/api/ml/status')
def ml_status():
    metrics = None
    if METRICS_PATH.exists():
        try: metrics = json.loads(METRICS_PATH.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError): metrics = None
    return jsonify({'trained': MODEL_PATH.exists(), 'metrics': metrics,
                    'note': 'Educational model trained on synthetic activity patterns; not validated for real-world ransomware detection.'})

@APP.get('/api/ml/insights')
def ml_insights():
    # Transparent feature importance for the educational Random Forest.
    if not MODEL_PATH.exists():
        return jsonify({'trained': False, 'features': []})
    try:
        from joblib import load
        model = load(MODEL_PATH)
        names = list(FEATURE_KEYS)
        values = list(getattr(model, 'feature_importances_', []))
        ranked = sorted([{'feature': names[i], 'importance_percent': round(float(values[i]) * 100, 2)}
                         for i in range(min(len(names), len(values)))],
                        key=lambda x: x['importance_percent'], reverse=True)
        return jsonify({'trained': True, 'features': ranked,
                        'note': 'Feature importance describes this synthetic training set, not universal ransomware indicators.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@APP.post('/api/ml/train')
def ml_train():
    try:
        proc = subprocess.run([sys.executable, str(ROOT/'train_model.py')], cwd=str(ROOT), capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            return jsonify({'error': (proc.stderr or proc.stdout or 'Training failed')[-2500:]}), 500
        metrics = json.loads(METRICS_PATH.read_text(encoding='utf-8'))
        log('INFO','ML_MODEL_TRAINED',str(MODEL_PATH),'Synthetic educational dataset; metrics are not real-world performance claims.')
        return jsonify({'trained': True, 'metrics': metrics, 'message':'Model trained successfully on synthetic demonstration data.'})
    except Exception as e:
        return jsonify({'error':str(e)}), 500

@APP.post('/api/ml/predict')
def ml_predict():
    if not MODEL_PATH.exists(): return jsonify({'error':'Train the demo model first.'}), 400
    try:
        from joblib import load
        payload=request.get_json(silent=True) or {}
        keys=('file_events_10s','rename_ratio','entropy_mean','extension_changes','canary_touched')
        features={k: float(payload.get(k,0)) for k in keys}
        model=load(MODEL_PATH)
        pred=int(model.predict([[features[k] for k in keys]])[0]); probs=model.predict_proba([[features[k] for k in keys]])[0]
        reasons=[]
        if features['file_events_10s'] >= 15: reasons.append('High file-event rate (15+ events in 10 seconds)')
        if features['rename_ratio'] >= .5: reasons.append('A large share of recent file events are renames')
        if features['entropy_mean'] >= 7.0: reasons.append('High average file entropy')
        if features['extension_changes'] >= 3: reasons.append('Multiple file-extension changes')
        if features['canary_touched'] >= 1: reasons.append('A canary tripwire was touched')
        confidence=round(float(max(probs))*100,1)
        risk='HIGH' if pred and confidence >= 80 else 'MEDIUM' if pred or reasons else 'LOW'
        return jsonify({'prediction':'suspicious-pattern' if pred else 'benign-pattern','confidence_percent':confidence,
                        'risk_level':risk,'risk_score':round(float(probs[1])*100,1),'explanation':reasons or ['No configured high-risk heuristic threshold was crossed'],
                        'features':features,'note':'Prediction is from a synthetic educational model; explanations are transparent threshold indicators, not SHAP values. Do not use as a real malware verdict.'})
    except Exception as e: return jsonify({'error':str(e)}), 400

@APP.post('/api/ml/anomaly')
def ml_anomaly():
    """Unsupervised Isolation Forest check trained on synthetic benign behavior samples."""
    anomaly_path = ML_DIR / 'ransomtrap_isolation_forest.joblib'
    if not anomaly_path.exists():
        return jsonify({'error':'Train/refresh the model first to create the anomaly detector.'}), 400
    try:
        from joblib import load
        payload = request.get_json(silent=True) or {}
        keys = ('file_events_10s','rename_ratio','entropy_mean','extension_changes','canary_touched')
        values = [float(payload.get(k, 0)) for k in keys]
        if any(not __import__('math').isfinite(v) for v in values):
            return jsonify({'error':'All feature values must be finite numbers.'}), 400
        if not (0 <= values[0] <= 500 and 0 <= values[1] <= 1 and 0 <= values[2] <= 8 and 0 <= values[3] <= 100 and 0 <= values[4] <= 1):
            return jsonify({'error':'Feature values are outside supported ranges.'}), 400
        detector = load(anomaly_path)
        sample = [values]
        label = int(detector.predict(sample)[0])
        raw_score = float(detector.decision_function(sample)[0])
        return jsonify({'anomaly': label == -1, 'label': 'anomalous' if label == -1 else 'within-learned-baseline',
                        'decision_score': round(raw_score, 4), 'features': dict(zip(keys, values)),
                        'note':'Isolation Forest was fitted to synthetic benign patterns. This is an educational anomaly signal, not a malware verdict.'})
    except Exception as e:
        return jsonify({'error':str(e)}), 400


SNAP_SKIP_DIRS = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', 'RansomTrap_Archive'}

def take_snapshot(root: Path, reason: str):
    """Copy the current state of a protected folder into snapshots/<id>/ (separate from baseline backups)."""
    sid = datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + hashlib.sha1(str(root).encode()).hexdigest()[:6]
    dest_base = SNAPS / sid; files = []; have = set(); total = 0; truncated = False; from_baseline = 0
    for _pass in range(2):   # second pass picks up files that were renamed while the first pass was running
        for base, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SNAP_SKIP_DIRS]
            for name in names:
                p = Path(base) / name
                try:
                    if p.is_symlink() or not p.is_file(): continue
                    rel = p.relative_to(root)
                    if str(rel) in have: continue
                    size = p.stat().st_size
                    if size > MAX_BACKUP_BYTES: continue
                    if len(files) >= MAX_SNAPSHOT_FILES or total + size > MAX_SNAPSHOT_BYTES: truncated = True; break
                    dst = dest_base / rel
                    dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(p, dst)
                    files.append(str(rel)); have.add(str(rel)); total += size
                except (OSError, ValueError): continue
            if truncated: break
        if truncated: break
    # files that disappeared or were renamed: recover the ORIGINAL clean copy from the baseline backup
    if not truncated:
        with db() as c: rows = c.execute("SELECT path, backup_path FROM baselines WHERE backup_path != ''").fetchall()
        for r in rows:
            try:
                rel = Path(r['path']).relative_to(root)
                if 'RansomTrap_Archive' in rel.parts or str(rel) in have: continue
                src = Path(r['backup_path'])
                if not src.is_file(): continue
                size = src.stat().st_size
                if len(files) >= MAX_SNAPSHOT_FILES or total + size > MAX_SNAPSHOT_BYTES: truncated = True; break
                dst = dest_base / rel; dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(src, dst)
                files.append(str(rel)); have.add(str(rel)); total += size; from_baseline += 1
            except (OSError, ValueError): continue
    dest_base.mkdir(parents=True, exist_ok=True)
    man = {'id': sid, 'root': str(root), 'created': now(), 'reason': reason, 'files_count': len(files), 'bytes': total, 'truncated': truncated, 'from_baseline': from_baseline, 'files': files}
    (dest_base / 'manifest.json').write_text(json.dumps(man), encoding='utf-8')
    # retention: keep only the newest SNAPSHOT_KEEP snapshots per root
    mine = sorted([m for m in list_manifests() if m['root'] == str(root)], key=lambda m: m['id'], reverse=True)
    for old in mine[SNAPSHOT_KEEP:]: shutil.rmtree(SNAPS / old['id'], ignore_errors=True)
    return {k: v for k, v in man.items() if k != 'files'}

def list_manifests(with_files=False):
    out = []
    for d in SNAPS.iterdir() if SNAPS.exists() else []:
        mf = d / 'manifest.json'
        if d.is_dir() and mf.exists() and SNAP_ID_RE.match(d.name):
            try:
                m = json.loads(mf.read_text(encoding='utf-8'))
                out.append(m if with_files else {k: v for k, v in m.items() if k != 'files'})
            except (OSError, json.JSONDecodeError): pass
    return sorted(out, key=lambda m: m['id'], reverse=True)

def root_for(path):
    try: pp = Path(path)
    except Exception: return None
    for r in load_roots():
        rp = Path(r['path'])
        if pp == rp or rp in pp.parents: return rp
    return None

def auto_snapshot(path, kind):
    """Automatic, non-destructive response: snapshot the affected folder (rate limited). Never kills processes."""
    try:
        root = root_for(path)
        if root is None: return
        with SNAP_LOCK:
            if time.time() - _LAST_SNAP.get(str(root), 0) < SNAPSHOT_COOLDOWN_S: return
            _LAST_SNAP[str(root)] = time.time()
            m = take_snapshot(root, f'auto:{kind}')
        log('INFO', 'CONTAINED', root, f"Auto-snapshot {m['id']} created ({m['files_count']} files, {m['from_baseline']} recovered from baseline) after {kind}. No process was killed.")
    except Exception as e:
        log('ERROR', 'SNAPSHOT_ERROR', str(path), str(e))

@APP.post('/api/panic')
def panic():
    made = []
    with SNAP_LOCK:
        for r in load_roots():
            try: made.append(take_snapshot(Path(r['path']), 'manual:panic')); _LAST_SNAP[r['path']] = time.time()
            except Exception as e: log('ERROR', 'SNAPSHOT_ERROR', r['path'], str(e))
    log('INFO', 'CONTAINED', '', f'Manual panic snapshot of {len(made)} protected folder(s).')
    return jsonify({'snapshots': len(made), 'items': made})

@APP.get('/api/snapshots')
def snapshots_list(): return jsonify(list_manifests())

@APP.post('/api/snapshots/restore')
def snapshots_restore():
    d = request.get_json(silent=True) or {}
    sid = str(d.get('id', ''))
    if not SNAP_ID_RE.match(sid): return jsonify({'error': 'Invalid snapshot id.'}), 400
    try:
        mf = SNAPS / sid / 'manifest.json'
        if not mf.exists(): return jsonify({'error': 'Snapshot not found.'}), 404
        man = json.loads(mf.read_text(encoding='utf-8')); root = Path(man['root'])
        if not any(Path(r['path']) == root for r in load_roots()): return jsonify({'error': 'Snapshot root is no longer a protected folder.'}), 400
        target = Path(d.get('path', '')).resolve()
        rel = target.relative_to(root)
        if str(rel) not in set(man['files']): return jsonify({'error': 'File is not part of this snapshot.'}), 404
        src = (SNAPS / sid / rel).resolve()
        if (SNAPS / sid).resolve() not in src.parents or not src.is_file(): return jsonify({'error': 'Snapshot copy missing.'}), 404
        if target.exists(): shutil.copy2(target, target.with_name(target.name + '.before_restore'))
        target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(src, target)
        log('INFO', 'FILE_RESTORED', target, f'Restored from snapshot {sid}.')
        return jsonify({'restored': True, 'path': str(target), 'snapshot': sid})
    except ValueError: return jsonify({'error': 'Path is not inside the snapshot root.'}), 400
    except Exception as e: return jsonify({'error': str(e)}), 400

@APP.get('/api/timeline')
def timeline():
    try: minutes = max(5, min(180, int(request.args.get('minutes', 30))))
    except ValueError: minutes = 30
    end = datetime.now().astimezone().replace(second=0, microsecond=0)
    start = end - timedelta(minutes=minutes - 1)
    with db() as c: rows = c.execute('SELECT ts, level FROM events WHERE ts >= ?', (start.isoformat(timespec='seconds'),)).fetchall()
    buckets = {}
    for i in range(minutes):
        t = start + timedelta(minutes=i); buckets[t.strftime('%Y-%m-%dT%H:%M')] = {'t': t.strftime('%H:%M'), 'critical': 0, 'warning': 0, 'info': 0}
    for r in rows:
        b = buckets.get(str(r['ts'])[:16])
        if b is None: continue
        lv = str(r['level']).upper(); b['critical' if lv == 'CRITICAL' else 'warning' if lv in ('WARNING', 'ERROR') else 'info'] += 1
    return jsonify({'minutes': minutes, 'buckets': list(buckets.values())})

@APP.get('/api/ml/live')
def ml_live():
    feats = live_features(); score = ml_score(feats)
    return jsonify({'features': feats, 'suspicious_score': score, 'model_loaded': score is not None,
                    'alert_threshold': ML_ALERT_CONFIDENCE,
                    'note': 'Live telemetry scored by the educational model. Heuristic only; verify manually.'})

@APP.get('/api/backups')
def backups_list():
    with db() as c: rows=[dict(x) for x in c.execute("SELECT path,sha256,size,backup_path,scanned_at FROM baselines WHERE backup_path!='' ORDER BY scanned_at DESC LIMIT 300")]
    return jsonify(rows)

@APP.post('/api/restore-file')
def restore_file():
    """Restore ONE file from the local baseline backup copy (only inside registered folders)."""
    raw=(request.get_json(silent=True) or {}).get('path','')
    try:
        target=Path(raw).resolve()
        if not any(target==Path(r['path']) or Path(r['path']) in target.parents for r in load_roots()):
            return jsonify({'error':'Path is not inside a protected folder.'}),400
        with db() as c: row=c.execute('SELECT backup_path,sha256 FROM baselines WHERE path=?',(str(target),)).fetchone()
        if not row or not row['backup_path'] or not Path(row['backup_path']).exists():
            return jsonify({'error':'No backup copy exists for this file.'}),404
        src=Path(row['backup_path'])
        if src.stat().st_size > MAX_BACKUP_BYTES: return jsonify({'error':'Backup is unexpectedly large.'}),400
        if target.exists():
            keep=target.with_name(target.name+'.before_restore'); shutil.copy2(target,keep)
        target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(src,target)
        ok = sha256_file(target)==row['sha256']
        log('INFO','FILE_RESTORED',target,'Restored from baseline backup; hash '+('matches' if ok else 'differs from')+' stored baseline.')
        return jsonify({'restored':True,'hash_matches_baseline':ok,'path':str(target)})
    except Exception as e: return jsonify({'error':str(e)}),400

@APP.get('/api/ai/local-summary')
def local_summary():
    """Works with NO API key: rule-based summary of recent events."""
    with db() as c: rows=[dict(x) for x in c.execute('SELECT level,kind FROM events ORDER BY id DESC LIMIT 200')]
    from collections import Counter
    kinds=Counter(r['kind'] for r in rows); levels=Counter(r['level'] for r in rows)
    steps=[]
    if kinds.get('CANARY_TOUCH'): steps.append('A canary file was touched. Check which program/user touched it (Task Manager, Resource Monitor) before taking action.')
    if kinds.get('RANSOM_EXTENSION') or kinds.get('RANSOM_NOTE_NAME'): steps.append('Ransomware-style file names were seen. Disconnect from network if files are really being renamed, and restore from backups.')
    if kinds.get('MASS_ACTIVITY') or kinds.get('ML_ALERT'): steps.append('High burst of file activity. Compare with a legitimate cause (sync, unzip, build, backup) before treating as malicious.')
    if kinds.get('INTEGRITY_MISMATCH'): steps.append('Some files differ from baseline. Review them; use Restore file if a change was not yours.')
    if not steps: steps.append('No notable alerts. Keep independent backups and Windows Defender enabled.')
    return jsonify({'summary':f"{levels.get('CRITICAL',0)} critical, {levels.get('WARNING',0)} warning, {len(rows)} total recent events.",
                    'top_kinds':kinds.most_common(5),'steps':steps,'note':'Rule-based, no AI used. Advisory only.'})

@APP.get('/api/system')
def system_info():
    return jsonify({'cpu_percent':psutil.cpu_percent(interval=None),'memory_percent':psutil.virtual_memory().percent,
                    'monitoring':MONITORING,
                    'model_trained':MODEL_PATH.exists(),'auto_snapshot':AUTO_SNAPSHOT})

init_db()
# Seed the safe demo directory only for a fresh installation with no roots.
# Users can remove it like any other monitored root; their real files are never deleted.
try:
    demo=ROOT/'demo_data'
    if not load_roots(): add_root(str(demo))
except Exception as exc: log('WARNING','DEMO_SETUP_WARNING','',str(exc))
for r in load_roots():
    try: start_observer(r['id'],r['path'])
    except Exception as exc: log('ERROR','MONITOR_ERROR',r['path'],str(exc))

if not MODEL_PATH.exists():
    try: subprocess.run([sys.executable,str(ROOT/'train_model.py')],cwd=str(ROOT),capture_output=True,timeout=120)
    except Exception: pass

if __name__=='__main__':
    print('\n RANSOMTRAP Windows Protection Prototype')
    print(' Open http://127.0.0.1:5000')
    print(' Add only folders you own and want monitored. Ctrl+C to stop.\n')
    APP.run(host='127.0.0.1',port=5000,debug=False,threaded=True)
