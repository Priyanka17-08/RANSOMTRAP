"""Smoke tests: python -m pytest tests  (or: python tests/test_app.py)"""
import sys, time, json, tempfile, shutil
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'backend'))
import app as A

def run():
    c = A.APP.test_client()
    # 1. demo folder must be registered (regression test for the safe_root bug)
    roots = c.get('/api/roots').get_json()
    assert any(Path(r['path']) == A.DEMO_DIR for r in roots), 'demo_data not registered'
    # 2. decoys + status
    st = c.get('/api/status').get_json(); assert st['decoys'] >= 1 and st['files_indexed'] >= 1
    # 3. ML status/predict/live
    # Train both supervised and unsupervised demonstration models before inference.
    tr = c.post('/api/ml/train'); assert tr.status_code == 200, tr.get_json()
    high = c.post('/api/ml/predict', json={'file_events_10s':30,'rename_ratio':.8,'entropy_mean':7.6,'extension_changes':6,'canary_touched':0})
    assert high.status_code == 200 and high.get_json()['prediction']=='suspicious-pattern', high.get_json()
    assert 'risk_level' in high.get_json() and 'explanation' in high.get_json()
    low = c.post('/api/ml/predict', json={'file_events_10s':2,'rename_ratio':0,'entropy_mean':4,'extension_changes':0,'canary_touched':0})
    assert low.status_code == 200 and low.get_json()['prediction']=='benign-pattern', low.get_json()
    assert 'features' in c.get('/api/ml/live').get_json()
    assert 'features' in c.get('/api/ml/insights').get_json()
    an = c.post('/api/ml/anomaly', json={'file_events_10s':2,'rename_ratio':0,'entropy_mean':4,'extension_changes':0,'canary_touched':0})
    assert an.status_code == 200 and 'decision_score' in an.get_json(), an.get_json()
    # 4. canary simulation -> CANARY_TOUCH
    c.post('/api/demo-attack'); time.sleep(2)
    kinds = [e['kind'] for e in c.get('/api/events').get_json()]
    assert 'CANARY_TOUCH' in kinds, kinds
    time.sleep(2)
    ev = c.get('/api/events').get_json()
    assert any(e['kind']=='CONTAINED' and 'Auto-snapshot' in e['detail'] for e in ev), 'auto-snapshot did not run'
    assert c.get('/api/snapshots').get_json(), 'no snapshot listed'
    # 5. ransom-extension indicator + restore from backup in a temp user folder
    tmp = Path(tempfile.mkdtemp(prefix='rt_test_'))
    try:
        f = tmp / 'doc.txt'; f.write_text('important data')
        assert c.post('/api/roots', json={'path': str(tmp)}).status_code == 201
        time.sleep(1)
        f.rename(tmp / 'doc.txt.locked'); time.sleep(2)
        kinds = [e['kind'] for e in c.get('/api/events').get_json()]
        assert 'RANSOM_EXTENSION' in kinds, kinds
        (tmp / 'doc.txt.locked').rename(f); f.write_text('XXXX corrupted')
        r = c.post('/api/restore-file', json={'path': str(f)}).get_json()
        assert r.get('restored') and r['hash_matches_baseline'], r
        assert f.read_text() == 'important data'
        # panic snapshot -> corrupt -> restore from snapshot
        r = c.post('/api/panic').get_json(); assert r['snapshots'] >= 2, r
        sid = next(m['id'] for m in c.get('/api/snapshots').get_json() if m['root'] == str(tmp.resolve()))
        f.write_text('ENCRYPTED GARBAGE')
        rr = c.post('/api/snapshots/restore', json={'id': sid, 'path': str(f)}); assert rr.status_code == 200, rr.get_json()
        assert f.read_text() == 'important data'
        assert c.post('/api/snapshots/restore', json={'id': '../../etc', 'path': str(f)}).status_code == 400   # bad id rejected
        assert c.post('/api/snapshots/restore', json={'id': sid, 'path': str(Path(tmp).parent / 'other.txt')}).status_code in (400, 404)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # 6. local summary works without any API key; system info
    assert 'steps' in c.get('/api/ai/local-summary').get_json()
    sysj=c.get('/api/system').get_json(); assert 'cpu_percent' in sysj and sysj['auto_snapshot'] is True
    # 7. system folders still blocked
    assert c.post('/api/roots', json={'path': 'C:\\Windows'}).status_code == 400

    # 8. regression: 20-file rename burst must not lose files from the auto-snapshot (was 8/20 on a real machine)
    tmp3 = Path(tempfile.mkdtemp(prefix='rt_test3_'))
    try:
        for i in range(1, 21): (tmp3 / f'file{i}.txt').write_text(f'hello {i}')
        assert c.post('/api/roots', json={'path': str(tmp3)}).status_code == 201
        time.sleep(1.5)
        for f3 in sorted(tmp3.glob('*.txt')): f3.rename(f3.with_name(f3.name + '.locked'))
        time.sleep(4)
        mans = [m for m in c.get('/api/snapshots').get_json() if m['root'] == str(tmp3.resolve()) and m['reason'].startswith('auto:')]
        assert mans, 'no auto snapshot for burst'
        assert max(m['files_count'] for m in mans) >= 20, [m['files_count'] for m in mans]
        evs = [e for e in c.get('/api/events').get_json() if 'rt_test3_' in e['path']]
        kinds = [e['kind'] for e in evs]
        assert kinds.count('MASS_ACTIVITY') <= 3, kinds.count('MASS_ACTIVITY')           # cooldown, no spam
        assert kinds.count('RANSOM_EXTENSION') <= 25, kinds.count('RANSOM_EXTENSION')     # about one per file, not several
        # 9. idempotent canaries: re-adding a folder must not create duplicate decoys
        n1 = c.get('/api/status').get_json()['decoys']
        assert c.post('/api/roots', json={'path': str(tmp3)}).status_code == 201
        assert c.get('/api/status').get_json()['decoys'] == n1, 'duplicate canaries created'
        # 10. remove folder: canaries deleted, user files untouched, root gone
        rid = next(r['id'] for r in c.get('/api/roots').get_json() if r['path'] == str(tmp3.resolve()))
        rm = c.delete(f'/api/roots/{rid}'); assert rm.status_code == 200, rm.get_json(); assert rm.get_json()['removed'] is True
        assert not any(r['path'] == str(tmp3.resolve()) for r in c.get('/api/roots').get_json())
        assert not (tmp3 / 'RansomTrap_Archive').exists()
        assert len(list(tmp3.glob('*.locked'))) == 20
    finally:
        shutil.rmtree(tmp3, ignore_errors=True)
    demo_id = next(r['id'] for r in c.get('/api/roots').get_json() if Path(r['path']) == A.DEMO_DIR)
    demo_remove = c.delete(f'/api/roots/{demo_id}')
    assert demo_remove.status_code == 200, demo_remove.get_json()
    assert A.DEMO_DIR.exists(), 'removing monitoring must not delete bundled demo files'
    # 11. stale entropy samples expire (previously showed old entropy forever)
    A.LIVE['entropy'].clear(); A.LIVE['entropy'].append((time.time() - 60, 5.0)); assert A.live_features()['entropy_mean'] == 0.0
    A.LIVE['entropy'].append((time.time(), 6.0)); assert A.live_features()['entropy_mean'] == 6.0
    tl = c.get('/api/timeline?minutes=10').get_json(); assert len(tl['buckets']) == 10 and sum(b['critical']+b['warning']+b['info'] for b in tl['buckets']) > 0
    print('ALL TESTS PASSED')

def test_all(): run()
if __name__ == '__main__': run()
