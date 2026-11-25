async function api(url,opts={}){const r=await fetch(url,{headers:{'Content-Type':'application/json'},...opts});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||'Request failed');return d}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
let lastSeenEventId=null, cachedEvents=[];
function riskScore(e){if(e.kind==='CANARY_TOUCH')return 95;if(e.kind==='MASS_ACTIVITY')return 85;if(e.kind==='RANSOM_EXTENSION'||e.kind==='RANSOM_NOTE_NAME')return 92;if(e.kind==='ML_ALERT')return 80;if(e.kind==='INTEGRITY_MISMATCH')return 65;if(e.kind==='HIGH_ENTROPY')return 60;if(e.level==='CRITICAL')return 90;if(e.level==='ERROR')return 45;if(e.level==='WARNING')return 40;return 10}
function riskLabel(e){const n=riskScore(e);return `<span class="risk risk-${n>=80?'high':n>=50?'medium':'low'}">${n}/100</span>`}
function showCriticalAlert(event){const box=document.getElementById('criticalAlert');document.getElementById('alertMessage').textContent=`${event.kind}: ${event.detail||'Suspicious canary activity detected.'}`;document.getElementById('alertMeta').textContent=`Time: ${event.ts} | File: ${event.path}`;box.hidden=false;if('Notification'in window&&Notification.permission==='granted'){try{new Notification('RansomTrap: Critical activity detected',{body:`${event.kind} — ${event.path}`})}catch(_){}}}
function dismissAlert(){document.getElementById('criticalAlert').hidden=true;}
async function enableNotifications(){if(!('Notification'in window)){alert('Browser notifications are not supported here.');return}try{const p=await Notification.requestPermission();alert(p==='granted'?'Desktop notifications enabled.':'Notification permission was not granted.')}catch(e){alert('Could not request notification permission.')}}
function renderEvents(){const q=(document.getElementById('eventSearch')?.value||'').toLowerCase();const level=document.getElementById('levelFilter')?.value||'ALL';const filtered=cachedEvents.filter(x=>(level==='ALL'||x.level===level)&&[x.kind,x.path,x.detail,x.process].some(v=>String(v||'').toLowerCase().includes(q)));document.getElementById('eventCount').textContent=`${filtered.length} events`;document.getElementById('eventRows').innerHTML=filtered.slice(0,100).map(x=>`<tr><td>${esc(x.ts)}</td><td><span class="level level-${esc(String(x.level||'INFO').toLowerCase())}">${esc(x.level)}</span></td><td>${riskLabel(x)}</td><td>${esc(x.kind)}</td><td>${esc(x.path)}</td><td>${esc(x.detail)}</td></tr>`).join('')||'<tr><td colspan="6">No matching events.</td></tr>'}
function renderAnalytics(events){const critical=events.filter(x=>x.level==='CRITICAL'||x.kind==='CANARY_TOUCH').length;const warnings=events.filter(x=>x.level==='WARNING').length;const changes=events.filter(x=>String(x.kind||'').startsWith('FILE_')).length;document.getElementById('criticalCount').textContent=critical;document.getElementById('warningCount').textContent=warnings;document.getElementById('changeCount').textContent=changes;document.getElementById('lastEvent').textContent=events.length?new Date(events[0].ts).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}):'—';const groups=[['Canary',events.filter(x=>x.kind==='CANARY_TOUCH').length],['Integrity',events.filter(x=>x.kind==='INTEGRITY_MISMATCH'||x.kind==='HIGH_ENTROPY').length],['File activity',changes]];const max=Math.max(1,...groups.map(x=>x[1]));document.getElementById('eventBars').innerHTML=groups.map(([label,n])=>`<div class="bar-row"><span>${label}</span><div class="bar-track"><i style="width:${Math.round(n/max*100)}%"></i></div><b>${n}</b></div>`).join('')}
async function refresh(){try{const [s,roots,decoys,events]=await Promise.all([api('/api/status'),api('/api/roots'),api('/api/decoys'),api('/api/events')]);if(lastSeenEventId===null){lastSeenEventId=events.length?Math.max(...events.map(x=>Number(x.id)||0)):0}else{const fresh=events.filter(x=>(Number(x.id)||0)>lastSeenEventId);const critical=fresh.filter(x=>x.level==='CRITICAL'||x.kind==='CANARY_TOUCH');if(critical.length)showCriticalAlert(critical[0]);if(fresh.length)lastSeenEventId=Math.max(lastSeenEventId,...fresh.map(x=>Number(x.id)||0))}cachedEvents=events;document.getElementById('files').textContent=s.files_indexed;document.getElementById('decoys').textContent=s.decoys;document.getElementById('detected').textContent=s.counters.detected||0;document.getElementById('contained').textContent=s.counters.contained||0;document.getElementById('state').textContent=s.monitoring?'Monitoring is active':'Monitoring is paused';document.getElementById('toggle').textContent=s.monitoring?'Pause monitoring':'Resume monitoring';document.getElementById('banner').classList.toggle('off',!s.monitoring);document.getElementById('rootList').innerHTML=roots.map(x=>`<div class="row"><div><b>${esc(x.path)}</b><small>Added ${esc(x.added_at)}</small></div><span class="status">MONITORED</span><button class="secondary" data-id="${esc(x.id)}" onclick="removeFolder(this.dataset.id)">Remove</button></div>`).join('')||'<div class="row">No folders added.</div>';document.getElementById('decoyList').innerHTML=decoys.map(x=>`<div class="row"><div><b>${esc(x.path)}</b><small>SHA-256 ${esc((x.sha256||'').slice(0,18))}…</small></div><span class="status">${esc(x.status)}</span></div>`).join('')||'<div class="row">Add a folder to deploy canaries.</div>';renderEvents();renderAnalytics(events)}catch(e){console.error(e)}}
async function addFolder(){const p=document.getElementById('folderPath').value.trim();if(!p)return alert('Enter a folder path first.');try{const d=await api('/api/roots',{method:'POST',body:JSON.stringify({path:p})});alert(`Folder added. ${d.files_indexed} files indexed and ${d.decoys_created} canaries deployed.`);document.getElementById('folderPath').value='';refresh()}catch(e){alert(e.message)}}
async function scan(){try{const d=await api('/api/scan',{method:'POST'});alert(`Integrity baseline scan finished. ${d.files_scanned} files processed; ${d.errors} errors.`);refresh()}catch(e){alert(e.message)}}
async function demo(){try{const d=await api('/api/demo-attack',{method:'POST'});alert(d.message);setTimeout(refresh,1000)}catch(e){alert(e.message)}}
async function restore(){if(!confirm('Restore synthetic canary files to their harmless demo content?'))return;try{const d=await api('/api/restore-decoys',{method:'POST'});alert(`${d.restored} canaries restored.`);refresh()}catch(e){alert(e.message)}}
document.getElementById('toggle').addEventListener('click',async()=>{try{await api('/api/monitor/toggle',{method:'POST'});refresh()}catch(e){alert(e.message)}});refresh();setInterval(refresh,3000);


// Folder removal is intentionally separate from deleting user files.
async function removeFolder(id){
  const row=document.querySelector(`#rootList button[data-id="${CSS.escape(String(id))}"]`);
  const label=row?.closest('.row')?.querySelector('b')?.textContent||'this folder';
  if(!confirm(`Stop monitoring ${label}? RansomTrap will remove only its own recorded canary files. Your files will NOT be deleted.`))return;
  try{const d=await api(`/api/roots/${encodeURIComponent(id)}`,{method:'DELETE'});alert(d.message||`Folder removed. ${d.decoys_deleted||0} canary files deleted.`);await refresh();await refreshRecovery();}
  catch(e){alert(`Could not remove folder: ${e.message}`)}
}

function metricCards(m){
  if(!m)return '<p class="hint">No training metrics available yet.</p>';
  const vals=[['Accuracy',m.accuracy_percent],['Precision',m.precision_percent],['Recall',m.recall_percent],['F1 score',m.f1_percent]];
  const cm=Array.isArray(m.confusion_matrix)?m.confusion_matrix:[];
  const matrix=cm.length===2?`<div class="ml-result"><b>Confusion matrix</b><div class="analytics-grid"><div class="metric"><small>True negative</small><strong>${Number(cm[0]?.[0]??0)}</strong></div><div class="metric"><small>False positive</small><strong>${Number(cm[0]?.[1]??0)}</strong></div><div class="metric"><small>False negative</small><strong>${Number(cm[1]?.[0]??0)}</strong></div><div class="metric"><small>True positive</small><strong>${Number(cm[1]?.[1]??0)}</strong></div></div></div>`:'';
  return `<div class="analytics-grid">${vals.map(([k,v])=>`<div class="metric"><small>${k}</small><strong>${Number(v??0).toFixed(1)}%</strong></div>`).join('')}</div><p class="hint">${esc(m.samples_total)} synthetic samples · ${esc(m.samples_train)} train / ${esc(m.samples_test)} test</p>${matrix}`;
}
async function refreshML(){
  try{
    const [s,ins,live]=await Promise.all([api('/api/ml/status'),api('/api/ml/insights'),api('/api/ml/live')]);
    document.getElementById('mlStatus').textContent=s.trained?'Model ready · Random Forest trained.':'Model not trained yet. Click Train / refresh model.';
    document.getElementById('mlMetrics').innerHTML=metricCards(s.metrics);
    const box=document.getElementById('featureImportance');
    if(ins.trained&&ins.features?.length){const max=Math.max(1,...ins.features.map(x=>x.importance_percent));box.innerHTML=ins.features.map(x=>`<div class="bar-row"><span>${esc(x.feature.replaceAll('_',' '))}</span><div class="bar-track"><i style="width:${Math.max(1,x.importance_percent/max*100)}%"></i></div><b>${x.importance_percent}%</b></div>`).join('')}
    else box.innerHTML='<div class="hint">Train the model to calculate feature importance.</div>';
    const score=live.suspicious_score;
    document.getElementById('liveScore').textContent=score===null?'Model unavailable':`${score}%`;
    document.getElementById('liveScoreBar').style.width=`${Math.max(0,Math.min(100,Number(score)||0))}%`;
    document.getElementById('mlLiveState').textContent=live.model_loaded?'MODEL ACTIVE':'MODEL OFFLINE';
    document.getElementById('liveFeatures').textContent=`${JSON.stringify(live.features,null,2)}\n\n${live.note}`;
  }catch(e){document.getElementById('mlStatus').textContent=`ML panel error: ${e.message}`}
}
async function trainModel(b){
  b?.setAttribute('disabled','disabled');
  document.getElementById('mlStatus').textContent='Training Random Forest on synthetic demonstration data…';
  try{const d=await api('/api/ml/train',{method:'POST'});document.getElementById('mlStatus').textContent=d.message;await refreshML();alert('Model training completed. Review the synthetic-data disclaimer and metrics.');}
  catch(e){document.getElementById('mlStatus').textContent=`Training failed: ${e.message}`;alert(e.message)}
  finally{b?.removeAttribute('disabled')}
}
async function runPrediction(){
  const payload={file_events_10s:Number(document.getElementById('predEvents').value),rename_ratio:Number(document.getElementById('predRename').value),entropy_mean:Number(document.getElementById('predEntropy').value),extension_changes:Number(document.getElementById('predExt').value),canary_touched:document.getElementById('predCanary').checked?1:0};
  try{const d=await api('/api/ml/predict',{method:'POST',body:JSON.stringify(payload)});document.getElementById('predictionResult').textContent=`Result: ${d.prediction}\nRisk: ${d.risk_level} (${d.risk_score}/100)\nModel confidence: ${d.confidence_percent}%\nWhy: ${d.explanation.join('; ')}\nSignals: ${JSON.stringify(d.features,null,2)}\n${d.note}`}
  catch(e){document.getElementById('predictionResult').textContent=e.message}
}
async function runAnomalyCheck(){
  const payload={file_events_10s:Number(document.getElementById('predEvents').value),rename_ratio:Number(document.getElementById('predRename').value),entropy_mean:Number(document.getElementById('predEntropy').value),extension_changes:Number(document.getElementById('predExt').value),canary_touched:document.getElementById('predCanary').checked?1:0};
  try{const d=await api('/api/ml/anomaly',{method:'POST',body:JSON.stringify(payload)});document.getElementById('anomalyResult').textContent=`Isolation Forest: ${d.label}\nAnomaly flag: ${d.anomaly?'YES':'NO'}\nDecision score: ${d.decision_score}\n${d.note}`}
  catch(e){document.getElementById('anomalyResult').textContent=e.message}
}
async function refreshRecovery(){
  try{
    const [snaps,backs]=await Promise.all([api('/api/snapshots'),api('/api/backups')]);
    document.getElementById('snapshotList').innerHTML=snaps.map(x=>`<div class="row"><div><b>${esc(x.id)} · ${esc(x.reason)}</b><small>${esc(x.root)} · ${esc(x.files_count)} files · ${esc(x.created)}</small></div><button class="secondary" data-snapshot="${esc(x.id)}" onclick="restoreSnapshot(this.dataset.snapshot)">Restore file…</button></div>`).join('')||'<div class="hint">No snapshots yet. Add a folder and create a panic snapshot.</div>';
    document.getElementById('backupList').innerHTML=backs.slice(0,25).map(x=>`<div class="row"><div><b>${esc(x.path)}</b><small>${esc(x.size)} bytes · baseline available</small></div><button class="secondary" data-path="${esc(x.path)}" onclick="restorePathFromButton(this.dataset.path)">Restore</button></div>`).join('')||'<div class="hint">No baseline backups available.</div>';
  }catch(e){document.getElementById('snapshotList').textContent=e.message}
}
async function panicSnapshot(){
  if(!confirm('Create a snapshot of every currently protected folder?'))return;
  try{const d=await api('/api/panic',{method:'POST'});alert(`Created ${d.snapshots} snapshot(s).`);await refreshRecovery()}
  catch(e){alert(e.message)}
}
async function restoreSnapshot(id){
  const path=prompt('Enter the full path of the file to restore from this snapshot:');if(!path)return;
  if(!confirm(`Restore ${path}? If it exists, a .before_restore copy will be kept.`))return;
  try{const d=await api('/api/snapshots/restore',{method:'POST',body:JSON.stringify({id,path})});alert(`Restored: ${d.path}`);await refresh()}
  catch(e){alert(e.message)}
}
async function restorePathFromButton(path){document.getElementById('restorePath').value=path;await restoreBaselineFile()}
async function restoreBaselineFile(){
  const path=document.getElementById('restorePath').value.trim();if(!path)return alert('Enter or select a full file path.');
  if(!confirm(`Restore ${path} from the baseline backup?`))return;
  try{const d=await api('/api/restore-file',{method:'POST',body:JSON.stringify({path})});alert(`File restored. SHA-256 baseline match: ${d.hash_matches_baseline?'Yes':'No'}`);await refreshRecovery()}
  catch(e){alert(e.message)}
}
async function refreshTimeline(){
  try{const d=await api('/api/timeline?minutes=30');const max=Math.max(1,...d.buckets.map(x=>x.critical+x.warning+x.info));
    document.getElementById('timelineBars').innerHTML=d.buckets.filter((x,i)=>i%3===0||i===d.buckets.length-1).map(x=>{const n=x.critical+x.warning+x.info;return `<div class="bar-row"><span>${esc(x.t)}</span><div class="timeline-stack"><i class="critical-seg" style="width:${x.critical/max*100}%"></i><i class="warning-seg" style="width:${x.warning/max*100}%"></i><i class="info-seg" style="width:${x.info/max*100}%"></i></div><b>${n}</b></div>`}).join('')||'<div class="hint">No events in this period.</div>';
  }catch(e){document.getElementById('timelineBars').textContent=e.message}
}

// Load optional enhanced panels without blocking the core dashboard.
refreshML();refreshRecovery();refreshTimeline();
setInterval(()=>{refreshML();refreshTimeline()},10000);
