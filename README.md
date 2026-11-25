# RansomTrap — Windows Protection Prototype

A local defensive research prototype for **user-selected folders**. It combines recursive filesystem event monitoring, SHA-256 baselines, versioned copies of small files, synthetic canary files, simple behaviour heuristics, SQLite event history, and downloadable reports.

## Run on Windows
1. Install Python 3.10+ and enable **Add Python to PATH**.
2. Extract this ZIP to a normal user-writable folder (not `Program Files`).
3. Double-click `run.bat` or run `run.bat` from PowerShell.
4. Open `http://127.0.0.1:5000` if it does not open automatically.
5. The included `demo_data` folder is monitored by default. Add other folders you own using the Protected folders field, e.g. `C:\Users\YourName\Documents`.

## What it does
- Watches only folders explicitly registered in the app (plus the included demo folder).
- Creates an initial SHA-256 inventory and copies eligible files up to 20 MB into the local `backups` directory.
- Deploys synthetic canary files into a separate `RansomTrap_Archive` subfolder. The canaries use plausible/same names where available but contain synthetic text only; originals are never overwritten.
- Records create, modify, delete and rename events.
- Flags canary touches, bursts of filesystem events, and high post-change entropy as **heuristics**.
- Stores events in `data/ransomtrap.sqlite3`; exports CSV and JSON reports.
- Includes a harmless canary-touch simulation that writes a marker to one synthetic canary only.

## Important limitations / safety
- This is **not a production antivirus or EDR** and does not guarantee ransomware prevention. Keep Microsoft Defender, Windows updates, and independent backups enabled.
- It does not install a Windows service, kernel driver, filesystem minifilter, or ETW provider.
- File events do not reliably identify the process responsible on Windows. The app therefore does **not** claim a PID and does **not** automatically kill unknown processes. This avoids terminating legitimate applications based on weak evidence.
- SHA-256 baseline inventory and initial backup copies are not a complete recovery system. Backups are local and may be reachable by malware running as your account. Use offline/cloud versioned backups too.
- Entropy and event-volume thresholds can produce false positives and are not proof of ransomware.
- Add only folders you own and want monitored. Do not add the entire C: drive, Windows, Program Files, AppData, network shares, or folders containing sensitive data unless you understand the implications. The app copies eligible small files into its local backup folder.
- Canary deployment creates a `RansomTrap_Archive` directory under each selected folder. Remove the folder only after stopping the app if you want to uninstall the canaries.

## Demo
Click **Simulate canary event**. It appends a harmless marker to one synthetic canary. The event stream should record `CANARY_TOUCH`. Click **Restore demo canaries** to reset the synthetic canary content.

## Data locations
- `data/ransomtrap.sqlite3` — local database
- `backups/` — initial copies of eligible files (up to 20 MB each)
- `reports/` — downloaded report files
- `demo_data/` — safe included demo folder

## Troubleshooting
- If `run.bat` cannot find Python, install Python 3.10+ and reopen VS Code/Terminal.
- If pip fails, check internet connectivity and rerun `run.bat`.
- If a folder cannot be added, check that it exists and that your Windows account can read it.
- Keep the terminal window open while using the dashboard. Press Ctrl+C to stop the server.


## Added dashboard enhancements

- **Heuristic risk indicators (0–100):** explainable, rule-based display scores for event kinds/severity. These are not machine-learning predictions or proof of malware.
- **Threat analytics summary:** critical events, warnings, file activity, last event time, and simple event-category bars.
- **Event search and severity filters:** filter the recent event stream by text and severity.
- **Browser desktop notifications:** click “Enable notifications” and grant permission to receive critical-event notifications while the dashboard is open. Browser permissions and browser support apply.

The project remains a local educational prototype. Do not use it as a replacement for Windows Defender or a production endpoint protection platform. Test only folders you own and keep independent backups.

## AI / ML Upgrade (added)

### Train the educational model
1. Run `run.bat` so the updated dependencies are installed.
2. In the dashboard, open **Machine Learning Lab** and click **Train / Retrain model**.
3. The script `train_model.py` generates 2,400 training and 800 independently generated test samples with overlapping benign/suspicious feature distributions, trains a Random Forest, and saves `ml/ransomtrap_rf.joblib`, `ml/ransomtrap_isolation_forest.joblib`, and `ml/training_metrics.json`.
4. Click **Run sample prediction** to test a sample feature vector.

**Honest limitation:** this is a working ML training pipeline, but the generated labels and features are synthetic. Its metrics are not evidence of real-world ransomware detection. For research-grade evaluation, replace the synthetic generator with a documented, labeled dataset and ensure the model features match the live telemetry.


### New endpoints
- `GET /api/ml/status` — model status and saved metrics
- `POST /api/ml/train` — train/retrain the synthetic demo model
- `POST /api/ml/predict` — predict a supplied feature vector using the trained model


## v3 Upgrade (this version)
- **Bug fix:** the bundled `demo_data` folder was being rejected by the folder safety check, so the demo never loaded. Fixed.
- **Live ML Monitor:** the model now scores REAL live file-event features (events/10s, rename ratio, entropy, extension changes, canary touched) and raises `ML_ALERT` at >= 90% (configurable via `ML_ALERT_CONFIDENCE`).
- **Ransomware indicators:** `RANSOM_EXTENSION` (e.g. .locked/.encrypted) and `RANSOM_NOTE_NAME` events (heuristic).
- **Restore from backup:** `POST /api/restore-file` / dashboard panel; keeps current file as `.before_restore` and verifies SHA-256.
- **Local summary without API key:** `GET /api/ai/local-summary`.
- **Extra endpoints:** `/api/ml/live`, `/api/backups`, `/api/system`.
- **Auto-train:** model is trained automatically on first start if missing.
- **Tests:** `.venv\\Scripts\\python.exe tests\\test_app.py`
- Tunables via `.env`: `MASS_THRESHOLD`, `ML_ALERT_CONFIDENCE`.




## v6: Automatic response + charts
- **Auto-snapshot:** on `CANARY_TOUCH`, `RANSOM_EXTENSION`, `RANSOM_NOTE_NAME` or `ML_ALERT`, the affected protected folder is copied to `snapshots/<id>/` (rate limited to once per 120 s per folder; newest 5 kept per folder; max 5000 files / 1 GB each). **No process is ever killed.** Each one is logged as a `CONTAINED` event and counted under "Containment actions".
- **Panic button:** snapshots all protected folders immediately (`POST /api/panic`).
- **Restore from snapshot:** `POST /api/snapshots/restore {id, path}`; the current file is kept as `.before_restore`. Dashboard: Response panel -> "Restore a file...".
- **Charts:** event timeline (events per minute, stacked by severity) and live ML score vs alert threshold, drawn with plain SVG (no internet needed). `GET /api/timeline`.
- **Settings (.env):** `AUTO_SNAPSHOT=1|0`, `SNAPSHOT_COOLDOWN_S`, `SNAPSHOT_KEEP`.
- **Limits:** a snapshot taken after encryption has started can contain encrypted files; snapshots are local and reachable by malware running as your account. Keep an offline/cloud backup.


## v7 fixes (found while testing on a real Windows machine)
- **Snapshot lost files during a rename burst** (8 of 20): the walk is now repeated and missing files are recovered from the baseline backup (originals). Manifest shows `from_baseline`.
- **Alert spam:** `MASS_ACTIVITY` is limited to once per 10 s per folder, `RANSOM_EXTENSION`/`HIGH_ENTROPY` once per file per 30 s. One rename no longer inflates the alert counter.
- **Stale entropy:** entropy samples now expire after 10 s (the Live ML panel kept showing an old value). Entropy is now also measured on created and renamed files, and files are read in a bounded way (max 1 MB).
- **Duplicate canaries:** re-adding a folder no longer creates more canaries.
- **Remove folder:** new button / `DELETE /api/roots/<id>`. Deletes only RansomTrap canaries, never your files. The bundled demo folder cannot be removed.
- Empty result boxes are hidden.


## Core edition (prepared 2026-11-24)

This package hides the advanced dashboard modules that could not be runtime-verified in the preparation environment: the ML training/live-scoring panels, ML/timeline charts, automatic/panic snapshots, and snapshot/baseline restore panels. The visible dashboard is limited to folder registration/removal, filesystem monitoring, canary deployment and harmless simulation, integrity scanning, event viewing, desktop notifications, and CSV/report export.

**Verification note:** Python and JavaScript syntax checks passed during packaging. Full runtime tests were not run because the preparation environment did not have Flask installed and could not reach the package index to install requirements. Therefore this is a reduced, syntax-checked package—not a claim that Windows runtime behavior has been proven. Run `python -m pip install -r requirements.txt` and `python -m pytest tests/test_app.py -v` on your Windows machine before relying on it. Use only folders you own and retain independent backups.


## Enhanced ML capabilities (educational)

- Random Forest supervised classifier with training metrics and feature-importance display.
- Explainable prediction output with a risk band, model score, and transparent threshold-based reason indicators (not SHAP).
- Isolation Forest unsupervised anomaly check, trained on generated synthetic benign-behavior samples.
- Live telemetry scoring and a prediction playground.

Use **Train / refresh model** in the dashboard before running predictions or Isolation Forest checks. The dataset is synthetic and the metrics/scores are not validated real-world ransomware detection performance.

## Protected-folder removal fix

The folder Remove action now safely removes only RansomTrap's recorded canary files inside its own `RansomTrap_Archive`, clears that folder's baseline records, stops monitoring, and removes the protected-folder registration. It never deletes the user's original files. If a canary is locked or access is denied, the API reports the failed cleanup rather than silently claiming it was deleted.


## ML evaluation correction (2026-11-25)
- The earlier synthetic generator made the two classes too easy to separate, which could produce misleading 100% metrics.
- The updated generator deliberately uses overlapping feature distributions and a separately generated holdout test set (different random seed).
- Expected dashboard metrics are now calculated from that holdout set; they are not hard-coded or artificially capped.
- After updating an existing installation, click **Train / refresh model** once to regenerate the model and metrics.
- Even improved synthetic metrics are educational only and must not be presented as real-world ransomware detection accuracy.
