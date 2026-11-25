"""Train an educational Random Forest on overlapping synthetic behavior patterns.

The holdout set is generated independently from the training set. These metrics
are useful for demonstrating evaluation, but are NOT real-world ransomware
performance estimates.
"""
from pathlib import Path
import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from joblib import dump

ROOT = Path(__file__).resolve().parent
ML = ROOT / 'ml'
ML.mkdir(exist_ok=True)
FEATURES = ['file_events_10s', 'rename_ratio', 'entropy_mean', 'extension_changes', 'canary_touched']


def make_data(n=2400, seed=42):
    """Create noisy, overlapping benign/suspicious behavior examples.

    The classes intentionally overlap: a busy legitimate app can create many
    file events, and suspicious activity does not always touch a canary.
    """
    rng = np.random.default_rng(seed)
    y = rng.binomial(1, 0.40, size=n)
    X = np.zeros((n, len(FEATURES)), dtype=float)
    for i, label in enumerate(y):
        if label:
            X[i] = [
                np.clip(rng.lognormal(mean=2.55, sigma=0.62), 0, 80),
                rng.beta(3.0, 3.0),
                np.clip(rng.normal(6.35, 0.85), 2.5, 8.0),
                rng.poisson(2.5),
                rng.binomial(1, 0.10),
            ]
        else:
            X[i] = [
                np.clip(rng.lognormal(mean=1.85, sigma=0.72), 0, 80),
                rng.beta(1.8, 6.5),
                np.clip(rng.normal(5.55, 0.95), 2.5, 8.0),
                rng.poisson(0.9),
                rng.binomial(1, 0.008),
            ]
    return X, y.astype(int)


# Separate random seeds mean the test set is independently generated rather
# than being a random slice of the exact same generated batch.
X_train, y_train = make_data(2400, seed=42)
X_test, y_test = make_data(800, seed=2026)

model = RandomForestClassifier(
    n_estimators=180,
    max_depth=7,
    min_samples_leaf=5,
    class_weight='balanced_subsample',
    random_state=42,
    n_jobs=-1,
)
model.fit(X_train, y_train)
pred = model.predict(X_test)
cm = confusion_matrix(y_test, pred, labels=[0, 1])

metrics = {
    'dataset': 'Synthetic educational behavior patterns (independently generated train/test sets)',
    'samples_total': int(len(y_train) + len(y_test)),
    'samples_train': int(len(y_train)),
    'samples_test': int(len(y_test)),
    'features': FEATURES,
    'accuracy_percent': round(accuracy_score(y_test, pred) * 100, 2),
    'precision_percent': round(precision_score(y_test, pred, zero_division=0) * 100, 2),
    'recall_percent': round(recall_score(y_test, pred, zero_division=0) * 100, 2),
    'f1_percent': round(f1_score(y_test, pred, zero_division=0) * 100, 2),
    'confusion_matrix': cm.tolist(),
    'evaluation_method': 'Train and test datasets generated independently with overlapping feature distributions.',
    'warning': 'Educational synthetic-data metrics only. They do not estimate real-world ransomware detection performance.',
}

dump(model, ML / 'ransomtrap_rf.joblib')
# Isolation Forest is trained only on benign examples from the training set.
anomaly_model = IsolationForest(n_estimators=160, contamination=0.05, random_state=42)
anomaly_model.fit(X_train[y_train == 0])
dump(anomaly_model, ML / 'ransomtrap_isolation_forest.joblib')
(ML / 'training_metrics.json').write_text(json.dumps(metrics, indent=2), encoding='utf-8')
print(json.dumps(metrics, indent=2))
