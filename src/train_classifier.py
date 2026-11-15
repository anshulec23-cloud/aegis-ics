"""Offline training for the attack-type classifier (detection brain) — Phase 4.

Trains a multi-class Random Forest that names the *physical-process* attack behind a device's
telemetry: ``normal``, ``fdi_spike``, ``stuxnet``, ``thermal_drift``, ``sensor_fault``. Trained once,
offline, and shipped as ``src/model/attack_classifier.pkl`` (+ SHA-256 + metadata json). At runtime
``src/detection.py`` loads it read-only.

The per-class synthetic envelopes are centred on the same malicious profiles the red-team harness and
simulator inject (see ``redteam._MALICIOUS``), so a drill is a genuine end-to-end check: inject an
FDI spike, and the classifier must answer "fdi_spike".

Usage:
    python src/train_classifier.py
"""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import time

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split

FEATURES = ["temperature", "pressure", "vibration", "hall_effect", "current"]
# Class order is fixed; index == label id.
CLASSES = ["normal", "fdi_spike", "stuxnet", "thermal_drift", "sensor_fault"]

# Representative malicious readings the harness/simulator inject — used for sanity checks so the
# trained model is verified against the exact vectors it will see in a drill.
SANITY_VECTORS = {
    # redteam._MALICIOUS
    "fdi_spike": [96.8, 12.4, 5.8, 3500.0, 19.2],
    "stuxnet": [55.0, 7.8, 6.9, 3250.0, 8.6],
    "thermal_drift": [61.0, 8.4, 2.4, 1200.0, 6.8],
    # a clearly nominal reading
    "normal": [26.0, 4.2, 1.1, 0.0, 4.5],
}


def _uniform(lo, hi, n):
    return np.random.uniform(lo, hi, n)


def generate_attack_dataset(n_per_class: int = 4000, random_state: int = 42):
    """Balanced multi-class dataset over the 5 sensor features. Returns (X, y_idx)."""
    np.random.seed(random_state)
    blocks = []
    labels = []

    # --- normal: the four nominal operating zones (mirrors train_model nominal zones) ---
    nominal_zones = [
        {"t": (26.0, 2.5), "p": (4.2, 0.4), "v": (1.1, 0.2), "h": (0.0, 20.0), "c": (4.5, 0.4)},
        {"t": (41.0, 2.5), "p": (5.4, 0.5), "v": (1.8, 0.3), "h": (1500.0, 80.0), "c": (5.2, 0.4)},
        {"t": (18.5, 1.8), "p": (2.2, 0.3), "v": (0.6, 0.1), "h": (0.0, 15.0), "c": (2.8, 0.3)},
        {"t": (33.0, 2.5), "p": (3.8, 0.4), "v": (2.2, 0.3), "h": (2200.0, 120.0), "c": (7.1, 0.5)},
    ]
    per_zone = n_per_class // len(nominal_zones)
    nom = []
    for i, z in enumerate(nominal_zones):
        sz = per_zone + (1 if i < n_per_class % len(nominal_zones) else 0)
        nom.append(
            np.column_stack([
                np.random.normal(z["t"][0], z["t"][1], sz),
                np.random.normal(z["p"][0], z["p"][1], sz),
                np.clip(np.random.normal(z["v"][0], z["v"][1], sz), 0.1, 4.0),
                np.clip(np.random.normal(z["h"][0], z["h"][1], sz), 0.0, 2500.0),
                np.clip(np.random.normal(z["c"][0], z["c"][1], sz), 0.5, 7.8),
            ])
        )
    blocks.append(np.vstack(nom))
    labels += [0] * n_per_class

    # --- fdi_spike: gross out-of-envelope injection (harness fdi: 96.8/12.4/5.8/3500/19.2) ---
    blocks.append(np.column_stack([
        _uniform(68.0, 115.0, n_per_class),
        _uniform(9.0, 15.5, n_per_class),
        _uniform(4.3, 9.5, n_per_class),
        np.random.choice([0.0, 1500.0, 2200.0, 3500.0], n_per_class) + np.random.normal(0, 60, n_per_class),
        _uniform(10.0, 23.0, n_per_class),
    ]))
    labels += [1] * n_per_class

    # --- stuxnet: coordinated moderate drift, high RPM (harness stux: 55/7.8/6.9/3250/8.6) ---
    blocks.append(np.column_stack([
        _uniform(45.0, 58.0, n_per_class),
        _uniform(6.0, 8.2, n_per_class),
        _uniform(5.0, 7.6, n_per_class),
        _uniform(2950.0, 3450.0, n_per_class),
        _uniform(7.4, 9.9, n_per_class),
    ]))
    labels += [2] * n_per_class

    # --- thermal_drift: elevated temperature, otherwise calm (harness: 61/8.4/2.4/1200/6.8) ---
    blocks.append(np.column_stack([
        _uniform(57.0, 67.0, n_per_class),
        _uniform(7.3, 9.2, n_per_class),
        _uniform(1.7, 3.1, n_per_class),
        _uniform(950.0, 1450.0, n_per_class),
        _uniform(5.9, 7.7, n_per_class),
    ]))
    labels += [3] * n_per_class

    # --- sensor_fault: cavitation / bearing failure — erratic vibration + current, mid temp ---
    blocks.append(np.column_stack([
        _uniform(47.0, 56.0, n_per_class),
        _uniform(4.3, 6.0, n_per_class),
        _uniform(6.6, 12.0, n_per_class),
        _uniform(1500.0, 2150.0, n_per_class),
        _uniform(9.0, 15.5, n_per_class),
    ]))
    labels += [4] * n_per_class

    X = np.vstack(blocks)
    y = np.array(labels, dtype=int)

    # Ambiguous boundary band between the adjacent elevated-temperature classes (stuxnet /
    # thermal_drift / sensor_fault overlap in the real world); label it randomly so the model
    # learns genuine uncertainty there instead of memorising disjoint boxes.
    n_bound = n_per_class // 5
    X_bound = np.column_stack([
        _uniform(52.0, 60.0, n_bound),
        _uniform(6.0, 8.5, n_bound),
        _uniform(3.0, 7.0, n_bound),
        _uniform(1300.0, 3100.0, n_bound),
        _uniform(6.5, 10.5, n_bound),
    ])
    y_bound = np.random.choice([2, 3, 4], n_bound)
    X = np.vstack([X, X_bound])
    y = np.concatenate([y, y_bound])

    # 6% sensor noise, then 1.5% label noise (mislabelled frames happen in the field).
    X = X * (1 + np.random.normal(0, 0.06, X.shape))
    n_flip = int(0.015 * len(y))
    flip = np.random.choice(len(y), n_flip, replace=False)
    y[flip] = np.random.choice(len(CLASSES), n_flip)

    idx = np.arange(len(X))
    np.random.shuffle(idx)
    return X[idx], y[idx]


def train(out_dir: str | None = None) -> dict:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_dir = out_dir or os.path.join(base_dir, "model")
    os.makedirs(model_dir, exist_ok=True)

    print("=" * 65)
    print("  Training multi-class attack-type classifier")
    print("  classes:", ", ".join(CLASSES))
    print("=" * 65)

    X, y = generate_attack_dataset(n_per_class=4000, random_state=42)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=120,
        max_depth=16,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    # Store labels as class names so detection.py reports strings directly. (We deliberately do
    # NOT set feature_names_in_: detection.py predicts from positional vectors, and stamping names
    # would make every list-input prediction emit a sklearn feature-name warning.)
    model.classes_ = np.array(CLASSES)[model.classes_]

    y_pred = model.predict(X_test)
    y_pred_idx = np.array([CLASSES.index(c) for c in y_pred])
    acc = float(accuracy_score(y_test, y_pred_idx))
    f1m = float(f1_score(y_test, y_pred_idx, average="macro"))
    print(f"\nAccuracy: {acc:.4f}   macro-F1: {f1m:.4f}")
    print("\nClassification report:")
    print(classification_report(y_test, y_pred_idx, target_names=CLASSES))
    cm = confusion_matrix(y_test, y_pred_idx)
    print("Confusion matrix (rows=true, cols=pred):")
    print(cm)

    model_path = os.path.join(model_dir, "attack_classifier.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    with open(model_path, "rb") as mf:
        digest = hashlib.sha256(mf.read()).hexdigest()
    with open(model_path + ".sha256", "w", encoding="utf-8") as hf:
        hf.write(digest + "\n")

    meta = {
        "algorithm": "RandomForestClassifier",
        "classes": CLASSES,
        "features": FEATURES,
        "accuracy": round(acc, 4),
        "f1_macro": round(f1m, 4),
        "confusion_matrix": cm.tolist(),
        "feature_importances": {
            FEATURES[i]: round(float(imp), 4) for i, imp in enumerate(model.feature_importances_)
        },
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "n_estimators": 120,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(os.path.join(model_dir, "attack_classifier_meta.json"), "w", encoding="utf-8") as mf:
        json.dump(meta, mf, indent=2)

    print(f"\n[+] Exported classifier: {model_path}")

    # --- sanity checks against the exact vectors a drill injects ---
    print("\nSanity checks (harness/simulator vectors):")
    ok = True
    for expected, vec in SANITY_VECTORS.items():
        probs = model.predict_proba([vec])[0]
        pred = str(model.classes_[int(np.argmax(probs))])
        conf = float(np.max(probs))
        flag = "OK" if pred == expected else "MISMATCH"
        if pred != expected:
            ok = False
        print(f"  {expected:14s} -> {pred:14s} (conf {conf:.2f})  [{flag}]")
    if not ok:
        raise SystemExit("[!] Sanity check failed: a known attack vector was misclassified.")
    print("[+] All sanity checks passed.")
    return meta


if __name__ == "__main__":
    train()
