"""
Aegis ICS — Industrial Anomaly Classifier Training Pipeline
============================================================
Generates balanced multi-variable cyber-physical datasets across normal
baseline operating conditions and realistic industrial attack vectors:
 - Stuxnet-style mechanical resonance / overspeed attacks
 - False Data Injection (FDI) sensor spikes
 - Thermal runaway and exotherm heat accumulation
 - Hydraulic overpressure and pipe rupture hazards
 - Motor cavitation, bearing friction, and vibration runaway

Trains a 5-dimensional Scikit-Learn RandomForestClassifier, evaluates
classification metrics, and exports the optimized model to src/model/rf_model.pkl.

Usage:
    python src/train_model.py
"""

import os
import sys
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score


def generate_synthetic_dataset(n_samples: int = 5000, random_state: int = 42):
    """
    Synthesizes a realistic balanced multi-sensor dataset across 4 operational zones.
    Features: ['temperature', 'pressure', 'vibration', 'hall_effect', 'current']
    Target: 0 = Nominal, 1 = Cyber-Physical Anomaly
    """
    np.random.seed(random_state)
    n_nominal = n_samples // 2
    n_anomaly = n_samples - n_nominal

    # 1. Generate Nominal Plant Operations across 4 Industrial Zones
    nominal_zones = [
        # Reactor 01: temp=26°C, pres=4.2 bar, vib=1.1, hall=0, curr=4.5A
        {"t": (26.0, 2.5), "p": (4.2, 0.4), "v": (1.1, 0.2), "h": (0.0, 20.0), "c": (4.5, 0.4)},
        # Pump 02: temp=41°C, pres=5.4 bar, vib=1.8, hall=1500 RPM, curr=5.2A
        {"t": (41.0, 2.5), "p": (5.4, 0.5), "v": (1.8, 0.3), "h": (1500.0, 80.0), "c": (5.2, 0.4)},
        # Cryo 03: temp=18.5°C, pres=2.2 bar, vib=0.6, hall=0, curr=2.8A
        {"t": (18.5, 1.8), "p": (2.2, 0.3), "v": (0.6, 0.1), "h": (0.0, 15.0), "c": (2.8, 0.3)},
        # Turbine 04: temp=33°C, pres=3.8 bar, vib=2.2, hall=2200 RPM, curr=7.1A
        {"t": (33.0, 2.5), "p": (3.8, 0.4), "v": (2.2, 0.3), "h": (2200.0, 120.0), "c": (7.1, 0.5)},
    ]

    nom_features = []
    samples_per_zone = n_nominal // len(nominal_zones)
    for z in nominal_zones:
        t = np.random.normal(z["t"][0], z["t"][1], samples_per_zone)
        p = np.random.normal(z["p"][0], z["p"][1], samples_per_zone)
        v = np.clip(np.random.normal(z["v"][0], z["v"][1], samples_per_zone), 0.1, 4.0)
        h = np.clip(np.random.normal(z["h"][0], z["h"][1], samples_per_zone), 0.0, 2500.0)
        c = np.clip(np.random.normal(z["c"][0], z["c"][1], samples_per_zone), 0.5, 7.8)
        zone_data = np.column_stack([t, p, v, h, c])
        nom_features.append(zone_data)

    X_nom = np.vstack(nom_features)
    y_nom = np.zeros(len(X_nom), dtype=int)

    # 2. Generate Realistic Cyber-Physical Anomalies
    anom_samples = []
    n_each = n_anomaly // 5

    # Attack Vector 1: Stuxnet Resonance (High Vibration + RPM Overspeed + Current Spike)
    t1 = np.random.normal(48.0, 6.0, n_each)
    p1 = np.random.normal(4.2, 0.5, n_each)
    v1 = np.random.normal(5.8, 1.2, n_each)  # Extreme vibration > 5.0
    h1 = np.random.normal(3300.0, 200.0, n_each)  # Turbine runaway > 3000 RPM
    c1 = np.random.normal(8.8, 1.0, n_each)
    anom_samples.append(np.column_stack([t1, p1, v1, h1, c1]))

    # Attack Vector 2: False Data Injection / Sensor Spike (Severe Out-of-Bounds)
    t2 = np.random.uniform(70.0, 110.0, n_each)
    p2 = np.random.uniform(9.0, 15.0, n_each)
    v2 = np.random.uniform(4.5, 9.0, n_each)
    h2 = np.random.choice([0.0, 1500.0, 2200.0], n_each) + np.random.normal(0, 50, n_each)
    c2 = np.random.uniform(10.0, 22.0, n_each)
    anom_samples.append(np.column_stack([t2, p2, v2, h2, c2]))

    # Attack Vector 3: Thermal Runaway (High Temperature while pressure rises)
    t3 = np.random.normal(65.0, 5.0, n_each)
    p3 = np.random.normal(7.2, 0.8, n_each)
    v3 = np.random.normal(2.5, 0.5, n_each)
    h3 = np.random.normal(1200.0, 100.0, n_each)
    c3 = np.random.normal(6.5, 0.5, n_each)
    anom_samples.append(np.column_stack([t3, p3, v3, h3, c3]))

    # Attack Vector 4: Hydraulic Overpressure & Burst Hazard
    t4 = np.random.normal(35.0, 4.0, n_each)
    p4 = np.random.uniform(8.5, 13.0, n_each)
    v4 = np.random.normal(3.5, 0.6, n_each)
    h4 = np.random.normal(1600.0, 150.0, n_each)
    c4 = np.random.normal(7.5, 0.8, n_each)
    anom_samples.append(np.column_stack([t4, p4, v4, h4, c4]))

    # Attack Vector 5: Motor Bearing Failure / Cavitation (Extreme Jitter & Current Draw)
    t5 = np.random.normal(52.0, 4.0, n_each)
    p5 = np.random.normal(5.0, 0.8, n_each)
    v5 = np.random.uniform(6.5, 12.0, n_each)
    h5 = np.random.normal(1800.0, 300.0, n_each)
    c5 = np.random.uniform(9.0, 15.0, n_each)
    anom_samples.append(np.column_stack([t5, p5, v5, h5, c5]))

    X_anom = np.vstack(anom_samples)
    y_anom = np.ones(len(X_anom), dtype=int)

    X = np.vstack([X_nom, X_anom])
    y = np.concatenate([y_nom, y_anom])

    # Shuffle dataset
    indices = np.arange(len(X))
    np.random.shuffle(indices)
    return X[indices], y[indices]


def train_and_export_model():
    print("=" * 65)
    print("  Aegis ICS — Industrial Anomaly Detection Model Training")
    print("=" * 65)

    feature_names = ["temperature", "pressure", "vibration", "hall_effect", "current"]
    print(f"[*] Generating synthetic multi-node industrial training data...")
    X, y = generate_synthetic_dataset(n_samples=6000, random_state=42)
    print(f"[*] Dataset shape: {X.shape[0]} records, {X.shape[1]} features")
    print(f"    - Nominal (Class 0): {np.sum(y == 0)} samples")
    print(f"    - Anomaly (Class 1): {np.sum(y == 1)} samples")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print("\n[*] Training Random Forest Classifier (50 estimators, balanced)...")
    model = RandomForestClassifier(
        n_estimators=50,
        max_depth=12,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    # Attach feature names for Scikit-Learn inspectability
    model.feature_names_in_ = np.array(feature_names)

    # Evaluation
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, y_prob)

    print("\n" + "=" * 45 + " EVALUATION REPORT " + "=" * 45)
    print(f"ROC-AUC Score: {auc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Nominal", "Anomaly"]))

    cm = confusion_matrix(y_test, y_pred)
    print("Confusion Matrix:")
    print(f"  [TN={cm[0,0]:4d}, FP={cm[0,1]:4d}]")
    print(f"  [FN={cm[1,0]:4d}, TP={cm[1,1]:4d}]")

    print("\nFeature Importances:")
    for name, imp in zip(feature_names, model.feature_importances_):
        bar = "#" * int(imp * 40)
        print(f"  {name:14s} : {imp:6.3f} | {bar}")

    # Cross-validation
    cv_scores = cross_val_score(model, X, y, cv=5, scoring="f1")
    print(f"\n5-Fold Cross-Validation F1-Score: {cv_scores.mean():.4f} (±{cv_scores.std():.4f})")

    # Export to src/model/rf_model.pkl
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_dir = os.path.join(base_dir, "model")
    os.makedirs(model_dir, exist_ok=True)
    out_path = os.path.join(model_dir, "rf_model.pkl")

    with open(out_path, "wb") as f:
        pickle.dump(model, f)
    print(f"\n[+] Successfully saved model to: {out_path} ({os.path.getsize(out_path):,} bytes)")

    # Test baseline predictions
    import pandas as pd
    test_nominal = pd.DataFrame([[26.0, 4.2, 1.1, 0.0, 4.5]], columns=feature_names)
    test_stuxnet = pd.DataFrame([[52.0, 4.2, 6.2, 3400.0, 9.2]], columns=feature_names)
    prob_nom = model.predict_proba(test_nominal)[0][1]
    prob_stx = model.predict_proba(test_stuxnet)[0][1]

    print("\nSanity Verification Checks:")
    print(f"  Nominal Test Vector  P(anomaly): {prob_nom:.4f} -> Anomaly={prob_nom > 0.5}")
    print(f"  Stuxnet Test Vector  P(anomaly): {prob_stx:.4f} -> Anomaly={prob_stx > 0.5}")
    assert prob_nom < 0.20, "Nominal vector misclassified as anomaly!"
    assert prob_stx > 0.80, "Stuxnet vector misclassified as normal!"
    print("[+] Model sanity verification PASSED.")


if __name__ == "__main__":
    train_and_export_model()
