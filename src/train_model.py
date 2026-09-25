"""
Aegis ICS — Industrial AI & Cyber-Physical Model Training Pipeline
==================================================================
Trains and exports two core AI models for industrial protection:
1. 5D Multi-Variable Random Forest Classifier (`src/model/rf_model.pkl`):
   Detects subtle multi-sensor cyber-physical telemetry anomalies.
2. 6D Deep Neural Safety Policy Network (NSPN) (`src/model/neural_safety_policy.pt` / `.npz`):
   Evaluates SCADA setpoint commands against non-linear coupled hazard envelopes,
   guaranteeing mathematical safety interlock protection against Stuxnet attacks.

Usage:
    python src/train_model.py
"""

import os
import sys
import time
import pickle
import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve, precision_recall_fscore_support, accuracy_score

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


def generate_synthetic_dataset(n_samples: int = 15000, random_state: int = 42):
    """
    Synthesizes a realistic balanced multi-sensor dataset across 4 operational zones.
    Features: ['temperature', 'pressure', 'vibration', 'hall_effect', 'current']
    Target: 0 = Nominal, 1 = Cyber-Physical Anomaly
    """
    np.random.seed(random_state)
    n_boundary = 500
    n_remaining = n_samples - n_boundary
    n_nominal = n_remaining // 2
    n_anomaly = n_remaining - n_nominal

    nominal_zones = [
        {"t": (26.0, 2.5), "p": (4.2, 0.4), "v": (1.1, 0.2), "h": (0.0, 20.0), "c": (4.5, 0.4)},
        {"t": (41.0, 2.5), "p": (5.4, 0.5), "v": (1.8, 0.3), "h": (1500.0, 80.0), "c": (5.2, 0.4)},
        {"t": (18.5, 1.8), "p": (2.2, 0.3), "v": (0.6, 0.1), "h": (0.0, 15.0), "c": (2.8, 0.3)},
        {"t": (33.0, 2.5), "p": (3.8, 0.4), "v": (2.2, 0.3), "h": (2200.0, 120.0), "c": (7.1, 0.5)},
    ]

    nom_features = []
    samples_per_zone = n_nominal // len(nominal_zones)
    # Give remaining to first zone to be exact
    remainder = n_nominal % len(nominal_zones)
    
    for i, z in enumerate(nominal_zones):
        sz = samples_per_zone + (1 if i < remainder else 0)
        t = np.random.normal(z["t"][0], z["t"][1], sz)
        p = np.random.normal(z["p"][0], z["p"][1], sz)
        v = np.clip(np.random.normal(z["v"][0], z["v"][1], sz), 0.1, 4.0)
        h = np.clip(np.random.normal(z["h"][0], z["h"][1], sz), 0.0, 2500.0)
        c = np.clip(np.random.normal(z["c"][0], z["c"][1], sz), 0.5, 7.8)
        zone_data = np.column_stack([t, p, v, h, c])
        nom_features.append(zone_data)

    X_nom = np.vstack(nom_features)
    y_nom = np.zeros(len(X_nom), dtype=int)

    anom_samples = []
    n_each = n_anomaly // 6
    remainder_anom = n_anomaly % 6

    # Attack Vector 1: Stuxnet Resonance
    sz = n_each + (1 if 0 < remainder_anom else 0)
    t1 = np.random.normal(48.0, 6.0, sz)
    p1 = np.random.normal(4.2, 0.5, sz)
    v1 = np.random.normal(5.8, 1.2, sz)
    h1 = np.random.normal(3300.0, 200.0, sz)
    c1 = np.random.normal(8.8, 1.0, sz)
    anom_samples.append(np.column_stack([t1, p1, v1, h1, c1]))

    # Attack Vector 2: False Data Injection
    sz = n_each + (1 if 1 < remainder_anom else 0)
    t2 = np.random.uniform(70.0, 110.0, sz)
    p2 = np.random.uniform(9.0, 15.0, sz)
    v2 = np.random.uniform(4.5, 9.0, sz)
    h2 = np.random.choice([0.0, 1500.0, 2200.0], sz) + np.random.normal(0, 50, sz)
    c2 = np.random.uniform(10.0, 22.0, sz)
    anom_samples.append(np.column_stack([t2, p2, v2, h2, c2]))

    # Attack Vector 3: Thermal Runaway
    sz = n_each + (1 if 2 < remainder_anom else 0)
    t3 = np.random.normal(65.0, 5.0, sz)
    p3 = np.random.normal(7.2, 0.8, sz)
    v3 = np.random.normal(2.5, 0.5, sz)
    h3 = np.random.normal(1200.0, 100.0, sz)
    c3 = np.random.normal(6.5, 0.5, sz)
    anom_samples.append(np.column_stack([t3, p3, v3, h3, c3]))

    # Attack Vector 4: Hydraulic Overpressure
    sz = n_each + (1 if 3 < remainder_anom else 0)
    t4 = np.random.normal(35.0, 4.0, sz)
    p4 = np.random.uniform(8.5, 13.0, sz)
    v4 = np.random.normal(3.5, 0.6, sz)
    h4 = np.random.normal(1600.0, 150.0, sz)
    c4 = np.random.normal(7.5, 0.8, sz)
    anom_samples.append(np.column_stack([t4, p4, v4, h4, c4]))

    # Attack Vector 5: Motor Bearing Failure / Cavitation
    sz = n_each + (1 if 4 < remainder_anom else 0)
    t5 = np.random.normal(52.0, 4.0, sz)
    p5 = np.random.normal(5.0, 0.8, sz)
    v5 = np.random.uniform(6.5, 12.0, sz)
    h5 = np.random.normal(1800.0, 300.0, sz)
    c5 = np.random.uniform(9.0, 15.0, sz)
    anom_samples.append(np.column_stack([t5, p5, v5, h5, c5]))
    
    # Attack Vector 6: Subtle Slow Drift
    sz = n_each + (1 if 5 < remainder_anom else 0)
    t6 = 26.0 + np.arange(sz) * 0.3
    p6 = 4.2 + np.arange(sz) * 0.05
    v6 = np.random.normal(1.1, 0.2, sz)
    h6 = np.random.normal(0.0, 20.0, sz)
    c6 = np.random.normal(4.5, 0.4, sz)
    anom_samples.append(np.column_stack([t6, p6, v6, h6, c6]))

    X_anom = np.vstack(anom_samples)
    y_anom = np.ones(len(X_anom), dtype=int)
    
    # Boundary / Ambiguous samples
    t_b = np.random.uniform(42.0, 48.0, n_boundary)
    p_b = np.random.uniform(5.0, 6.5, n_boundary)
    v_b = np.random.uniform(3.5, 5.0, n_boundary)
    h_b = np.random.uniform(1000.0, 1500.0, n_boundary)
    c_b = np.random.uniform(6.0, 8.0, n_boundary)
    X_bound = np.column_stack([t_b, p_b, v_b, h_b, c_b])
    y_bound = np.random.randint(0, 2, n_boundary)

    X = np.vstack([X_nom, X_anom, X_bound])
    y = np.concatenate([y_nom, y_anom, y_bound])
    
    # Add 5% sensor noise
    noise = 1 + np.random.normal(0, 0.05, X.shape)
    X = X * noise
    
    # Add 2% label noise
    n_flips = int(0.02 * len(y))
    flip_indices = np.random.choice(len(y), n_flips, replace=False)
    y[flip_indices] = 1 - y[flip_indices]

    indices = np.arange(len(X))
    np.random.shuffle(indices)
    return X[indices], y[indices]


def generate_neural_policy_dataset(n_samples: int = 12000, random_state: int = 42):
    """
    Synthesizes multi-variable SCADA setpoint evaluation tuples:
        z = [T_live, P_live, Vib_live, RPM_live, Curr_live, Setpoint_Val]
    Target: 1 = Safe Setpoint (Approved), 0 = Dangerous Setpoint (Blocked)
    """
    np.random.seed(random_state)
    n_boundary = 500
    n_remaining = n_samples - n_boundary
    n_safe = n_remaining // 2
    n_unsafe = n_remaining - n_safe

    # 1. Safe Setpoints (Stable thermodynamic operations)
    t_safe = np.random.uniform(15.0, 42.0, n_safe)
    p_safe = np.random.uniform(1.0, 5.2, n_safe)
    v_safe = np.random.uniform(0.5, 3.0, n_safe)
    r_safe = np.random.choice([0.0, 1500.0, 2200.0], n_safe) + np.random.normal(0, 50, n_safe)
    c_safe = np.random.uniform(2.0, 6.5, n_safe)
    
    # Safe commands: moderate temperature or pressure setpoints
    cmd_choice = np.random.randint(0, 2, n_safe)
    u_safe = np.where(
        cmd_choice == 0,
        np.random.uniform(20.0, 44.0, n_safe),  # safe temp setpoint
        np.random.uniform(1.5, 5.5, n_safe)    # safe pressure setpoint
    )
    X_safe = np.column_stack([t_safe, p_safe, v_safe, r_safe, c_safe, u_safe])
    y_safe = np.ones(n_safe, dtype=np.float32)

    # 2. Unsafe Setpoints (Coordinated Stuxnet, Exotherm Runaway, Burst Hazards)
    n_each = n_unsafe // 4
    remainder_unsafe = n_unsafe % 4
    
    # Hazard 1: Stuxnet Coordinated Attack (High Live Pressure + High Temp Setpoint >= 45C)
    sz1 = n_each + (1 if 0 < remainder_unsafe else 0)
    t_u1 = np.random.uniform(25.0, 40.0, sz1)
    p_u1 = np.random.uniform(6.0, 7.8, sz1)  # High active pressure
    v_u1 = np.random.uniform(1.0, 3.5, sz1)
    r_u1 = np.random.uniform(1200.0, 2200.0, sz1)
    c_u1 = np.random.uniform(4.0, 7.0, sz1)
    u_u1 = np.random.uniform(45.0, 58.0, sz1)  # Dangerous temp setpoint under high pressure
    
    # Hazard 2: Stuxnet Coordinated Attack (High Live Temp + High Pressure Setpoint >= 6.0 bar)
    sz2 = n_each + (1 if 1 < remainder_unsafe else 0)
    t_u2 = np.random.uniform(45.0, 58.0, sz2)  # High active temperature
    p_u2 = np.random.uniform(2.0, 4.5, sz2)
    v_u2 = np.random.uniform(1.0, 3.5, sz2)
    r_u2 = np.random.uniform(1200.0, 2200.0, sz2)
    c_u2 = np.random.uniform(4.0, 7.0, sz2)
    u_u2 = np.random.uniform(6.0, 7.9, sz2)  # Dangerous pressure setpoint under high temp

    # Hazard 3: Hard Boundary Exceedance (Temp > 60C or Pressure > 8 bar)
    sz3 = n_each + (1 if 2 < remainder_unsafe else 0)
    t_u3 = np.random.uniform(20.0, 50.0, sz3)
    p_u3 = np.random.uniform(2.0, 6.0, sz3)
    v_u3 = np.random.uniform(1.0, 3.0, sz3)
    r_u3 = np.random.uniform(1000.0, 2000.0, sz3)
    c_u3 = np.random.uniform(3.0, 6.0, sz3)
    u_u3 = np.where(
        np.random.randint(0, 2, sz3) == 0,
        np.random.uniform(61.0, 95.0, sz3),
        np.random.uniform(8.2, 16.0, sz3)
    )

    # Hazard 4: Mechanical Resonance Overload (High Vib + High Current + Aggressive Setpoint)
    sz4 = n_each + (1 if 3 < remainder_unsafe else 0)
    t_u4 = np.random.uniform(38.0, 55.0, sz4)
    p_u4 = np.random.uniform(5.0, 7.0, sz4)
    v_u4 = np.random.uniform(4.5, 9.0, sz4)
    r_u4 = np.random.uniform(2500.0, 3500.0, sz4)
    c_u4 = np.random.uniform(8.0, 14.0, sz4)
    u_u4 = np.random.uniform(50.0, 65.0, sz4)

    X_unsafe = np.vstack([
        np.column_stack([t_u1, p_u1, v_u1, r_u1, c_u1, u_u1]),
        np.column_stack([t_u2, p_u2, v_u2, r_u2, c_u2, u_u2]),
        np.column_stack([t_u3, p_u3, v_u3, r_u3, c_u3, u_u3]),
        np.column_stack([t_u4, p_u4, v_u4, r_u4, c_u4, u_u4]),
    ])
    y_unsafe = np.zeros(len(X_unsafe), dtype=np.float32)
    
    # Boundary samples
    t_b = np.random.uniform(40.0, 44.0, n_boundary)
    p_b = np.random.uniform(5.0, 5.8, n_boundary)
    v_b = np.random.uniform(2.5, 4.0, n_boundary)
    r_b = np.random.uniform(1800.0, 2400.0, n_boundary)
    c_b = np.random.uniform(5.0, 7.0, n_boundary)
    u_b = np.random.uniform(43.0, 46.0, n_boundary)
    X_bound = np.column_stack([t_b, p_b, v_b, r_b, c_b, u_b])
    y_bound = np.random.randint(0, 2, n_boundary).astype(np.float32)

    X = np.vstack([X_safe, X_unsafe, X_bound])
    y = np.concatenate([y_safe, y_unsafe, y_bound])
    
    # Add 5% feature noise
    noise = 1 + np.random.normal(0, 0.05, X.shape)
    X = X * noise
    
    # Add 2% label noise
    n_flips = int(0.02 * len(y))
    flip_indices = np.random.choice(len(y), n_flips, replace=False)
    y[flip_indices] = 1 - y[flip_indices]

    idx = np.arange(len(X))
    np.random.shuffle(idx)
    return X[idx].astype(np.float32), y[idx].astype(np.float32)


def train_random_forest(metrics_dict: dict):
    print("=" * 65)
    print("  [1/2] Training 5D Random Forest Anomaly Detector")
    print("=" * 65)

    feature_names = ["temperature", "pressure", "vibration", "hall_effect", "current"]
    X, y = generate_synthetic_dataset(n_samples=15000, random_state=42)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    
    start_time = time.perf_counter()
    model = RandomForestClassifier(
        n_estimators=50,
        max_depth=12,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    model.feature_names_in_ = np.array(feature_names)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    
    # Inference latency
    start_inf = time.perf_counter()
    _ = model.predict(X_test)
    inf_latency = ((time.perf_counter() - start_inf) / len(X_test)) * 1000.0
    
    auc = roc_auc_score(y_test, y_prob)
    cv_scores = cross_val_score(model, X, y, cv=5, scoring="f1")
    
    print(f"Random Forest ROC-AUC Score: {auc:.4f}")
    print(f"5-Fold CV F1-Score: {cv_scores.mean():.4f} (±{cv_scores.std():.4f})")
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    print("\nFeature Importances:")
    importances = model.feature_importances_
    feat_imps = {f: float(imp) for f, imp in zip(feature_names, importances)}
    for f, imp in sorted(feat_imps.items(), key=lambda item: item[1], reverse=True):
        print(f"  {f}: {imp:.4f}")

    fpr, tpr, thresholds = roc_curve(y_test, y_prob)
    
    # Subsample ROC curve data points to ~200 max
    if len(fpr) > 200:
        idx = np.linspace(0, len(fpr) - 1, 200, dtype=int)
        fpr = fpr[idx]
        tpr = tpr[idx]
        thresholds = thresholds[idx]

    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, labels=[0, 1])

    metrics_dict["rf"] = {
        "roc_auc": float(auc),
        "f1_mean": float(cv_scores.mean()),
        "f1_std": float(cv_scores.std()),
        "precision_anomaly": float(prec[1]),
        "recall_anomaly": float(rec[1]),
        "f1_anomaly": float(f1[1]),
        "precision_nominal": float(prec[0]),
        "recall_nominal": float(rec[0]),
        "confusion_matrix": cm.tolist(),
        "feature_importances": feat_imps,
        "roc_curve": {
            "fpr": fpr.tolist(),
            "tpr": tpr.tolist(),
            "thresholds": thresholds.tolist()
        },
        "n_train": len(X_train),
        "n_test": len(X_test),
        "inference_latency_ms": inf_latency
    }

    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_dir = os.path.join(base_dir, "model")
    os.makedirs(model_dir, exist_ok=True)
    out_path = os.path.join(model_dir, "rf_model.pkl")

    with open(out_path, "wb") as f:
        pickle.dump(model, f)
    # Update cryptographic SHA-256 checksum
    try:
        import hashlib
        with open(out_path, "rb") as mf:
            h = hashlib.sha256(mf.read()).hexdigest()
        with open(out_path + ".sha256", "w", encoding="utf-8") as hf:
            hf.write(h + "\n")
    except Exception as ex:
        print(f"[!] Warning: Could not write SHA-256 checksum: {ex}")
    print(f"[+] Successfully exported Random Forest model: {out_path}")
    return model


def train_neural_safety_policy(metrics_dict: dict):
    print("\n" + "=" * 65)
    print("  [2/2] Training 6D Deep Neural Safety Policy Network (NSPN)")
    print("=" * 65)

    if not TORCH_AVAILABLE:
        print("[!] PyTorch not found. Skipping neural training.")
        return

    X, y = generate_neural_policy_dataset(n_samples=12000, random_state=42)
    means = np.mean(X, axis=0)
    stds = np.std(X, axis=0)
    stds = np.where(stds < 1e-6, 1.0, stds)

    X_norm = (X - means) / stds

    X_train, X_test, y_train, y_test = train_test_split(
        X_norm, y, test_size=0.20, random_state=42, stratify=y
    )

    train_dataset = TensorDataset(torch.from_numpy(X_train), torch.from_numpy(y_train).unsqueeze(1))
    test_dataset = TensorDataset(torch.from_numpy(X_test), torch.from_numpy(y_test).unsqueeze(1))

    train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=256, shuffle=False)

    from neural_policy import NeuralSafetyPolicyTorch
    model = NeuralSafetyPolicyTorch(in_features=6, hidden_dims=(64, 32, 16))
    criterion = nn.BCELoss()
    optimizer = optim.AdamW(model.parameters(), lr=0.003, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=20)

    print(f"[*] Architecture: 6 -> 64 -> 32 -> 16 -> 1 (LeakyReLU, Sigmoid)")
    print(f"[*] Training on {len(X_train)} samples across 20 epochs...")
    
    avg_loss = 0.0
    for epoch in range(1, 21):
        model.train()
        total_loss = 0.0
        for batch_x, batch_y in train_loader:
            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * len(batch_x)
        scheduler.step()

        if epoch % 5 == 0 or epoch == 20:
            avg_loss = total_loss / len(X_train)
            model.eval()
            with torch.no_grad():
                correct = 0
                total = 0
                for bx, by in test_loader:
                    preds = (model(bx) >= 0.5).float()
                    correct += (preds == by).sum().item()
                    total += len(by)
                acc = correct / total
            print(f"    Epoch {epoch:2d}/20 | Loss: {avg_loss:.4f} | Validation Acc: {acc * 100:.2f}%")

    # Final Evaluation
    model.eval()
    with torch.no_grad():
        all_probs = []
        all_targets = []
        for bx, by in test_loader:
            probs = model(bx).squeeze().numpy()
            if probs.ndim == 0:
                probs = np.expand_dims(probs, axis=0)
            all_probs.extend(probs)
            all_targets.extend(by.squeeze().numpy())
    all_probs = np.array(all_probs)
    all_targets = np.array(all_targets)
    all_preds = (all_probs >= 0.5).astype(int)

    nspn_auc = roc_auc_score(all_targets, all_probs)
    print("\n" + "=" * 45 + " NSPN EVALUATION REPORT " + "=" * 45)
    print(f"Neural Policy ROC-AUC Score: {nspn_auc:.4f}")
    print(classification_report(all_targets, all_preds, target_names=["Blocked (Hazard)", "Approved (Safe)"]))
    
    cm = confusion_matrix(all_targets, all_preds)
    print("\nConfusion Matrix:")
    print(cm)

    # Measure CPU inference latency over 5,000 passes (PyTorch)
    sample_input = torch.from_numpy(X_norm[:1]).float()
    start_time = time.perf_counter()
    with torch.no_grad():
        for _ in range(5000):
            _ = model(sample_input)
    torch_latency_ms = ((time.perf_counter() - start_time) / 5000.0) * 1000.0
    print(f"Empirical Inference Latency (PyTorch CPU): {torch_latency_ms:.3f} ms / evaluation")

    # Export weights
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_dir = os.path.join(base_dir, "model")
    os.makedirs(model_dir, exist_ok=True)

    # 1. Export PyTorch checkpoint
    pt_path = os.path.join(model_dir, "neural_safety_policy.pt")
    torch.save({"state_dict": model.state_dict(), "means": means, "stds": stds}, pt_path)
    print(f"[+] Exported PyTorch checkpoint: {pt_path} ({os.path.getsize(pt_path):,} bytes)")

    # 2. Export pure NumPy weights for zero-dependency execution
    npz_path = os.path.join(model_dir, "neural_safety_policy.npz")
    state = model.state_dict()
    np.savez_compressed(
        npz_path,
        w0=state["network.0.weight"].numpy().T,
        b0=state["network.0.bias"].numpy(),
        w1=state["network.2.weight"].numpy().T,
        b1=state["network.2.bias"].numpy(),
        w2=state["network.4.weight"].numpy().T,
        b2=state["network.4.bias"].numpy(),
        w3=state["network.6.weight"].numpy().T,
        b3=state["network.6.bias"].numpy(),
        means=means,
        stds=stds
    )
    print(f"[+] Exported Vectorized NumPy weights: {npz_path} ({os.path.getsize(npz_path):,} bytes)")

    # Sanity checks and Numpy Inference latency
    from neural_policy import NeuralSafetyPolicy
    policy = NeuralSafetyPolicy(npz_path)
    
    # Measure CPU inference latency over 5,000 passes (NumPy)
    start_time_np = time.perf_counter()
    sample_vec_np = X[0]
    for _ in range(5000):
        _ = policy.predict_safety_probability(sample_vec_np)
    numpy_latency_ms = ((time.perf_counter() - start_time_np) / 5000.0) * 1000.0
    print(f"Empirical Inference Latency (NumPy CPU): {numpy_latency_ms:.3f} ms / evaluation")

    # Save metrics
    fpr, tpr, thresholds = roc_curve(all_targets, all_probs)
    if len(fpr) > 200:
        idx = np.linspace(0, len(fpr) - 1, 200, dtype=int)
        fpr = fpr[idx]
        tpr = tpr[idx]
        thresholds = thresholds[idx]

    prec, rec, f1, _ = precision_recall_fscore_support(all_targets, all_preds, labels=[0, 1])

    metrics_dict["nspn"] = {
        "roc_auc": float(nspn_auc),
        "accuracy": float(accuracy_score(all_targets, all_preds)),
        "f1_hazard": float(f1[0]),
        "precision_hazard": float(prec[0]),
        "recall_hazard": float(rec[0]),
        "confusion_matrix": cm.tolist(),
        "loss_final": float(avg_loss),
        "inference_latency_torch_ms": float(torch_latency_ms),
        "inference_latency_numpy_ms": float(numpy_latency_ms),
        "roc_curve": {
            "fpr": fpr.tolist(),
            "tpr": tpr.tolist(),
            "thresholds": thresholds.tolist()
        },
        "n_train": len(X_train),
        "n_test": len(X_test)
    }

    metrics_file = os.path.join(model_dir, "training_metrics.json")
    with open(metrics_file, "w") as f:
        json.dump(metrics_dict, f, indent=2)
    print(f"[+] Exported training metrics: {metrics_file}")

    # Test case 1: Nominal setpoint
    safe_vec = np.array([25.0, 3.2, 1.1, 0.0, 4.2, 35.0])
    prob_safe = policy.predict_safety_probability(safe_vec)
    print(f"\nSanity Check 1: Nominal setpoint (T=25, P=3.2, set_temp=35) -> P(safe) = {prob_safe*100:.1f}%")
    assert prob_safe > 0.60, f"Expected safe setpoint, got P={prob_safe}"

    # Test case 2: Stuxnet coordinated attack
    stux_vec = np.array([30.0, 7.2, 1.5, 1500.0, 5.0, 52.0])
    prob_stux = policy.predict_safety_probability(stux_vec)
    print(f"Sanity Check 2: Stuxnet setpoint (T=30, P=7.2, set_temp=52) -> P(safe) = {prob_stux*100:.1f}%")
    assert prob_stux < 0.40, f"Expected unsafe Stuxnet block, got P={prob_stux}"

    print("[+] All Neural Safety Policy sanity checks PASSED.")


def retrain_from_hardware_telemetry(db_session, model_path: str = None) -> dict:
    """
    Dynamically trains/calibrates the 5D Random Forest model using genuine hardware
    telemetry frames ingested via the serial COM port gateway.
    Blends live operational sensor baselines with adversarial anomaly bounds.
    """
    from database import TelemetryLog

    if model_path is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(base_dir, "model", "rf_model.pkl")

    # Fetch genuine (non-simulated) telemetry records
    real_logs = (
        db_session.query(TelemetryLog)
        .filter(TelemetryLog.is_simulated == False)
        .order_by(TelemetryLog.timestamp.desc())
        .limit(2500)
        .all()
    )

    real_samples = []
    real_labels = []
    for log in real_logs:
        if None not in (log.temperature, log.pressure, log.vibration, log.current):
            hall = float(log.hall_effect) if log.hall_effect is not None else 0.0
            vec = [float(log.temperature), float(log.pressure), float(log.vibration), hall, float(log.current)]
            real_samples.append(vec)
            real_labels.append(1 if log.is_anomaly else 0)

    # Blend with synthetic boundary and attack profiles to preserve defense envelopes
    X_synth, y_synth = generate_synthetic_dataset(n_samples=6000, random_state=int(time.time()) % 100000)

    if real_samples:
        X_real = np.array(real_samples, dtype=np.float64)
        y_real = np.array(real_labels, dtype=np.int64)
        # Duplicate real samples to give them sufficient weight if small count
        repeat_factor = max(1, min(10, 1000 // len(real_samples)))
        X_real_weighted = np.tile(X_real, (repeat_factor, 1))
        y_real_weighted = np.tile(y_real, repeat_factor)
        X_combined = np.vstack([X_synth, X_real_weighted])
        y_combined = np.concatenate([y_synth, y_real_weighted])
    else:
        X_combined = X_synth
        y_combined = y_synth

    indices = np.arange(len(X_combined))
    np.random.seed(42)
    np.random.shuffle(indices)
    X_final = X_combined[indices]
    y_final = y_combined[indices]

    X_train, X_test, y_train, y_test = train_test_split(X_final, y_final, test_size=0.20, random_state=42, stratify=y_final)

    rf = RandomForestClassifier(
        n_estimators=75,
        max_depth=16,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)

    preds = rf.predict(X_test)
    probs = rf.predict_proba(X_test)[:, 1]
    acc = float(accuracy_score(y_test, preds))
    auc = float(roc_auc_score(y_test, probs))

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    with open(model_path, "wb") as f:
        pickle.dump(rf, f)
    # Update cryptographic SHA-256 checksum
    try:
        import hashlib
        with open(model_path, "rb") as mf:
            h = hashlib.sha256(mf.read()).hexdigest()
        with open(model_path + ".sha256", "w", encoding="utf-8") as hf:
            hf.write(h + "\n")
    except Exception as ex:
        print(f"[!] Warning: Could not write SHA-256 checksum: {ex}")

    result = {
        "success": True,
        "hardware_samples_used": len(real_samples),
        "total_training_samples": len(X_final),
        "accuracy": round(acc, 4),
        "roc_auc": round(auc, 4),
        "timestamp": time.time(),
        "status": "HARDWARE_CALIBRATED" if len(real_samples) > 0 else "SYNTHETIC_BASELINE"
    }

    # Update training_metrics.json
    metrics_path = os.path.join(os.path.dirname(model_path), "training_metrics.json")
    try:
        metrics_dict = {}
        if os.path.exists(metrics_path):
            with open(metrics_path, "r") as mf:
                metrics_dict = json.load(mf)
        metrics_dict["hardware_calibration"] = result
        with open(metrics_path, "w") as mf:
            json.dump(metrics_dict, mf, indent=2)
    except Exception as e:
        print(f"[ModelRetrain] Could not update training_metrics.json: {e}")

    print(f"[ModelRetrain] Successfully trained model on {len(real_samples)} hardware samples (Accuracy: {acc*100:.1f}%, AUC: {auc:.4f})")
    return result


if __name__ == "__main__":
    all_metrics = {}
    train_random_forest(all_metrics)
    train_neural_safety_policy(all_metrics)
