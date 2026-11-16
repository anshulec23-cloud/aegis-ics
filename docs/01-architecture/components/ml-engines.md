# Detection and safety ML

Three models with different jobs:

| | Random Forest anomaly detector | Attack-type classifier (detection brain) | Neural Safety Policy Network (NSPN) |
|---|---|---|---|
| Question | "Does this **telemetry** look abnormal?" | "**What kind** of attack is this?" | "Is this **command** safe in the current state?" |
| Input | `[T, P, V, RPM, I]` | `[T, P, V, RPM, I]` | `[T, P, V, RPM, I, setpoint_value]` |
| Output | P(anomaly) | class ∈ {normal, fdi_spike, stuxnet, thermal_drift, sensor_fault} + confidence | P(safe) |
| Runtime | `LocalRFModel` in `app.py` | `detection.py` | `NeuralSafetyPolicy` in `neural_policy.py` |
| Artifact | `src/model/rf_model.pkl` (+ `.sha256`) | `src/model/attack_classifier.pkl` (+ `.sha256` + `_meta.json`) | `src/model/neural_safety_policy.npz` (preferred), `.pt` |
| Threshold | 0.5 (vote adds 0.6 to the anomaly score) | 0.55 confidence to override the audit view; abstains on `normal`/protocol attacks | 0.5 |

The three play distinct roles: the RF (+ rules) decides **that** a frame is anomalous and the trust
score drives **quarantine**; the attack-type classifier then **names** the attack so the loss engine
can price it and the report can recommend mitigation; the NSPN gates **commands** before they reach a
device.

## Random Forest
- **Training** (`train_model.train_random_forest`): 15,000 synthetic samples. Nominal clusters for the four node baselines; six anomaly families (Stuxnet resonance, false data injection, thermal runaway, hydraulic over-pressure, bearing failure, slow drift); 500 random-label boundary samples; ×(1+N(0,0.05)) noise; 2 % label flips. Stratified split, 5-fold CV, metrics saved to `model/training_metrics.json`.
- **Inference**: if the sklearn model exposes `estimators_`, the wrapper caches each `tree_` and walks the trees in pure Python (`fast_trees`). This avoids per-call sklearn overhead. The RF only runs when T, P, V and I are all present; missing RPM is set to 0.
- **Combination with rules**: the RF vote and each rule breach each add 0.6, so any single signal flags the frame.
- **Online retrain** (`retrain_from_hardware_telemetry`, `POST /api/model/retrain`): latest 2,500 non-simulated rows (with all four core sensors) + 6,000 fresh synthetic samples. Real rows are tiled up to 10×. Labels come from the stored `is_anomaly` flag. Writes the pickle, rewrites the `.sha256` and updates the metrics JSON.

## Attack-type classifier (detection brain)
- **Training** (`train_classifier.py`, `python src/train_classifier.py`): a 5-class `RandomForestClassifier` (120 trees) on ~24k balanced synthetic samples. Each class is a sensor envelope centred on the malicious profiles the red-team harness injects (`redteam._MALICIOUS`), plus an ambiguous boundary band between the elevated-temperature classes with random labels, 6 % sensor noise and 1.5 % label flips → **96.3 % accuracy / 0.96 macro-F1**. The script sanity-checks that the exact harness vectors classify correctly and refuses to export if not.
- **Runtime** (`detection.py`): loads the pickle read-only, verifying the SHA-256 sidecar before unpickling (same pattern as the RF). `classify_vector`/`classify_row` return `{attack_type, confidence, scores}`. `detect_device(db, id)` reads a device's recent telemetry (newest flagged-anomalous frame preferred), classifies it, and returns a detection only when the class is a **physical** attack above the confidence threshold — otherwise `None`.
- **Integration**: `app._current_detections` runs the classifier over quarantined + recently anomalous devices and hands `{device_id: {attack_type, confidence, source:"ml_classifier"}}` to `loss_engine.assess`. Protocol attacks (replay, signature tampering, DoS) produce no malicious telemetry, so the classifier abstains and the loss engine falls back to the audit-trail heuristic. `/api/model/status` returns the model card (`detection.status()`).
- **Division of labour**: this names attacks; it does **not** trigger isolation — the deterministic rules + trust score do. That keeps a mute/compromised classifier from ever *weakening* the defensive response.

## NSPN
- **Architecture**: Linear(6,64) → LeakyReLU(0.1) → Linear(64,32) → LeakyReLU → Linear(32,16) → LeakyReLU → Linear(16,1) → Sigmoid. Inputs are z-scored with stored `means`/`stds`.
- **Training** (`train_neural_safety_policy`, requires PyTorch): synthetic state–action tuples. Safe: moderate states with moderate setpoints. Unsafe: four hazard families (high temp setpoint under high pressure, high pressure setpoint under high temperature, …). Weights are exported to `.npz` for the dependency-free NumPy forward pass.
- **Loading**: `.npz` with `allow_pickle=False` first, then `.pt` with `weights_only=True`. If neither loads, a hard-coded heuristic is used.
- **Overrides**: after inference, `set_temp ≥ 45 ∧ P ≥ 6` or `set_pressure ≥ 6 ∧ T ≥ 45` clamps P(safe) to ≤ 0.08.

## Scientific caveats (read before citing numbers)
1. The data is synthetic, with hand-placed cluster means far apart. The reported AUCs/accuracies (RF and attack classifier alike) measure how well the model recovers the generator, not real-world detection performance. The attack classifier's envelopes are deliberately centred on the harness profiles, so a drill confirms the wiring end-to-end but is not an independent benchmark.
2. The NSPN input doesn't encode the command type, so a 7.5 °C temperature setpoint and a 7.5 bar pressure setpoint are the same vector (debug report F6).
3. Online retraining is self-labelled (confirmation bias) and can be poisoned by anyone who can inject telemetry.
4. Model artifacts are pickles. The SHA-256 sidecar is stored and rewritten next to them, so it detects corruption, not tampering.

## Reproducing the models
```bash
pip install torch               # only needed for NSPN training
python src/train_model.py       # writes rf_model + NSPN to src/model/*
python src/train_classifier.py  # writes attack_classifier.pkl (+ sha256 + meta)
```
The benchmark figures are regenerated by `tests/benchmark_suite.py`, then `tests/generate_graphs.py`, which writes to `docs/figures/`.
