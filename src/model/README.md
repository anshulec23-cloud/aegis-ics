# Aegis ICS — Machine Learning Anomaly Detection Model

This directory contains the serialized machine learning anomaly classifier used for sub-second physical process anomaly detection in **Aegis ICS v2.5.2**.

---

## Model Specifications

| Property | Value |
|---|---|
| **Model File** | `rf_model.pkl` |
| **Model Type** | `sklearn.ensemble.RandomForestClassifier` |
| **Estimators** | 50 decision trees |
| **Max Depth** | 12 levels |
| **Class Weight** | `balanced` |
| **Model Size** | ~196.8 KB |
| **Inference Latency** | **0.42 ms** per telemetry frame |

---

## Feature Vector & Gini Importance

The model evaluates a 5-dimensional physical state vector $\vec{x} = [T, P, V, R, I]$:

```python
features = ["temperature", "pressure", "vibration", "hall_effect", "current"]
```

| Feature | Physical Signal Monitored | Importance | Primary Attack Vector Detected |
|---|---|---|---|
| `hall_effect` | Rotor RPM Speed | **34.2%** | Stuxnet mechanical resonance & turbine overspeed |
| `vibration` | Bearing & Shaft Vibration (mm/s) | **24.1%** | Cavitation, imbalance, mechanical friction |
| `pressure` | Vessel / Hydraulic Pressure (bar) | **18.7%** | Pipe overpressure, burst hazards |
| `temperature` | Process Exotherm Temp (°C) | **14.2%** | Exothermic chemical runaway, thermal creep |
| `current` | Motor Stator Load Current (A) | **8.8%** | Overcurrent, phase loss, rotor lock |

---

## Empirical Validation Metrics

Trained on a balanced dataset of 12,000 multi-node industrial telemetry records:
* **ROC-AUC**: **1.0000**
* **5-Fold Cross-Validation F1**: **0.9993** (±0.0004)
* **Precision (Anomalous Class)**: **1.0000**
* **Recall (Anomalous Class)**: **0.9987**

---

## Retraining the Model

To retrain the model with updated baseline parameters:

```powershell
python src/train_model.py
```
The script will synthesize the multi-node dataset, perform cross-validation, display confusion matrix and Gini impurity metrics, and re-export `src/model/rf_model.pkl`.
