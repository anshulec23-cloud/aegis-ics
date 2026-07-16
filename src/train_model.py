#!/usr/bin/env python3
"""
Aegis ICS V2 — Random Forest Classifier Model Trainer

Trains a 5-feature Random Forest model (Temperature, Pressure, Vibration, Hall Effect, Current)
using a synthesized dataset containing normal operations and cybersecurity stress anomalies.
"""

import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Features: [temperature, pressure, vibration, hall_effect, current]
def generate_synthetic_data(num_samples=2000):
    np.random.seed(42)
    
    # 1. Normal Operations (PLC Pump ESP32_001)
    # Temp: 20-40C, Pressure: 3-5 bar, Vibration: 0.5-2.0, Hall: 0, Current: 3.5-5.5 Amps
    n_normal_plc = num_samples // 4
    normal_plc = pd.DataFrame({
        "temperature": np.random.uniform(20.0, 40.0, n_normal_plc),
        "pressure": np.random.uniform(3.0, 5.0, n_normal_plc),
        "vibration": np.random.uniform(0.5, 2.0, n_normal_plc),
        "hall_effect": np.zeros(n_normal_plc),
        "current": np.random.uniform(3.5, 5.5, n_normal_plc),
        "label": 0
    })

    # 2. Normal Operations (Non-PLC Stepper ESP32_002)
    # Temp: 0C, Pressure: 0.5-1.5 (Vib), Vibration: 0.5-1.5, Hall: 800-1500 RPM, Current: 0 Amps
    n_normal_stepper = num_samples // 4
    normal_stepper = pd.DataFrame({
        "temperature": np.zeros(n_normal_stepper),
        "pressure": np.random.uniform(0.5, 1.5, n_normal_stepper),
        "vibration": np.random.uniform(0.5, 1.5, n_normal_stepper),
        "hall_effect": np.random.uniform(800.0, 1500.0, n_normal_stepper),
        "current": np.zeros(n_normal_stepper),
        "label": 0
    })

    # 3. Anomalous Stuxnet & Overpressure (PLC Pump)
    # Coordinated high temperature (> 45C) + high pressure (> 6 bar) + high vibration
    n_anomaly_plc = num_samples // 4
    anomaly_plc = pd.DataFrame({
        "temperature": np.random.uniform(46.0, 58.0, n_anomaly_plc),
        "pressure": np.random.uniform(6.1, 7.8, n_anomaly_plc),
        "vibration": np.random.uniform(4.0, 8.0, n_anomaly_plc),
        "hall_effect": np.zeros(n_anomaly_plc),
        "current": np.random.uniform(7.0, 10.0, n_anomaly_plc),
        "label": 1
    })

    # 4. Stepper Motor Anomaly (Non-PLC)
    # Vibration spikes (> 6.0 g) or excessive RPM (> 1800)
    n_anomaly_stepper = num_samples // 4
    anomaly_stepper = pd.DataFrame({
        "temperature": np.zeros(n_anomaly_stepper),
        "pressure": np.random.uniform(6.0, 9.0, n_anomaly_stepper), # Vib mapped to pressure
        "vibration": np.random.uniform(6.0, 9.0, n_anomaly_stepper),
        "hall_effect": np.random.uniform(1850.0, 2400.0, n_anomaly_stepper),
        "current": np.zeros(n_anomaly_stepper),
        "label": 1
    })

    df = pd.concat([normal_plc, normal_stepper, anomaly_plc, anomaly_stepper], ignore_index=True)
    # Add random noise/shuffling
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df

def main():
    print("[Trainer] Generating synthetic dataset...")
    df = generate_synthetic_data(4000)
    
    X = df[["temperature", "pressure", "vibration", "hall_effect", "current"]]
    y = df["label"]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("[Trainer] Training Random Forest model...")
    # Initialize classifier with safety constraints
    clf = RandomForestClassifier(n_estimators=50, max_depth=8, random_state=42)
    clf.fit(X_train, y_train)
    
    # Evaluate
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"[Trainer] Model training completed. Accuracy: {accuracy * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save the model binaries
    model_dirs = [
        "version-two/model",
        "server/ai_engine/model"
    ]
    
    for d in model_dirs:
        os.makedirs(d, exist_ok=True)
        model_path = os.path.join(d, "rf_model.pkl")
        with open(model_path, "wb") as f:
            pickle.dump(clf, f)
        print(f"[Trainer] Model saved successfully to: {model_path}")

if __name__ == "__main__":
    main()
