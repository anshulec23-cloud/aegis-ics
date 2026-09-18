"""
Aegis ICS — Continuous Mathematical Trust Scoring Engine
========================================================
Implements the 4-parameter mathematical trust scoring formalism specified in docs/trust_scoring.md:

    T_score = 0.35 * (1.0 - S_anomaly) + 0.30 * S_signature + 0.20 * S_history + 0.15 * S_stability

Includes deterministic fallback penalties when model confidence is low or in degraded states.
"""

from typing import Dict, Any, List, Optional
from database import TelemetryLog, DeviceState, Rule


def compute_device_trust_score(
    device_id: str,
    db_session,
    latest_is_anomaly: Optional[bool] = None,
    latest_sig_valid: Optional[bool] = None,
    anomaly_prob: float = 0.0,
    model_confidence: float = 0.85
) -> Dict[str, Any]:
    """
    Computes real-time 4-parameter continuous trust score for a specific ESP32 node.
    """
    # 1. Query device quarantine state
    dev_state = db_session.query(DeviceState).filter_by(device_id=device_id).first()
    if dev_state and dev_state.is_isolated:
        return {
            "device_id": device_id,
            "trust_score": 0.0,
            "trust_percentage": 0.0,
            "status": "ISOLATED",
            "is_isolated": True,
            "s_anomaly": 1.0,
            "s_signature": 0.0,
            "s_history": 0.0,
            "s_stability": 0.0,
            "details": "Device quarantined by Zero-Trust microsegmentation policy"
        }

    # 2. Query historical telemetry for this device (last 15 readings)
    logs: List[TelemetryLog] = (
        db_session.query(TelemetryLog)
        .filter_by(device_id=device_id)
        .order_by(TelemetryLog.timestamp.desc())
        .limit(15)
        .all()
    )

    if not logs:
        known_devices = {"ESP32_001", "ESP32_002", "ESP32_003", "ESP32_004"}
        if device_id in known_devices:
            return {
                "device_id": device_id,
                "trust_score": 0.50,
                "trust_percentage": 50.0,
                "status": "INITIALIZING",
                "is_isolated": False,
                "s_anomaly": 0.0,
                "s_signature": 1.0,
                "s_history": 0.5,
                "s_stability": 0.5,
                "details": "Registered device — building baseline trust profile"
            }
        else:
            return {
                "device_id": device_id,
                "trust_score": 0.25,
                "trust_percentage": 25.0,
                "status": "UNREGISTERED",
                "is_isolated": False,
                "s_anomaly": 0.5,
                "s_signature": 0.0,
                "s_history": 0.0,
                "s_stability": 0.0,
                "details": "Unknown device ID — requires registration before trust elevation"
            }

    # --- Metric 1: Anomaly Frequency (S_anomaly) ---
    recent_anomalies = [1.0 if t.is_anomaly else 0.0 for t in logs]
    s_anomaly = sum(recent_anomalies) / len(recent_anomalies) if recent_anomalies else 0.0
    if latest_is_anomaly is True:
        s_anomaly = max(s_anomaly, 0.7)

    # --- Metric 2: Cryptographic Signature Validity (S_signature) ---
    if latest_sig_valid is not None:
        s_signature = 1.0 if latest_sig_valid else 0.0
    else:
        # Cryptographic integrity is decoupled from physical process anomalies (captured by S_anomaly)
        s_signature = 1.0

    # --- Metric 3: Historical Deviation (S_history) ---
    valid_temps = [t.temperature for t in logs if t.temperature is not None]
    valid_press = [t.pressure for t in logs if t.pressure is not None]

    if len(valid_temps) >= 2 and len(valid_press) >= 2:
        mu_t = sum(valid_temps) / len(valid_temps)
        mu_p = sum(valid_press) / len(valid_press)
        delta_t = abs(valid_temps[0] - mu_t)
        delta_p = abs(valid_press[0] - mu_p)
        combined_dev = (delta_t / 25.0) + (delta_p / 5.0)
        s_history = max(0.0, 1.0 - min(1.0, combined_dev / 2.0))
    else:
        s_history = 0.50

    # --- Metric 4: Signal Stability / Population Variance (S_stability) ---
    if len(valid_temps) >= 3 and len(valid_press) >= 3:
        mu_t = sum(valid_temps) / len(valid_temps)
        mu_p = sum(valid_press) / len(valid_press)
        var_t = sum((x - mu_t) ** 2 for x in valid_temps) / len(valid_temps)
        var_p = sum((x - mu_p) ** 2 for x in valid_press) / len(valid_press)
        combined_var = (var_t / 100.0) + (var_p / 10.0)
        s_stability = max(0.0, 1.0 - min(1.0, combined_var))
    else:
        s_stability = 0.50

    # --- Combine Scores ---
    t_score = (
        0.35 * (1.0 - s_anomaly)
        + 0.30 * s_signature
        + 0.20 * s_history
        + 0.15 * s_stability
    )

    # Smooth Zero-Trust warming from 0.50 registration baseline across first 10 observations
    if len(logs) < 10:
        warmup_factor = len(logs) / 10.0
        t_score = 0.50 * (1.0 - warmup_factor) + t_score * warmup_factor

    # --- Low-Confidence Fallback Logic ---
    if model_confidence < 0.50:
        penalties = 0.0
        if valid_temps and (valid_temps[0] < 0.0 or valid_temps[0] > 60.0):
            penalties += 0.35
        if valid_press and (valid_press[0] < 0.0 or valid_press[0] > 8.0):
            penalties += 0.25
        if s_signature < 1.0:
            penalties += 0.40
        s_fallback = max(0.0, 1.0 - penalties)
        t_final = (t_score + s_fallback) / 2.0
    else:
        t_final = t_score

    t_final = max(0.0, min(1.0, t_final))
    trust_pct = round(t_final * 100.0, 1)

    if t_final >= 0.80:
        status = "TRUSTED"
    elif t_final >= 0.50:
        status = "DEGRADED"
    elif t_final >= 0.40:
        status = "SUSPICIOUS"
    else:
        status = "CRITICAL"

    return {
        "device_id": device_id,
        "trust_score": round(t_final, 3),
        "trust_percentage": trust_pct,
        "status": status,
        "is_isolated": False,
        "s_anomaly": round(s_anomaly, 2),
        "s_signature": round(s_signature, 2),
        "s_history": round(s_history, 2),
        "s_stability": round(s_stability, 2),
        "details": f"{status} operational profile"
    }

def get_device_trust_score(device_id: str, db_session) -> float:
    """Convenience helper returning the trust percentage float (0.0 - 100.0)."""
    res = compute_device_trust_score(device_id, db_session)
    return float(res.get("trust_percentage", 100.0))


def get_trust_breakdown(device_id: str, db_session) -> Dict[str, Any]:
    """
    Returns full mathematical trust scoring breakdown with weights, raw values,
    hardware zone, and historical packet telemetry statistics.
    """
    score_info = compute_device_trust_score(device_id, db_session)
    dev_state = db_session.query(DeviceState).filter_by(device_id=device_id).first()
    is_isolated = bool(dev_state.is_isolated) if dev_state else False

    total_packets = db_session.query(TelemetryLog).filter_by(device_id=device_id).count()
    recent_anomalies = db_session.query(TelemetryLog).filter_by(device_id=device_id, is_anomaly=True).count()
    latest_log = db_session.query(TelemetryLog).filter_by(device_id=device_id).order_by(TelemetryLog.timestamp.desc()).first()

    zones = {
        "ESP32_001": {"name": "Catalytic Reactor 01", "zone": "Zone A: High-Exotherm Reaction Unit", "type": "Microcontroller Unit (MCU)"},
        "ESP32_002": {"name": "Centrifugal Pump 02", "zone": "Zone B: Secondary Feed Booster", "type": "High-Pressure Impeller"},
        "ESP32_003": {"name": "Cooling Cryo 03", "zone": "Zone C: Primary Cryogenic Heat Exchanger", "type": "Chilled Liquid Loop"},
        "ESP32_004": {"name": "Turbine Generator 04", "zone": "Zone D: Main Turbine Hall Generation", "type": "High-Speed Alternator"},
    }
    zone_meta = zones.get(device_id, {"name": f"Slave Node {device_id}", "zone": "Auxiliary Field Bus", "type": "Field Sensor"})

    return {
        "device_id": device_id,
        "name": zone_meta["name"],
        "zone": zone_meta["zone"],
        "type": zone_meta["type"],
        "is_isolated": is_isolated,
        "trust_percentage": score_info["trust_percentage"],
        "trust_score": score_info["trust_score"],
        "status": score_info["status"],
        "components": {
            "s_anomaly": {
                "name": "ML Anomaly Score (1 - Sanomaly)",
                "value": score_info["s_anomaly"],
                "weight": 0.35,
                "contribution_pct": round(0.35 * (1.0 - score_info["s_anomaly"]) * 100.0, 1),
                "desc": "Random Forest anomaly probability evaluation"
            },
            "s_signature": {
                "name": "Cryptographic HMAC Integrity",
                "value": score_info["s_signature"],
                "weight": 0.30,
                "contribution_pct": round(0.30 * score_info["s_signature"] * 100.0, 1),
                "desc": "HMAC-SHA256 frame payload signature verification"
            },
            "s_history": {
                "name": "Historical Mean Deviation",
                "value": score_info["s_history"],
                "weight": 0.20,
                "contribution_pct": round(0.20 * score_info["s_history"] * 100.0, 1),
                "desc": "Euclidean deviation from 15-packet rolling mean"
            },
            "s_stability": {
                "name": "Sensor Signal Stability",
                "value": score_info["s_stability"],
                "weight": 0.15,
                "contribution_pct": round(0.15 * score_info["s_stability"] * 100.0, 1),
                "desc": "Population variance of sensor jitter"
            }
        },
        "stats": {
            "total_packets": total_packets,
            "recent_anomalies": recent_anomalies,
            "last_seen": latest_log.timestamp if latest_log else None,
            "last_temp": latest_log.temperature if latest_log else None,
            "last_pres": latest_log.pressure if latest_log else None,
        }
    }


