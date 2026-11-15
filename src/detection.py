"""Attack-type classifier (detection brain) — Phase 4.

The deterministic layer (rules + trust score) decides *that* a node is misbehaving and quarantines
it. This module decides *what kind* of attack it is, from the device's own telemetry, using a
trained offline Random Forest multi-class classifier (``src/model/attack_classifier.pkl``, built by
``src/train_classifier.py``). Its answer feeds the loss engine (which prices the incident by attack
type) and the incident report's mitigation steps.

Scope: the classifier reads sensor values, so it names the *physical-process* attacks that show up in
telemetry — false data injection, Stuxnet-style coordination, thermal drift, sensor faults — plus
``normal``. Protocol attacks (replay, signature tampering, DoS) never produce malicious telemetry
values (their frames are rejected before ingestion), so they are left to the deterministic/audit layer
and this module returns ``None`` for them, by design.

The model is loaded read-only at runtime (never trained here) and its SHA-256 is verified before
unpickling, mirroring the anomaly model in app.py.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

# The 5 sensor features, in the exact order the classifier was trained on.
FEATURES: List[str] = ["temperature", "pressure", "vibration", "hall_effect", "current"]

# Attacks this classifier can name (telemetry-visible). Protocol attacks are intentionally absent.
PHYSICAL_CLASSES = {"fdi_spike", "stuxnet", "thermal_drift", "sensor_fault"}

# Minimum predicted probability before we override the deterministic/audit view.
DEFAULT_MIN_CONFIDENCE = 0.55

_MODEL = None
_META: Dict[str, Any] = {}
_LOAD_ATTEMPTED = False


def _resource_path(relative_path: str) -> str:
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)


def _model_path() -> str:
    return _resource_path(os.path.join("model", "attack_classifier.pkl"))


def _meta_path() -> str:
    return _resource_path(os.path.join("model", "attack_classifier_meta.json"))


def _load() -> bool:
    """Lazily load and cache the classifier + metadata, verifying integrity first."""
    global _MODEL, _META, _LOAD_ATTEMPTED
    if _MODEL is not None:
        return True
    if _LOAD_ATTEMPTED and _MODEL is None:
        return False
    _LOAD_ATTEMPTED = True

    path = _model_path()
    if not os.path.exists(path):
        print(f"[Detection] Attack classifier not found at {path}; run src/train_classifier.py.")
        return False
    try:
        hash_path = path + ".sha256"
        if os.path.exists(hash_path):
            import hashlib
            import hmac

            with open(hash_path, "r", encoding="utf-8") as hf:
                expected = hf.read().strip()
            with open(path, "rb") as mf:
                actual = hashlib.sha256(mf.read()).hexdigest()
            if not hmac.compare_digest(expected, actual):
                print(f"[Security Error] Attack classifier integrity check failed for {path}.")
                return False
        import pickle

        with open(path, "rb") as f:
            _MODEL = pickle.load(f)
        try:
            with open(_meta_path(), "r", encoding="utf-8") as mf:
                _META = json.load(mf)
        except (OSError, ValueError):
            _META = {}
        print(f"[Detection] Loaded attack classifier ({', '.join(classes())}).")
        return True
    except Exception as e:  # pragma: no cover - defensive
        print(f"[Detection] Failed to load attack classifier: {e}")
        _MODEL = None
        return False


def model_available() -> bool:
    return _load()


def classes() -> List[str]:
    if _META.get("classes"):
        return list(_META["classes"])
    if _MODEL is not None and hasattr(_MODEL, "classes_"):
        return [str(c) for c in _MODEL.classes_]
    return []


def _to_vector(row: Dict[str, Any]) -> List[float]:
    def num(key: str) -> float:
        val = row.get(key)
        try:
            return float(val) if val is not None else 0.0
        except (TypeError, ValueError):
            return 0.0

    return [num(f) for f in FEATURES]


def classify_vector(vec: List[float]) -> Optional[Dict[str, Any]]:
    """Classify one [temperature, pressure, vibration, hall_effect, current] vector."""
    if not _load():
        return None
    probs = _MODEL.predict_proba([vec])[0]
    labels = [str(c) for c in _MODEL.classes_]
    scores = {labels[i]: round(float(probs[i]), 4) for i in range(len(labels))}
    best = max(scores, key=scores.get)
    return {"attack_type": best, "confidence": scores[best], "scores": scores}


def classify_row(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Classify one telemetry reading (dict with sensor keys)."""
    return classify_vector(_to_vector(row))


def _recent_rows(db, device_id: str, window: int) -> List[Dict[str, Any]]:
    from database import TelemetryLog

    logs = (
        db.query(TelemetryLog)
        .filter(TelemetryLog.device_id == device_id)
        .order_by(TelemetryLog.timestamp.desc())
        .limit(window)
        .all()
    )
    rows = []
    for log in logs:
        rows.append(
            {
                "temperature": log.temperature,
                "pressure": log.pressure,
                "vibration": log.vibration,
                "hall_effect": log.hall_effect,
                "current": log.current,
                "is_anomaly": bool(log.is_anomaly),
            }
        )
    return rows


def detect_device(
    db, device_id: str, window: int = 8, min_confidence: float = DEFAULT_MIN_CONFIDENCE
) -> Optional[Dict[str, Any]]:
    """Classify a device's recent telemetry into an attack type.

    Returns ``{attack_type, confidence, source, scores}`` only when the classifier is confident of a
    *physical* attack; returns ``None`` for normal behaviour, low confidence, no telemetry, or a
    protocol attack (which leaves no malicious telemetry to read) so the caller falls back to the
    deterministic/audit view.
    """
    if not _load():
        return None
    rows = _recent_rows(db, device_id, window)
    if not rows:
        return None
    # Prefer the most recent flagged-anomalous frame; otherwise the latest frame.
    row = next((r for r in rows if r.get("is_anomaly")), rows[0])
    result = classify_vector(_to_vector(row))
    if result is None:
        return None
    if result["attack_type"] not in PHYSICAL_CLASSES:
        return None
    if result["confidence"] < min_confidence:
        return None
    return {
        "attack_type": result["attack_type"],
        "confidence": result["confidence"],
        "scores": result["scores"],
        "source": "ml_classifier",
    }


def status() -> Dict[str, Any]:
    """Model card for the UI / /api/model/status."""
    available = _load()
    return {
        "available": available,
        "classes": classes(),
        "features": FEATURES,
        "accuracy": _META.get("accuracy"),
        "f1_macro": _META.get("f1_macro"),
        "trained_at": _META.get("trained_at"),
        "n_train": _META.get("n_train"),
        "algorithm": _META.get("algorithm", "RandomForestClassifier"),
    }
