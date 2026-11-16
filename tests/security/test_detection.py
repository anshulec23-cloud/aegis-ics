"""Attack-type classifier (detection brain, Phase 4) — detection.py + train_classifier.py.

Covers the trained model's class contract, feature extraction, per-device detection from telemetry,
abstention on normal/low-confidence, and the end-to-end link where a red-team injection is named by
the classifier and priced by the loss engine.
"""

import time

import pytest

import app as app_module  # noqa: F401 (triggers init_db)
import detection
import enrollment
import registry
from database import SessionLocal, TelemetryLog

# Representative sensor readings per class (centres of the trained envelopes / harness vectors).
VECTORS = {
    "normal": {"temperature": 26.0, "pressure": 4.2, "vibration": 1.1, "hall_effect": 0.0, "current": 4.5},
    "fdi_spike": {"temperature": 96.8, "pressure": 12.4, "vibration": 5.8, "hall_effect": 3500.0, "current": 19.2},
    "stuxnet": {"temperature": 55.0, "pressure": 7.8, "vibration": 6.9, "hall_effect": 3250.0, "current": 8.6},
    "thermal_drift": {"temperature": 61.0, "pressure": 8.4, "vibration": 2.4, "hall_effect": 1200.0, "current": 6.8},
}


def _insert_telemetry(device_id, reading, anomaly=True, n=3):
    db = SessionLocal()
    try:
        for i in range(n):
            db.add(
                TelemetryLog(
                    timestamp=time.time() + i * 0.01,
                    device_id=device_id,
                    temperature=reading["temperature"],
                    pressure=reading["pressure"],
                    vibration=reading["vibration"],
                    hall_effect=reading["hall_effect"],
                    current=reading["current"],
                    is_anomaly=anomaly,
                    is_simulated=True,
                )
            )
        db.commit()
    finally:
        db.close()


# ------------------------------------------------------------------- model ---


def test_model_loads_and_reports_its_card():
    assert detection.model_available() is True
    st = detection.status()
    assert st["available"] is True
    assert set(st["classes"]) == {"normal", "fdi_spike", "stuxnet", "thermal_drift", "sensor_fault"}
    assert st["accuracy"] and st["accuracy"] > 0.85
    assert st["features"] == ["temperature", "pressure", "vibration", "hall_effect", "current"]


@pytest.mark.parametrize("expected", ["normal", "fdi_spike", "stuxnet", "thermal_drift"])
def test_classifier_names_each_attack(expected):
    res = detection.classify_row(VECTORS[expected])
    assert res["attack_type"] == expected
    assert res["confidence"] >= 0.5
    assert abs(sum(res["scores"].values()) - 1.0) < 0.01


def test_missing_sensor_defaults_to_zero_not_crash():
    res = detection.classify_row({"temperature": 26.0})  # others absent
    assert res is not None and "attack_type" in res


# -------------------------------------------------------------- detect_device ---


def test_detect_device_names_injected_fdi_from_telemetry():
    dev = "ESP32_DET_FDI"
    _insert_telemetry(dev, VECTORS["fdi_spike"])
    db = SessionLocal()
    try:
        hit = detection.detect_device(db, dev)
    finally:
        db.close()
    assert hit and hit["attack_type"] == "fdi_spike"
    assert hit["source"] == "ml_classifier" and hit["confidence"] >= 0.55


def test_detect_device_abstains_on_normal_telemetry():
    dev = "ESP32_DET_NOM"
    _insert_telemetry(dev, VECTORS["normal"], anomaly=False)
    db = SessionLocal()
    try:
        hit = detection.detect_device(db, dev)
    finally:
        db.close()
    assert hit is None  # normal is not a physical attack -> abstain


def test_detect_device_none_without_telemetry():
    db = SessionLocal()
    try:
        assert detection.detect_device(db, "ESP32_NO_TELEM_AT_ALL") is None
    finally:
        db.close()


# ----------------------------------------------- end-to-end with the harness ---


def _enroll(dev):
    priv, pub = enrollment.generate_keypair()
    app_module.handle_device_frame(
        {
            "v": 1,
            "type": "HELLO",
            "id": dev,
            "pub": pub,
            "fw": "t",
            "boot": 7,
            "sensors": ["temperature", "pressure", "vibration", "current", "hall_effect"],
            "enrolled": False,
        }
    )
    registry.approve(dev, user_id=None)


def test_model_status_endpoint_returns_valid_json_with_classifier_card():
    """Regression: training_metrics.json carries +inf ROC thresholds; the endpoint must still
    emit valid JSON (no bare `Infinity`) and include the attack-classifier card."""
    from app import app
    from database import SessionLocal, User

    db = SessionLocal()
    admin_id = db.query(User).filter_by(username="admin").first().id
    db.close()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess.update(user_id=admin_id, username="admin", location="T", csrf_token="t")
    res = client.get("/api/model/status")
    assert res.status_code == 200
    body = res.get_data(as_text=True)
    assert "Infinity" not in body and "NaN" not in body
    data = res.get_json()  # raises if invalid JSON
    assert data["success"] is True
    assert data["attack_classifier"]["available"] is True


def test_redteam_injection_is_named_by_classifier_and_priced():
    import loss_engine
    import redteam

    dev = "ESP32_DET_E2E"
    _enroll(dev)
    redteam.run_physical_attack("stuxnet", dev)  # drives real ingestion + quarantine

    db = SessionLocal()
    try:
        detections = app_module._current_detections(db)
        assert detections is not None and dev in detections
        assert detections[dev]["attack_type"] == "stuxnet"
        assert detections[dev]["source"] == "ml_classifier"

        # The loss engine prices the incident using the ML-named attack type.
        incident = loss_engine.assess(db, detections=detections)
        this = next(i for i in incident["incidents"] if i["device_id"] == dev)
        assert this["attack_type"] == "stuxnet"
        assert this["prevented_loss"] > 0
    finally:
        db.close()
    redteam.reset()