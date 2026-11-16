"""NIST SP 800 report generation (reporting.py, Phase 8).

Checks the report renders as a valid PDF, that the new ML-classification / loss-accounting /
mitigation section (Section 6) is driven by the attack classifier + loss engine, and that an
active incident makes the report grow (the section materialises).
"""

import app as app_module  # noqa: F401 (triggers init_db)
import enrollment
import registry
from database import DeviceState, SessionLocal
from reporting import generate_incident_report_pdf


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


def _clear_all_isolation():
    db = SessionLocal()
    try:
        for st in db.query(DeviceState).filter_by(is_isolated=True).all():
            st.is_isolated = False
        db.commit()
    finally:
        db.close()


def test_report_generates_valid_pdf_without_incident():
    _clear_all_isolation()
    db = SessionLocal()
    try:
        pdf = generate_incident_report_pdf(db, "admin", "Lat 1, Lon 2", detections={})
    finally:
        db.close()
    assert pdf[:4] == b"%PDF"
    assert len(pdf) > 5000


def test_report_includes_ml_incident_section_when_under_attack():
    import redteam

    _clear_all_isolation()
    db = SessionLocal()
    try:
        baseline = generate_incident_report_pdf(db, "admin", "Lat 1, Lon 2", detections={})
    finally:
        db.close()

    dev = "ESP32_REP_T8"
    _enroll(dev)
    redteam.run_physical_attack("stuxnet", dev)

    db = SessionLocal()
    try:
        detections = app_module._current_detections(db)
        assert detections and detections.get(dev, {}).get("attack_type") == "stuxnet"
        pdf = generate_incident_report_pdf(db, "admin", "Lat 1, Lon 2", detections=detections)
    finally:
        db.close()

    assert pdf[:4] == b"%PDF"
    # The active-incident section (table + mitigation plan) makes the report meaningfully larger.
    assert len(pdf) > len(baseline) + 500
    redteam.reset()


def test_report_defaults_detections_when_not_supplied():
    """Called with no detections, the report computes them itself and still renders."""
    _clear_all_isolation()
    db = SessionLocal()
    try:
        pdf = generate_incident_report_pdf(db, "admin", "Lat 1, Lon 2")
    finally:
        db.close()
    assert pdf[:4] == b"%PDF"