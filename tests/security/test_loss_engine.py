"""Live incident loss engine (loss_engine.py + attacks.py)."""

import time

import app  # noqa: F401  (triggers init_db so tables exist)
import attacks
import financials
import loss_engine
from database import AuditLog, Device, DeviceFinancials, DeviceState, SessionLocal


def _approved_device(db, dev_id, role="reactor", isolated=False, when=None):
    dev = db.query(Device).filter_by(device_id=dev_id).first()
    if dev is None:
        dev = Device(device_id=dev_id, status="approved")
        db.add(dev)
        db.flush()
    fin = financials.normalize_input({"role": role})
    # Financial profile lives in device_financials, not on the device row.
    frow = dev.financials_row
    if frow is None:
        frow = DeviceFinancials(device_id=dev_id)
        db.add(frow)
        dev.financials_row = frow
    frow.role = fin["role"]
    frow.criticality = fin["criticality"]
    frow.zone = fin["zone"]
    for f in ("equipment_value", "downtime_rate_per_hour", "cleanup_cost", "regulatory_exposure"):
        setattr(frow, f, fin[f])
    st = db.query(DeviceState).filter_by(device_id=dev_id).first()
    if not st:
        st = DeviceState(device_id=dev_id)
        db.add(st)
    st.is_isolated = isolated
    if when is not None:
        from datetime import datetime, timezone

        st.updated_at = datetime.fromtimestamp(when, timezone.utc)
    db.commit()


def test_attack_catalog_canonicalises_aliases():
    assert attacks.canonical("injection") == "fdi_spike"
    assert attacks.canonical("tamper") == "hmac_tamper"
    assert attacks.canonical("nonsense") == "unknown"
    assert attacks.info("stuxnet")["damages_equipment"] is True


def test_no_incident_is_zero():
    db = SessionLocal()
    try:
        # Clear any isolation state so the baseline is clean.
        for st in db.query(DeviceState).all():
            st.is_isolated = False
        db.commit()
        result = loss_engine.assess(db, detections={})
        assert result["incident_active"] is False
        assert result["totals"]["actual_loss"] == 0.0
    finally:
        db.close()


def test_isolated_reactor_incident_numbers():
    db = SessionLocal()
    try:
        two_hours_ago = time.time() - 2 * 3600
        _approved_device(db, "ESP32_LOSS01", role="reactor", isolated=True, when=two_hours_ago)
        res = loss_engine.assess(db, detections={"ESP32_LOSS01": {"attack_type": "stuxnet"}})
        inc = next(i for i in res["incidents"] if i["device_id"] == "ESP32_LOSS01")
        assert inc["attack_type"] == "stuxnet"
        assert inc["is_isolated"] is True
        # ~2 h of downtime at the reactor's $/h burn.
        assert inc["actual_loss"] > 0
        assert abs(inc["duration_hours"] - 2.0) < 0.2
        # Isolating a Stuxnet-class attack prevents equipment damage (base_sle * severity).
        assert inc["prevented_loss"] > 0
        assert inc["time_to_fix_hours"] > 0
        assert inc["restabilization_cost"] > 0
        assert inc["regulatory_exposure"] > 0  # stuxnet is reportable
        assert res["totals"]["net_risk_reduction_pct"] > 0
    finally:
        db.close()


def test_replay_does_not_count_as_equipment_damage():
    db = SessionLocal()
    try:
        _approved_device(db, "ESP32_LOSS02", role="pump", isolated=True, when=time.time() - 600)
        res = loss_engine.assess(db, detections={"ESP32_LOSS02": {"attack_type": "replay"}})
        inc = next(i for i in res["incidents"] if i["device_id"] == "ESP32_LOSS02")
        assert inc["attack_type"] == "replay"
        assert inc["prevented_loss"] == 0.0  # replay doesn't reach the actuator
        assert inc["regulatory_exposure"] == 0.0  # not reportable
    finally:
        db.close()
