"""Portable red-team drill harness (redteam.py + /api/redteam/* endpoints).

Covers the drill token, the physical-process attack engine driving the real detection and
loss pipeline, the localhost-only + token-guarded endpoints, and that the perimeter attack
surface the portable script fires at is actually rejected.
"""

import pytest

import app as app_module
from app import GATEWAY_TOKEN, GATEWAY_TOKEN_HEADER, REDTEAM_TOKEN_HEADER, app
from database import DeviceState, SessionLocal
import enrollment
import redteam
import registry


@pytest.fixture(autouse=True)
def _testing():
    app.config["TESTING"] = False
    yield


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
    welcome = registry.approve(dev, user_id=None)
    return enrollment.derive_session_key(priv, welcome["hpub"], dev, pub, welcome["hpub"])


def _clear_isolation(dev):
    db = SessionLocal()
    try:
        st = db.query(DeviceState).filter_by(device_id=dev).first()
        if st:
            st.is_isolated = False
            db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------- drill token ---


def test_token_is_stable_and_checked():
    token = redteam.ensure_token()
    assert token and redteam.ensure_token() == token  # idempotent
    assert redteam.check_token(token) is True
    assert redteam.check_token("wrong") is False
    assert redteam.check_token("") is False
    assert redteam.check_token(None) is False


def test_campaign_has_perimeter_and_physical_stages():
    kinds = {s["kind"] for s in redteam.CAMPAIGN}
    assert kinds == {"perimeter", "physical"}
    assert len(redteam.CAMPAIGN) == 8
    assert all({"id", "kind", "name", "expect"} <= set(s) for s in redteam.CAMPAIGN)


# --------------------------------------------------------- physical attack engine ---


def test_replay_attack_is_rejected_without_equipment_damage():
    dev = "ESP32_RTE_REP"
    _enroll(dev)
    _clear_isolation(dev)
    res = redteam.run_physical_attack("replay", dev)
    assert res["ok"] and res["defended"]
    assert res["frames_rejected"] >= 1  # the resent copies are dropped (409)
    assert res["incident"]["prevented_loss"] == 0.0  # replay never reaches the actuator


def test_signature_tampering_quarantines_the_node():
    dev = "ESP32_RTE_HMAC"
    _enroll(dev)
    _clear_isolation(dev)
    res = redteam.run_physical_attack("hmac_tamper", dev)
    assert res["ok"] and res["defended"] and res["quarantined"]
    assert res["frames_rejected"] == res["frames_sent"]  # every forged frame bounced


@pytest.mark.parametrize("attack", ["fdi_spike", "stuxnet"])
def test_process_attacks_quarantine_and_price_the_incident(attack):
    dev = f"ESP32_RTE_{attack[:4].upper()}"
    _enroll(dev)
    _clear_isolation(dev)
    res = redteam.run_physical_attack(attack, dev)
    assert res["ok"] and res["defended"] and res["quarantined"]
    inc = res["incident"]
    assert inc["attack_type"] == attack
    assert inc["actual_loss"] > 0  # downtime cost of defending
    assert inc["prevented_loss"] > 0  # catastrophe averted by isolating
    assert inc["time_to_fix_hours"] > 0


def test_no_approved_target_is_reported_cleanly(monkeypatch):
    monkeypatch.setattr(registry, "approved_device_ids", lambda: [])
    monkeypatch.setattr(registry, "get_key", lambda _dev: None)
    res = redteam.run_physical_attack("fdi_spike")
    assert res["ok"] is False and "No approved device" in res["error"]


def test_reset_rejoins_quarantined_nodes():
    dev = "ESP32_RTE_RST"
    _enroll(dev)
    redteam.run_physical_attack("fdi_spike", dev)
    out = redteam.reset()
    assert out["ok"] and dev in out["rejoined"]
    db = SessionLocal()
    try:
        assert db.query(DeviceState).filter_by(device_id=dev).first().is_isolated is False
    finally:
        db.close()


# --------------------------------------------------------------- endpoints ---


def _client():
    return app.test_client()


def test_endpoints_are_localhost_only():
    c = _client()
    r = c.get("/api/redteam/plan", environ_base={"REMOTE_ADDR": "10.0.0.9"})
    assert r.status_code == 403


def test_endpoints_require_the_drill_token():
    c = _client()
    assert c.get("/api/redteam/plan").status_code == 401  # no token
    assert c.get("/api/redteam/plan", headers={REDTEAM_TOKEN_HEADER: "bad"}).status_code == 401


def test_plan_endpoint_returns_the_campaign():
    c = _client()
    r = c.get("/api/redteam/plan", headers={REDTEAM_TOKEN_HEADER: redteam.ensure_token()})
    assert r.status_code == 200
    assert len(r.get_json()["campaign"]) == 8


def test_inject_endpoint_runs_a_physical_stage():
    dev = "ESP32_RTE_EP"
    _enroll(dev)
    _clear_isolation(dev)
    c = _client()
    r = c.post(
        "/api/redteam/inject",
        json={"attack": "stuxnet", "device_id": dev},
        headers={REDTEAM_TOKEN_HEADER: redteam.ensure_token()},
    )
    assert r.status_code == 200
    result = r.get_json()["result"]
    assert result["defended"] and result["quarantined"]
    # cleanup
    c.post("/api/redteam/reset", headers={REDTEAM_TOKEN_HEADER: redteam.ensure_token()})


def test_inject_requires_an_attack_name():
    c = _client()
    r = c.post("/api/redteam/inject", json={}, headers={REDTEAM_TOKEN_HEADER: redteam.ensure_token()})
    assert r.status_code == 400


# ---------------------------------------- perimeter surface the USB script fires at ---


def test_unauthenticated_telemetry_is_rejected():
    c = _client()
    r = c.post("/api/telemetry", json={"device_id": "ESP32_EVIL", "temperature": 999})
    assert r.status_code == 401


def test_forged_gateway_token_is_rejected():
    c = _client()
    r = c.post(
        "/api/telemetry",
        json={"device_id": "ESP32_EVIL", "temperature": 999},
        headers={GATEWAY_TOKEN_HEADER: "forged" + "x" * 32},
    )
    assert r.status_code == 401
    # sanity: the real token is accepted (not a 401), proving the check is live
    good = c.post(
        "/api/telemetry",
        json={"device_id": "ESP32_EVIL", "temperature": 999},
        headers={GATEWAY_TOKEN_HEADER: GATEWAY_TOKEN},
    )
    assert good.status_code != 401


def test_control_command_without_csrf_is_rejected():
    c = _client()
    r = c.post("/api/device/isolate", json={"device_id": "ESP32_EVIL"})
    assert r.status_code in (400, 401, 403, 302)
