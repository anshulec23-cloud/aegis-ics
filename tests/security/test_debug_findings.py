"""Regression tests for the findings in docs/07-reports/DEBUG_REPORT.md.

One test (or a few) per finding ID. Tests for findings that are not fixed yet
are marked ``xfail(strict=True)``: they must keep failing until the fix lands,
and the fix PR removes the marker. This file runs with security controls ON
(``TESTING`` does not bypass anything any more).
"""

import os
import re
import sys
import time
import json
import types

import pytest

from conftest import GATEWAY_HEADERS, TEST_ADMIN_PASSWORD, TEST_DEVICE_KEYS

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

from app import app  # noqa: E402
from database import SessionLocal, AuditLog, DeviceState, TelemetryLog, User  # noqa: E402
import serial_gateway  # noqa: E402

PHASE2 = "Fixed in restructure plan Phase 2 (firmware / protocol v1)"
PHASE4 = "Fixed in restructure plan Phase 4 (ML)"

DEVICES = ("ESP32_001", "ESP32_002", "ESP32_003", "ESP32_004")


# ----------------------------------------------------------------- helpers ---


@pytest.fixture(autouse=True)
def clean_state():
    """Every test starts with all nodes un-isolated, no queued commands, gateway stopped."""
    app.config["TESTING"] = False
    db = SessionLocal()
    for dev in DEVICES:
        st = db.query(DeviceState).filter_by(device_id=dev).first()
        if st:
            st.is_isolated = False
    db.commit()
    db.close()
    _drain_queue()
    serial_gateway.stop_gateway()
    import app as app_module

    app_module._sig_failures.clear()
    app_module._seen_signatures.clear()
    yield
    _drain_queue()


def _drain_queue():
    q = serial_gateway._command_queue
    while not q.empty():
        q.get_nowait()


def _isolated(dev):
    db = SessionLocal()
    st = db.query(DeviceState).filter_by(device_id=dev).first()
    db.close()
    return bool(st and st.is_isolated)


def _signed(dev, key=None, **fields):
    payload = {
        "device_id": dev,
        "temperature": 25.0,
        "pressure": 3.0,
        "vibration": 1.0,
        "current": 4.0,
    }
    payload.update(fields)
    payload["signature"] = serial_gateway.sign_message(payload, key or TEST_DEVICE_KEYS[dev])
    return payload


def _client_logged_in():
    client = app.test_client()
    db = SessionLocal()
    admin = db.query(User).filter_by(username="admin").first()
    db.close()
    with client.session_transaction() as sess:
        sess["user_id"] = admin.id
        sess["username"] = "admin"
        sess["location"] = "TEST"
        sess["csrf_token"] = "csrf-test-token"
    return client, {"X-CSRF-Token": "csrf-test-token"}


def _login(client, username, password):
    page = client.get("/login").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    return client.post(
        "/login", data={"username": username, "password": password, "csrf_token": token}
    )


# ------------------------------------------------------------ S1 ingestion ---


def test_s1_telemetry_requires_gateway_token():
    res = app.test_client().post("/api/telemetry", json=_signed("ESP32_001"))
    assert res.status_code == 401


def test_s1_single_bad_signature_does_not_quarantine():
    res = app.test_client().post(
        "/api/telemetry",
        json={"device_id": "ESP32_002", "temperature": 25, "signature": "00"},
        headers=GATEWAY_HEADERS,
    )
    assert res.status_code == 401
    assert not _isolated("ESP32_002")
    assert serial_gateway._command_queue.empty()


def test_s1_repeated_bad_signatures_do_quarantine():
    client = app.test_client()
    for _ in range(5):
        client.post(
            "/api/telemetry",
            json={"device_id": "ESP32_002", "temperature": 25, "signature": "00"},
            headers=GATEWAY_HEADERS,
        )
    assert _isolated("ESP32_002")


def test_s1_valid_frame_with_token_accepted():
    res = app.test_client().post(
        "/api/telemetry", json=_signed("ESP32_001", timestamp=time.time()), headers=GATEWAY_HEADERS
    )
    assert res.status_code == 200, res.get_json()


# ------------------------------------------------------------- S2 keys ---


def test_s2_no_hardcoded_device_keys_in_python():
    import security

    assert not hasattr(security, "DEFAULT_DEVICE_KEYS")
    assert security.get_device_key("ROGUE_PLC_99") is None
    src = open(os.path.join(ROOT, "src", "security.py"), encoding="utf-8").read()
    assert "aegis_shared_" not in src


def test_s2_no_hardcoded_device_keys_in_firmware():
    path = os.path.join(ROOT, "firmware", "esp32_slave_sensor", "esp32_slave_sensor.ino")
    assert "aegis_shared_" not in open(path, encoding="utf-8").read()


def test_s2_unknown_device_rejected():
    payload = _signed("ESP32_001")
    payload["device_id"] = "ROGUE_PLC_99"
    payload["signature"] = serial_gateway.sign_message(
        {k: v for k, v in payload.items() if k != "signature"}, "aegis_shared_default_secret_key_v2"
    )
    res = app.test_client().post("/api/telemetry", json=payload, headers=GATEWAY_HEADERS)
    assert res.status_code in (401, 403)


# ----------------------------------------------------- S4 default accounts ---


@pytest.mark.parametrize("username", ["noodles", "admin"])
def test_s4_default_noodles_password_rejected(username):
    res = _login(app.test_client(), username, "noodles")
    assert res.status_code == 401


def test_s4_configured_admin_password_works():
    res = _login(app.test_client(), "admin", TEST_ADMIN_PASSWORD)
    assert res.status_code == 302


def test_s4_weak_or_legacy_admin_password_env_is_ignored():
    import bootstrap

    assert bootstrap.configured_admin_password({"ADMIN_PASSWORD": "noodles"}) is None
    assert bootstrap.configured_admin_password({"ADMIN_PASSWORD": "short"}) is None
    assert bootstrap.configured_admin_password({}) is None
    assert bootstrap.configured_admin_password({"ADMIN_PASSWORD": "x" * 12}) == "x" * 12


def test_first_run_setup_flow_when_no_usable_password():
    """Packaged-app first run: everything redirects to /setup until the admin password is set."""
    import app as app_module
    import bootstrap
    from database import DATA_DIR
    from werkzeug.security import generate_password_hash

    db = SessionLocal()
    admin = db.query(User).filter_by(username="admin").first()
    original_hash = admin.password_hash
    admin.password_hash = bootstrap.locked_password_hash()
    db.commit()
    db.close()
    app_module.refresh_setup_state()
    try:
        client = app.test_client()
        assert client.get("/").headers["Location"].endswith("/setup")
        assert client.get("/api/devices").status_code == 503
        assert "Invalid" not in client.get("/setup").get_data(as_text=True)

        start = app_module.setup_url()
        token = start.split("token=", 1)[1]
        page = client.get(start).get_data(as_text=True)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)

        bad = client.post("/setup", data={"token": "wrong", "password": "p" * 14, "confirm": "p" * 14, "csrf_token": csrf})
        assert bad.status_code == 403
        weak = client.post("/setup", data={"token": token, "password": "short", "confirm": "short", "csrf_token": csrf})
        assert weak.status_code == 400

        ok = client.post(
            "/setup",
            data={"token": token, "password": "correct-horse-battery", "confirm": "correct-horse-battery", "csrf_token": csrf},
        )
        assert ok.status_code == 302 and ok.headers["Location"].endswith("/")
        assert client.get("/api/devices").status_code == 200  # signed in by setup
        assert not os.path.exists(os.path.join(DATA_DIR, bootstrap.SETUP_TOKEN_FILE))
        assert _login(app.test_client(), "admin", "correct-horse-battery").status_code == 302
        assert client.get("/setup").status_code == 302  # setup can't be re-run
    finally:
        db = SessionLocal()
        db.query(User).filter_by(username="admin").first().password_hash = generate_password_hash(
            TEST_ADMIN_PASSWORD
        )
        db.commit()
        db.close()
        app_module.refresh_setup_state()
        bootstrap.clear_setup_token(DATA_DIR)


# ----------------------------------------------------------- S5 replay ---


def test_s5_identical_frame_replay_rejected():
    client = app.test_client()
    frame = _signed("ESP32_003", temperature=21.37)
    first = client.post("/api/telemetry", json=frame, headers=GATEWAY_HEADERS)
    second = client.post("/api/telemetry", json=frame, headers=GATEWAY_HEADERS)
    assert first.status_code == 200
    assert second.status_code == 409
    assert not _isolated("ESP32_003")


# --------------------------------------------- S6 / F1 gateway signing ---


def test_s6_gateway_does_not_sign_unsigned_frames():
    raw = {"device_id": "ESP32_001", "temperature": 25.0}
    assert serial_gateway.build_forward_payload(raw) is None


def test_s6_gateway_forwards_device_signed_frames_unchanged():
    raw = serial_gateway.parse_serial_line(json.dumps(_signed("ESP32_001")))
    fwd = serial_gateway.build_forward_payload(raw)
    assert fwd["signature"] == raw["signature"]


def test_f1_connect_does_not_force_single_hmac_key(monkeypatch):
    import app as app_module

    captured = {}
    monkeypatch.setattr(app_module, "_spawn_gateway_thread", lambda **kw: captured.update(kw))
    client, headers = _client_logged_in()
    res = client.post("/api/com_ports/connect", json={"port": "MOCK"}, headers=headers)
    assert res.status_code == 200
    assert captured.get("hmac_key") is None


def test_f1_simulator_frames_verify_for_every_node():
    from app import verify_signature

    for _ in range(8):
        line = serial_gateway.mock_serial_stream("plc")
        frame = serial_gateway.parse_serial_line(line)
        if frame.get("_is_bridge_msg"):
            continue
        fwd = serial_gateway.build_forward_payload(frame)
        assert fwd is not None and verify_signature(fwd), frame.get("device_id")


# ---------------------------------------------------------------- S7 XSS ---


def test_s7_failed_login_username_is_sanitised_in_audit():
    _login(app.test_client(), "<img src=x onerror=alert(1)>", "x")
    db = SessionLocal()
    last = db.query(AuditLog).filter_by(action="LOGIN_FAILED").order_by(AuditLog.id.desc()).first()
    db.close()
    assert "<img" not in last.details


def test_s7_invalid_device_id_rejected():
    payload = _signed("ESP32_001")
    payload["device_id"] = "<script>alert(1)</script>"
    res = app.test_client().post("/api/telemetry", json=payload, headers=GATEWAY_HEADERS)
    assert res.status_code == 400


def test_s7_dashboard_escapes_server_strings():
    html = open(os.path.join(ROOT, "src", "templates", "dashboard.html"), encoding="utf-8").read()
    assert "function escapeHtml" in html
    for unsafe in ("${log.details || ''}", "${dev.name}", "${sub.name}", "${sub.zone}"):
        assert unsafe not in html, unsafe


def test_s7_security_headers_present():
    res = app.test_client().get("/login")
    assert "Content-Security-Policy" in res.headers
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"


# ------------------------------------------------- S8 quarantine bypass ---


def test_s8_connect_does_not_clear_quarantine(monkeypatch):
    import app as app_module

    captured = {}
    monkeypatch.setattr(app_module, "_spawn_gateway_thread", lambda **kw: captured.update(kw))
    db = SessionLocal()
    db.query(DeviceState).filter_by(device_id="ESP32_002").first().is_isolated = True
    db.commit()
    db.close()
    client, headers = _client_logged_in()
    client.post("/api/com_ports/connect", json={"port": "MOCK"}, headers=headers)
    assert _isolated("ESP32_002")
    # ...and the gateway is told to re-trip it once the link is up.
    resync = captured["initial_commands"]
    assert [c["device_id"] for c in resync if c["command"] == "ISOLATE"] == ["ESP32_002"]


# ------------------------------------------------------ S11 save dialog ---


def test_s11_native_save_dialog_not_opened_in_web_mode(monkeypatch):
    calls = []
    fake_tk = types.ModuleType("tkinter")
    fake_tk.Tk = lambda *a, **k: calls.append("Tk")
    monkeypatch.setitem(sys.modules, "tkinter", fake_tk)
    monkeypatch.delenv("AEGIS_DESKTOP_MODE", raising=False)
    client, _ = _client_logged_in()
    res = client.get("/api/report/save_dialog?native=1")
    assert res.get_json()["download_url"] == "/api/report/download"
    assert calls == []


# ----------------------------------------------- F3 command delivery ---


def test_f3_setpoint_fails_when_no_gateway_connected():
    client, headers = _client_logged_in()
    res = client.post(
        "/api/setpoint",
        json={"type": "set_temp", "value": 30, "target_device": "ESP32_001"},
        headers=headers,
    )
    assert res.status_code == 503
    assert serial_gateway._command_queue.empty()


def test_f3_queued_commands_expire():
    serial_gateway.send_command({"command": "ISOLATE", "device_id": "ESP32_001"})
    later = time.time() + serial_gateway.COMMAND_TTL_SECONDS + 1
    assert serial_gateway.pop_ready_commands(now=later) == []


def test_f3_fresh_commands_delivered_without_internal_fields():
    serial_gateway.send_command({"command": "ISOLATE", "device_id": "ESP32_001"})
    ready = serial_gateway.pop_ready_commands()
    assert len(ready) == 1 and not any(k.startswith("_") for k in ready[0])


# ------------------------------------------------ R1/R2 evidence integrity ---


def test_r1_simulated_attack_audit_is_flagged_and_does_not_isolate():
    client, headers = _client_logged_in()
    client.post("/api/simulate-attack", json={"type": "injection"}, headers=headers)
    db = SessionLocal()
    last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    db.close()
    assert last.is_simulated is True
    assert last.action.startswith("SIMULATED_")
    assert not _isolated("ESP32_001")


def test_r2_no_fabricated_seed_audit_records():
    db = SessionLocal()
    n = (
        db.query(AuditLog)
        .filter(AuditLog.action.in_(["KEYRING_VALIDATED", "STATION_GEOLOCATION_LOCKED"]))
        .count()
    )
    db.close()
    assert n == 0


# ------------------------------------------- test-mode security bypasses ---


def test_csrf_enforced_even_when_testing():
    app.config["TESTING"] = True
    client, _ = _client_logged_in()
    res = client.post("/api/rules/update", json={"temp_max": 61})
    assert res.status_code == 400


def test_replay_window_enforced_even_when_testing():
    app.config["TESTING"] = True
    res = app.test_client().post(
        "/api/telemetry",
        json=_signed("ESP32_001", timestamp=time.time() - 3600),
        headers=GATEWAY_HEADERS,
    )
    assert res.status_code == 400


# ------------------------------------------------------ small correctness ---


def test_f8_iso_timestamp_accepted_and_stored_as_epoch():
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    res = app.test_client().post(
        "/api/telemetry", json=_signed("ESP32_004", timestamp=iso), headers=GATEWAY_HEADERS
    )
    assert res.status_code == 200, res.get_json()
    db = SessionLocal()
    row = (
        db.query(TelemetryLog)
        .filter_by(device_id="ESP32_004")
        .order_by(TelemetryLog.id.desc())
        .first()
    )
    db.close()
    assert isinstance(row.timestamp, float) and abs(row.timestamp - time.time()) < 120


def test_f9_audit_epoch_is_utc():
    client, headers = _client_logged_in()
    _login(app.test_client(), "nobody", "x")
    logs = client.get("/api/audit/logs?limit=1", headers=headers).get_json()["logs"]
    assert abs(logs[0]["timestamp_epoch"] - time.time()) < 120


@pytest.mark.parametrize("limit", ["abc", "-5", ""])
def test_f10_bad_audit_limit_does_not_500(limit):
    client, headers = _client_logged_in()
    res = client.get(f"/api/audit/logs?limit={limit}", headers=headers)
    assert res.status_code in (200, 400)


def test_f14_ping_does_not_fabricate_latency():
    client, headers = _client_logged_in()
    data = client.post(
        "/api/device/ping", json={"device_id": "ESP32_001"}, headers=headers
    ).get_json()
    assert data.get("latency_ms") is None
    assert "14.2" not in json.dumps(data)


# ------------------------------------------------------ deployment config ---


def test_debian_service_not_root_and_not_public():
    unit = open(os.path.join(ROOT, "debian", "aegis-ics.service"), encoding="utf-8").read()
    assert "User=root" not in unit
    assert "0.0.0.0" not in unit
    init = open(os.path.join(ROOT, "debian", "aegis-ics.init"), encoding="utf-8").read()
    assert "0.0.0.0" not in init


# ------------------------------------------- later phases (stay xfail) ---


@pytest.mark.xfail(strict=True, reason=PHASE2)
def test_s3_firmware_verifies_command_signatures():
    src = open(
        os.path.join(ROOT, "firmware", "esp32_slave_sensor", "esp32_slave_sensor.ino"),
        encoding="utf-8",
    ).read()
    body = src[src.index("void process_incoming_command") :]
    assert "verify" in body[: body.index("\n}\n")].lower()


@pytest.mark.xfail(strict=True, reason=PHASE2)
def test_f2_setpoint_command_matches_firmware_contract(monkeypatch):
    monkeypatch.setattr(serial_gateway, "is_connected", lambda: True)
    client, headers = _client_logged_in()
    client.post(
        "/api/setpoint",
        json={"type": "set_temp", "value": 30, "target_device": "ESP32_001"},
        headers=headers,
    )
    cmd = serial_gateway.pop_ready_commands()[0]
    assert cmd["command"] == "SETPOINT" and "temperature" in cmd


@pytest.mark.xfail(strict=True, reason=PHASE4)
def test_f6_nspn_distinguishes_command_types():
    from neural_policy import get_neural_policy

    pol = get_neural_policy()
    state = {
        "temperature": 44.0,
        "pressure": 5.9,
        "vibration": 1.5,
        "hall_effect": 1500,
        "current": 5,
    }
    p_temp = pol.evaluate_safety(state, "set_temp", 7.5)[1]
    p_pres = pol.evaluate_safety(state, "set_pressure", 7.5)[1]
    assert abs(p_temp - p_pres) > 1e-3
