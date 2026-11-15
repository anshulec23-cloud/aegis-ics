"""Protocol v1 + zero-touch enrollment (ADR 0006, restructure plan Phase 2).

Covers the crypto contract shared with the firmware, the enrollment state machine, replay
protection, key-change detection, and an end-to-end run of the real gateway thread with the
protocol-v1 simulator (N slaves, ACKed commands).
"""

import json
import time

import pytest

from app import app
from database import AuditLog, CommandLog, Device, DeviceState, SessionLocal
import enrollment
import protocol
import registry
import serial_gateway
import simulator

# ------------------------------------------------------------------ helpers ---


@pytest.fixture(autouse=True)
def _clean():
    app.config["TESTING"] = False
    serial_gateway.stop_gateway()
    serial_gateway.purge_command_queue()
    simulator.reset_attacks()
    yield
    serial_gateway.stop_gateway()
    serial_gateway.purge_command_queue()


def _new_device(device_id):
    priv, pub = enrollment.generate_keypair()
    return priv, pub


def _hello(device_id, pub, enrolled=False, sensors=("temperature", "pressure")):
    return {
        "v": 1,
        "type": "HELLO",
        "id": device_id,
        "pub": pub,
        "fw": "test",
        "boot": 7,
        "sensors": list(sensors),
        "enrolled": enrolled,
    }


def _enroll(device_id):
    """Run discovery + approval for a fresh device; return (device_private, key)."""
    import app as app_module

    priv, pub = _new_device(device_id)
    ok, status, msg = app_module.handle_device_frame(_hello(device_id, pub))
    assert ok and "pending_new" in msg
    welcome = registry.approve(device_id, user_id=None)
    key = enrollment.derive_session_key(priv, welcome["hpub"], device_id, pub, welcome["hpub"])
    assert protocol.verify(welcome, key), "device must be able to verify the host's WELCOME"
    return priv, key


def _tel(device_id, key, boot, seq, **readings):
    frame = {
        "v": 1,
        "type": "TEL",
        "id": device_id,
        "boot": boot,
        "seq": seq,
        "faults": [],
        "tripped": False,
    }
    frame.update({k: protocol.fmt2(v) for k, v in readings.items()})
    return protocol.sign(frame, key)


def _audit_actions(device_id):
    db = SessionLocal()
    try:
        return [
            a.action
            for a in db.query(AuditLog).filter(AuditLog.details.like(f"%{device_id}%")).all()
        ]
    finally:
        db.close()


# ------------------------------------------------------------- crypto contract ---


def test_key_agreement_is_symmetric_and_bound_to_identity():
    dev_priv, dev_pub = enrollment.generate_keypair()
    host_priv, host_pub = enrollment.generate_keypair()
    k_dev = enrollment.derive_session_key(dev_priv, host_pub, "ESP32_ABC123", dev_pub, host_pub)
    k_host = enrollment.derive_session_key(host_priv, dev_pub, "ESP32_ABC123", dev_pub, host_pub)
    assert k_dev == k_host and len(k_dev) == 64
    # Bound to the device id: a different id yields a different key.
    assert (
        enrollment.derive_session_key(host_priv, dev_pub, "ESP32_FFFFFF", dev_pub, host_pub)
        != k_host
    )


def test_known_answer_vector_for_firmware():
    """Fixed-key vector; firmware/esp32_slave_sensor must reproduce this (see firmware README)."""
    dev = enrollment.private_from_hex(
        "a8abababababababababababababababababababababababababababababab6b"
    )
    host = enrollment.private_from_hex(
        "c8cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd4d"
    )
    dev_pub, host_pub = enrollment.public_hex(dev), enrollment.public_hex(host)
    key = enrollment.derive_session_key(dev, host_pub, "ESP32_0A1B2C", dev_pub, host_pub)
    import os

    path = os.path.join(os.path.dirname(__file__), "protocol_v1_vectors.json")
    with open(path, encoding="utf-8") as fh:
        stored = json.load(fh)
    expected = stored["x25519_hkdf"]
    assert (dev_pub, host_pub, key) == (expected["dev_pub"], expected["host_pub"], expected["key"])
    frame = {
        "v": 1,
        "type": "TEL",
        "id": "ESP32_0A1B2C",
        "boot": 1,
        "seq": 1,
        "faults": [],
        "tripped": False,
        "temperature": "26.10",
    }
    assert protocol.canonical(frame) == stored["canonical_tel"]["canonical"]
    assert protocol.sign(frame, key)["sig"] == stored["canonical_tel"]["sig"]


def test_fingerprint_format():
    _, pub = enrollment.generate_keypair()
    fp = enrollment.fingerprint(pub)
    assert len(fp) == 14 and fp.count("-") == 2


# ------------------------------------------------------------- enrollment ---


def test_unapproved_device_is_pending_and_its_telemetry_rejected():
    import app as app_module

    priv, pub = _new_device("ESP32_P00001")
    app_module.handle_device_frame(_hello("ESP32_P00001", pub))
    assert registry.device_info("ESP32_P00001")["status"] == "pending"
    forged_key = "f" * 64
    ok, status, _ = app_module.handle_device_frame(
        _tel("ESP32_P00001", forged_key, 1, 1, temperature=20)
    )
    assert (ok, status) == (False, 403)
    assert "DEVICE_DISCOVERED" in _audit_actions("ESP32_P00001")


def test_approved_device_streams_and_any_number_of_devices_are_listed():
    import app as app_module

    ids = [f"ESP32_N{i:05d}" for i in range(6)]  # more than the old fixed four
    keys = {d: _enroll(d)[1] for d in ids}
    for d in ids:
        ok, status, msg = app_module.handle_device_frame(
            _tel(
                d,
                keys[d],
                100,
                1,
                temperature=25,
                pressure=3,
                vibration=1,
                current=4,
                hall_effect=0,
            )
        )
        assert (ok, status) == (True, 200), msg
    listed = set(app_module._known_device_ids())
    assert set(ids) <= listed


def test_replay_and_old_boot_rejected():
    import app as app_module

    _, key = _enroll("ESP32_R00001")
    first = _tel("ESP32_R00001", key, 500, 10, temperature=22)
    assert app_module.handle_device_frame(first)[1] == 200
    assert app_module.handle_device_frame(first)[1] == 409  # exact replay
    assert (
        app_module.handle_device_frame(_tel("ESP32_R00001", key, 500, 9, temperature=22))[1] == 409
    )
    assert (
        app_module.handle_device_frame(_tel("ESP32_R00001", key, 501, 1, temperature=22))[1] == 200
    )  # reboot
    assert (
        app_module.handle_device_frame(_tel("ESP32_R00001", key, 500, 11, temperature=22))[1] == 409
    )  # old boot


def test_bad_signature_counts_toward_quarantine():
    import app as app_module

    _, key = _enroll("ESP32_B00001")
    for i in range(3):
        frame = _tel("ESP32_B00001", key, 1, i + 1, temperature=22)
        frame["sig"] = "0" * 64
        assert app_module.handle_device_frame(frame)[1] == 401
    db = SessionLocal()
    assert db.query(DeviceState).filter_by(device_id="ESP32_B00001").first().is_isolated
    db.close()


def test_key_change_drops_device_back_to_pending():
    import app as app_module

    _enroll("ESP32_K00001")
    _, other_pub = enrollment.generate_keypair()
    ok, _, msg = app_module.handle_device_frame(_hello("ESP32_K00001", other_pub, enrolled=True))
    assert "key_changed" in msg
    assert registry.device_info("ESP32_K00001")["status"] == "pending"
    assert registry.get_key("ESP32_K00001") is None
    assert "DEVICE_KEY_CHANGED" in _audit_actions("ESP32_K00001")


def test_registry_api_requires_login_and_approves():
    import app as app_module

    _, pub = _new_device("ESP32_A00001")
    app_module.handle_device_frame(_hello("ESP32_A00001", pub))
    anon = app.test_client()
    assert anon.get("/api/registry").status_code == 302
    client = app.test_client()
    db = SessionLocal()
    from database import User

    admin_id = db.query(User).filter_by(username="admin").first().id
    db.close()
    with client.session_transaction() as sess:
        sess.update(user_id=admin_id, username="admin", location="T", csrf_token="t")
    data = client.get("/api/registry").get_json()
    assert data["pending_count"] >= 1
    res = client.post(
        "/api/registry/ESP32_A00001/approve",
        json={"name": "Boiler feed pump"},
        headers={"X-CSRF-Token": "t"},
    )
    assert res.status_code == 200, res.get_json()
    info = registry.device_info("ESP32_A00001")
    assert info["status"] == "approved" and info["name"] == "Boiler feed pump"
    assert (
        client.post("/api/registry/ESP32_A00001/approve", headers={"X-CSRF-Token": "t"}).status_code
        == 409
    )
    assert (
        client.post("/api/registry/ESP32_A00001/reject", headers={"X-CSRF-Token": "t"}).status_code
        == 200
    )
    assert registry.device_info("ESP32_A00001")["status"] == "revoked"


# ------------------------------------------------- end-to-end with the simulator ---


def _wait(predicate, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.1)
    return False


def test_end_to_end_simulator_enroll_stream_and_acked_commands(monkeypatch):
    """Real gateway thread + simulated bus (5 slaves): discovery -> approve -> telemetry ->
    SETPOINT / ISOLATE / REARM acknowledged by the devices."""
    import threading
    import app as app_module

    monkeypatch.setenv("AEGIS_SIM_DEVICES", "5")
    thread = threading.Thread(
        target=serial_gateway.start_gateway, kwargs={"mock": True, "port": None}, daemon=True
    )
    thread.start()
    try:
        assert _wait(
            lambda: serial_gateway.get_simulated_bus() is not None and serial_gateway.is_connected()
        )
        bus = serial_gateway.get_simulated_bus()
        sim_ids = [d.id for d in bus.devices]
        assert len(sim_ids) == 5
        assert _wait(lambda: all((registry.device_info(d) or {}).get("status") for d in sim_ids))

        for d in sim_ids:
            if registry.device_info(d)["status"] != "approved":
                serial_gateway.send_frame(registry.approve(d, user_id=None))
        assert _wait(lambda: all(registry.device_info(d)["enrollment_confirmed"] for d in sim_ids))

        def has_telemetry(dev):
            from database import TelemetryLog

            db = SessionLocal()
            try:
                return (
                    db.query(TelemetryLog).filter_by(device_id=dev, is_simulated=True).count() > 0
                )
            finally:
                db.close()

        assert _wait(lambda: all(has_telemetry(d) for d in sim_ids), timeout=20)

        target = sim_ids[0]
        db = SessionLocal()
        st = db.query(DeviceState).filter_by(device_id=target).first()
        st.is_isolated = False
        db.commit()
        db.close()

        ok = app_module.send_device_command(
            target, "SETPOINT", {"param": "temperature", "value": "31.50"}, wait_ack_s=5
        )
        assert ok["status"] == "ACKED", ok
        assert bus.device(target).sp_t == 31.5
        bad = app_module.send_device_command(
            target, "SETPOINT", {"param": "temperature", "value": "99.00"}, wait_ack_s=5
        )
        assert bad["status"] == "REJECTED" and "envelope" in bad["result"]
        assert app_module.send_device_command(target, "ISOLATE", wait_ack_s=5)["status"] == "ACKED"
        assert bus.device(target).tripped is True
        assert app_module.send_device_command(target, "REARM", wait_ack_s=5)["status"] == "ACKED"
        assert bus.device(target).tripped is False

        ping = app_module.send_device_command(target, "PING", wait_ack_s=5)
        assert ping["status"] == "ACKED"
        db = SessionLocal()
        statuses = {r.status for r in db.query(CommandLog).filter_by(device_id=target).all()}
        db.close()
        assert {"ACKED", "REJECTED"} <= statuses
    finally:
        serial_gateway.stop_gateway()
        thread.join(timeout=5)


def test_setpoint_route_waits_for_device_ack(monkeypatch):
    """/api/setpoint for a v1 device returns success only after the device acknowledges."""
    import threading

    monkeypatch.setenv("AEGIS_SIM_DEVICES", "1")
    thread = threading.Thread(
        target=serial_gateway.start_gateway, kwargs={"mock": True, "port": None}, daemon=True
    )
    thread.start()
    try:
        assert _wait(
            lambda: serial_gateway.get_simulated_bus() is not None and serial_gateway.is_connected()
        )
        dev = serial_gateway.get_simulated_bus().devices[0].id
        assert _wait(lambda: registry.device_info(dev) is not None)
        if registry.device_info(dev)["status"] != "approved":
            serial_gateway.send_frame(registry.approve(dev, user_id=None))
        assert _wait(lambda: registry.device_info(dev)["enrollment_confirmed"])
        db = SessionLocal()
        st = db.query(DeviceState).filter_by(device_id=dev).first()
        st.is_isolated = False
        db.commit()
        from database import User

        admin_id = db.query(User).filter_by(username="admin").first().id
        db.close()
        # Telemetry must be fresh for the safety enforcer (low-risk setpoints pass regardless).
        client = app.test_client()
        with client.session_transaction() as sess:
            sess.update(user_id=admin_id, username="admin", location="T", csrf_token="t")
        res = client.post(
            "/api/setpoint",
            json={"type": "set_temp", "value": 30, "target_device": dev},
            headers={"X-CSRF-Token": "t"},
        )
        body = res.get_json()
        assert res.status_code == 200, body
        assert body["command"]["status"] == "ACKED"
    finally:
        serial_gateway.stop_gateway()
        thread.join(timeout=5)


def test_simulated_device_keeps_key_and_trip_state_across_restart(tmp_path):
    """The simulator mirrors firmware NVS: key, host sequence and trip state survive a reboot."""
    bus = simulator.SimulatedBus(str(tmp_path), 1)
    dev = bus.devices[0]
    host_priv, host_pub = enrollment.generate_keypair()
    key = enrollment.derive_session_key(host_priv, dev.pub, dev.id, dev.pub, host_pub)
    assert dev.on_welcome(protocol.build_welcome(dev.id, host_pub, key))["result"] == "OK"
    assert dev.on_command(protocol.build_cmd(dev.id, 1, "ISOLATE", {}, key))["result"] == "OK"

    rebooted = simulator.SimulatedBus(str(tmp_path), 1).devices[0]
    assert (rebooted.id, rebooted.key, rebooted.tripped, rebooted.last_host_seq) == (
        dev.id,
        key,
        True,
        1,
    )
    assert rebooted.boot != dev.boot  # new boot id on power-up
    # The old command can't be replayed against the rebooted device.
    assert (
        rebooted.on_command(protocol.build_cmd(dev.id, 1, "REARM", {}, key))["result"] == "REPLAY"
    )


def test_quarantined_device_is_retripped_when_it_reenrolls(monkeypatch):
    import app as app_module

    priv, key = _enroll("ESP32_Q00001")
    db = SessionLocal()
    db.query(DeviceState).filter_by(device_id="ESP32_Q00001").first().is_isolated = True
    db.commit()
    db.close()
    monkeypatch.setattr(serial_gateway, "is_connected", lambda: True)
    ack = protocol.sign(
        {
            "v": 1,
            "type": "ACK",
            "id": "ESP32_Q00001",
            "boot": 3,
            "seq": 1,
            "ack": 0,
            "result": "OK",
        },
        key,
    )
    assert app_module.handle_device_frame(ack)[1] == 200
    queued = serial_gateway.pop_ready_commands()
    assert any(
        f.get("type") == "CMD" and f.get("cmd") == "ISOLATE" and f.get("id") == "ESP32_Q00001"
        for f in queued
    )
