"""Static contract checks between the ESP32 firmware and the host (protocol v1).

The firmware can't run in CI, so these tests pin down the properties the host relies on:
canonical key order, command verification, the SETPOINT contract and bus discipline. The
known-answer crypto vector is shared with the firmware self-test (AEGIS_SELFTEST).
"""

import json
import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SLAVE = open(os.path.join(ROOT, "firmware", "esp32_slave_sensor", "esp32_slave_sensor.ino"), encoding="utf-8").read()
MASTER = open(os.path.join(ROOT, "firmware", "esp32_master_bridge", "esp32_master_bridge.ino"), encoding="utf-8").read()
VECTORS = json.load(open(os.path.join(os.path.dirname(__file__), "protocol_v1_vectors.json"), encoding="utf-8"))


def _function_body(src, signature):
    """Body of a C++ function, counting braces outside string/char literals."""
    start = src.index(signature)
    i = src.index("{", start)
    depth, j, quote = 0, i, None
    while j < len(src):
        c = src[j]
        if quote:
            if c == "\\":
                j += 1
            elif c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
        j += 1
    raise AssertionError(signature)


def _doc_keys(body):
    keys = []
    for m in re.finditer(r'doc\["(\w+)"\]\s*=|doc\.createNestedArray\("(\w+)"\)', body):
        key = m.group(1) or m.group(2)
        if key not in keys and key != "sig":
            keys.append(key)
    return keys


def test_no_keys_or_per_node_config_in_firmware():
    assert "aegis_shared_" not in SLAVE and "PRE_SHARED_HMAC_KEY" not in SLAVE
    assert "NODE_CONFIG_" not in SLAVE and "aegis_secrets.h" not in SLAVE
    assert "getEfuseMac" in SLAVE  # identity derived from the chip


def test_signed_frames_are_built_in_canonical_sorted_order():
    """ArduinoJson keeps insertion order, so keys must be inserted sorted to match the host."""
    for fn in ("static void send_telemetry()", "static void send_ack(", "static void send_hello()"):
        keys = _doc_keys(_function_body(SLAVE, fn))
        assert keys == sorted(keys), (fn, keys)


def test_s3_commands_are_verified_before_acting():
    body = _function_body(SLAVE, "static void handle_command(")
    verify_at = body.index("verify_frame_signature")
    replay_at = body.index("seq <= host_seq")
    first_action = min(body.index(w) for w in ("tripped = true", "tripped = false", "sp_temp = value"))
    assert verify_at < first_action and replay_at < first_action
    assert '"BAD_SIG"' in body and '"REPLAY"' in body


def test_f2_setpoint_contract_matches_host():
    import protocol

    body = _function_body(SLAVE, "static void handle_command(")
    assert '"SETPOINT"' in body and 'doc["args"]["param"]' in body and 'doc["args"]["value"]' in body
    frame = protocol.build_cmd("ESP32_0A1B2C", 1, "SETPOINT", {"param": "temperature", "value": "30.00"}, "k" * 64)
    assert set(frame["args"]) == {"param", "value"} and isinstance(frame["args"]["value"], str)
    assert set(protocol.SETPOINT_PARAMS.values()) == {"temperature", "pressure"}


def test_trip_state_restored_before_anything_else_on_boot():
    body = _function_body(SLAVE, "void setup()")
    assert body.index('nvs.getBool("tripped"') < body.index("apply_relay()") < body.index("send_hello()")


def test_firmware_selftest_uses_the_shared_vectors():
    v = VECTORS["x25519_hkdf"]
    for value in (v["dev_priv"], v["dev_pub"], v["host_pub"], v["key"], VECTORS["canonical_tel"]["sig"]):
        assert value in SLAVE


def test_f5_slaves_only_transmit_when_addressed_on_the_bus():
    loop = _function_body(SLAVE, "void loop()")
    assert "send_telemetry" in loop and "usb_only_tx = true" in loop  # free-run is USB-only
    handle = _function_body(SLAVE, "static void handle_line(")
    assert '"POLL"' in handle and "esp_random() % 300" in handle
    assert '"POLL"' in MASTER and "DISCOVER" in MASTER and "POLL_REPLY_TIMEOUT_MS" in MASTER


def test_f7_faulted_sensors_are_reported_not_faked():
    assert not re.search(r"(?<![\w])random\(", SLAVE)  # Arduino random() was used to fake readings
    body = _function_body(SLAVE, "static void send_telemetry()")
    assert 'faults.add("temperature")' in body
