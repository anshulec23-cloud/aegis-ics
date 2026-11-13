import os
import sys
import time
import json
import hmac
import hashlib
import tempfile
import pytest

# Ensure src is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from app import app, process_telemetry, LocalRFModel, rf_model
from serial_gateway import send_command, _command_queue, sign_message
from security import get_device_key
from database import init_db, SessionLocal, User


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-security-secret-key"
    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client


def test_rf_model_sha256_integrity_verification():
    """Verify pre-trained Random Forest model SHA-256 integrity file exists, matches, and protects against tampering."""
    model_path = rf_model.model_path
    hash_path = model_path + ".sha256"

    assert os.path.exists(hash_path), f"Expected hash file at {hash_path}"
    with open(hash_path, "r", encoding="utf-8") as f:
        expected_hash = f.read().strip()

    with open(model_path, "rb") as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()

    assert expected_hash == actual_hash, "Model hash mismatch!"

    # Verify reload succeeds with authentic model
    assert rf_model.reload() is True

    # Test tampering defense with temporary fake model and mismatched hash
    with tempfile.TemporaryDirectory() as tmpdir:
        fake_model_path = os.path.join(tmpdir, "fake_model.pkl")
        fake_hash_path = fake_model_path + ".sha256"

        with open(fake_model_path, "wb") as f:
            f.write(b"corrupted_or_malicious_payload")

        with open(fake_hash_path, "w", encoding="utf-8") as f:
            f.write("0000000000000000000000000000000000000000000000000000000000000000")

        tampered_loader = LocalRFModel(fake_model_path)
        # Loader must fail closed and refuse to unpickle
        assert tampered_loader.model is None


def test_telemetry_anti_replay_window():
    """Verify telemetry payloads with expired timestamps (>60s skew) are rejected."""
    key = get_device_key("ESP32_001")

    # Stale payload (120 seconds in the past)
    stale_ts = time.time() - 120.0
    stale_payload = {
        "device_id": "ESP32_001",
        "temperature": 25.0,
        "pressure": 3.0,
        "vibration": 0.05,
        "current": 1.5,
        "timestamp": stale_ts
    }
    stale_payload["signature"] = sign_message(stale_payload, key)

    # Disable TESTING mode bypass to enforce anti-replay window
    app.config["TESTING"] = False
    try:
        success, code, msg = process_telemetry(stale_payload)
        assert success is False
        assert code == 400
        assert "expired" in msg.lower() or "skew" in msg.lower()

        # Fresh payload (< 5 seconds skew)
        fresh_payload = {
            "device_id": "ESP32_001",
            "temperature": 25.0,
            "pressure": 3.0,
            "vibration": 0.05,
            "current": 1.5,
            "timestamp": time.time()
        }
        fresh_payload["signature"] = sign_message(fresh_payload, key)
        fresh_success, fresh_code, fresh_msg = process_telemetry(fresh_payload)
        # Should not be rejected for timestamp expiration
        assert "expired" not in fresh_msg.lower()
    finally:
        app.config["TESTING"] = True


def test_actuator_commands_hmac_signing():
    """Verify all enqueued actuator commands are cryptographically signed with HMAC-SHA256."""
    while not _command_queue.empty():
        try:
            _command_queue.get_nowait()
        except Exception:
            break

    # Dispatch command without signature
    unsigned_cmd = {
        "command": "SHUTDOWN",
        "action": "SHUTDOWN",
        "device_id": "ESP32_001",
        "target_device": "ESP32_001",
        "timestamp": time.time()
    }
    send_command(unsigned_cmd)

    assert not _command_queue.empty()
    queued = _command_queue.get_nowait()
    assert "signature" in queued
    assert len(queued["signature"]) == 64  # SHA-256 hex digest length

    # Validate that signature matches canonical HMAC
    key = get_device_key("ESP32_001")
    body = {k: v for k, v in queued.items() if k != "signature"}
    expected_sig = sign_message(body, key)
    assert hmac.compare_digest(queued["signature"], expected_sig)


def test_login_placeholder_credential_sanitization(client):
    """Verify login HTML does not expose default passwords or credentials in input placeholders."""
    res = client.get("/login")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert 'placeholder="Enter password"' in html
    assert 'placeholder="noodles"' not in html
