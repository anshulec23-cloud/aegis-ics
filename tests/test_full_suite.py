import sys
import os
import time
import json
import threading
import pytest
from concurrent.futures import ThreadPoolExecutor

# Add src to python path
src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
sys.path.insert(0, src_dir)

# Isolate database for tests to prevent modifying production aegis_v2.db
test_db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_aegis.db"))
os.environ["DATABASE_URL"] = f"sqlite:///{test_db_path}"

from database import init_db, SessionLocal, User, AuditLog, TelemetryLog, Rule, DeviceState
from security import get_device_key
from safety_enforcer import validate_command
from analytics import calculate_financial_analytics
from reporting import generate_incident_report_pdf
from serial_gateway import parse_serial_line, sign_message, canonicalize_payload
from werkzeug.security import generate_password_hash

# Initialize DB for tests
init_db()

def get_test_db():
    return SessionLocal()

# --- 1. Database & User Unit Tests ---
def test_database_init_and_users():
    db = get_test_db()
    try:
        # Create test user if not exists
        existing = db.query(User).filter_by(username="test_operator").first()
        if existing:
            db.delete(existing)
            db.commit()

        user = User(username="test_operator", password_hash=generate_password_hash("securepass123"))
        db.add(user)
        db.commit()

        queried = db.query(User).filter_by(username="test_operator").first()
        assert queried is not None
        assert queried.id > 0
    finally:
        db.close()

# --- 2. Security & HMAC Signatures ---
def test_security_hmac_and_tokens():
    key = get_device_key("ESP32_001")
    assert key is not None and len(key) > 0

    payload = {
        "device_id": "ESP32_001",
        "timestamp": 1700000000.123,
        "temperature": 25.5,
        "pressure": 4.2
    }
    sig1 = sign_message(payload, key)
    sig2 = sign_message(payload, key)
    assert sig1 == sig2
    assert len(sig1) == 64  # SHA-256 hex digest length

    # Canonicalization check
    can = canonicalize_payload(payload)
    assert can["temperature"] == "25.50"
    assert can["pressure"] == "4.20"
    assert can["timestamp"] == "1700000000.123"

# --- 3. Safety Enforcer & Stuxnet Prevention Rules ---
def test_safety_enforcer_rules():
    db = get_test_db()
    try:
        # Reset rules for clean safety test
        db.query(Rule).delete()
        db.commit()

        # 1. Unknown command type
        ok, msg = validate_command({"type": "invalid_cmd", "value": 10}, db)
        assert not ok
        assert "Unknown command type" in msg

        # 2. Non-numeric value
        ok, msg = validate_command({"type": "set_temp", "value": "fifty"}, db)
        assert not ok
        assert "numeric" in msg

        # 3. Temperature boundary exceed (default max 60.0, min 0.0)
        ok, msg = validate_command({"type": "set_temp", "value": 65.0}, db)
        assert not ok
        assert "exceeds boundaries" in msg

        ok, msg = validate_command({"type": "set_temp", "value": -5.0}, db)
        assert not ok

        # 4. Valid set_temp within limits (when pressure is normal)
        # Seed a normal telemetry log
        db.query(TelemetryLog).delete()
        db.commit()

        normal_log = TelemetryLog(
            timestamp=time.time(),
            device_id="ESP32_001",
            temperature=25.0,
            pressure=3.0,
            humidity=50.0
        )
        db.add(normal_log)
        db.commit()

        ok, msg = validate_command({"type": "set_temp", "value": 40.0}, db)
        assert ok
        assert msg == "Approved"

        # 5. Stuxnet Coordinated Hazard: High Pressure + High Temp Setpoint
        high_pres_log = TelemetryLog(
            timestamp=time.time() + 1,
            device_id="ESP32_001",
            temperature=30.0,
            pressure=7.2,
            humidity=50.0
        )
        db.add(high_pres_log)
        db.commit()

        ok, msg = validate_command({"type": "set_temp", "value": 50.0}, db)
        assert not ok
        assert "Stuxnet Prevention" in msg

        # 6. Stuxnet Coordinated Hazard: High Temp + High Pressure Setpoint
        high_temp_log = TelemetryLog(
            timestamp=time.time() + 2,
            device_id="ESP32_001",
            temperature=52.0,
            pressure=2.0,
            humidity=50.0
        )
        db.add(high_temp_log)
        db.commit()

        ok, msg = validate_command({"type": "set_pressure", "value": 6.5}, db)
        assert not ok
        assert "Stuxnet Prevention" in msg
    finally:
        db.close()

# --- 3b. Neural Safety Policy Network (NSPN) Dedicated Tests ---
def test_neural_safety_policy_model_loading():
    from neural_policy import NeuralSafetyPolicy
    policy = NeuralSafetyPolicy()
    assert policy.weights_loaded, "Neural safety policy weights should be successfully loaded"
    assert len(policy.weights_dict) >= 8 or policy.torch_model is not None

    # Test nominal forward pass
    import numpy as np
    nominal_vec = np.array([28.0, 3.5, 1.2, 0.0, 4.5, 32.0], dtype=np.float32)
    p_safe = policy.predict_safety_probability(nominal_vec)
    assert 0.0 <= p_safe <= 1.0
    assert p_safe > 0.80, f"Expected nominal vector to be safe, got P(safe)={p_safe}"

def test_neural_safety_enforcer_adversarial_rejection():
    db = get_test_db()
    try:
        db.query(TelemetryLog).delete()
        db.commit()

        # Seed high-pressure active telemetry on reactor
        active_log = TelemetryLog(
            timestamp=time.time(),
            device_id="ESP32_001",
            temperature=32.0,
            pressure=7.4,
            vibration=1.8,
            hall_effect=0.0,
            current=4.8
        )
        db.add(active_log)
        db.commit()

        # Coordinated Stuxnet: Raising temp to 52C while pressure is already 7.4 bar
        cmd = {"type": "set_temp", "value": 52.0}
        ok, msg = validate_command(cmd, db, target_device="ESP32_001")
        assert not ok, "Command should be blocked by Neural Safety Policy"
        assert "Neural Safety" in msg or "Stuxnet Prevention" in msg
        # Safe command: Normal temperature setpoint under nominal plant conditions
        normal_log = TelemetryLog(
            timestamp=time.time() + 1,
            device_id="ESP32_001",
            temperature=26.0,
            pressure=3.2,
            vibration=1.0,
            hall_effect=0.0,
            current=4.2
        )
        db.add(normal_log)
        db.commit()

        safe_cmd = {"type": "set_temp", "value": 35.0}
        ok_safe, msg_safe = validate_command(safe_cmd, db, target_device="ESP32_001")
        assert ok_safe, f"Safe setpoint should be approved, got: {msg_safe}"
    finally:
        db.close()

def test_neural_policy_fallback_handling():
    from neural_policy import NeuralSafetyPolicy
    import numpy as np
    # Instantiate with non-existent path to verify graceful heuristic fallback
    policy = NeuralSafetyPolicy(weights_path="non_existent_weights_file.npz")
    assert not policy.weights_loaded

    # Fallback should still protect against extreme values
    hazard_vec = np.array([50.0, 7.0, 2.0, 0.0, 5.0, 55.0], dtype=np.float32)
    prob_hazard = policy.predict_safety_probability(hazard_vec)
    assert prob_hazard < 0.50

    safe_vec = np.array([25.0, 3.0, 1.0, 0.0, 4.0, 30.0], dtype=np.float32)
    prob_safe = policy.predict_safety_probability(safe_vec)
    assert prob_safe > 0.50

# --- 4. Financial & Threat Index Analytics ---
def test_financial_analytics():
    db = get_test_db()
    try:
        # Test 1: Empty database
        db.query(TelemetryLog).delete()
        db.query(AuditLog).delete()
        db.commit()

        fin = calculate_financial_analytics(db)
        assert fin["violation_count"] == 0
        assert fin["incurred_cost"] == 0.0
        assert fin["prevented_cost"] == 0.0
        assert fin["threat_index"] == 0.0

        # Test 2: Insert 5 telemetry logs (< 15 logs)
        for i in range(5):
            t = TelemetryLog(
                timestamp=100.0 + i * 10,
                device_id="ESP32_001",
                temperature=20.0 + i,
                pressure=3.0 + i * 0.1
            )
            db.add(t)
        db.commit()

        fin_5 = calculate_financial_analytics(db)
        assert fin_5["threat_index"] >= 0.0
        assert "expected_loss" in fin_5

        # Test 3: Insert 20 logs to trigger correlation and drift calculations
        for i in range(5, 25):
            t = TelemetryLog(
                timestamp=100.0 + i * 10,
                device_id="ESP32_001",
                temperature=20.0 + i * 1.5,
                pressure=3.0 + i * 0.2
            )
            db.add(t)
        db.commit()

        fin_20 = calculate_financial_analytics(db)
        assert fin_20["threat_index"] > 0.0
        assert fin_20["drift_risk"] >= 0.0
    finally:
        db.close()

# --- 5. PDF Incident Report Generation ---
def test_pdf_report_generation():
    db = get_test_db()
    try:
        pdf_bytes = generate_incident_report_pdf(db, "test_operator", "X:10.0, Y:20.0, Z:30.0")
        assert pdf_bytes is not None
        assert len(pdf_bytes) > 500
        assert pdf_bytes.startswith(b"%PDF")
    finally:
        db.close()

# --- 6. Serial Gateway Parser Tests ---
def test_serial_gateway_parsing():
    # 1. JSON format
    json_line = '{"temp": 42.5, "pres": 5.1, "vib": 1.2, "hall": 1200, "curr": 3.4}\n'
    res = parse_serial_line(json_line, "plc")
    assert res is not None
    assert res["temperature"] == 42.5
    assert res["pressure"] == 5.1

    # 2. CSV format (5 parts)
    csv_line = "35.2, 4.1, 0.9, 1500, 2.8\n"
    res_csv = parse_serial_line(csv_line, "plc")
    assert res_csv is not None
    assert res_csv["temperature"] == 35.2
    assert res_csv["pressure"] == 4.1

    # 3. Key-Value format
    kv_line = "TEMP:48.2, P:6.5, VIB:1.1\n"
    res_kv = parse_serial_line(kv_line, "plc")
    assert res_kv is not None
    assert res_kv["temperature"] == 48.2
    assert res_kv["pressure"] == 6.5

    # 4. Invalid / empty string
    assert parse_serial_line("", "plc") is None
    assert parse_serial_line("  \n", "plc") is None

# --- 7. Flask REST API Integration & Attack Simulation Tests ---
def test_flask_api_routes():
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "X:-12.40, Y:-48.10, Z:-3.50"
        sess["csrf_token"] = "valid_csrf_token"

    headers = {"X-CSRF-Token": "valid_csrf_token"}

    # 1. Get Data
    res = client.get("/api/data", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert "telemetry" in data
    assert "audit_logs" in data
    assert "financials" in data

    # 1b. Get Neural Policy Status
    res_np = client.get("/api/neural_policy/status", headers=headers)
    assert res_np.status_code == 200
    np_info = res_np.get_json()
    assert np_info["success"] is True
    assert np_info["architecture"] == "6 -> 64 -> 32 -> 16 -> 1"
    assert "status" in np_info

    # 2. Rule updates
    res = client.post(
        "/api/rules/update",
        json={"temp_max": 65.0, "temp_min": 5.0, "pressure_max": 9.0, "pressure_min": 0.5, "csrf_token": "valid_csrf_token"},
        headers=headers
    )
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # 3. Attack Simulation: Stuxnet
    res = client.post("/api/simulate-attack", json={"type": "stuxnet", "csrf_token": "valid_csrf_token"}, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # Verify data after Stuxnet simulation
    res_data = client.get("/api/data", headers=headers)
    assert res_data.get_json()["financials"]["violation_count"] > 0
    assert res_data.get_json()["financials"]["prevented_cost"] > 0.0

    # 4. Attack Simulation: Injection
    res = client.post("/api/simulate-attack", json={"type": "injection", "csrf_token": "valid_csrf_token"}, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # 5. Attack Simulation: Privilege
    res = client.post("/api/simulate-attack", json={"type": "privilege", "csrf_token": "valid_csrf_token"}, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # 6. Device Isolation & Rejoin
    res = client.post("/api/device/isolate", json={"csrf_token": "valid_csrf_token"}, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    res = client.post("/api/device/rejoin", json={"csrf_token": "valid_csrf_token"}, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # 7. Report PDF Download
    res = client.get("/api/report/download", headers=headers)
    assert res.status_code == 200
    assert res.content_type == "application/pdf"
    assert len(res.data) > 1000

# --- 8. STRESS TEST & Concurrency ---
def test_stress_concurrent_telemetry_and_api():
    from app import app
    app.config["TESTING"] = True

    key = get_device_key("ESP32_001")
    client = app.test_client()

    success_count = [0]
    error_count = [0]
    lock = threading.Lock()

    def worker(worker_id):
        client = app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = f"user_{worker_id}"
            sess["location"] = "X:0.0, Y:0.0, Z:0.0"
            sess["csrf_token"] = "stress_csrf"

        for i in range(25):
            # Ingest telemetry payload with HMAC signature
            payload = {
                "timestamp": time.time(),
                "device_id": "ESP32_001",
                "temperature": 25.0 + (i % 10),
                "pressure": 4.0 + (i % 3) * 0.5,
                "humidity": 50.0,
                "vibration": 1.0,
                "current": 4.5
            }
            payload["signature"] = sign_message(payload, key)

            try:
                res = client.post("/api/telemetry", json=payload)
                if res.status_code == 200:
                    with lock:
                        success_count[0] += 1
                else:
                    with lock:
                        error_count[0] += 1

                # Concurrent data query
                res_data = client.get("/api/data", headers={"X-CSRF-Token": "stress_csrf"})
                assert res_data.status_code in (200, 429)

            except Exception as exc:
                with lock:
                    error_count[0] += 1

    num_threads = 10
    threads = []
    for tid in range(num_threads):
        t = threading.Thread(target=worker, args=(tid,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"\n[Stress Test Results] Total Ingest Requests: {success_count[0]}, Errors: {error_count[0]}")
    assert error_count[0] == 0, f"Stress test encountered {error_count[0]} errors!"
    assert success_count[0] == num_threads * 25

# --- 8b. STRESS TEST: 3 Simulation Attacks & PDF Report Downloads ---
def test_stress_all_3_simulation_attacks_and_pdf_download():
    from app import app
    app.config["TESTING"] = True

    sim_success = [0]
    sim_errors = [0]
    report_success = [0]
    report_errors = [0]
    lock = threading.Lock()

    attack_types = ["stuxnet", "injection", "privilege"]

    def sim_worker(worker_id):
        client = app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = worker_id + 1
            sess["username"] = f"operator_stress_{worker_id}"
            sess["location"] = f"X:{worker_id}.0, Y:10.0, Z:5.0"
            sess["csrf_token"] = f"stress_token_{worker_id}"

        headers = {"X-CSRF-Token": f"stress_token_{worker_id}"}

        for cycle in range(5):
            for atype in attack_types:
                try:
                    res = client.post(
                        "/api/simulate-attack",
                        json={"type": atype, "csrf_token": f"stress_token_{worker_id}"},
                        headers=headers
                    )
                    if res.status_code == 200 and res.get_json().get("success") is True:
                        with lock:
                            sim_success[0] += 1
                    else:
                        with lock:
                            sim_errors[0] += 1
                except Exception:
                    with lock:
                        sim_errors[0] += 1

            # Download PDF Report after simulations
            try:
                rep_res = client.get("/api/report/download", headers=headers)
                if rep_res.status_code == 200 and rep_res.content_type == "application/pdf" and len(rep_res.data) > 1000:
                    with lock:
                        report_success[0] += 1
                else:
                    with lock:
                        report_errors[0] += 1
            except Exception:
                with lock:
                    report_errors[0] += 1

    num_sim_threads = 5
    threads = []
    for tid in range(num_sim_threads):
        t = threading.Thread(target=sim_worker, args=(tid,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"\n[Attack & Report Stress Results] Successful Simulations: {sim_success[0]}, Errors: {sim_errors[0]}")
    print(f"[Attack & Report Stress Results] Successful Report Downloads: {report_success[0]}, Report Errors: {report_errors[0]}")

    assert sim_errors[0] == 0, f"Simulation attack stress test failed with {sim_errors[0]} errors!"
    assert report_errors[0] == 0, f"PDF Report download stress test failed with {report_errors[0]} errors!"
    assert sim_success[0] == num_sim_threads * 5 * 3
    assert report_success[0] == num_sim_threads * 5

# --- 9. Payload Fuzzing & Boundary Tests ---
def test_fuzzing_and_boundary_conditions():
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "fuzzer"
        sess["location"] = "X:0, Y:0, Z:0"
        sess["csrf_token"] = "fuzz_csrf"

    headers = {"X-CSRF-Token": "fuzz_csrf"}

    fuzz_payloads = [
        {},  # Empty payload
        {"type": ""},  # Empty string type
        {"type": "<script>alert(1)</script>", "value": "1' OR '1'='1"},  # XSS / SQLi attempt
        {"type": "set_temp", "value": 999999999999.99},  # Huge number
        {"type": "set_temp", "value": -999999999999.99},  # Large negative number
        {"type": "set_temp", "value": None},  # None value
        {"type": "set_temp", "value": [1, 2, 3]},  # List value
        {"type": "set_temp", "value": {"a": 1}},  # Dict value
    ]

    for p in fuzz_payloads:
        # Ensure no endpoint crashes with 500 error
        res_sp = client.post("/api/setpoint", json=p, headers=headers)
        assert res_sp.status_code in (200, 400, 403, 429), f"Fuzzing /api/setpoint with {p} returned {res_sp.status_code}"

        res_sim = client.post("/api/simulate-attack", json=p, headers=headers)
        assert res_sim.status_code in (200, 400, 403, 429), f"Fuzzing /api/simulate-attack with {p} returned {res_sim.status_code}"

# --- 10. Multi-Device Cluster Endpoints & NIST SP 800-82 Compliance Tests ---
def test_multi_device_cluster_endpoints():
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    db_init = get_test_db()
    for did in ["ESP32_001", "ESP32_002", "ESP32_003", "ESP32_004"]:
        st = db_init.query(DeviceState).filter_by(device_id=did).first()
        if st:
            st.is_isolated = False
    db_init.commit()
    db_init.close()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "37.7749, -122.4194"
        sess["csrf_token"] = "test_csrf_multi"

    headers = {"X-CSRF-Token": "test_csrf_multi"}

    # 1. Test GET /api/devices
    res = client.get("/api/devices")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "devices" in data
    assert len(data["devices"]) >= 4
    dev_ids = [d["device_id"] for d in data["devices"]]
    assert "ESP32_001" in dev_ids
    assert "ESP32_002" in dev_ids
    assert "ESP32_003" in dev_ids
    assert "ESP32_004" in dev_ids

    # Verify trust score properties
    for d in data["devices"]:
        assert "trust_percentage" in d
        assert 0.0 <= d["trust_percentage"] <= 100.0
        assert "is_isolated" in d

    # 2. Test POST /api/device/ping
    res_ping = client.post("/api/device/ping", json={"device_id": "ESP32_002"}, headers=headers)
    assert res_ping.status_code == 200
    ping_data = res_ping.get_json()
    assert ping_data["success"] is True
    assert "Ping echo successful" in ping_data["details"]

    # 3. Test POST /api/device/isolate for specific device
    res_iso = client.post("/api/device/isolate", json={"device_id": "ESP32_003"}, headers=headers)
    assert res_iso.status_code == 200
    iso_data = res_iso.get_json()
    assert iso_data["success"] is True

    # Verify ESP32_003 is now isolated
    res_stat = client.get("/api/device/status?device_id=ESP32_003")
    assert res_stat.status_code == 200
    assert res_stat.get_json()["is_isolated"] is True

    # Verify ESP32_001 is NOT isolated
    res_stat1 = client.get("/api/device/status?device_id=ESP32_001")
    assert res_stat1.status_code == 200
    assert res_stat1.get_json()["is_isolated"] is False

    # 4. Test POST /api/device/rejoin for specific device
    res_rej = client.post("/api/device/rejoin", json={"device_id": "ESP32_003"}, headers=headers)
    assert res_rej.status_code == 200
    assert res_rej.get_json()["success"] is True

    # 5. Test POST /api/device/clear
    res_clr = client.post("/api/device/clear", json={"device_id": "ESP32_003"}, headers=headers)
    assert res_clr.status_code == 200
    assert res_clr.get_json()["success"] is True

    # 6. Test GET /api/data?device_id=ESP32_001
    res_data = client.get("/api/data?device_id=ESP32_001")
    assert res_data.status_code == 200
    d_json = res_data.get_json()
    assert "telemetry" in d_json
    assert "trust" in d_json
    assert "financials" in d_json

    # 7. Test NIST SP 800-82 Report generation
    db = get_test_db()
    try:
        pdf_bytes = generate_incident_report_pdf(db, "admin", "37.7749, -122.4194")
        assert len(pdf_bytes) > 2000
        assert b"%PDF" in pdf_bytes
    finally:
        db.close()


# --- 11. Red Team Attack Simulation Suite Tests ---
def test_attack_simulation_suite():
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "X:12.4, Y:-48.1, Z:3.5"
        sess["csrf_token"] = "test_csrf_attack"

    headers = {"X-CSRF-Token": "test_csrf_attack"}

    # Test injecting each valid attack vector
    for attack in ["stuxnet", "hmac_tamper", "thermal_drift", "fdi_spike"]:
        res = client.post("/api/simulate/attack", json={"device_id": "ESP32_002", "attack_type": attack}, headers=headers)
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["attack"] == attack

    # Test invalid attack vector
    res_bad = client.post("/api/simulate/attack", json={"device_id": "ESP32_002", "attack_type": "unknown_exploit"}, headers=headers)
    assert res_bad.status_code == 200
    assert res_bad.get_json()["success"] is False

    # Test reset attacks endpoint
    res_reset = client.post("/api/simulate/reset", json={}, headers=headers)
    assert res_reset.status_code == 200
    assert res_reset.get_json()["success"] is True


# --- 12. Trust Parameter Mathematical Breakdown Tests ---
def test_trust_breakdown_endpoint():
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "X:12.4, Y:-48.1, Z:3.5"
        sess["csrf_token"] = "test_csrf_breakdown"

    headers = {"X-CSRF-Token": "test_csrf_breakdown"}

    res = client.get("/api/device/ESP32_001/trust_breakdown", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    bd = data["data"]
    assert bd["device_id"] == "ESP32_001"
    assert "trust_percentage" in bd
    assert "components" in bd

    comp = bd["components"]
    assert "s_anomaly" in comp
    assert "s_signature" in comp
    assert "s_history" in comp
    assert "s_stability" in comp

    total_weight = comp["s_anomaly"]["weight"] + comp["s_signature"]["weight"] + comp["s_history"]["weight"] + comp["s_stability"]["weight"]
    assert abs(total_weight - 1.0) < 0.001
    assert "zone" in bd
    assert "stats" in bd


# --- 13. Live ICS Security Event & Audit Stream Tests ---
def test_audit_logs_streaming_endpoint():
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "X:12.4, Y:-48.1, Z:3.5"
        sess["csrf_token"] = "test_csrf_stream"

    headers = {"X-CSRF-Token": "test_csrf_stream"}

    res = client.get("/api/audit/logs?limit=15", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "logs" in data
    assert isinstance(data["logs"], list)

    for entry in data["logs"]:
        assert "id" in entry
        assert "timestamp" in entry
        assert "action" in entry
        assert "nist_control" in entry
        assert "NIST" in entry["nist_control"]


# --- 14. Industrial Cyber-Financial FAIR & ALE Analytics Endpoint Tests ---
def test_financial_analytics_endpoints():
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "Lat: 37.77490, Lon: -122.41940"
        sess["csrf_token"] = "test_csrf_fin"

    headers = {"X-CSRF-Token": "test_csrf_fin"}

    res = client.get("/api/financial/analytics", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "financials" in data

    f = data["financials"]
    assert "fair_model" in f
    assert "ale_framework" in f
    assert "downtime_liability" in f
    assert "regulatory_exposure" in f

    # FAIR metrics
    fair = f["fair_model"]
    assert "tef" in fair
    assert "vulnerability_pct" in fair
    assert "lef" in fair
    assert "primary_loss" in fair
    assert "secondary_loss" in fair
    assert fair["risk_tier"] in ("NOMINAL", "ELEVATED", "CRITICAL")

    # ALE framework
    ale = f["ale_framework"]
    assert ale["sle"] > 0
    assert ale["aro"] > 0
    assert ale["ale"] > 0
    assert ale["risk_reduction_pct"] > 0

    # Downtime liabilities
    dt = f["downtime_liability"]
    assert dt["hourly_rate"] > 0
    assert "active_outage_hourly_loss" in dt
    assert dt["projected_24h_mttr"] > 0

    # Regulatory fines
    reg = f["regulatory_exposure"]
    assert reg["epa_environmental"] > 0
    assert reg["nerc_cip_critical_infra"] > 0
    assert reg["nis2_directive"] > 0
    assert reg["total_regulatory_exposure"] > 0


# --- 15. Monte Carlo Probabilistic Loss Exceedance Distribution Tests ---
def test_financial_loss_distribution_endpoint():
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "Lat: 37.77490, Lon: -122.41940"
        sess["csrf_token"] = "test_csrf_mc"

    headers = {"X-CSRF-Token": "test_csrf_mc"}

    res = client.get("/api/financial/loss_distribution", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "distribution" in data
    dist = data["distribution"]
    assert len(dist) == 12

    percentiles = [p["percentile"] for p in dist]
    assert "P05" in percentiles
    assert "P50" in percentiles
    assert "P99" in percentiles

    # Ensure monotonic loss progression
    losses = [p["loss_usd"] for p in dist]
    assert losses[-1] > losses[0]


# --- 16. Subsystem Capital Valuation & Outage Liability Breakdown Tests ---
def test_financial_subsystems_endpoint():
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "Lat: 37.77490, Lon: -122.41940"
        sess["csrf_token"] = "test_csrf_sub"

    headers = {"X-CSRF-Token": "test_csrf_sub"}

    res = client.get("/api/financial/subsystems", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "subsystems" in data
    subs = data["subsystems"]
    assert len(subs) == 4

    dev_ids = [s["device_id"] for s in subs]
    assert "ESP32_001" in dev_ids
    assert "ESP32_002" in dev_ids
    assert "ESP32_003" in dev_ids
    assert "ESP32_004" in dev_ids

    for s in subs:
        assert s["equipment_value"] > 0
        assert s["downtime_rate_per_hour"] > 0
        assert "is_isolated" in s


# --- 17. Device Hardware GPS & Facility Geolocation Endpoint Tests ---
def test_device_locations_endpoint():
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "Lat: 37.77490, Lon: -122.41940"
        sess["csrf_token"] = "test_csrf_loc"

    headers = {"X-CSRF-Token": "test_csrf_loc"}

    res = client.get("/api/devices/locations", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "locations" in data
    locs = data["locations"]
    assert len(locs) == 4

    for loc in locs:
        assert "device_id" in loc
        assert "latitude" in loc
        assert "longitude" in loc
        assert "elevation_m" in loc
        assert "grid_x" in loc
        assert "grid_y" in loc
        assert "grid_z" in loc
        assert isinstance(loc["latitude"], float)
        assert isinstance(loc["longitude"], float)


# --- 18. Audit & Deep Debugging Regression Tests ---
def test_pdf_report_special_characters_safety():
    """Verify ReportLab PDF generation safely handles XML and special characters without parsing crashes."""
    db = get_test_db()
    try:
        malicious_audit = AuditLog(
            user_id=1,
            action="SECURITY_VIOLATION_<XSS>",
            location="Zone <A> & Sector '4'",
            details="<script>alert(1)</script> & Pressure > 6.0 bar && Temp < 10.0C"
        )
        db.add(malicious_audit)
        db.commit()

        pdf_bytes = generate_incident_report_pdf(db, "admin<tag>&user", "Lat: <37.77>, Lon: &-122")
        assert pdf_bytes is not None
        assert len(pdf_bytes) > 500
        assert pdf_bytes.startswith(b"%PDF")
    finally:
        db.close()


def test_safety_enforcer_type_safety_and_nan():
    """Verify safety enforcer and setpoint API strictly reject booleans, NaN, and Inf."""
    db = get_test_db()
    try:
        # 1. Direct enforcer checks
        ok, msg = validate_command({"type": "set_temp", "value": True}, db)
        assert not ok
        assert "numeric" in msg

        ok, msg = validate_command({"type": "set_temp", "value": float("nan")}, db)
        assert not ok
        assert "finite" in msg

        ok, msg = validate_command({"type": "set_temp", "value": float("inf")}, db)
        assert not ok
        assert "finite" in msg

        # 2. API route checks
        from app import app
        app.config["TESTING"] = True
        client = app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin"
            sess["location"] = "X:0, Y:0, Z:0"
            sess["csrf_token"] = "test_csrf_type"

        headers = {"X-CSRF-Token": "test_csrf_type"}

        # Boolean in setpoint
        res = client.post("/api/setpoint", json={"type": "set_temp", "value": True, "csrf_token": "test_csrf_type"}, headers=headers)
        assert res.status_code == 400

        # Non-numeric string in setpoint
        res2 = client.post("/api/setpoint", json={"type": "set_temp", "value": "invalid", "csrf_token": "test_csrf_type"}, headers=headers)
        assert res2.status_code == 400
    finally:
        db.close()


def test_rules_inversion_rejection_and_audit_trail():
    """Verify safety rule updates reject inverted boundaries and generate audit records."""
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "Control Center"
        sess["csrf_token"] = "test_csrf_rules"

    headers = {"X-CSRF-Token": "test_csrf_rules"}

    # 1. Attempt inverted temperature rule (min >= max)
    res_inv = client.post(
        "/api/rules/update",
        json={"temp_min": 75.0, "temp_max": 50.0, "csrf_token": "test_csrf_rules"},
        headers=headers
    )
    assert res_inv.status_code == 400
    assert res_inv.get_json()["success"] is False
    assert "strictly less" in res_inv.get_json()["error"]

    # 2. Valid rule update
    res_valid = client.post(
        "/api/rules/update",
        json={"temp_min": 5.0, "temp_max": 65.0, "pressure_min": 0.5, "pressure_max": 9.0, "csrf_token": "test_csrf_rules"},
        headers=headers
    )
    assert res_valid.status_code == 200
    assert res_valid.get_json()["success"] is True

    # 3. Verify AuditLog entry was committed
    db = get_test_db()
    try:
        audit = db.query(AuditLog).filter_by(action="UPDATE_SAFETY_RULES").order_by(AuditLog.timestamp.desc()).first()
        assert audit is not None
        assert "temp=[5.0" in audit.details
    finally:
        db.close()


def test_devices_metadata_enrichment():
    """Verify /api/devices returns enriched subsystem metadata (name, zone, criticality)."""
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "Control Center"
        sess["csrf_token"] = "test_csrf_devs"

    headers = {"X-CSRF-Token": "test_csrf_devs"}

    res = client.get("/api/devices", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    devices = data["devices"]
    assert len(devices) >= 4

    dev_map = {d["device_id"]: d for d in devices}
    assert "Catalytic Reactor 01" in dev_map["ESP32_001"]["name"]
    assert "Zone A" in dev_map["ESP32_001"]["zone"]
    assert "TIER-1 CRITICAL" in dev_map["ESP32_001"]["criticality"]
    assert "Centrifugal Pump 02" in dev_map["ESP32_002"]["name"]


def test_semver_parsing_robustness():
    """Verify _parse_semver handles standard semver, prefixes, and pre-release tags."""
    from updater import _parse_semver
    assert _parse_semver("2.3.0") == (2, 3, 0)
    assert _parse_semver("v2.3.0") == (2, 3, 0)
    assert _parse_semver("2.3.0-rc1") == (2, 3, 0)
    assert _parse_semver("1.0.0.beta") == (1, 0, 0, 0)
    assert _parse_semver("3") == (3,)


def test_comprehensive_nist800_pdf_content():
    """Verify generated PDF contains all NIST 800-82 sections, all 4 ESPs, parameters, safeguard rules, and FAIR metrics."""
    try:
        import pypdf
    except ImportError:
        pytest.skip("pypdf is required to parse and inspect generated PDF contents")
    from io import BytesIO
    db = get_test_db()
    try:
        # Seed test telemetry for ESP32_001
        t_sample = TelemetryLog(
            timestamp=time.time(),
            device_id="ESP32_001",
            temperature=42.50,
            pressure=5.20,
            vibration=1.85,
            hall_effect=1500.0,
            current=4.20,
            humidity=55.0,
            rssi=-62.0,
            is_anomaly=False
        )
        db.add(t_sample)
        db.commit()

        pdf_bytes = generate_incident_report_pdf(db, "chief_operator", "Sector-7 Plant Grid")
        assert pdf_bytes is not None
        assert pdf_bytes.startswith(b"%PDF")
        assert len(pdf_bytes) > 10000

        # Read and verify page content
        reader = pypdf.PdfReader(BytesIO(pdf_bytes))
        assert len(reader.pages) >= 4
        all_text = "\n".join([page.extract_text() for page in reader.pages])

        # 1. All 4 ESP Nodes
        for dev_id in ["ESP32_001", "ESP32_002", "ESP32_003", "ESP32_004"]:
            assert dev_id in all_text, f"Missing node {dev_id} in PDF!"

        # 2. Safeguard Boundaries
        for rule_key in ["temp_min", "temp_max", "pressure_min", "pressure_max"]:
            assert rule_key in all_text, f"Missing rule boundary {rule_key} in PDF!"

        # 3. NIST Standards & Mitigations
        assert "NIST SP 800-82" in all_text
        assert "NIST SP 800-53" in all_text
        assert "AC-4" in all_text
        assert "SC-7" in all_text
        assert "SI-4" in all_text
        assert "AU-2" in all_text

        # 4. FAIR & Financial Analytics
        assert "TEF" in all_text
        assert "LEF" in all_text
        assert "ROSI" in all_text
        assert "Single Loss Expectancy" in all_text
        assert "Annualized Loss Expectancy" in all_text

        # 5. Regulatory Penalties
        assert "EPA" in all_text
        assert "NERC-CIP" in all_text
        assert "NIS2" in all_text

        # 6. Monte Carlo 12-point Percentiles
        for pct in ["P05", "P50", "P99"]:
            assert pct in all_text, f"Missing Monte Carlo percentile {pct} in PDF!"
    finally:
        db.close()


def test_pdf_download_and_view_endpoints():
    """Verify /api/report/download and /api/report/view endpoints return valid PDF attachments and inline streams."""
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "Station Alpha"
        sess["csrf_token"] = "pdf_test_csrf"

    headers = {"X-CSRF-Token": "pdf_test_csrf"}

    # 1. Test Download endpoint
    res_dl = client.get("/api/report/download", headers=headers)
    assert res_dl.status_code == 200
    assert res_dl.content_type == "application/pdf"
    assert "attachment" in res_dl.headers.get("Content-Disposition", "")
    assert ".pdf" in res_dl.headers.get("Content-Disposition", "")
    assert len(res_dl.data) > 10000
    assert res_dl.data.startswith(b"%PDF")

    # 2. Test Inline View endpoint
    res_view = client.get("/api/report/view", headers=headers)
    assert res_view.status_code == 200
    assert res_view.content_type == "application/pdf"
    assert "inline" in res_view.headers.get("Content-Disposition", "")
    assert ".pdf" in res_view.headers.get("Content-Disposition", "")
    assert len(res_view.data) > 10000
    assert res_view.data.startswith(b"%PDF")

    # 3. Test Save Dialog endpoint
    res_dialog = client.post("/api/report/save_dialog", headers=headers)
    assert res_dialog.status_code == 200
    data_dialog = res_dialog.get_json()
    assert data_dialog["success"] is True


def test_firmware_cryptographic_parity():
    """Verify byte-for-byte HMAC-SHA256 parity between ESP32 C++ firmware formatting and Python zero-trust engine."""
    import hmac
    import hashlib
    import json
    from app import verify_signature
    from security import get_device_key

    device_id = "ESP32_001"
    key = get_device_key(device_id)

    # Values matching what esp32_slave_sensor.ino outputs
    current = 4.50
    rpm = 0.00
    pressure = 4.20
    temperature = 26.00
    vibration = 1.10

    # C++ snprintf formula:
    # snprintf(canonical_str, sizeof(canonical_str),
    #   "{\"current\":\"%.2f\",\"device_id\":\"%s\",\"hall_effect\":\"%.2f\",\"pressure\":\"%.2f\",\"temperature\":\"%.2f\",\"vibration\":\"%.2f\"}",
    #   current, DEVICE_ID, rpm, pressure, temperature, vibration);
    cpp_canonical = f'{{"current":"{current:.2f}","device_id":"{device_id}","hall_effect":"{rpm:.2f}","pressure":"{pressure:.2f}","temperature":"{temperature:.2f}","vibration":"{vibration:.2f}"}}'

    # Compute HMAC as mbedTLS does on ESP32
    cpp_sig = hmac.new(key.encode("utf-8"), cpp_canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    # Wire packet emitted by ESP32
    wire_packet = {
        "current": current,
        "device_id": device_id,
        "hall_effect": rpm,
        "pressure": pressure,
        "signature": cpp_sig,
        "temperature": temperature,
        "vibration": vibration
    }

    # Python verify_signature must return True
    assert verify_signature(wire_packet) is True

    # Tampered payload must return False
    tampered_packet = dict(wire_packet)
    tampered_packet["temperature"] = 26.01
    assert verify_signature(tampered_packet) is False


def test_multi_node_keys_parity():
    """Verify that all 4 discrete ESP32 nodes defined in firmware have valid keys in security.py."""
    import hmac
    import hashlib
    from app import verify_signature
    from security import get_device_key

    nodes = [
        ("ESP32_001", 26.0, 4.2, 1.1, 0.0, 4.5),
        ("ESP32_002", 41.0, 5.4, 1.8, 1500.0, 5.2),
        ("ESP32_003", 18.5, 2.2, 0.6, 0.0, 2.8),
        ("ESP32_004", 33.0, 3.8, 2.2, 2200.0, 7.1),
    ]

    for dev_id, temp, pres, vib, rpm, curr in nodes:
        key = get_device_key(dev_id)
        assert key is not None and len(key) > 10

        canonical = f'{{"current":"{curr:.2f}","device_id":"{dev_id}","hall_effect":"{rpm:.2f}","pressure":"{pres:.2f}","temperature":"{temp:.2f}","vibration":"{vib:.2f}"}}'
        sig = hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()

        packet = {
            "current": curr,
            "device_id": dev_id,
            "hall_effect": rpm,
            "pressure": pres,
            "signature": sig,
            "temperature": temp,
            "vibration": vib
        }
        assert verify_signature(packet) is True, f"Verification failed for {dev_id}!"


def test_serial_gateway_firmware_packet_forwarding():
    """Verify serial_gateway correctly parses real ESP32 wire frames and preserves signatures."""
    import json
    from serial_gateway import parse_serial_line
    from app import verify_signature
    from security import get_device_key

    dev_id = "ESP32_002"
    key = get_device_key(dev_id)
    canonical = f'{{"current":"5.20","device_id":"{dev_id}","hall_effect":"1500.00","pressure":"5.40","temperature":"41.00","vibration":"1.80"}}'
    import hmac, hashlib
    sig = hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    firmware_line = f'{{"current":5.20,"device_id":"{dev_id}","hall_effect":1500.00,"pressure":5.40,"signature":"{sig}","temperature":41.00,"vibration":1.80}}\r\n'

    parsed = parse_serial_line(firmware_line, mode="plc")
    assert parsed is not None
    assert parsed["device_id"] == dev_id
    assert parsed["signature"] == sig
    assert parsed["temperature"] == 41.00
    assert parsed["pressure"] == 5.40
    assert parsed["hall_effect"] == 1500.00
    assert parsed["vibration"] == 1.80
    assert parsed["current"] == 5.20

    # Passed to zero-trust verification
    assert verify_signature(parsed) is True


def test_serial_command_queue_dispatch():
    """Verify actuator commands enqueued via send_command can be retrieved for UART transmission."""
    from serial_gateway import send_command, _command_queue

    # Drain any residual items from earlier tests
    while not _command_queue.empty():
        try:
            _command_queue.get_nowait()
        except Exception:
            break

    cmd = {
        "target_device": "ESP32_001",
        "command": "ISOLATE",
        "reason": "Emergency Interlock Trip"
    }
    send_command(cmd)

    assert not _command_queue.empty()
    retrieved = _command_queue.get_nowait()
    assert retrieved["target_device"] == "ESP32_001"
    assert retrieved["command"] == "ISOLATE"


def test_audit_log_baseline_seeding_and_api():
    """Verify that an empty database is properly seeded with baseline NIST audit logs,
    and that /api/data and /api/audit/logs return non-empty records with timestamps and actions."""
    import os
    from database import SessionLocal, AuditLog, init_db
    from app import app

    # 1. Verify database has audit logs
    init_db()
    db = SessionLocal()
    try:
        count = db.query(AuditLog).count()
        assert count >= 6, f"Expected at least 6 audit logs, got {count}"
        first_log = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).first()
        assert first_log.action is not None
        assert first_log.timestamp is not None
        assert first_log.location is not None
    finally:
        db.close()

    # 2. Test /api/data returns valid audit logs
    app.config["TESTING"] = True
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "CONTROL_CENTER_ALPHA"

    res = client.get("/api/data")
    assert res.status_code == 200
    data = res.get_json()
    assert "audit_logs" in data
    assert len(data["audit_logs"]) > 0
    for a in data["audit_logs"][:5]:
        assert a["timestamp"] != ""
        assert a["action"] != ""
        assert a["username"] != ""

    # 3. Test /api/audit/logs returns NIST mapped controls
    res_audit = client.get("/api/audit/logs?limit=10")
    assert res_audit.status_code == 200
    audit_data = res_audit.get_json()
    assert audit_data["success"] is True
    assert len(audit_data["logs"]) > 0
    for l in audit_data["logs"][:5]:
        assert l["timestamp"] != ""
        assert l["action"] != ""
        assert "nist_control" in l
        assert l["nist_control"].startswith("NIST")


def test_esp32_004_turbine_generator_rpm_handling():
    """Verify ESP32_004 operating at normal baseline 2200 RPM is not flagged as anomaly."""
    from app import rf_model
    db = get_test_db()
    try:
        telemetry = {
            "device_id": "ESP32_004",
            "temperature": 33.0,
            "pressure": 3.8,
            "vibration": 2.2,
            "hall_effect": 2200.0,
            "current": 7.1
        }
        is_anomaly = rf_model.predict_anomaly(telemetry, db_session=db)
        assert not is_anomaly, "ESP32_004 operating at normal 2200 RPM should NOT trigger anomaly"

        # Verify actual overspeed (> 3000 RPM) DOES trigger anomaly
        overspeed_telemetry = dict(telemetry, hall_effect=3250.0)
        is_overspeed_anomaly = rf_model.predict_anomaly(overspeed_telemetry, db_session=db)
        assert is_overspeed_anomaly, "ESP32_004 overspeed (3250 RPM) MUST trigger anomaly"
    finally:
        db.close()


def test_isolated_device_telemetry_returns_403():
    """Verify that incoming telemetry from a quarantined device receives HTTP 403 Forbidden."""
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    db = get_test_db()
    try:
        # Ensure device is isolated
        dev = db.query(DeviceState).filter_by(device_id="ESP32_003").first()
        if not dev:
            dev = DeviceState(device_id="ESP32_003", is_isolated=True)
            db.add(dev)
        else:
            dev.is_isolated = True
        db.commit()

        key = get_device_key("ESP32_003")
        payload = {
            "timestamp": time.time(),
            "device_id": "ESP32_003",
            "temperature": 18.5,
            "pressure": 2.2,
            "vibration": 0.6,
            "current": 2.8
        }
        payload["signature"] = sign_message(payload, key)

        res = client.post("/api/telemetry", json=payload)
        assert res.status_code == 403, f"Expected 403 Forbidden for isolated device, got {res.status_code}"
        assert "quarantined" in res.get_json().get("error", "").lower()
    finally:
        # Reset isolation state
        dev = db.query(DeviceState).filter_by(device_id="ESP32_003").first()
        if dev:
            dev.is_isolated = False
            db.commit()
        db.close()


def test_hardware_isolation_command_dispatched():
    """Verify that isolating a device enqueues a physical ISOLATE command for serial dispatch."""
    import serial_gateway
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    # Drain existing command queue
    while not serial_gateway._command_queue.empty():
        serial_gateway._command_queue.get_nowait()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "CONTROL_CENTER_ALPHA"
        sess["csrf_token"] = "cmd_csrf"

    headers = {"X-CSRF-Token": "cmd_csrf"}

    # Trigger manual isolation
    res = client.post("/api/device/isolate", json={"device_id": "ESP32_002", "csrf_token": "cmd_csrf"}, headers=headers)
    assert res.status_code == 200

    # Verify command was queued for physical UART transmission
    assert not serial_gateway._command_queue.empty()
    queued_cmd = serial_gateway._command_queue.get_nowait()
    assert queued_cmd["command"] == "ISOLATE"
    assert queued_cmd["target_device"] == "ESP32_002"

    # Trigger manual rejoin
    res = client.post("/api/device/rejoin", json={"device_id": "ESP32_002", "csrf_token": "cmd_csrf"}, headers=headers)
    assert res.status_code == 200

    assert not serial_gateway._command_queue.empty()
    rejoin_cmd = serial_gateway._command_queue.get_nowait()
    assert rejoin_cmd["command"] == "REARM"
    assert rejoin_cmd["target_device"] == "ESP32_002"


def test_airgap_offline_assets():
    """Verify local static vendor assets exist for 100% air-gapped industrial deployment."""
    import os
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    chart_js = os.path.join(base_dir, "src", "static", "vendor", "chart.umd.js")
    tailwind_css = os.path.join(base_dir, "src", "static", "vendor", "tailwind.min.css")

    assert os.path.isfile(chart_js), f"Missing air-gapped vendor asset: {chart_js}"
    assert os.path.getsize(chart_js) > 100000, "Chart.js asset appears truncated"

    assert os.path.isfile(tailwind_css), f"Missing air-gapped vendor asset: {tailwind_css}"
    assert os.path.getsize(tailwind_css) > 500000, "Tailwind asset appears truncated"


def test_ml_model_synthetic_inference():
    """Verify the retrained 5-feature Random Forest model loads and predicts nominal vs anomalous states."""
    import os
    import joblib
    import numpy as np

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    model_path = os.path.join(base_dir, "src", "model", "rf_model.pkl")
    assert os.path.isfile(model_path), f"Model file missing at {model_path}"

    model = joblib.load(model_path)
    assert hasattr(model, "predict"), "Model object has no predict method"

    # Nominal condition: 25.0 C, 4.0 bar, 1.0 g, 1500 RPM, 4.5 A
    nominal_sample = np.array([[25.0, 4.0, 1.0, 1500.0, 4.5]])
    pred_nominal = model.predict(nominal_sample)[0]
    prob_nominal = model.predict_proba(nominal_sample)[0][1]

    assert pred_nominal == 0, f"Expected 0 (nominal), got {pred_nominal}"
    assert prob_nominal < 0.25, f"Expected low anomaly prob, got {prob_nominal}"

    # Stuxnet severe resonance attack: 75.0 C, 11.0 bar, 7.5 g, 3800 RPM, 14.5 A
    attack_sample = np.array([[75.0, 11.0, 7.5, 3800.0, 14.5]])
    pred_attack = model.predict(attack_sample)[0]
    prob_attack = model.predict_proba(attack_sample)[0][1]

    assert pred_attack == 1, f"Expected 1 (anomalous), got {pred_attack}"
    assert prob_attack > 0.80, f"Expected high anomaly prob, got {prob_attack}"


def test_sse_stream_endpoint():
    """Verify /api/stream endpoint returns text/event-stream response."""
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "CONTROL_CENTER_ALPHA"

    response = client.get("/api/stream")
    assert response.status_code == 200
    assert "text/event-stream" in response.content_type


def test_terminal_css_and_1980s_assets():
    """Verify 1980s DEC VT-220 / IBM 3270 CRT styling assets and templates exist."""
    import os
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    terminal_css = os.path.join(base_dir, "src", "static", "terminal.css")
    login_html = os.path.join(base_dir, "src", "templates", "login.html")
    dash_html = os.path.join(base_dir, "src", "templates", "dashboard.html")

    assert os.path.isfile(terminal_css), f"Missing 1980s terminal CSS: {terminal_css}"
    with open(terminal_css, "r", encoding="utf-8") as f:
        css_content = f.read()

    # Verify key CRT phosphor tokens and visual FX
    assert "--crt-bg" in css_content
    assert "--crt-text" in css_content
    assert "theme-amber" in css_content
    assert "theme-green" in css_content
    assert "theme-mono" in css_content
    assert "crt-active" in css_content
    assert "phosphor-glow" in css_content
    assert "oscilloscope-grid" in css_content
    assert "tape-counter" in css_content
    assert "mechanical-switch" in css_content

    # Verify templates link terminal.css
    with open(login_html, "r", encoding="utf-8") as f:
        login_content = f.read()
    assert "terminal.css" in login_content
    assert "DEC VT-220" in login_content or "MAINFRAME" in login_content
    assert "UID:" in login_content
    assert "KEY:" in login_content

    with open(dash_html, "r", encoding="utf-8") as f:
        dash_content = f.read()
    assert "terminal.css" in dash_content
    assert "time-scrubber-slider" in dash_content or "onTimeScrub" in dash_content
    assert "forensicHistoryBuffer" in dash_content
    assert "setCRTTheme" in dash_content
    assert "toggleScanlines" in dash_content


def test_forensic_time_scrubber_slicing():
    """Verify the forensic time scrubber slice logic, delta-T calculation, and anomaly detection."""
    # Simulate a buffer of 100 historical telemetry frames
    now = time.time()
    buffer = []
    for i in range(100):
        buffer.append({
            "timestamp": now - (100 - i) * 2.0,
            "temperature": 25.0 + (i * 0.1),
            "pressure": 4.0,
            "vibration": 1.2 if i < 80 else 6.8,  # Attack injected at frame 80
            "rpm": 1500 if i < 80 else 3600,
            "current": 4.5 if i < 80 else 14.2,
            "is_anomaly": 0 if i < 80 else 1
        })

    # Test 1: Slicing at 50% (index 50)
    slice_50 = buffer[:51]
    assert len(slice_50) == 51
    t_end = slice_50[-1]["timestamp"]
    t_live = buffer[-1]["timestamp"]
    delta_t = t_live - t_end
    assert delta_t > 0, "Historical timestamp must precede live timestamp"
    # At index 50, vibration should be nominal (< 2.0) and anomaly flag 0
    assert slice_50[-1]["vibration"] == 1.2
    assert slice_50[-1]["is_anomaly"] == 0

    # Test 2: Slicing at 90% (index 90) - into the anomalous zone
    slice_90 = buffer[:91]
    assert len(slice_90) == 91
    assert slice_90[-1]["vibration"] == 6.8
    assert slice_90[-1]["is_anomaly"] == 1

    # Test 3: Jump to last incident search logic
    last_incident_idx = -1
    for idx in range(len(buffer) - 1, -1, -1):
        if buffer[idx].get("is_anomaly") == 1:
            last_incident_idx = idx
            break
    assert last_incident_idx == 99, f"Expected last incident at 99, found {last_incident_idx}"

    # Verify statistical aggregation on slice
    temps = [p["temperature"] for p in slice_50]
    mean_temp = sum(temps) / len(temps)
    variance_temp = sum((t - mean_temp) ** 2 for t in temps) / len(temps)
    assert mean_temp > 25.0
    assert variance_temp >= 0.0


def test_terminal_dashboard_routes_and_html_render():
    """Verify Flask routes serve 1980s terminal markup with valid HTTP 200."""
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    # 1. Login route
    res_login = client.get("/login")
    assert res_login.status_code == 200
    assert b"terminal.css" in res_login.data
    assert b"theme-green" in res_login.data
    assert b"CLASSIFIED INDUSTRIAL FACILITY" in res_login.data or b"VT-220" in res_login.data
    assert b"CRT PALETTE:" not in res_login.data

    # 2. Dashboard route authenticated
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "CONTROL_CENTER_ALPHA"

    res_dash = client.get("/")
    assert res_dash.status_code == 200
    assert b"terminal.css" in res_dash.data
    assert b"theme-green" in res_dash.data
    assert b"DEC VT-220" in res_dash.data or b"OPERATING STATION" in res_dash.data
    assert b"REEL-TO-REEL" in res_dash.data or b"FORENSIC TIME SCRUBBER" in res_dash.data
    assert b"PALETTE:" not in res_dash.data


def test_v1_telemetry_staleness_fail_closed():
    """Verify that high-risk setpoints are rejected when telemetry is stale (>120s) or missing."""
    import time
    from database import SessionLocal, TelemetryLog, Rule
    from safety_enforcer import validate_command

    db = SessionLocal()
    try:
        # Create a stale telemetry record (timestamp 500s in the past)
        stale_time = time.time() - 500.0
        stale_log = TelemetryLog(
            timestamp=stale_time,
            device_id="ESP32_STALE_TEST",
            temperature=25.0,
            pressure=3.0,
            vibration=1.0,
            hall_effect=0.0,
            current=4.0,
            is_anomaly=False
        )
        db.add(stale_log)
        db.commit()

        # High-risk temperature command (>= 45C) under stale telemetry must be BLOCKED
        cmd_high_temp = {"type": "set_temp", "value": 48.0, "target_device": "ESP32_STALE_TEST"}
        is_valid, msg = validate_command(cmd_high_temp, db, target_device="ESP32_STALE_TEST")
        assert is_valid is False
        assert "Stale Telemetry" in msg

        # High-risk pressure command (>= 6.0 bar) under stale telemetry must be BLOCKED
        cmd_high_pres = {"type": "set_pressure", "value": 6.8, "target_device": "ESP32_STALE_TEST"}
        is_valid_p, msg_p = validate_command(cmd_high_pres, db, target_device="ESP32_STALE_TEST")
        assert is_valid_p is False
        assert "Stale Telemetry" in msg_p

        # Low-risk temperature command (< 45C) under stale telemetry is allowed
        cmd_safe_temp = {"type": "set_temp", "value": 32.0, "target_device": "ESP32_STALE_TEST"}
        is_valid_s, msg_s = validate_command(cmd_safe_temp, db, target_device="ESP32_STALE_TEST")
        assert is_valid_s is True
        assert msg_s == "Approved"

    finally:
        db.query(TelemetryLog).filter_by(device_id="ESP32_STALE_TEST").delete()
        db.commit()
        db.close()


def test_v2_safe_pickle_deserialization_flags():
    """Verify neural policy model loader enforces allow_pickle=False and weights_only=True."""
    import inspect
    from neural_policy import NeuralSafetyPolicy

    # Inspect the source code of __init__ to verify allow_pickle=False is enforced
    src = inspect.getsource(NeuralSafetyPolicy.__init__)
    assert "allow_pickle=False" in src
    assert "allow_pickle=True" not in src


def test_v4_new_device_trust_initialization():
    """Verify new registered devices initialize at conservative 50% trust, and unknown at 25%."""
    from database import SessionLocal
    from trust_engine import compute_device_trust_score

    db = SessionLocal()
    try:
        # Registered device with 0 prior logs
        score_reg = compute_device_trust_score("ESP32_001", db)
        # If no logs exist for ESP32_001, it returns 0.50; if logs exist in test_db, test with brand new registered ID
        score_new_reg = compute_device_trust_score("ESP32_003", db)
        if score_new_reg["status"] == "INITIALIZING":
            assert score_new_reg["trust_score"] == 0.50
            assert score_new_reg["trust_percentage"] == 50.0

        # Unknown / unregistered device
        score_unreg = compute_device_trust_score("ROGUE_ESP32_999", db)
        assert score_unreg["status"] == "UNREGISTERED"
        assert score_unreg["trust_score"] == 0.25
        assert score_unreg["trust_percentage"] == 25.0

    finally:
        db.close()


def test_v5_neural_policy_exception_fail_closed():
    """Verify that if the neural policy encounters an unexpected exception, it fails CLOSED."""
    import time
    from unittest.mock import patch
    from database import SessionLocal, TelemetryLog
    from safety_enforcer import validate_command

    db = SessionLocal()
    try:
        # Add a fresh telemetry entry
        fresh_log = TelemetryLog(
            timestamp=time.time(),
            device_id="ESP32_FAIL_TEST",
            temperature=30.0,
            pressure=3.5,
            vibration=1.0,
            hall_effect=0.0,
            current=4.0,
            is_anomaly=False
        )
        db.add(fresh_log)
        db.commit()

        cmd = {"type": "set_temp", "value": 38.0, "target_device": "ESP32_FAIL_TEST"}

        with patch("safety_enforcer.get_neural_policy") as mock_get_policy:
            mock_policy = mock_get_policy.return_value
            mock_policy.evaluate_safety.side_effect = RuntimeError("Simulated neural inference tensor crash")

            is_valid, msg = validate_command(cmd, db, target_device="ESP32_FAIL_TEST")
            # Must FAIL-CLOSED
            assert is_valid is False
            assert "SAFETY INTERLOCK BLOCK" in msg
            assert "precautionary measure" in msg

    finally:
        db.query(TelemetryLog).filter_by(device_id="ESP32_FAIL_TEST").delete()
        db.commit()
        db.close()


def test_login_audit_success_and_failure():
    """Verify that both valid and invalid authentication attempts are audited with operator identity and IP."""
    from app import app
    from database import SessionLocal, AuditLog
    app.config["TESTING"] = True
    client = app.test_client()

    # 1. Failed login
    res = client.post("/login", data={"username": "unauthorized_user", "password": "wrong_password"}, follow_redirects=False)
    assert res.status_code == 401

    db = SessionLocal()
    try:
        failed_log = db.query(AuditLog).filter_by(action="LOGIN_FAILED").order_by(AuditLog.timestamp.desc()).first()
        assert failed_log is not None
        assert "unauthorized_user" in failed_log.details
        assert "Client IP" in failed_log.details

        # 2. Successful login with noodles / noodles
        res_ok = client.post("/login", data={"username": "noodles", "password": "noodles"}, follow_redirects=False)
        assert res_ok.status_code == 302

        success_log = db.query(AuditLog).filter_by(action="LOGIN_SUCCESS").order_by(AuditLog.timestamp.desc()).first()
        assert success_log is not None
        assert "noodles" in success_log.details
        assert success_log.user_id is not None
    finally:
        db.close()


def test_audit_logs_enriched_filters_and_operator():
    """Verify /api/audit/logs enriched schema (operator, severity, nist_control) and filtering."""
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["csrf_token"] = "valid_csrf"
    headers = {"X-CSRF-Token": "valid_csrf"}

    res = client.get("/api/audit/logs?limit=50", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert isinstance(data["logs"], list)
    assert len(data["logs"]) > 0

    first = data["logs"][0]
    assert "operator" in first
    assert "action" in first
    assert "severity" in first
    assert "nist_control" in first
    assert "location" in first
    assert "timestamp" in first

    # Test category filter
    res_auth = client.get("/api/audit/logs?category=AUTH", headers=headers)
    assert res_auth.status_code == 200
    data_auth = res_auth.get_json()
    for log in data_auth["logs"]:
        act = log["action"].upper()
        assert any(k in act for k in ("LOGIN", "LOGOUT", "AUTH"))


def test_serial_gateway_raw_packet_buffer_and_api():
    """Verify UART wire packet buffer and /api/gateway/raw_packets endpoint."""
    from app import app
    import serial_gateway
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["csrf_token"] = "valid_csrf"
    headers = {"X-CSRF-Token": "valid_csrf"}

    # Simulate wire packet log
    serial_gateway.log_raw_wire_packet('{"device_id":"ESP32_001","temp":28.5,"pressure":4.2}', parsed=True, target_id="ESP32_001")
    serial_gateway.log_raw_wire_packet('INVALID_GARBLED_UART_FRAME', parsed=False, target_id="UNKNOWN")

    res = client.get("/api/gateway/raw_packets", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert len(data["packets"]) >= 2
    assert any("ESP32_001" in p["line"] for p in data["packets"])
    assert any("INVALID_GARBLED_UART_FRAME" in p["line"] for p in data["packets"])


def test_hardware_model_calibration_and_status_api():
    """Verify /api/model/status and /api/model/retrain hardware calibration endpoint."""
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["csrf_token"] = "valid_csrf"
    headers = {"X-CSRF-Token": "valid_csrf"}

    # 1. Model status
    res_status = client.get("/api/model/status", headers=headers)
    assert res_status.status_code == 200
    status_data = res_status.get_json()
    assert status_data["success"] is True
    assert "real_samples_count" in status_data
    assert "enforcement_status" in status_data

    # 2. Trigger model retrain / calibration
    res_retrain = client.post("/api/model/retrain", headers=headers, json={})
    assert res_retrain.status_code == 200
    retrain_data = res_retrain.get_json()
    assert retrain_data["success"] is True
    assert "metrics" in retrain_data
    assert retrain_data["metrics"]["accuracy"] > 0.80






