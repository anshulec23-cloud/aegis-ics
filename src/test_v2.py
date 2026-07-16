import unittest
import os
import json
import time

# MUST set before any imports touch database.py
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from database import Base, engine, SessionLocal, User, AuditLog, TelemetryLog, Rule, DeviceState, init_db
from safety_enforcer import validate_command
from app import app, limiter

class AegisV2Tests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        limiter.enabled = False
        self.client = app.test_client()
        # Recreate all tables fresh for each test
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        init_db()

    def tearDown(self):
        # Clean up all tables after each test
        Base.metadata.drop_all(bind=engine)

    def test_coordinate_login_and_auditing(self):
        response = self.client.post("/login", data={
            "username": "admin",
            "password": "admin",
            "coord_x": "10.0",
            "coord_y": "20.0",
            "coord_z": "30.0"
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)

        db = SessionLocal()
        logs = db.query(AuditLog).all()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].action, "LOGIN")
        self.assertEqual(logs[0].location, "X=10.00, Y=20.00, Z=30.00")
        db.close()

    def test_safety_enforcer_static_rules(self):
        db = SessionLocal()
        # Valid temperature setpoint
        allowed, reason = validate_command({"type": "set_temp", "value": 40.0}, db)
        self.assertTrue(allowed)

        # Out of bounds temperature setpoint (max 60.0)
        allowed, reason = validate_command({"type": "set_temp", "value": 85.0}, db)
        self.assertFalse(allowed)
        self.assertIn("exceeds boundaries", reason)

        # Unknown command type should be denied (deny-by-default)
        allowed, reason = validate_command({"type": "emergency_override", "value": 0}, db)
        self.assertFalse(allowed)
        self.assertIn("Denied", reason)

        db.close()

    def test_stuxnet_correlation_block(self):
        db = SessionLocal()

        # Seed telemetry with elevated pressure
        log = TelemetryLog(
            timestamp=12345.6,
            device_id="ESP32_001",
            temperature=30.0,
            pressure=7.2,
            humidity=50.0
        )
        db.add(log)
        db.commit()

        # Try to raise temperature to 50C while pressure is 7.2 bar
        allowed, reason = validate_command({"type": "set_temp", "value": 50.0}, db)
        self.assertFalse(allowed)
        self.assertIn("Stuxnet Prevention", reason)

        # Test boundary bypass is now fixed (>= instead of >)
        allowed, reason = validate_command({"type": "set_temp", "value": 45.0}, db)
        self.assertFalse(allowed)
        self.assertIn("Stuxnet Prevention", reason)

        db.close()

    def test_enforcer_blocks_api_and_audits_violation(self):
        # Login
        self.client.post("/login", data={
            "username": "admin",
            "password": "admin",
            "coord_x": "5.0",
            "coord_y": "5.0",
            "coord_z": "5.0"
        })

        # Seed high pressure
        db = SessionLocal()
        log = TelemetryLog(
            timestamp=12345.6,
            device_id="ESP32_001",
            temperature=30.0,
            pressure=7.5,
            humidity=50.0
        )
        db.add(log)
        db.commit()
        db.close()

        # Call setpoint API with hazardous value
        response = self.client.post("/api/setpoint", json={
            "type": "set_temp",
            "value": 55.0
        })

        self.assertEqual(response.status_code, 403)
        self.assertIn("Stuxnet Prevention", response.json["error"])

        # Verify violation was audited
        db = SessionLocal()
        violations = db.query(AuditLog).filter_by(action="SECURITY_VIOLATION_BLOCKED").all()
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].location, "X=5.00, Y=5.00, Z=5.00")
        self.assertIn("Blocked attempt", violations[0].details)
        db.close()


    def test_manual_isolation_and_command_block(self):
        # Log in
        self.client.post("/login", data={
            "username": "admin",
            "password": "admin",
            "coord_x": "5.0",
            "coord_y": "5.0",
            "coord_z": "5.0"
        })

        # Manual Isolate
        iso_resp = self.client.post("/api/device/isolate")
        self.assertEqual(iso_resp.status_code, 200)
        self.assertTrue(iso_resp.json["success"])

        # Try to dispatch setpoint (should be blocked)
        set_resp = self.client.post("/api/setpoint", json={
            "type": "set_temp",
            "value": 30.0
        })
        self.assertEqual(set_resp.status_code, 403)
        self.assertIn("isolated", set_resp.json["error"])

        # Manual Rejoin
        rej_resp = self.client.post("/api/device/rejoin")
        self.assertEqual(rej_resp.status_code, 200)
        self.assertTrue(rej_resp.json["success"])

        # Try setpoint again (should succeed)
        set_resp2 = self.client.post("/api/setpoint", json={
            "type": "set_temp",
            "value": 30.0
        })
        self.assertEqual(set_resp2.status_code, 200)

    def test_pdf_report_download(self):
        # Log in
        self.client.post("/login", data={
            "username": "admin",
            "password": "admin",
            "coord_x": "5.0",
            "coord_y": "5.0",
            "coord_z": "5.0"
        })

        # Download PDF Report
        response = self.client.get("/api/report/download")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, "application/pdf")
        self.assertTrue(len(response.data) > 0)

    def test_simulate_attack_endpoints(self):
        # Log in
        login_resp = self.client.post("/login", data={
            "username": "admin",
            "password": "admin",
            "coord_x": "5.0",
            "coord_y": "5.0",
            "coord_z": "5.0"
        })
        print("LOGIN RESP:", login_resp.status_code, login_resp.data)

        # 1. Test Stuxnet Attack Simulation
        resp = self.client.post("/api/simulate-attack", json={"type": "stuxnet"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json["success"])
        self.assertIn("Stuxnet", resp.json["details"])

        # Verify security violation was written to DB
        db = SessionLocal()
        violations = db.query(AuditLog).filter_by(action="SECURITY_VIOLATION_BLOCKED").all()
        self.assertTrue(len(violations) >= 1)
        db.close()

        # 2. Test Telemetry Injection Attack Simulation (triggers auto-isolation)
        resp2 = self.client.post("/api/simulate-attack", json={"type": "injection"})
        self.assertEqual(resp2.status_code, 200)
        self.assertTrue(resp2.json["success"])
        self.assertIn("Injection", resp2.json["details"])

        # Verify device is now isolated in DB
        db = SessionLocal()
        state = db.query(DeviceState).filter_by(device_id="ESP32_001").first()
        self.assertTrue(state.is_isolated)
        db.close()

        # 3. Test Privilege Escalation Attack Simulation
        resp3 = self.client.post("/api/simulate-attack", json={"type": "privilege"})
        self.assertEqual(resp3.status_code, 200)
        self.assertTrue(resp3.json["success"])
        self.assertIn("Privilege", resp3.json["details"])

    def test_five_sensor_architecture(self):
        # 1. Test CSV and JSON parsing inside serial gateway
        from serial_gateway import parse_serial_line
        
        # Test JSON parsing
        json_line = '{"temp": 24.5, "pres": 4.1, "vib": 1.2, "hall": 1200, "curr": 4.6}'
        res_json = parse_serial_line(json_line, "plc")
        self.assertIsNotNone(res_json)
        self.assertEqual(res_json["temperature"], 24.5)
        self.assertEqual(res_json["current"], 4.6)
        
        # Test CSV parsing
        csv_line = "24.5,4.1,1.2,1200,4.6"
        res_csv = parse_serial_line(csv_line, "plc")
        self.assertIsNotNone(res_csv)
        self.assertEqual(res_csv["vibration"], 1.2)
        
        # 2. Test telemetry ingestion with 5 parameters
        self.client.post("/login", data={
            "username": "admin",
            "password": "admin",
            "coord_x": "5.0",
            "coord_y": "5.0",
            "coord_z": "5.0"
        })
        
        # Build 5-sensor payload
        payload = {
            "timestamp": time.time(),
            "device_id": "ESP32_001",
            "temperature": 25.0,
            "pressure": 4.0,
            "humidity": 4.5,
            "vibration": 1.1,
            "hall_effect": 0.0,
            "current": 4.5,
            "rssi": -55.0
        }
        
        # Calculate signature matching key for ESP32_001
        import hmac
        import hashlib
        import json
        
        canonical = {
            "device_id": "ESP32_001",
            "temperature": f"{float(25.0):.2f}",
            "pressure": f"{float(4.0):.2f}",
            "humidity": f"{float(4.5):.2f}",
            "vibration": f"{float(1.1):.2f}",
            "hall_effect": f"{float(0.0):.2f}",
            "current": f"{float(4.5):.2f}",
            "rssi": f"{float(-55.0):.2f}",
            "timestamp": f"{float(payload['timestamp']):.3f}"
        }
        serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        key = "device_key_001"
        signature = hmac.new(key.encode("utf-8"), serialized.encode("utf-8"), hashlib.sha256).hexdigest()
        payload["signature"] = signature

        resp = self.client.post("/api/telemetry", json=payload)
        self.assertEqual(resp.status_code, 200)
        
        # Verify db log contains the new fields
        db = SessionLocal()
        log = db.query(TelemetryLog).filter_by(device_id="ESP32_001").order_by(TelemetryLog.timestamp.desc()).first()
        self.assertEqual(log.vibration, 1.1)
        self.assertEqual(log.current, 4.5)
        db.close()


if __name__ == "__main__":
    unittest.main()
