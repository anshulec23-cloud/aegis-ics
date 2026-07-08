import unittest
import os
import json
from pathlib import Path
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash

# Set test environment database
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from database import init_db, SessionLocal, User, AuditLog, TelemetryLog, Rule
from safety_enforcer import validate_command
from app import app

class AegisV2Tests(unittest.TestCase):
    def setUp(self):
        # Override database to file-based or in-memory temp DB for the app
        app.config["TESTING"] = True
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        self.client = app.test_client()
        init_db()
        
    def test_coordinate_login_and_auditing(self):
        # 1. Login with coordinates
        response = self.client.post("/login", data={
            "username": "admin",
            "password": "admin",
            "coord_x": "10.0",
            "coord_y": "20.0",
            "coord_z": "30.0"
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        
        # Verify Audit Log entry exists in database
        db = SessionLocal()
        logs = db.query(AuditLog).all()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].action, "LOGIN")
        self.assertEqual(logs[0].location, "X=10.0, Y=20.0, Z=30.0")
        db.close()
        
    def test_safety_enforcer_static_rules(self):
        db = SessionLocal()
        # Test valid temperature setpoint
        allowed, reason = validate_command({"type": "set_temp", "value": 40.0}, db)
        self.assertTrue(allowed)
        
        # Test out of bounds temperature setpoint (Temp Limit: max 60.0)
        allowed, reason = validate_command({"type": "set_temp", "value": 85.0}, db)
        self.assertFalse(allowed)
        self.assertIn("exceeds boundaries", reason)
        
        db.close()

    def test_stuxnet_correlation_block(self):
        db = SessionLocal()
        
        # Seed telemetry with elevated pressure (e.g. 7.0 bar)
        log = TelemetryLog(
            timestamp=12345.6,
            device_id="ESP32_001",
            temperature=30.0,
            pressure=7.2,
            humidity=50.0
        )
        db.add(log)
        db.commit()
        
        # Try to raise temperature to 50C while pressure is already 7.2 bar
        allowed, reason = validate_command({"type": "set_temp", "value": 50.0}, db)
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
        
        # Assert 403 Forbidden
        self.assertEqual(response.status_code, 403)
        self.assertIn("Stuxnet Prevention", response.json["error"])
        
        # Verify that the violation attempt was audited in database
        db = SessionLocal()
        violations = db.query(AuditLog).filter_by(action="SECURITY_VIOLATION_BLOCKED").all()
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].location, "X=5.0, Y=5.0, Z=5.0")
        self.assertIn("Blocked attempt", violations[0].details)
        db.close()

if __name__ == "__main__":
    unittest.main()
