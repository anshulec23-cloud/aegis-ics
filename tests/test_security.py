from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from esp32_sim.device_policy import DevicePolicy
from policies.policy_engine import PolicyEngine
from server.ai_engine.engine import TrustEngine
from server.ai_engine.microseg import MicroSegmentationStore
from server.api import app as api_app
from server.api.state_store import StateStore


class DevicePolicyTests(unittest.TestCase):
    def test_rejects_unsafe_command(self) -> None:
        policy = DevicePolicy.from_mapping({"temp_range": [0, 50], "pressure_range": [0, 8]})

        allowed, reason = policy.validate_command({"type": "set_temp", "value": 90})

        self.assertFalse(allowed)
        self.assertIn("outside allowed range", reason)


class PolicyEngineTests(unittest.TestCase):
    def test_blocks_privilege_escalation_and_allows_valid_setpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "device_policies").mkdir()
            (root / "server_policy.json").write_text(
                """{
  "allowed_temp_setpoint_range": [0, 50],
  "allowed_pressure_setpoint_range": [0, 8],
  "can_isolate_devices": true,
  "can_grant_privileges": false
}
""",
                encoding="utf-8",
            )
            (root / "device_policies" / "ESP32_001.json").write_text(
                """{
  "allowed_commands": ["set_temp", "set_pressure", "ping"]
}
""",
                encoding="utf-8",
            )

            engine = PolicyEngine(root / "server_policy.json", root / "device_policies")

            allowed = engine.validate_outgoing_command("ESP32_001", {"type": "set_temp", "value": 25})
            denied = engine.validate_outgoing_command("ESP32_001", {"type": "grant_privileges", "value": 1})

        self.assertTrue(allowed.allowed)
        self.assertFalse(denied.allowed)
        self.assertIn("privilege escalation", denied.reason)


class TrustEngineTests(unittest.TestCase):
    def test_invalid_signature_triggers_isolation(self) -> None:
        class FakeModel:
            def predict_anomaly_probability(self, telemetry: dict[str, object]) -> tuple[float, float]:
                return 1.0, 1.0

        with tempfile.TemporaryDirectory() as tmp:
            engine = TrustEngine(model_path=Path(tmp) / "missing.pkl", store_path=Path(tmp) / "isolated.json")
            engine.rf_model = FakeModel()
            engine.microseg = MicroSegmentationStore(Path(tmp) / "isolated.json")

            decision = engine.score(
                {
                    "device_id": "ESP32_001",
                    "timestamp": 1.0,
                    "temperature": 100.0,
                    "pressure": 20.0,
                    "humidity": 50.0,
                    "sequence": 1,
                },
                history=[],
                device_key=None,
            )

        self.assertEqual(decision.action, "isolate")
        self.assertLess(decision.trust_score, 0.4)
        self.assertIn("ESP32_001", engine.microseg.isolated_devices)


class StateStoreTests(unittest.TestCase):
    def test_isolate_and_log_device_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp))
            store.update_device(
                "ESP32_001",
                0.2,
                {"timestamp": 1.0, "temperature": 80.0, "pressure": 10.0, "signature_valid": False},
                "ALERT",
            )
            record = store.isolate_device("ESP32_001")

            self.assertEqual(record["status"], "ISOLATED")
            self.assertGreaterEqual(len(store.logs("all")), 2)
            self.assertEqual(store.alerts()[0]["device_id"], "ESP32_001")


class ApiAuthTests(unittest.TestCase):
    def test_sensitive_routes_require_token_when_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_store = StateStore(Path(tmp))
            with patch.object(api_app, "store", temp_store), patch.dict(os.environ, {"API_ADMIN_TOKEN": "secret"}, clear=False):
                client = api_app.app.test_client()
                denied = client.get("/api/alerts")
                allowed = client.get("/api/alerts", headers={"X-Admin-Token": "secret"})

            self.assertEqual(denied.status_code, 401)
            self.assertEqual(allowed.status_code, 200)

    def test_ingest_rejects_malformed_payload(self) -> None:
        client = api_app.app.test_client()

        response = client.post("/api/ingest", json={"device_id": "ESP32_001", "temperature": "hot"})

        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
