from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DeviceRecord:
    device_id: str
    trust_score: float = 1.0
    status: str = "NORMAL"
    last_seen: float = 0.0
    telemetry: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)


class StateStore:
    def __init__(self, root: str | Path = "data") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.devices: dict[str, DeviceRecord] = {}
        self.readings: list[dict[str, Any]] = []
        self.anomalies: list[dict[str, Any]] = []
        self.log_file = self.root / "events.jsonl"
        self.alert_file = self.root / "alerts.json"

    def seed_device(self, device_id: str) -> DeviceRecord:
        record = self.devices.get(device_id)
        if record is None:
            record = DeviceRecord(device_id=device_id)
            self.devices[device_id] = record
        return record

    def seed_demo_data(self) -> None:
        if self.readings:
            return

        now = time.time()
        demo_rows = [
            ("ESP32_001", 0.87, 24.3, 58.1, 3.2, False),
            ("ESP32_002", 0.64, 43.5, 14.2, 2.9, True),
            ("ESP32_003", 0.41, 22.1, 61.4, 2.8, True),
        ]
        for idx, (device_id, score, temp, humidity, pressure, anomaly) in enumerate(demo_rows):
            record = self.seed_device(device_id)
            record.trust_score = score
            record.status = "NORMAL" if score >= 0.75 else "ALERT" if score >= 0.4 else "ISOLATED"
            record.last_seen = now - idx * 5
            telemetry = {
                "device_id": device_id,
                "timestamp": now - idx * 5,
                "temperature": temp,
                "humidity": humidity,
                "pressure": pressure,
                "signature_valid": not anomaly,
            }
            self.readings.append({
                "timestamp": telemetry["timestamp"],
                "device_id": device_id,
                "payload": {"temperature": temp, "humidity": humidity, "pressure": pressure, "signature_valid": not anomaly},
                "trust_score": int(round(score * 100)),
                "has_anomaly": anomaly,
            })
            if anomaly:
                self.anomalies.append({
                    "timestamp": telemetry["timestamp"],
                    "device_id": device_id,
                    "sensor_name": "signature" if idx == 1 else "temperature",
                    "value": temp,
                    "expected": "0.0 - 50.0 C",
                    "severity": "critical" if score < 0.4 else "warning",
                })

    def list_devices(self) -> list[dict[str, Any]]:
        return [self._as_dict(record) for record in sorted(self.devices.values(), key=lambda item: item.device_id)]

    def get_device(self, device_id: str) -> dict[str, Any] | None:
        record = self.devices.get(device_id)
        return self._as_dict(record) if record else None

    def update_device(self, device_id: str, trust_score: float, telemetry: dict[str, Any], status: str) -> dict[str, Any]:
        record = self.seed_device(device_id)
        record.trust_score = trust_score
        record.status = status
        record.last_seen = float(telemetry.get("timestamp", time.time()))
        record.telemetry.append(telemetry)
        record.telemetry = record.telemetry[-20:]
        self._append_log({"type": "telemetry", "device_id": device_id, "payload": telemetry, "timestamp": time.time()})

        reading = {
            "timestamp": telemetry.get("timestamp", time.time()),
            "device_id": device_id,
            "payload": {
                "temperature": telemetry.get("temperature"),
                "humidity": telemetry.get("humidity"),
                "pressure": telemetry.get("pressure"),
                "signature_valid": telemetry.get("signature_valid", False),
            },
            "trust_score": round(trust_score * 100, 0),
            "has_anomaly": trust_score < 0.75 or not telemetry.get("signature_valid", False),
        }
        self.readings.insert(0, reading)
        self.readings = self.readings[:50]

        if reading["has_anomaly"]:
            anomaly = {
                "timestamp": reading["timestamp"],
                "device_id": device_id,
                "sensor_name": "signature" if not telemetry.get("signature_valid", False) else self._anomaly_sensor(telemetry),
                "value": telemetry.get("temperature") if telemetry.get("temperature") is not None else telemetry.get("pressure"),
                "expected": self._expected_range(telemetry),
                "severity": "critical" if trust_score < 0.4 or not telemetry.get("signature_valid", False) else "warning",
            }
            self.anomalies.insert(0, anomaly)
            self.anomalies = self.anomalies[:50]
        return self._as_dict(record)

    def isolate_device(self, device_id: str) -> dict[str, Any]:
        record = self.seed_device(device_id)
        record.status = "ISOLATED"
        alert = {"device_id": device_id, "type": "isolation", "timestamp": time.time()}
        record.alerts.append(alert)
        self._append_alert(alert)
        self._append_log({"type": "isolation", "device_id": device_id, "timestamp": time.time()})
        return self._as_dict(record)

    def rejoin_device(self, device_id: str) -> dict[str, Any]:
        record = self.seed_device(device_id)
        record.status = "NORMAL"
        self._append_log({"type": "rejoin", "device_id": device_id, "timestamp": time.time()})
        return self._as_dict(record)

    def logs(self, log_type: str) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        if self.log_file.exists():
            for line in self.log_file.read_text(encoding="utf-8").splitlines():
                if not line:
                    continue
                event = json.loads(line)
                if log_type == "all" or event.get("type") == log_type:
                    events.append(event)
        return events

    def alerts(self) -> list[dict[str, Any]]:
        if self.alert_file.exists():
            return json.loads(self.alert_file.read_text(encoding="utf-8"))
        return []

    def latest(self) -> dict[str, Any]:
        return {
            "readings": self.readings[:15],
            "anomalies": self.anomalies[:15],
            "devices": self.trust_devices(),
        }

    def history(self) -> list[dict[str, Any]]:
        return self.readings

    def _append_log(self, event: dict[str, Any]) -> None:
        with self.log_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")

    def _append_alert(self, alert: dict[str, Any]) -> None:
        alerts = self.alerts()
        alerts.append(alert)
        self.alert_file.write_text(json.dumps(alerts, indent=2) + "\n", encoding="utf-8")

    def trust_devices(self) -> list[dict[str, Any]]:
        devices = []
        for record in sorted(self.devices.values(), key=lambda item: item.device_id):
            devices.append({
                "device_id": record.device_id,
                "score": int(round(record.trust_score * 100)),
                "last_seen": record.last_seen or time.time(),
            })
        return devices

    @staticmethod
    def _as_dict(record: DeviceRecord | None) -> dict[str, Any]:
        if record is None:
            return {}
        return {
            "device_id": record.device_id,
            "trust_score": record.trust_score,
            "status": record.status,
            "last_seen": record.last_seen,
            "telemetry": record.telemetry,
            "alerts": record.alerts,
        }

    @staticmethod
    def _anomaly_sensor(telemetry: dict[str, Any]) -> str:
        if telemetry.get("temperature") is not None:
            return "temperature"
        if telemetry.get("pressure") is not None:
            return "pressure"
        return "telemetry"

    @staticmethod
    def _expected_range(telemetry: dict[str, Any]) -> str:
        if telemetry.get("temperature") is not None:
            return "0.0 - 50.0 C"
        if telemetry.get("pressure") is not None:
            return "0.0 - 8.0 bar"
        return "valid signed telemetry"
