from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import random
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from esp32_sim.anomaly_injector import AnomalyInjector  # type: ignore[import-not-found]
    from esp32_sim.device_policy import DevicePolicy  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - direct script fallback
    from anomaly_injector import AnomalyInjector  # type: ignore[import-not-found]
    from device_policy import DevicePolicy  # type: ignore[import-not-found]

try:
    import paho.mqtt.client as mqtt  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional dependency
    mqtt = None


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sign_message(payload: dict[str, Any], key: str) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass
class SimState:
    device_id: str
    hmac_key: str
    policy: DevicePolicy
    injector: AnomalyInjector
    publish_interval_sec: int
    telemetry_seq: int = 0
    running: bool = True


class Simulator:
    def __init__(self, config: dict[str, Any], dry_run: bool = False) -> None:
        self.device_id = config["device_id"]
        self.hmac_key = os.getenv(f"DEVICE_KEY_{self.device_id}", "")
        if not self.hmac_key:
            raise ValueError(f"missing HMAC key for {self.device_id}")
        self.policy = DevicePolicy.from_mapping(config)
        self.injector = AnomalyInjector(mode=config.get("anomaly_mode", "normal"))
        self.publish_interval_sec = int(config.get("publish_interval_sec", 10))
        self.dry_run = dry_run or mqtt is None
        self.state = SimState(
            device_id=self.device_id,
            hmac_key=self.hmac_key,
            policy=self.policy,
            injector=self.injector,
            publish_interval_sec=self.publish_interval_sec,
        )
        self.mqtt_cfg = config.get("mqtt", {})
        self.api_cfg = config.get("api", {})
        self.mqtt_username = self.mqtt_cfg.get("username") or os.getenv("MQTT_USERNAME")
        self.mqtt_password = self.mqtt_cfg.get("password") or os.getenv("MQTT_PASSWORD")
        self.use_tls = bool(self.mqtt_cfg.get("use_tls", True))
        self.ca_cert = self.mqtt_cfg.get("ca_cert") or os.getenv("MQTT_CA_CERT")
        self.client = None

    def connect(self) -> None:
        if self.dry_run:
            return

        if mqtt is None:
            return

        try:
            self.client = mqtt.Client(client_id=self.device_id, protocol=mqtt.MQTTv311)
            if self.mqtt_username or self.mqtt_password:
                self.client.username_pw_set(self.mqtt_username or "", self.mqtt_password or "")
            self.client.on_message = self._on_message
            self.client.on_connect = self._on_connect
            if self.use_tls:
                if self.ca_cert:
                    self.client.tls_set(ca_certs=self.ca_cert)
                else:
                    self.client.tls_set()

            host = self.mqtt_cfg.get("host", "127.0.0.1")
            port = int(self.mqtt_cfg.get("port", 8883))
            self.client.connect(host, port, keepalive=60)
            self.client.loop_start()
        except Exception:
            self.client = None

    def _topic(self, kind: str) -> str:
        return f"ics/{kind}/{self.device_id}"

    def _on_connect(self, client: Any, userdata: Any, flags: Any, rc: Any) -> None:
        client.subscribe(self._topic("control"))

    def _on_message(self, client: Any, userdata: Any, msg: Any) -> None:
        try:
            command = json.loads(msg.payload.decode("utf-8"))
        except Exception as exc:
            print(f"[{self.device_id}] rejected malformed command: {exc}", file=sys.stderr)
            return

        allowed, reason = self.policy.validate_command(command)
        if not allowed:
            print(f"[{self.device_id}] rejected command: {reason}", file=sys.stderr)
            return

        print(f"[{self.device_id}] accepted command: {command}")

    def _publish(self, topic: str, payload: dict[str, Any]) -> None:
        message = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        if self.dry_run:
            print(f"PUBLISH {topic} {message}")
            return
        if self.client is not None:
            self.client.publish(topic, message, qos=1)

    def _post_api(self, payload: dict[str, Any]) -> None:
        base_url = self.api_cfg.get("base_url")
        if not base_url:
            return
        request = Request(
            f"{str(base_url).rstrip('/')}/api/ingest",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:
                response.read()
        except URLError:
            pass

    def _telemetry(self) -> dict[str, Any]:
        base_temp = random.uniform(*self.policy.temp_range)
        base_humidity = random.uniform(20.0, 80.0)
        base_pressure = random.uniform(*self.policy.pressure_range)
        temp, pressure = self.injector.apply(base_temp, base_pressure)
        if self.injector.mode == "spike":
            base_humidity += random.uniform(-15.0, 20.0)
        elif self.injector.mode == "drift":
            base_humidity += self.injector.drift_step * 0.5
        elif self.injector.mode == "flatline":
            base_humidity = max(0.0, min(100.0, base_humidity))
        elif self.injector.mode == "noise_burst":
            base_humidity += random.uniform(-12.0, 12.0)
        temp = round(max(-50.0, min(150.0, temp)), 2)
        pressure = round(max(0.0, min(20.0, pressure)), 2)
        humidity = round(max(0.0, min(100.0, base_humidity)), 2)

        telemetry = {
            "device_id": self.device_id,
            "timestamp": time.time(),
            "sequence": self.state.telemetry_seq,
            "temperature": temp,
            "humidity": humidity,
            "pressure": pressure,
            "anomaly_mode": self.injector.mode,
        }
        telemetry["signature"] = sign_message(telemetry, self.hmac_key)
        return telemetry

    def run(self) -> None:
        self.connect()
        try:
            while self.state.running:
                telemetry = self._telemetry()
                self._publish(self._topic("telemetry"), telemetry)
                self._post_api(telemetry)
                self.state.telemetry_seq += 1
                time.sleep(self.publish_interval_sec)
        except KeyboardInterrupt:
            self.state.running = False
        finally:
            if self.client is not None:
                self.client.loop_stop()
                self.client.disconnect()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Zero-trust ICS ESP32 simulator")
    parser.add_argument("--config", default="device_config.json", help="Path to device config JSON")
    parser.add_argument("--dry-run", action="store_true", help="Print MQTT messages instead of publishing")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = Path(args.config)
    if not config_path.is_absolute() and not config_path.exists():
        config_path = Path(__file__).resolve().parent / config_path
    config = load_json(config_path)
    simulator = Simulator(config, dry_run=args.dry_run)

    def stop(*_: Any) -> None:
        simulator.state.running = False

    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop)

    simulator.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
