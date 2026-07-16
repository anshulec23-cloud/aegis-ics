from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .device_keys import load_device_key

try:
    import paho.mqtt.client as mqtt  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional dependency
    mqtt = None


class MQTTBridge:
    def __init__(self, store: Any, trust_engine: Any, host: str = "127.0.0.1", port: int = 8883) -> None:
        self.store = store
        self.trust_engine = trust_engine
        self.host = os.getenv("MQTT_HOST", host)
        self.port = int(os.getenv("MQTT_PORT", str(port)))
        self.use_tls = os.getenv("MQTT_USE_TLS", "true").lower() in {"1", "true", "yes", "on"}
        self.ca_cert = os.getenv("MQTT_CA_CERT")
        self.username = os.getenv("MQTT_USERNAME")
        self.password = os.getenv("MQTT_PASSWORD")
        self.client = None
        self._started = False
        self.policy_dir = Path(__file__).resolve().parents[2] / "policies" / "device_policies"

    def start(self) -> None:
        if mqtt is None or self._started:
            return
        self._started = True
        self.client = mqtt.Client(client_id="ics-api", protocol=mqtt.MQTTv311)
        if self.use_tls:
            if self.ca_cert:
                self.client.tls_set(ca_certs=self.ca_cert)
            else:
                self.client.tls_set()
        if self.username or self.password:
            self.client.username_pw_set(self.username or "", self.password or "")
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.loop_start()
        client = self.client

        def connect_forever() -> None:
            while True:
                try:
                    assert client is not None
                    client.connect(self.host, self.port, keepalive=60)
                    break
                except Exception:
                    time.sleep(2)

        threading.Thread(target=connect_forever, daemon=True).start()

    def _on_connect(self, client: Any, userdata: Any, flags: Any, rc: Any) -> None:
        client.subscribe("ics/telemetry/#")

    def _on_message(self, client: Any, userdata: Any, msg: Any) -> None:
        try:
            telemetry = json.loads(msg.payload.decode("utf-8"))
        except Exception:
            return

        device_id = str(telemetry.get("device_id", "unknown"))
        device = self.store.get_device(device_id)
        history = device.get("telemetry", []) if device else []
        decision = self.trust_engine.score(telemetry, history, device_key=load_device_key(device_id))
        status = "ISOLATED" if decision.action == "isolate" else "ALERT" if decision.trust_score < 0.75 else "NORMAL"
        self.store.update_device(device_id, decision.trust_score, telemetry, status)
        if decision.action == "isolate":
            self.store.isolate_device(device_id)
