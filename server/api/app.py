"""API entry point."""

# pyright: reportMissingImports=false

from __future__ import annotations

import json
import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request  # type: ignore[import-not-found]

try:
    from flask_sock import Sock  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional dependency
    Sock = None

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.ai_engine.engine import TrustEngine  # noqa: E402
from server.api.device_keys import load_device_key  # noqa: E402
from server.api.mqtt_bridge import MQTTBridge  # noqa: E402
from server.api.ollama_client import query_ollama  # noqa: E402
from server.api.state_store import StateStore  # noqa: E402


store = StateStore()
trust_engine = TrustEngine()
bridge = MQTTBridge(store=store, trust_engine=trust_engine)

app = Flask(__name__)
sock = Sock(app) if Sock is not None else None

for device_id in ("ESP32_001", "ESP32_002"):
    store.seed_device(device_id)
store.seed_demo_data()


@app.get("/api/devices")
def get_devices():
    return jsonify(store.list_devices())


@app.get("/api/latest")
def get_latest():
    return jsonify(store.latest())


@app.get("/api/history")
def get_history():
    return jsonify(store.history())


@app.get("/api/device/<device_id>")
def get_device(device_id: str):
    device = store.get_device(device_id)
    if not device:
        return jsonify({"error": "device not found"}), 404
    return jsonify(device)


@app.post("/api/device/<device_id>/isolate")
def isolate_device(device_id: str):
    trust_engine.microseg.isolate(device_id)
    return jsonify(store.isolate_device(device_id))


@app.post("/api/device/<device_id>/rejoin")
def rejoin_device(device_id: str):
    trust_engine.rejoin(device_id)
    return jsonify(store.rejoin_device(device_id))


@app.get("/api/logs/<log_type>")
def get_logs(log_type: str):
    return jsonify(store.logs(log_type))


@app.post("/api/ai/query")
def ai_query():
    payload = request.get_json(force=True, silent=True) or {}
    message = str(payload.get("message", ""))
    context = payload.get("context")
    prompt = message if not context else f"{context}\n\n{message}"
    return jsonify(query_ollama(prompt))


@app.get("/api/alerts")
def get_alerts():
    return jsonify(store.alerts())


def _ingest_telemetry(telemetry: dict[str, object]) -> dict[str, object]:
    device_id = str(telemetry.get("device_id", "unknown"))
    device = store.get_device(device_id)
    history = device.get("telemetry", []) if device else []
    decision = trust_engine.score(telemetry, history, device_key=load_device_key(device_id))
    status = "ISOLATED" if decision.action == "isolate" else "ALERT" if decision.trust_score < 0.75 else "NORMAL"
    store.update_device(device_id, decision.trust_score, telemetry, status)
    if decision.action == "isolate":
        store.isolate_device(device_id)
    return {
        "device_id": device_id,
        "status": status,
        "trust_score": decision.trust_score,
        "action": decision.action,
        "breakdown": decision.breakdown,
    }


@app.post("/api/ingest")
def ingest_telemetry():
    payload = request.get_json(force=True, silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid telemetry payload"}), 400
    return jsonify(_ingest_telemetry(payload))


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/")
def index():
    return render_template("dashboard.html")


def create_app() -> Flask:
    bridge.start()
    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
