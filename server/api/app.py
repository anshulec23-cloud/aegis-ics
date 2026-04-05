"""API entry point."""

# pyright: reportMissingImports=false

from __future__ import annotations

import json
import hmac
import os
import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request  # type: ignore[import-not-found]

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
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024


def _admin_token() -> str | None:
    token = os.getenv("API_ADMIN_TOKEN", "").strip()
    return token or None


def _require_admin_token() -> tuple[dict[str, str], int] | None:
    expected = _admin_token()
    if expected is None:
        return None
    provided = request.headers.get("X-Admin-Token", "")
    if not hmac.compare_digest(provided, expected):
        return {"error": "unauthorized"}, 401
    return None


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _validate_telemetry_payload(payload: object) -> tuple[dict[str, str], int] | None:
    if not isinstance(payload, dict):
        return {"error": "invalid telemetry payload"}, 400

    device_id = payload.get("device_id")
    if not isinstance(device_id, str) or not device_id.strip():
        return {"error": "invalid telemetry payload"}, 400

    for field in ("timestamp", "temperature", "pressure", "sequence"):
        if field not in payload or not _is_number(payload[field]):
            return {"error": "invalid telemetry payload"}, 400

    humidity = payload.get("humidity")
    if humidity is not None and not _is_number(humidity):
        return {"error": "invalid telemetry payload"}, 400

    return None

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
    denied = _require_admin_token()
    if denied:
        return jsonify(denied[0]), denied[1]
    device = store.get_device(device_id)
    if not device:
        return jsonify({"error": "device not found"}), 404
    return jsonify(device)


@app.post("/api/device/<device_id>/isolate")
def isolate_device(device_id: str):
    denied = _require_admin_token()
    if denied:
        return jsonify(denied[0]), denied[1]
    trust_engine.microseg.isolate(device_id)
    return jsonify(store.isolate_device(device_id))


@app.post("/api/device/<device_id>/rejoin")
def rejoin_device(device_id: str):
    denied = _require_admin_token()
    if denied:
        return jsonify(denied[0]), denied[1]
    trust_engine.rejoin(device_id)
    return jsonify(store.rejoin_device(device_id))


@app.get("/api/logs/<log_type>")
def get_logs(log_type: str):
    denied = _require_admin_token()
    if denied:
        return jsonify(denied[0]), denied[1]
    return jsonify(store.logs(log_type))


@app.post("/api/ai/query")
def ai_query():
    denied = _require_admin_token()
    if denied:
        return jsonify(denied[0]), denied[1]
    payload = request.get_json(force=True, silent=True) or {}
    message = str(payload.get("message", ""))
    context = payload.get("context")
    prompt = message if not context else f"{context}\n\n{message}"
    return jsonify(query_ollama(prompt))


@app.get("/api/alerts")
def get_alerts():
    denied = _require_admin_token()
    if denied:
        return jsonify(denied[0]), denied[1]
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
    denied = _validate_telemetry_payload(payload)
    if denied:
        return jsonify(denied[0]), denied[1]
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
