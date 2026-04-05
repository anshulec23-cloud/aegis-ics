# Flask REST API

Backend API connecting the dashboard to the AI engine, MQTT broker, and log store.

## Files
- `__init__.py` - marks `server.api` as a Python package.
- `app.py` - Flask routes, startup, telemetry ingest, and dashboard rendering.
- `mqtt_bridge.py` - subscribes to MQTT telemetry and forwards it into the trust engine.
- `device_keys.py` - reads device HMAC keys from environment variables.
- `ollama_client.py` - sends prompts to the local Ollama server.
- `state_store.py` - stores devices, alerts, readings, and logs on disk.
- `templates/dashboard.html` - browser dashboard UI.
- `requirements.txt` - Python dependencies for the API.

## Endpoints
- `GET /api/devices`
- `GET /api/device/<id>`
- `POST /api/device/<id>/isolate`
- `POST /api/device/<id>/rejoin`
- `GET /api/logs/<type>`
- `POST /api/ai/query`
- `GET /api/alerts`
- `GET /ws`
