# Server

This folder contains the backend runtime for the ICS demo.

## What Lives Here
- `__init__.py` - marks `server` as a Python package.
- `api/` - Flask app, dashboard UI, telemetry ingestion, and Ollama client.
- `ai_engine/` - trust scoring and isolation state.
- `mqtt_broker/` - Mosquitto config and ACL management.

## What It Does
The server receives telemetry, checks it, stores state, and decides whether a device should be isolated.
