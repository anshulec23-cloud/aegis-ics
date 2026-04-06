# Aegis ICS

Zero-trust micro-segmentation and device-side policy enforcement for industrial telemetry.

## Novel Contributions
1. Micro-segmentation engine
- Automatically isolates suspicious devices based on live trust scoring.
- Keeps the device running while cutting off unsafe network access.

2. Device-side policy engine
- Rejects unsafe server commands on the device before execution.
- Prevents server compromise from turning into field-device compromise.

## Why This Matters
Most ICS demos stop at anomaly detection. Aegis ICS goes one step further: it enforces policy at the broker, the server, and the device itself, so the system can contain bad behavior instead of only observing it.

## Results In v1
- TLS-only MQTT broker configuration.
- No anonymous broker access.
- Sensitive API routes can require an admin token.
- Telemetry ingest validates payload shape before processing.
- Device isolation is persisted and test-covered.
- Security-critical unit tests pass.

## What Problem It Solves
- Stops malformed or malicious telemetry from crashing the API.
- Blocks invalid control commands at the device boundary.
- Reduces blast radius when a device or server is compromised.
- Prevents unnecessary exposure of secrets, keys, and logs in the repo.

## System Overview
- `esp32_sim/` simulates devices and their local policy checks.
- `server/api/` receives telemetry, scores trust, and serves the dashboard.
- `server/ai_engine/` computes trust and isolates risky devices.
- `server/mqtt_broker/` defines broker TLS and ACL rules.
- `policies/` defines server and device command limits.
- `certs/` generates local TLS certificates.
- `docs/` explains architecture, threats, and evaluation.
- `tests/` verifies the security-critical behavior.

## Quickstart
1. Read `QUICKSTART.md`.
2. Copy `.env.example` to `.env` and fill in your local values.
3. Generate certs in `certs/`.
4. Start the MQTT broker with TLS and ACLs.
5. Start the Flask API.
6. Run one or more simulator instances.

## Validation
- Run: `python -m unittest discover -s tests`
- CI: GitHub Actions runs the test suite on push and pull request.

## Important Env Vars
- `MQTT_HOST`, `MQTT_PORT`, `MQTT_USE_TLS`, `MQTT_CA_CERT`
- `MQTT_USERNAME`, `MQTT_PASSWORD`
- `FLASK_SECRET_KEY`
- `API_ADMIN_TOKEN`
- `DEVICE_KEY_ESP32_001`, `DEVICE_KEY_ESP32_002`

## Safety Defaults
- TLS is on by default.
- Plain MQTT is not the default.
- Sensitive API routes can require `API_ADMIN_TOKEN`.
- Secrets and generated data are ignored by git.

## Repo Map
- `.env.example` - template for local environment values.
- `.gitignore` - keeps secrets, certs, virtualenvs, and generated data out of git.
- `QUICKSTART.md` - exact commands to run the demo.
- `README.md` - this overview.
