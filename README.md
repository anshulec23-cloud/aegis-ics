# AI Zero Trust Cybersecurity for ICS Protocols

## What This Repo Is
This is a small ICS security demo. It simulates field devices, scores their behavior, isolates bad devices, and shows the results in a dashboard.

## Quickstart
1. Read `QUICKSTART.md`.
2. Copy `.env.example` to `.env` and fill in your local values.
3. Generate certs in `certs/`.
4. Start the MQTT broker with TLS and ACLs.
5. Start the Flask API.
6. Run one or more simulator instances.

## Run Order
- `certs/` - generate root, server, and device certificates.
- `server/mqtt_broker/` - start Mosquitto.
- `server/api/` - start the Flask dashboard/API.
- `esp32_sim/` - run the device simulator.

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

## Tests
- Run: `python -m unittest discover -s tests`
- Coverage target: policy checks, trust scoring, state store, and API auth.

## CI
- GitHub Actions runs the test suite on push and pull request.

## Best Starting Point
- `QUICKSTART.md` - exact commands to run the demo.

## Top-Level Files
- `.env.example` - template for local environment values.
- `.gitignore` - keeps secrets, certs, virtualenvs, and generated data out of git.
- `README.md` - this overview file.

## Top-Level Folders
- `certs/` - certificate generation helper and notes.
- `docs/` - architecture diagram, threat model, evaluation notes, and paper draft.
- `esp32_sim/` - fake ESP32 device simulator and local device policy.
- `policies/` - server and device policy rules.
- `server/` - Flask API, AI scoring, and MQTT broker config.
- `tests/` - unit tests for security-critical behavior.

## Runtime Pieces
- Field devices publish signed telemetry.
- The broker enforces topic access with ACLs.
- The API ingests telemetry and updates device state.
- The AI engine scores trust and requests isolation when needed.
- The dashboard displays live state.
