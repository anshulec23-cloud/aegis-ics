# AI Zero Trust Cybersecurity for ICS Protocols

## What This Repo Is
This is a small ICS security demo. It simulates field devices, scores their behavior, isolates bad devices, and shows the results in a dashboard.

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

## Runtime Pieces
- Field devices publish signed telemetry.
- The broker enforces topic access with ACLs.
- The API ingests telemetry and updates device state.
- The AI engine scores trust and requests isolation when needed.
- The dashboard displays live state.
