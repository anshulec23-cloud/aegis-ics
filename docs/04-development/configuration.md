# Configuration

All configuration comes from **environment variables**, read ad hoc where they're used. Nothing loads `.env` automatically.

| Variable | Default | Read in | Purpose |
|---|---|---|---|
| `ADMIN_PASSWORD` | `noodles` ⚠️ | `database.init_db` | Password for the seeded `admin` and `noodles` accounts (only applied when the user is first created) |
| `FLASK_SECRET_KEY` | contents of `src/.aegis_session_key` (auto-generated) | `app.py` | Session-cookie signing key |
| `FLASK_SESSION_SECURE` | `False` | `app.py` | Set `true` behind HTTPS so the session cookie gets `Secure` |
| `DATABASE_URL` | – | `database.py` | Full SQLAlchemy URL; overrides everything below |
| `AEGIS_DATA_DIR` | – | `database.py` | Directory for `aegis_v2.db` (used by the Debian service: `/var/lib/aegis-ics`) |
| `DEVICE_KEY_<DEVICE_ID>` | hard-coded default ⚠️ | `security.get_device_key` | Per-device HMAC key, e.g. `DEVICE_KEY_ESP32_001` |
| `HOST` / `PORT` | `127.0.0.1` / `5000` | `app.py __main__` | Dev-server bind address |
| `FLASK_PORT` | random (desktop) / `5000` (server) | `main.py`, `app.connect_com_port` | Port the gateway posts back to; exported by `main.py` |
| `AEGIS_DESKTOP_MODE` | set to `1` by `main.py` | `app.py`, `security.py` | Disables default rate limits; enables the webview-token check; enables the native save dialog |
| `AEGIS_SERVER_MODE` | – | `main.py` | `1` = headless (same as `--server`) |
| `DISPLAY` / `WAYLAND_DISPLAY` | – | `main.py` | Absent on Linux means automatic headless mode |
| `LOCALAPPDATA`, `XDG_DATA_HOME` | OS | `database.py` | Fallback DB directories for frozen builds |

## CLI flags (`src/main.py`)
`--server | --headless | -s`, `--host <addr>` / `--host=`, `--port <n>` / `--port=`, `--version`, `--check`.

## CLI flags (`src/serial_gateway.py`)
`--port COM3`, `--baud 115200`, `--mode plc|non-plc`, `--device-id`, `--key`, `--url`, `--mock`.

## Stale entries in `.env.example`
`OLLAMA_HOST`, `OLLAMA_MODEL`, `MQTT_*` and `API_ADMIN_TOKEN` aren't read by any code. `paho-mqtt` and `pandas` in `requirements.txt` aren't imported by `src/`. Remove them, or implement the features, as part of the restructure.

## Production checklist
- [ ] `ADMIN_PASSWORD` set (and the `noodles` user removed)
- [ ] `FLASK_SECRET_KEY` set from a secret store
- [ ] `DEVICE_KEY_*` set for every node, matching the flashed firmware
- [ ] Bind to `127.0.0.1` behind a TLS reverse proxy; `FLASK_SESSION_SECURE=true`
- [ ] Service runs as a non-root user in the `dialout` group
