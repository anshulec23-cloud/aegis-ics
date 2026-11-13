# Configuration

All configuration comes from **environment variables** (template: [`.env.example`](../../.env.example)). Nothing loads `.env` automatically. On Debian, put site values in `/etc/default/aegis-ics`; both service units read it. A single typed `Settings` object replaces ad-hoc `os.environ` reads in restructure plan Phase 3.

## Accounts and sessions
| Variable | Default | Read in | Purpose |
|---|---|---|---|
| `ADMIN_PASSWORD` | *generated* | `bootstrap.py` via `database.init_db` | Password for the `admin` account when it's created. Minimum 12 characters; the legacy `noodles` value is refused. If unset, a random password is printed once and written to `<data dir>/initial_admin_password.txt` (mode 0600). Delete that file after first login. |
| `FLASK_SECRET_KEY` | contents of `src/.aegis_session_key` (auto-generated) | `app.py` | Session-cookie signing key |
| `FLASK_SESSION_SECURE` | `False` | `app.py` | Set `true` behind HTTPS so the session cookie gets `Secure` |

On upgrade from ≤ 2.5.x, `init_db()` rotates an `admin` account still using the old default password, and deletes the `noodles` account if it still has its default password. Both actions are recorded as `ACCOUNT_BOOTSTRAP` audit entries.

## Device keys
| Variable | Default | Read in | Purpose |
|---|---|---|---|
| `DEVICE_KEY_<DEVICE_ID>` | – | `device_keys.get_device_key` | Per-device HMAC key (≥ 16 chars), e.g. `DEVICE_KEY_ESP32_001`. Takes precedence over the key file. |
| `AEGIS_DEVICE_KEYS_FILE` | `<data dir>/device_keys.json` | `device_keys.py` | JSON `{"ESP32_001": "<key>", ...}`. Re-read automatically when the file changes. |

There is **no default or fallback key**. A device without a key is *unprovisioned*: its frames get `403`, and no command can be signed for it. At startup, a warning lists any of ESP32_001–004 that have no key.

Generate keys and the matching firmware header:
```bash
python src/device_keys.py generate ESP32_001 ESP32_002 ESP32_003 ESP32_004 \
    --out device_keys.json --firmware-header firmware/esp32_slave_sensor/aegis_secrets.h
```
Re-running keeps existing keys; `--force` rotates them. Both outputs are git-ignored.

## Gateway and ingestion
| Variable | Default | Read in | Purpose |
|---|---|---|---|
| `AEGIS_GATEWAY_TOKEN` | random per process | `app.py`, `serial_gateway.py` | Shared secret for `POST /api/telemetry` (header `X-Aegis-Gateway-Token`). Set it explicitly only when running `serial_gateway.py` as a **separate** process. |
| `AEGIS_COMMAND_TTL_S` | `5` | `serial_gateway.py` | Queued commands older than this are dropped, never written late |
| `AEGIS_SIG_FAILURE_THRESHOLD` | `3` | `app.py` | Invalid signatures from one device that trigger quarantine… |
| `AEGIS_SIG_FAILURE_WINDOW_S` | `60` | `app.py` | …within this many seconds |
| `AEGIS_REPLAY_WINDOW_S` | `300` | `app.py` | Identical signed frames within this window are rejected as replays (409) |
| `FLASK_PORT` | random (desktop) / `5000` (server) | `main.py`, `app.connect_com_port` | Port the in-process gateway posts back to; exported by `main.py` |

## Storage and runtime
| Variable | Default | Read in | Purpose |
|---|---|---|---|
| `DATABASE_URL` | – | `database.py` | Full SQLAlchemy URL; overrides everything below |
| `AEGIS_DATA_DIR` | – | `database.py` | Directory for `aegis_v2.db`, `device_keys.json` and `initial_admin_password.txt` (Debian: `/var/lib/aegis-ics`) |
| `HOST` / `PORT` | `127.0.0.1` / `5000` | `app.py __main__` | Dev-server bind address |
| `AEGIS_DESKTOP_MODE` | set to `1` by `main.py` | `app.py`, `security.py` | Disables default rate limits; enables the webview-token check and the native save dialog |
| `AEGIS_SERVER_MODE` | – | `main.py` | `1` = headless (same as `--server`) |
| `DISPLAY` / `WAYLAND_DISPLAY` | – | `main.py` | Absent on Linux means automatic headless mode |
| `LOCALAPPDATA`, `XDG_DATA_HOME` | OS | `database.py` | Fallback DB directories for frozen builds |

## CLI flags
- `src/main.py`: `--server | --headless | -s`, `--host <addr>` / `--host=`, `--port <n>` / `--port=`, `--version`, `--check`.
- `src/serial_gateway.py`: `--port COM3`, `--baud 115200`, `--mode plc|non-plc`, `--device-id`, `--url`, `--mock`. Bench testing only: `--allow-unsigned` (with optional `--key`) signs frames from sensors that can't sign themselves. Never use it in production.
- `src/device_keys.py`: `generate <ids...> [--out] [--firmware-header] [--force]`.

## Production checklist
- [ ] `ADMIN_PASSWORD` set, or the generated password used once and its file deleted
- [ ] `FLASK_SECRET_KEY` set from a secret store
- [ ] Device keys provisioned for every node and flashed into matching firmware (`aegis_secrets.h`)
- [ ] Bound to `127.0.0.1` behind a TLS reverse proxy; `FLASK_SESSION_SECURE=true` (the Debian units do the binding)
- [ ] Service runs as the unprivileged `aegis` user in `dialout` (the Debian packaging does this)
