# Configuration

**Nothing needs to be configured for a normal installation.** The admin account is created on the first-run setup screen, and field devices enroll themselves after a one-click approval ([ADR 0006](../adr/0006-zero-touch-enrollment.md)). Everything below is optional and comes from **environment variables** (template: [`.env.example`](../../.env.example)). Nothing loads `.env` automatically. On Debian, put site values in `/etc/default/aegis-ics`; both service units read it. A typed `Settings` object replaces these ad-hoc reads in restructure plan Phase 3.

## Data directory
All mutable state lives in one directory: `aegis_v2.db`, `host_identity.key` (X25519, 0600), `.aegis_session_key`, `setup_token.txt` (first run only), `simulator_devices.json`, and legacy `device_keys.json`.

| Situation | Data directory |
|---|---|
| `AEGIS_DATA_DIR` set | that directory |
| `DATABASE_URL` set (SQLite) | the database file's directory |
| Packaged app, Windows | `%LOCALAPPDATA%\AegisICS` (or next to the exe if an `aegis_portable` file is there) |
| Packaged app, Linux user / root | `~/.local/share/aegis-ics` / `/var/lib/aegis-ics` |
| Development | repository root |

## Accounts and sessions
| Variable | Default | Purpose |
|---|---|---|
| `ADMIN_PASSWORD` | – | Creates `admin` with this password (≥ 12 chars; the legacy `noodles` is refused) and skips the setup screen. Without it the app starts in **setup mode**: every page redirects to `/setup`, which needs the one-time token the desktop app opens automatically (headless installs: log line or `setup_token.txt`). |
| `FLASK_SECRET_KEY` | `<data dir>/.aegis_session_key` (auto-generated) | Session-cookie signing key |
| `FLASK_SESSION_SECURE` | `False` | `true` behind HTTPS so the cookie gets `Secure` |

Upgrading from ≤ 2.5.x: an `admin` still on the old default password is **locked** and the setup screen appears; a `noodles` account still on its default password is deleted. Both are audited as `ACCOUNT_BOOTSTRAP`.

## Field devices
| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_SIM_DEVICES` | `4` | Number of slaves the software simulator emulates (1–64) |
| `AEGIS_RPM_MAX` | `3000` | Overspeed rule threshold (RPM) for every device |
| `DEVICE_KEY_<ID>` | – | **Legacy v0 firmware only:** pre-shared key for a device with a compiled-in key |
| `AEGIS_DEVICE_KEYS_FILE` | `<data dir>/device_keys.json` | **Legacy v0 only:** JSON `{id: key}` (generator: `python src/device_keys.py generate ...`) |

## Gateway and ingestion
| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_GATEWAY_TOKEN` | random per process | Token for `POST /api/telemetry` (header `X-Aegis-Gateway-Token`). Only needed when `serial_gateway.py` runs as a separate process. |
| `AEGIS_COMMAND_TTL_S` | `5` | Queued frames older than this are dropped (`command_log` → `EXPIRED`) |
| `AEGIS_SIG_FAILURE_THRESHOLD` / `_WINDOW_S` | `3` / `60` | Invalid signatures from one device within the window that trigger quarantine |
| `AEGIS_REPLAY_WINDOW_S` | `300` | v0 duplicate-frame window (v1 uses boot/seq) |
| `FLASK_PORT` | random (desktop) / `5000` (server) | Port the gateway posts back to (external mode); exported by `main.py` |

## Runtime
| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | – | Full SQLAlchemy URL (overrides the data-directory database) |
| `HOST` / `PORT` | `127.0.0.1` / `5000` | `python src/app.py` dev-server bind |
| `AEGIS_DESKTOP_MODE` | set by `main.py` | Disables default rate limits; enables the webview-token check and native save dialog |
| `AEGIS_SERVER_MODE` | – | `1` = headless (same as `--server`) |

## CLI flags
- `src/main.py`: `--server | --headless | -s`, `--host <addr>`, `--port <n>`, `--version`, `--check`.
- `src/serial_gateway.py`: `--port`, `--baud`, `--url`, `--mock`, `--sim-devices N`; legacy bench only: `--device-id`, `--allow-unsigned`, `--key`.

## Production checklist
- [ ] Admin password set on the setup screen (or `ADMIN_PASSWORD`), and `setup_token.txt` gone
- [ ] Bound to `127.0.0.1` behind a TLS reverse proxy; `FLASK_SESSION_SECURE=true` (the Debian units do the binding)
- [ ] Service runs as the unprivileged `aegis` user in `dialout` (the Debian packaging does this)
- [ ] Every field device approved after comparing fingerprints; unknown pending devices rejected
- [ ] The data directory is backed up (it holds the host identity: losing it means re-approving every device)
