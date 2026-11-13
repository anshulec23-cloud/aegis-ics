# HTTP backend — `src/app.py`

## Responsibility
The single Flask application: authentication, CSRF, rate limiting, the telemetry ingestion pipeline, operator control endpoints, read APIs for the dashboard, SSE streaming, report download, and the Random Forest wrapper.

## Module-level side effects at import
Importing `app` does all of the following, so tests and tools can't import it cheaply:
1. `init_db()` creates tables, migrates and seeds users, rules, device states and audit records.
2. Creates `Flask(...)` with template/static folders resolved for PyInstaller.
3. Loads or creates the session secret (`FLASK_SECRET_KEY`, else `src/.aegis_session_key`, mode 0600).
4. Configures Flask-Limiter (in-memory; default 10000/h and 200/min, disabled in desktop mode).
5. Loads `model/rf_model.pkl` after checking the `.sha256` sidecar (`LocalRFModel`).

## Request pipeline
```
before_request: csrf_protect()      # skipped if TESTING or path == /api/telemetry
route decorators (order matters):   @app.route → @login_required → @require_webview_token → @limiter.limit
```
`login_required` redirects to `/login` (HTML redirect even for JSON APIs).

## Route groups (40 routes)

| Group | Routes |
|---|---|
| Auth / pages | `GET /`, `GET|POST /login`, `GET /logout` |
| Ingestion | `POST /api/telemetry` (no auth, CSRF-exempt, rate-limit-exempt) |
| Control | `POST /api/setpoint`, `/api/device/isolate`, `/api/device/rejoin`, `/api/device/shutdown`, `/api/device/ping`, `/api/device/clear`, `/api/rules/update` |
| Devices / topology | `GET /api/devices`, `/api/device/status`, `/api/device/<id>/trust_breakdown`, `/api/cluster/topology`, `GET|POST /api/cluster/discover`, `/api/devices/locations` |
| Gateway | `GET /api/com_ports`, `/api/com_ports/status`, `/api/gateway/raw_packets`, `POST /api/com_ports/connect`, `/api/com_ports/disconnect` |
| Dashboard data | `GET /api/data`, `/api/stream` (SSE), `/api/audit/logs`, `/api/rules` |
| Models | `GET /api/model/status`, `POST /api/model/retrain`, `GET /api/neural_policy/status` |
| Analytics / reports | `GET /api/financial/analytics`, `/api/financial/loss_distribution`, `/api/financial/subsystems`, `/api/report/download`, `/api/report/view`, `GET|POST /api/report/save_dialog` |
| Red team | `POST /api/simulate/attack`, `/api/simulate/reset` (gateway simulator), `POST /api/simulate-attack` (writes synthetic DB rows) |
| Meta | `GET /health`, `GET /api/version` |

Full contract: [REST API reference](../../03-api/rest-api.md).

## `process_telemetry(payload)` — the core function
1. Replay window: if `timestamp` exists (epoch float or ISO string), reject when |now − ts| > 60 s (skipped under `TESTING`).
2. If the device is isolated, store the row with `is_anomaly=True` and return 403.
3. `verify_signature`, then `rf_model.predict_anomaly(payload, db)`.
4. Insert `TelemetryLog`.
5. `compute_device_trust_score(...)`.
6. Quarantine if `!sig_valid or trust<0.40 or (anomaly and trust<0.50)`: update `DeviceState`, write an `AUTO_ISOLATION` audit, enqueue a signed `ISOLATE`.

## Conventions and quirks
- DB sessions are opened with `SessionLocal()` and closed manually; several early-return paths rely on `finally`, others don't.
- Errors are logged with `print` and returned as generic JSON messages (no stack traces leak, which is good).
- Device IDs from the request are passed through `bleach.clean` in control routes, but not in ingestion.
- The source uses an unusual token spacing (`db .close ()`) throughout. It's valid Python but should be reformatted with `ruff format`.

## Known issues
S1, S4, S7, S8, S9, S11, F1, F3, F8–F11, F14, R1 in the [debug report](../../07-reports/DEBUG_REPORT.md).

## Target state
Split into an application factory plus blueprints (`auth`, `ingest`, `control`, `devices`, `gateway`, `audit`, `analytics`, `reports`, `stream`, `meta`). Business logic moves into services (`TelemetryIngestService`, `QuarantineService`, `CommandService`), and data access into repositories. See [RESTRUCTURE_PLAN §3](../../08-roadmap/RESTRUCTURE_PLAN.md).
