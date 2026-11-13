# REST API reference

Base URL: `http://<host>:<port>` (desktop: random port; server: 5000).

**Conventions**
- **Auth:** session cookie from `POST /login`. Unauthenticated calls to protected routes get a **302 redirect to `/login`** (not 401).
- **CSRF:** every POST/PUT/PATCH/DELETE except `/api/telemetry` must send the session's token as the `X-CSRF-Token` header (or `csrf_token` in form/JSON). Failure → `400 {"success":false,"error":"CSRF token missing or invalid."}`.
- **Desktop mode:** routes marked 🅦 also need `X-PYWEBVIEW-TOKEN` when there is no session.
- **Errors:** `{"success": false, "error": "<message>"}` with 400/403/500.
- **Rate limits:** default 200/min and 10,000/h per IP (off in desktop mode); per-route limits noted below.

---

## Authentication

### `GET /login` → login page
### `POST /login` (form, rate limit 120/min)
Fields: `username`, `password`, `csrf_token`; optional location as `location_coords`, `latitude`+`longitude`[+`elevation`], or `coord_x`+`coord_y`[+`coord_z`].
→ `302 /` on success; `401` login page on failure. Both are audited.
### `GET /logout` → clears the session, `302 /login`.

---

## Telemetry ingestion

### `POST /api/telemetry` — gateway token + device HMAC (no session, no CSRF)
Header `X-Aegis-Gateway-Token: <AEGIS_GATEWAY_TOKEN>` is required. The in-process gateway sends it automatically.
```json
{"device_id":"ESP32_001","temperature":26.1,"pressure":4.21,"vibration":1.08,
 "hall_effect":0.0,"current":4.52,"humidity":45.0,"rssi":-62.0,
 "timestamp":1763050000.123,"signature":"<hex HMAC>"}
```
| Status | Meaning |
|---|---|
| 200 `{"success":true,"message":"Telemetry ingested successfully."}` | stored (the device may be quarantined by trust collapse) |
| 400 | body isn't a JSON object, missing/invalid `device_id` (`[A-Za-z0-9_-]{1,50}`), timestamp skew > 60 s, bad timestamp |
| 401 | missing/wrong gateway token, or invalid HMAC signature. 3 invalid signatures from one device within 60 s quarantine it |
| 403 | device isn't provisioned (no key), or is isolated (frame still stored, flagged anomalous) |
| 409 | identical signed frame seen within 300 s (replay) |
| 500 | DB failure |

`timestamp` may be epoch seconds or ISO-8601; it's stored as epoch seconds.

Signature format: [protocols.md](../01-architecture/protocols.md#canonical-signing-string).

---

## Control (login + CSRF)

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/api/setpoint` (30/min) 🅦 | `{"type":"set_temp"|"set_pressure","value":number,"target_device":"ESP32_001"}` | 200 `{"success":true,"details":…}` (sent; no device ACK in protocol v0) · 400 invalid · 403 isolated or safety-blocked (`error` holds the reason) · 503 no hardware gateway connected (nothing queued) · 500 enqueue failed |
| POST | `/api/device/isolate` 🅦 | `{"device_id"}` | sends `ISOLATE` if a gateway is connected; response field `hardware_command_sent` |
| POST | `/api/device/rejoin` 🅦 | `{"device_id"}` | sends `REARM` (same field) |
| POST | `/api/device/shutdown` 🅦 | `{"device_id": "ESP32_00x" | "ALL"}` | sends `SHUTDOWN`; `ALL` isolates every known and provisioned node |
| POST | `/api/device/ping` 🅦 | `{"device_id"}` | sends a ping frame; `latency_ms` is always `null` (firmware v2.5 doesn't reply) |
| POST | `/api/device/clear` 🅦 | `{"device_id" | "ALL"}` | clears simulator attacks + audit entry |
| POST | `/api/rules/update` 🅦 | any of `temp_min,temp_max,pressure_min,pressure_max` | rejects non-finite values and inverted ranges |
| GET | `/api/rules` 🅦 | – | `{"rules":{key:value}}` |

---

## Devices and topology (login)

| Method | Path | Response highlights |
|---|---|---|
| GET | `/api/devices` 🅦 | `devices[]`: `device_id, name, zone, criticality, is_isolated, is_active (≤10 s), trust_score, trust_percentage, status, last_seen, sensors[], latest_temp/pres/vib/curr/hall/hum` |
| GET | `/api/device/status?device_id=` 🅦 | `{device_id, is_isolated, trust{…}}` |
| GET | `/api/device/<id>/trust_breakdown` 🅦 | weighted components + packet stats |
| GET | `/api/cluster/topology` 🅦 | master-bridge info, gateway state, node list with `latest_readings` |
| GET/POST | `/api/cluster/discover` 🅦 | enqueues `DISCOVER`; returns health + active nodes |
| GET | `/api/devices/locations` 🅦 | static plant coordinates + isolation flag |

## Serial gateway (login)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/com_ports` 🅦 | `ports[]: {device, description, hwid, is_esp32_candidate}` |
| GET | `/api/com_ports/status` 🅦 | `{port, state, health}` |
| GET | `/api/gateway/raw_packets` 🅦 | last 60 raw lines |
| POST | `/api/com_ports/connect` 🅦 | `{"port":"COM3"|"/dev/ttyUSB0"|"MOCK","baud":115200}`. Quarantine is kept; ISOLATE is re-sent to every isolated node once connected |
| POST | `/api/com_ports/disconnect` 🅦 | stops the gateway |

## Dashboard data (login)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/data?mode=all|real&device_id=` 🅦 | last 100 telemetry rows, 30 per node, 30 audit rows, financials, trust |
| GET | `/api/stream` 🅦 | SSE: `telemetry`, `heartbeat`, `topology`, `error` |
| GET | `/api/audit/logs?limit=≤300&category=ALL|AUTH|SETPOINT|QUARANTINE|VIOLATION|GATEWAY|MODEL&operator=&search=` 🅦 | adds `severity` (`SIMULATED` for drill entries), `nist_control`, `is_simulated`. Invalid `limit` falls back to 100 |

## Models (login)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/model/status` 🅦 | real sample count, tree count, metrics JSON |
| POST | `/api/model/retrain` (10/min) 🅦 | synchronous RF retrain; returns metrics |
| GET | `/api/neural_policy/status` 🅦 | NSPN load status, architecture, latency |

## Analytics and reports (login)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/financial/analytics?device_id=` 🅦 | FAIR metrics |
| GET | `/api/financial/loss_distribution?device_id=` 🅦 | 12-point curve |
| GET | `/api/financial/subsystems` 🅦 | per-node costs |
| GET | `/api/report/download` | PDF attachment |
| GET | `/api/report/view` | PDF inline |
| GET/POST | `/api/report/save_dialog[?native=1]` | desktop: native save dialog; web: `{"download_url"}` |

## Red team (login + CSRF)

| Method | Path | Body |
|---|---|---|
| POST | `/api/simulate/attack` 🅦 | `{"device_id","attack_type":"stuxnet|hmac_tamper|thermal_drift|fdi_spike|injection|ddos"}` (affects the mock gateway stream) |
| POST | `/api/simulate/reset` 🅦 | – |
| POST | `/api/simulate-attack` (30/min) 🅦 | `{"type":"stuxnet|injection|privilege"}`. Writes drill telemetry and `SIMULATED_*` audit rows, all flagged `is_simulated`; doesn't change device state; excluded from PDF reports |

## Meta (public)

| Method | Path | Response |
|---|---|---|
| GET | `/health` | `{"status":"healthy","components":{"database":"connected"}}` |
| GET | `/api/version` | `{"version":"2.5.2","name":"Aegis ICS"}` |

---

## Example session (curl)

```bash
BASE=http://127.0.0.1:5000
TOKEN=$(curl -s -c jar $BASE/login | grep -o 'name="csrf_token" value="[^"]*"' | cut -d'"' -f4)
curl -s -b jar -c jar -d "username=admin&password=$ADMIN_PASSWORD&csrf_token=$TOKEN" $BASE/login -o /dev/null
curl -s -b jar $BASE/api/devices | python -m json.tool
curl -s -b jar -H "X-CSRF-Token: $TOKEN" -H "Content-Type: application/json" \
     -d '{"type":"set_temp","value":30,"target_device":"ESP32_001"}' $BASE/api/setpoint
```
