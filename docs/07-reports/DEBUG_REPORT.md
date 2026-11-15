# Aegis ICS v2.5.x — Full Debug Session Report

Date: 2026-11-13 · Scope: every file in `src/`, `firmware/`, `tests/`, `debian/`, `build_scripts/`, plus the README/release notes claims.
Method: (1) read all source, (2) ran the pytest suite in a clean venv, (3) wrote a separate reproduction script that drives the real Flask app against a throw-away database (`TESTING=False`, so CSRF / replay checks are live) to confirm each bug. The project source was not modified by the debug session.

Legend: ✅ CONFIRMED = reproduced live · 🔍 CODE = verified by reading the code (not executed, e.g. needs hardware) · Severity = impact if deployed as the README describes (Linux service on `0.0.0.0:5000`).

---

## Fix status (updated 2026-11-15, v2.6.0.dev0 — restructure plan Phases 0–2)

Every finding has a regression test in [`tests/security/test_debug_findings.py`](../../tests/security/test_debug_findings.py). That suite runs with all security controls on. Findings still open there are marked `xfail(strict=True)`, so the fix that closes one must also remove its marker.

| Status | Findings |
|---|---|
| **Fixed in v2.6** | S1 (gateway token on ingestion, 3-strike signature quarantine, loopback-only non-root service), S2 (no keys in source; zero-touch X25519 enrollment with one-click approval; unknown devices rejected), S3 (firmware verifies command HMAC + sequence before acting), S5 (protocol v1 boot/seq replay protection in both directions), S4 (generated/required admin password, legacy `noodles` removed), S6 (gateway never signs for devices), S7 (dashboard escaping, sanitised audit input, device-id validation, CSP and security headers), S8 (reconnect keeps quarantine and re-sends ISOLATE), S11, F1, F2 (setpoints applied on the device and acknowledged), F3 (no queueing without a gateway, 5 s command TTL, ACK tracking), F4 (per-run stop event), F5 (master-polled bus), F7 (faulted sensors reported, never faked), F8, F9, F10, F13, F14, F15 (no invented GPS; no hard-coded device lists), R1 (drills flagged `is_simulated`, excluded from reports, no longer change device state), R2 |
| **Partially fixed** | S13 (client IP no longer taken from `X-Forwarded-For`; hash-chained audit is Phase 3) |
| **Open: Phase 3 (restructure)** | S9 (RBAC), S12, F11, F12 |
| **Open: Phase 4 (ML/research)** | S10, F6, R3, R4, R5, R6 |
| **Open: Phase 5** | S14 (updater opt-out for air-gapped installs) |

Verification: `python -m pytest tests` → **126 passed, 1 xfailed** (F6). An end-to-end browser run of a fresh install (first-run setup, 6 simulated slaves, approval, ACKed setpoint/isolate/rearm, tamper and replay drills, restart) confirmed the behaviour. The firmware fixes (S3, F2, F5, F7) are verified by static contract tests and shared crypto vectors but **haven't been compiled or run on hardware** in this environment.

The findings below describe the code **as it was at v2.5.3** (git tag `v2.5.3-baseline`).

---

## 0. Executive summary

The project is large and ambitious, and the shape is right: field nodes, a gateway, ML scoring, a deterministic safety layer, an audit trail and a dashboard. The problem is that several core security claims don't hold end-to-end, and some "working" features are simulated or not wired through:

1. **The zero-trust layer can be bypassed or turned against the plant.** All HMAC keys are hard-coded in the public source. Any unauthenticated client can quarantine a node, which sends a physical relay trip, with one bad packet. Commands sent to the ESP32s are never verified by the firmware.
2. **The hardware path is broken in normal use.** Starting the gateway from the dashboard signs every node's frames with ESP32_001's key, so nodes 002–004 quarantine themselves on their first packet. Setpoints are sent in a format the firmware ignores, so they never reach the hardware.
3. **Some evidence is synthetic but presented as real.** The red-team "attack" button writes "BLOCKED" entries into the real audit log. Ping returns a hard-coded 14.2 ms. "Real GPS" coordinates are constants. Startup seeds six audit records for checks that never ran. The ML metrics come from synthetic data the generator was designed to separate.
4. **The test suite passes partly because tests turn security off** (`app.config["TESTING"]=True` skips CSRF, rate limiting, the replay window and the webview token), and one test asserts that the default password `noodles` works.

None of this is unusual for a research prototype, and all of it is fixable. Sections 1–4 list the findings, section 5 is the fix plan, and section 6 covers feature improvements.

---

## 1. Test-suite results

Environment: Windows 11, Python 3.11.9, clean venv from `src/requirements.txt` (Flask 3.1.3, SQLAlchemy 2.1.8, scikit-learn 1.9.1, NumPy 2.4.6, ReportLab 5.1.0). Run on a scratch copy of the repo.

```
python -m pytest tests -q
69 passed, 9 warnings in 43.41s
```

**All 69 tests pass**, but passing doesn't mean the system is secure or correct:

| Observation | Why it matters |
|---|---|
| `InconsistentVersionWarning`: `rf_model.pkl` was pickled with scikit-learn 1.9.0 and loaded with 1.9.1 | Unpinned dependency; pickles aren't guaranteed across versions. Pin sklearn, or move to skops/ONNX. |
| `SAWarning`: column-level `distinct()` in `analytics.py:366` (also `app.py:728, 892`) | Will break in a future SQLAlchemy; use `select(...).distinct()`. |
| The suite **rewrites `src/model/training_metrics.json`** in the source tree | Tests mutate shipped artifacts; they must write to a temp dir. |
| `tests/test_aegis.db` persists between runs | Non-hermetic tests. |
| API tests set `TESTING=True`, which disables CSRF, the limiter, the webview token and the replay window | 13 of the bugs below pass the suite unnoticed. |
| README/badges claim 46, 60 and 65 tests | The actual count is 69. |

---

## 2. Findings — security (ranked)

| # | Sev | Status | Finding | Where |
|---|---|---|---|---|
| S1 | CRITICAL | ✅ | **Unauthenticated remote relay trip / DoS.** `/api/telemetry` has no auth, is CSRF- and rate-limit-exempt, and quarantines any device on a single bad signature (`is_quarantine = not sig_valid or …`). It also queues a signed `ISOLATE` to the hardware. The Debian service binds `0.0.0.0:5000` as **root**, so anyone on the network can trip every relay with 4 HTTP requests. | `app.py:300-431`, `app.py:1926`, `debian/aegis-ics.service` |
| S2 | CRITICAL | ✅ | **HMAC keys hard-coded in the public repo** (`security.py:30-35` and in firmware `#define PRE_SHARED_HMAC_KEY`). Any unknown device ID falls back to the shared key `aegis_shared_default_secret_key_v2`, so an attacker can forge telemetry for real nodes and register rogue ones. | `security.py:37-42`, `esp32_slave_sensor.ino:28-52` |
| S3 | CRITICAL | 🔍 | **Firmware never verifies command signatures.** `process_incoming_command()` acts on `ISOLATE`/`REARM`/`SHUTDOWN` from any frame on the RS-485 bus or USB. The host's command signing protects nothing. The master bridge comment says "Forward verified frame", but no verification happens. | `esp32_slave_sensor.ino:216-275`, `esp32_master_bridge.ino:200-206` |
| S4 | CRITICAL | ✅ | **Default credentials `admin/noodles` and `noodles/noodles`**, created at every start when `ADMIN_PASSWORD` is unset. The README (V3) claims `secrets.token_urlsafe(16)` replaced the static password; the code doesn't do that. A test asserts the default login works. | `database.py:359-375`, `tests/test_full_suite.py:1755` |
| S5 | HIGH | ✅ | **Replay attacks.** Firmware frames carry no timestamp, nonce or counter, and the server only checks skew *if* a timestamp is present. A captured frame can be replayed indefinitely, e.g. to mask a real fault with "normal" readings. | `app.py:301-316`, firmware telemetry block |
| S6 | HIGH | 🔍 | **The gateway signs unsigned frames itself.** If a bus frame has no `signature`, `serial_gateway` signs it on the host before posting. An attacker on the bus just omits the signature and gets a valid one. Unsigned CSV and key:value lines are accepted the same way. | `serial_gateway.py:640-645` |
| S7 | HIGH | ✅ | **Stored XSS from an unauthenticated user.** A failed-login username is written raw into `AuditLog.details`, and the dashboard renders `log.details` with `innerHTML`. Telemetry `device_id` (unauthenticated, not escaped) also reaches `innerHTML` in device cards. Session cookies are HttpOnly, but script can still call every API, including isolate/rejoin/rules. | `app.py:510-515`, `dashboard.html:1561, 2154` |
| S8 | HIGH | ✅ | **Reconnecting the COM port clears all quarantines** (`connect_com_port` sets `is_isolated=False` on all 4 nodes) with no `MANUAL_REJOIN` audit entry and no REARM review. That bypasses the quarantine workflow. | `app.py:833-840` |
| S9 | HIGH | 🔍 | **No authorization model.** Every logged-in user can change safety limits, rejoin quarantined nodes, retrain the model, and run attacks. The "privilege escalation blocked" event exists only as simulated text. | all `/api/*` routes |
| S10 | HIGH | 🔍 | **Model poisoning via `/api/model/retrain`.** Labels are the system's own past `is_anomaly` outputs (self-training). Real samples are up-weighted up to 10×, the retrain runs inside the HTTP request, and it overwrites `rf_model.pkl` *and* the `.sha256` sidecar. Because the hash sits next to the pickle, the "integrity check" can't stop tampering: anyone who can write one can write both. `pickle.load` of that file is code execution. | `train_model.py:553-660`, `app.py:171-194` |
| S11 | MEDIUM | 🔍 | `/api/report/save_dialog?native=1` opens a Tk dialog **on the server** even in web/headless mode (blocks a worker thread; on a service it fails or hangs). The V7 fix only covers the default path. | `app.py:1455-1520` |
| S12 | MEDIUM | 🔍 | `require_webview_token` returns early whenever a session exists, so in desktop mode the token adds nothing on top of the login. Desktop mode also disables all default rate limits. | `security.py:111-137`, `app.py:73-78` |
| S13 | MEDIUM | 🔍 | Audit integrity: the client IP is taken from the spoofable `X-Forwarded-For`. The audit table isn't append-only or hash-chained, so anyone with DB access can edit history undetected. | `app.py:488`, `database.py` |
| S14 | LOW | 🔍 | The desktop updater calls `api.github.com` at startup, which contradicts the "100% air-gapped" claim. `find_free_port` sets `SO_REUSEADDR` after `bind` (no effect). `-h` means both `--help` and `--host`. | `main.py`, `security.py:58-62` |

## 3. Findings — functional / correctness bugs

| # | Sev | Status | Finding | Where |
|---|---|---|---|---|
| F1 | CRITICAL | ✅ | **Multi-node gateway self-quarantines.** `/api/com_ports/connect` starts the gateway with `hmac_key=get_device_key("ESP32_001")`. The V8 "fix" then makes that key override the per-device key for every unsigned frame. Frames from ESP32_002/003/004 fail verification and those nodes are isolated on their first packet, including in the built-in MOCK simulator. | `app.py:823-826`, `serial_gateway.py:643` |
| F2 | CRITICAL | 🔍 | **Setpoints never reach the hardware.** The host sends `{"command":"setpoint","target":"set_temp","value":…}`. The firmware matches only `"SETPOINT"` (uppercase) and reads `temperature`/`pressure` keys. Even when matched, the firmware branch only *validates* and never actuates anything. | `app.py:593-605`, `esp32_slave_sensor.ino:254-273` |
| F3 | HIGH | ✅ | **Commands queue silently while no gateway runs.** `/api/setpoint` returns `success:true` with no gateway connected. The command waits in `_command_queue` and is written to the bus whenever a port is next connected, possibly hours later. Stale setpoints, ISOLATEs and SHUTDOWNs replay on reconnect. Commands have no expiry, sequence number or ACK. | `serial_gateway.py:122-130, 566-573` |
| F4 | HIGH | 🔍 | **Two gateway threads can run at once.** `stop_gateway()` sets the event, sleeps 0.2 s, then the new thread *clears* the same event. The old thread, blocked in `readline(timeout=1)`, never sees the stop and keeps running, so two readers fight over the port and duplicate posts. Use one stop event per thread, plus `join()`. | `app.py:816-830`, `serial_gateway.py:50, 529` |
| F5 | HIGH | 🔍 | **RS-485 bus collisions.** Every slave transmits on its own timer on a half-duplex multi-drop bus with no polling, token or addressing scheme. With 4 nodes, frames will collide and garble. It needs master polling (Modbus-style request/response) or TDMA slots. | firmware loops |
| F6 | HIGH | ✅ | **NSPN can't tell a temperature setpoint from a pressure setpoint.** The 6th input is the raw value regardless of `cmd_type`, so "set_pressure 7.5 bar" looks identical to "set_temp 7.5 °C". The network's decision for pressure commands is effectively random relative to physics, and only the hard-coded 45 °C / 6 bar invariants save it. Add a one-hot command-type feature or train two models. | `neural_policy.py:237`, `train_model.py:178-210` |
| F7 | HIGH | 🔍 | **Firmware sends fake data when sensors are disconnected.** If the ADC reading is ≤ 50 (floating pin or broken sensor), it signs and sends `BASE_TEMP + random(...)` as if it were real. A failed sensor looks healthy. That's the opposite of fail-safe. | `esp32_slave_sensor.ino:310-314` |
| F8 | MEDIUM | ✅ | **ISO-8601 timestamps crash ingestion.** The replay check explicitly parses ISO strings, but `verify_signature` then calls `float(v)` on the same string (ValueError outside any try), and the TelemetryLog `timestamp` Float column would receive a string. | `app.py:142-153, 302-316` |
| F9 | MEDIUM | ✅ | **Audit timestamps are shifted by the local UTC offset.** `datetime.now(timezone.utc)` is stored, SQLite returns it naive, and `.timestamp()` interprets it as local time. In India (+5:30), every `timestamp_epoch` is off by 19,800 s. | `app.py:1313, 1835`, `database.py:273` |
| F10 | MEDIUM | ✅ | `/api/audit/logs?limit=abc` → unhandled 500 (`int()` outside the try). A negative limit becomes "no limit". | `app.py:1250` |
| F11 | MEDIUM | 🔍 | **SSE drops rows.** `last_seen_ts` uses device-supplied timestamps with a strict `>`. Frames that arrive late (allowed up to 60 s skew) or share the same timestamp beyond the 20-row page are never streamed. Each SSE client also holds a thread and a DB session forever on the Werkzeug dev server. | `app.py:1868-1919` |
| F12 | MEDIUM | 🔍 | Safety enforcer "freshness" uses the latest row for the device, including `is_simulated` rows and quarantine-period rows. The simulator can therefore satisfy or break the freshness gate. Zero readings are replaced by defaults (`temp or 25.0`, `pres or 3.0`), so a genuine 0 bar reads as 3 bar. | `safety_enforcer.py:70-83`, `neural_policy.py:230-234` |
| F13 | MEDIUM | 🔍 | The emergency `SHUTDOWN ALL` only marks devices that already have a `DeviceState` row. Retrain writes into `_MEIPASS` in the frozen exe, which is a temp folder, so calibration is lost on restart. | `app.py:1052-1055`, `train_model.py:563-565` |
| F14 | LOW | ✅ | `/api/device/ping` always returns `latency_ms: 14.2` and "Ping echo successful". The firmware doesn't implement `ping`. | `app.py:1117-1144` |
| F15 | LOW | 🔍 | Other functional nits: `predict_anomaly` ignores humidity. `get_device_locations()` returns hard-coded simulator coordinates labelled "real GPS". The financial "active attack" state comes from the simulator dictionary. | various |

## 4. Findings — research / documentation integrity

These matter a lot if this goes into a paper or a viva.

| # | Finding |
|---|---|
| R1 | **The `/api/simulate-attack` audit entries are indistinguishable from real ones.** `SECURITY_VIOLATION_STUXNET_BLOCKED` and `…AUTO_ISOLATION` are written to the real audit log by a button press, describing blocks that never happened. These entries then flow into the NIST PDF report and the financial model. |
| R2 | **`init_db()` seeds six fabricated audit records** ("KEYRING_VALIDATED", "Cartesian coordinates verified", …) for checks the code never performs. |
| R3 | **The ML metrics come from data that was generated to be separable.** RF AUC 0.9755 and NSPN 96 % are measured on synthetic clusters whose means are hand-placed far apart, with noise added afterwards to bring the score below 1.0 (v2.5.0 reported 1.0000). That's fine as a sanity check, but it isn't evidence of real-world detection. You need real or public ICS datasets (SWaT, WADI, HAI, BATADAL) for the claims in the paper. |
| R4 | **The "12.74 ms / 13.72 ms closed-loop trip" claim isn't supported by the architecture.** The path is HTTP → SQLite commit → Python queue → gateway loop. The queue is drained only between `readline(timeout=1s)` calls, then goes over UART, the bridge and RS-485. Worst case is about 1 s plus the bus time. Measure it with a logic analyser on GPIO 25 before publishing. |
| R5 | Inconsistent numbers: README badge 65/65, test section 60 passed, release notes 46/46 and 39/39, actual test count 69. Version 2.5.2 in code vs 2.5.3 in the folder. NSPN accuracy listed as 96.08 % and 96.46 % in different places. |
| R6 | The README security table (V1–V9) states fixes that aren't in the code (V3), or that are incomplete (V7, V8 — V8 actually caused F1). |

---

## 5. How to make it actually work — prioritized fix plan

> The detailed, phased version of this plan (target layout, file migration map, timeline, exit criteria) is [`RESTRUCTURE_PLAN.md`](../08-roadmap/RESTRUCTURE_PLAN.md).

**Phase 1 — stop the bleeding (1–2 days)**
1. Remove `DEFAULT_DEVICE_KEYS` and the default-key fallback. Load per-device keys from env or a key file and refuse to start if one is missing. Reject unknown `device_id`s (allow-list in a `devices` table).
2. Require `ADMIN_PASSWORD` (or generate one, print it once, force a change on first login). Delete the `noodles` user.
3. Fix F1: pass `hmac_key=None` from `/api/com_ports/connect`, and stop the gateway signing unsigned frames. Unsigned means rejected (S6).
4. Escape everything rendered with `innerHTML` (one `escapeHtml()` helper, or use `textContent`) and `bleach.clean` the username before logging (S7).
5. Bind to `127.0.0.1` by default, run the service as a dedicated non-root user, and put TLS in front (Caddy/nginx) if remote access is needed.
6. Don't auto-quarantine on a single bad signature from an unauthenticated source. Count failures per device over a window, and require the request to arrive from the gateway (shared secret header or a Unix socket).

**Phase 2 — make the hardware loop real (1 week)**
7. Firmware: verify HMAC on every command, and add a monotonic `seq` counter plus a timestamp or boot nonce to telemetry and commands. Reject replays on both sides.
8. Define one command schema (`{"cmd":"SETPOINT","device_id":…,"param":"temp","value":…,"seq":…,"sig":…}`), implement real actuation in the firmware, and send an ACK frame back. Show "applied" only after the ACK arrives.
9. Give commands a TTL. Drop queued commands older than N seconds, and return an error when no gateway is connected (F3).
10. Make the RS-485 master poll each slave in turn (or adopt Modbus RTU) to remove collisions (F5).
11. Firmware fail-safe: if a sensor reads out of range or floats, send `null` plus a `sensor_fault` flag instead of random baseline values (F7).
12. Run the gateway in its own process (or at least one stop event per thread with `join()`), and post through a local queue instead of HTTP to itself (F4).

**Phase 3 — make the research claims defensible (2–4 weeks)**
13. Store simulated events in a separate table, or tag them `is_simulated` in the audit log too, and exclude them from reports. Remove the seeded fake audit rows (R1, R2).
14. NSPN: add command type as an input (or train one model per command), train against a physics model of the process, and evaluate on held-out *scenarios*, not random splits (F6).
15. Evaluate the RF on a public ICS dataset. Report precision/recall per attack type and detection delay.
16. Measure end-to-end trip latency on real hardware and publish the distribution (R4).
17. Make the tests run with security *on*: delete the `TESTING` bypasses in `csrf_protect`, `require_webview_token` and the replay check, and use fixtures that send CSRF tokens and signed frames instead. Add the reproduction cases from this report as regression tests.

---

## 6. Feature improvements (after the fixes)

- **RBAC:** viewer / operator / engineer / admin roles. Changing safety limits, rejoining nodes and retraining require engineer plus a second approver (two-person rule, IEC 62443 SL-2).
- **Tamper-evident audit log:** hash-chain each record (`hash = H(prev_hash || record)`), export it periodically to WORM storage, and use UTC-aware columns.
- **Proper persistence:** Alembic is already present, so use it. Consider TimescaleDB/InfluxDB for telemetry, and add retention plus downsampling.
- **Model lifecycle:** sign models with an offline key (ed25519) instead of a sidecar SHA, use a shadow-model evaluation before promotion, roll back on drift, and use `skops` or ONNX instead of pickle.
- **Detection quality:** per-device baselines (each node has a different normal range), temporal models (rolling windows / LSTM / isolation forest on residuals), and physics residuals (expected vs measured).
- **Protocol support:** Modbus TCP/RTU and OPC UA adapters so it can sit in front of real PLCs, not only the custom JSON.
- **Ops:** run under Gunicorn/Waitress instead of the Werkzeug dev server; add health metrics (Prometheus), structured logging and a watchdog on the gateway.
- **Dashboard:** show "simulated" banners clearly; show command ACK state; separate the red-team console behind its own role.
- **Code hygiene:** the files have odd tokenized spacing (`db .close ()`) from a formatter or obfuscator. Run `black`/`ruff` over the codebase, split `app.py` (1,967 lines) into blueprints (`telemetry`, `control`, `audit`, `reports`, `gateway`), and dedupe the copy-pasted device-listing logic between `/api/devices` and `/api/cluster/topology`.

---

## Appendix A — Reproduction script output

Script: a standalone harness (kept outside the repo) that imports `src/app.py` with `DATABASE_URL` pointed at a temp DB and `TESTING=False`, and drives it with Flask's test client. It can be added to `tests/security/` as part of restructure plan task 0.5.

| Case | Finding | Observed result |
|---|---|---|
| R1 | S1 | Unauthenticated POST with `"signature":"00"` for ESP32_002 → **HTTP 200 "Telemetry ingested successfully"**, device isolated = **true**, **1 ISOLATE command queued** for the relay |
| R2 | S2 | Frame for ESP32_003 signed with the key copied from `security.py` → **200**. Frame for unknown `ROGUE_PLC_99` signed with the default fallback key → **200** |
| R3 | S5 | Same signed frame (no timestamp) posted three times → **[200, 200, 200]** |
| R4 | F8 | Frame with ISO-8601 timestamp → **500** (ValueError in `verify_signature`) |
| R5 | F1 | One normal frame per node, signed the way `/api/com_ports/connect` configures the gateway → ESP32_001 ok; **ESP32_002, 003, 004 all isolated** |
| R6 | S4, S7 | `admin` / `noodles` login → **success**. Failed login with username `<img src=x onerror=alert(document.cookie)>` → payload returned **verbatim** in `/api/audit/logs` `details` (rendered via `innerHTML`) |
| R7 | F9 | `timestamp_epoch − now` for a just-written audit row = **−19800 s** (exactly the IST +5:30 offset) |
| R8 | F10 | `/api/audit/logs?limit=abc` → **500**, unhandled `ValueError` |
| R9 | F3, F2 | `/api/setpoint` with **no gateway connected** → **200 "Successfully updated setpoint"**; 5 commands waiting in the queue. Command sent: `{"command":"setpoint","target":"set_temp","value":30.0,…}` (the firmware expects `SETPOINT` + `temperature`) |
| R10 | F14 | `/api/device/ping` → `latency_ms: 14.2`, "Ping echo successful" with no device attached |
| R11 | F6 | State T=44 °C, P=5.9 bar: P(safe) for **set_temp 7.5 °C = 0.0591** and for **set_pressure 7.5 bar = 0.0591**, identical. A harmless 7.5 °C temperature setpoint is **blocked** because the network reads it as a 7.5 bar pressure command |
| R12 | R1 | `/api/simulate-attack {"type":"stuxnet"}` → newest real audit row is `SECURITY_VIOLATION_STUXNET_BLOCKED` |
| R13 | S8 | ESP32_002 isolated, then `/api/com_ports/connect {"port":"MOCK"}` → isolated = **false** (silently un-quarantined) |
| R14 | S10 | `rf_model.pkl.sha256` sits next to the pickle in `src/model/` (same write permissions) |

Not executed (would need hardware or would open a dialog on this machine): S3, S6, S11, F4, F5, F7, and the trip-latency claim (§4 R4). These are verified by reading the code; the reasoning is in the tables above.
