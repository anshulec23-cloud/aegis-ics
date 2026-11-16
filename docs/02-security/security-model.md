# Security model

This page answers four questions: what we protect, what we trust, which controls exist **in code today**, and where the gaps are. The adversary catalogue is in [`threat-model.md`](threat-model.md). Note that `threat-model.md` describes *intended* defences; several are not yet true (see §4).

## 1. Assets
| Asset | Why it matters |
|---|---|
| Physical process (relays, setpoints) | Safety: wrong commands can damage equipment or hurt people |
| Telemetry integrity | Operators and models decide based on it |
| Quarantine state | Controls which nodes may operate |
| Safety rules (`rules` table) | Bound every setpoint |
| ML models | Drive anomaly flags, trust and command approval |
| Audit trail | Accountability and forensics |
| Operator credentials, session secret, device keys | Root of all authentication |

## 2. Trust boundaries
```
[Field bus: slaves ⇄ bridge]  ── B1 (RS-485, physical access) ──
[USB serial]                  ── B2 (host USB) ──
[Gateway thread → /api/telemetry over loopback HTTP]  ── B3 ──
[Browser ⇄ Flask]             ── B4 (network) ──
[Filesystem: DB, models, keys] ── B5 (host OS) ──
```

## 3. Controls implemented
| Boundary | Control | Code |
|---|---|---|
| B1/B2 | HMAC-SHA256 telemetry signature per device; keys provisioned per deployment, no fallback key; unknown devices rejected | firmware, `device_keys.py`, `app.verify_signature` |
| B1/B2 | Host-signed commands | `serial_gateway.send_command` (not verified by firmware yet) |
| B2 | Gateway forwards only device-signed frames (never signs on a device's behalf) | `serial_gateway.build_forward_payload` |
| B3 | Gateway token on `/api/telemetry`; ±60 s timestamp window; duplicate-frame (replay) cache; 3-strike signature quarantine | `app.api_telemetry`, `process_telemetry` |
| B3 | Commands expire after 5 s; nothing is queued without a connected gateway; quarantine re-sent on reconnect | `serial_gateway.pop_ready_commands`, `app._dispatch_command` |
| B4 | Password login, Werkzeug hashes; no default password (generated or ≥ 12-char `ADMIN_PASSWORD`); session regenerated on login | `app.login`, `bootstrap.py` |
| B4 | Security headers: CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy` | `app.set_security_headers` |
| B4 | Output escaping in the dashboard (`escapeHtml`), sanitised audit input, strict device-id format | `dashboard.html`, `app.py` |
| B4 | Session cookie: HttpOnly, SameSite=Strict, Secure if `FLASK_SESSION_SECURE`, 30 min | `app.py` config |
| B4 | CSRF token on mutating requests | `csrf_protect` |
| B4 | Rate limiting (memory store) | Flask-Limiter |
| B4 | Input validation on setpoints and rules (type, NaN/inf, inverted ranges) | `setpoint`, `update_rules`, `validate_command` |
| B4 | `bleach.clean` on device IDs in control routes | `app.py` |
| B5 | Model SHA-256 sidecar; `allow_pickle=False` / `weights_only=True` for NSPN | `LocalRFModel.reload`, `neural_policy.py` |
| B5 | Session key file created with mode 0600 | `_load_or_generate_session_token` |
| Desktop | Random localhost port, webview token, debugger check | `main.py`, `security.py` |

## 4. Gaps (see [DEBUG_REPORT](../07-reports/DEBUG_REPORT.md))
| ID | Gap | Boundary | Status (v2.6) |
|---|---|---|---|
| S1 | Unauthenticated ingestion endpoint could quarantine nodes and trip relays | B3/B4 | Fixed |
| S2 | Device keys in source; shared fallback key | B1 | Fixed: per-device X25519 enrollment, keys only in NVS and the registry |
| S3 | Firmware ignores command signatures | B1 | Fixed: firmware verifies HMAC + host sequence before acting (v2.6 firmware) |
| S4 | Default operator passwords | B4 | Fixed |
| S5 | No replay protection for firmware frames | B1 | Fixed for v1 (boot/seq both directions); legacy v0 keeps the duplicate-frame cache |
| S6 | Gateway signed unsigned frames | B2 | Fixed |
| S7 | Stored XSS in the dashboard | B4 | Fixed (CSP still allows inline script until Phase 3) |
| S8 | COM reconnect cleared quarantine | B4 | Fixed |
| S9 | No RBAC | B4 | **Open**, Phase 3 |
| S10 | Model poisoning; sidecar hash isn't an integrity control | B5 | **Open**, Phase 4 |
| S13 | Mutable audit log, spoofable client IP | B5/B4 | Partial: client IP fixed; hash chain in Phase 3 |
| – | Service ran as root on `0.0.0.0` | Host | Fixed: `aegis` user, loopback, systemd sandboxing |

## 5. Target security architecture (summary)
- **Device identity:** per-device keys provisioned at manufacture into ESP32 NVS (encrypted), registered in a `devices` table; no fallback key.
- **Freshness:** per-device monotonic `seq` plus boot nonce on all frames, both directions.
- **Ingestion:** in-process hand-off from the gateway (no public endpoint), or an mTLS/Unix socket if kept separate.
- **Operators:** RBAC (viewer, operator, engineer, admin), forced password set on first run, lockout/backoff, two-person approval for rules, rejoin and retrain.
- **Transport:** TLS via a reverse proxy; HSTS; strict CSP with no inline script.
- **Audit:** append-only, hash-chained, UTC-aware, simulation entries segregated.
- **Models:** signed artifacts (ed25519, offline key), non-pickle format (skops/ONNX), promotion gate.
- **Runtime:** non-root systemd service with `ProtectSystem=strict`, `NoNewPrivileges`, `DeviceAllow=/dev/ttyUSB*`.

## 6. Reporting a vulnerability
Open a private GitHub security advisory on the repository rather than a public issue.
