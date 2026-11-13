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
| B1/B2 | HMAC-SHA256 telemetry signature per device | firmware, `app.verify_signature` |
| B1/B2 | Host-signed commands | `serial_gateway.send_command` (not verified by firmware) |
| B3 | Optional ±60 s timestamp window | `process_telemetry` |
| B4 | Password login, Werkzeug hashes | `app.login` |
| B4 | Session cookie: HttpOnly, SameSite=Strict, Secure if `FLASK_SESSION_SECURE`, 30 min | `app.py` config |
| B4 | CSRF token on mutating requests | `csrf_protect` |
| B4 | Rate limiting (memory store) | Flask-Limiter |
| B4 | Input validation on setpoints and rules (type, NaN/inf, inverted ranges) | `setpoint`, `update_rules`, `validate_command` |
| B4 | `bleach.clean` on device IDs in control routes | `app.py` |
| B5 | Model SHA-256 sidecar; `allow_pickle=False` / `weights_only=True` for NSPN | `LocalRFModel.reload`, `neural_policy.py` |
| B5 | Session key file created with mode 0600 | `_load_or_generate_session_token` |
| Desktop | Random localhost port, webview token, debugger check | `main.py`, `security.py` |

## 4. Gaps (verified, see [DEBUG_REPORT §2](../07-reports/DEBUG_REPORT.md))
| ID | Gap | Boundary |
|---|---|---|
| S1 | Unauthenticated ingestion endpoint can quarantine nodes and trip relays | B3/B4 |
| S2 | Device keys in source; shared fallback key | B1 |
| S3 | Firmware ignores command signatures | B1 |
| S4 | Default operator passwords | B4 |
| S5 | No replay protection for firmware frames | B1 |
| S6 | Gateway signs unsigned frames | B2 |
| S7 | Stored XSS in the dashboard | B4 |
| S8 | COM reconnect clears quarantine | B4 |
| S9 | No RBAC | B4 |
| S10 | Model poisoning; sidecar hash isn't an integrity control | B5 |
| S13 | Mutable audit log, spoofable client IP | B5/B4 |

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
