# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · Versioning: [SemVer](https://semver.org/).
The version number lives in exactly one place: `src/version.py`.

## [Unreleased] — 2.6.0

### Security (restructure plan Phase 1; finding IDs refer to docs/07-reports/DEBUG_REPORT.md)
- **S1** `/api/telemetry` requires the `X-Aegis-Gateway-Token` header. One invalid signature no longer quarantines a node: it takes 3 within 60 s (`AEGIS_SIG_FAILURE_*`). Frames with invalid signatures are no longer stored.
- **S2** Removed all hard-coded HMAC keys (Python and firmware) and the shared fallback key. Keys come from `DEVICE_KEY_<ID>` or `device_keys.json` (`python src/device_keys.py generate ...`); firmware includes a git-ignored `aegis_secrets.h`. Unprovisioned devices are rejected (403).
- **S4** No default password. `admin` uses `ADMIN_PASSWORD` (≥ 12 chars) or a generated password printed once and saved to `initial_admin_password.txt`. On upgrade, an `admin` still on the legacy default is rotated, and the legacy `noodles` account is deleted if it still uses its default.
- **S5** Interim replay defence: identical signed frames within 300 s are rejected (409).
- **S6 / F1** The gateway no longer signs frames on behalf of devices, and no longer forces ESP32_001's key on every node. The simulator signs each node with its own key. `--allow-unsigned` exists for bench testing only.
- **S7** Dashboard escapes all server data (`escapeHtml`; no inline handlers built from data). Login usernames are sanitised before auditing, device ids must match `[A-Za-z0-9_-]{1,50}`, and CSP, `X-Frame-Options`, `X-Content-Type-Options` and `Referrer-Policy` headers are set.
- **S8** Connecting a COM port keeps quarantine and re-sends `ISOLATE` to isolated nodes.
- **S11** `?native=1` no longer opens a Tk dialog on the server in web/headless mode.
- **S13 (partial)** Audit client IP no longer taken from `X-Forwarded-For`; session regenerated on login.
- Debian: service runs as the unprivileged `aegis` user (in `dialout`) on `127.0.0.1`, with systemd sandboxing; secrets go in `/etc/default/aegis-ics` (mode 0640).

### Fixed
- **F3** Setpoints return 503 when no gateway is connected; queued commands expire after 5 s (`AEGIS_COMMAND_TTL_S`) instead of replaying on the next connection.
- **F4** Each gateway run has its own stop event, so a restarted gateway can't revive the old thread.
- **F8** ISO-8601 telemetry timestamps are accepted and stored as epoch seconds.
- **F9** Audit `timestamp_epoch` is correct UTC (was shifted by the server's UTC offset).
- **F10** Invalid `limit` on `/api/audit/logs` no longer causes a 500.
- **F13** `SHUTDOWN ALL` isolates every known and provisioned node.
- **F14** `/api/device/ping` no longer reports a fabricated 14.2 ms round trip.
- SQLAlchemy `distinct()` deprecation warnings.

### Changed
- **R1** Red-team drills write `SIMULATED_*` audit rows flagged `is_simulated` (new column, Alembic `b7d2e4a91c05`), no longer change device state, and are excluded from PDF reports. Simulator telemetry is flagged `is_simulated`.
- **R2** Startup no longer seeds fabricated audit records; it writes one real `SYSTEM_STARTUP` entry.
- Tests run with all security controls on (`TESTING` only disables rate limiting). New regression suite `tests/security/test_debug_findings.py`; `tests/conftest.py` makes runs hermetic.
- `.env.example` rewritten to list only variables the code reads.

### Added
- `docs/` restructured into a full documentation tree (architecture, protocols, API, security model, runbook, ADRs, debug report, restructure plan).
- `src/version.py` as the single version source; build scripts and the Debian control file are stamped from it.
- `pyproject.toml` with project metadata, dependency pins and `desktop` / `ml` / `dev` extras; ruff and pytest configuration.
- `CHANGELOG.md`.

### Removed
- Unused dependencies `paho-mqtt` and `pandas`.

## [2.5.3-baseline] — 2026-11-13
Snapshot of the project before the restructure (git tag `v2.5.3-baseline`).
