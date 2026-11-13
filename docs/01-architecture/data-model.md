# Data model

Source of truth: `src/database.py`. Engine: SQLite (SQLAlchemy 2.x), opened with `check_same_thread=False`, `timeout=15`, and per-connection pragmas `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`.

## Database location

Resolved by `get_database_url()` in this order:

1. `DATABASE_URL` env var (any SQLAlchemy URL; tests use this).
2. `AEGIS_DATA_DIR/aegis_v2.db`. If missing and running frozen, it's copied from the bundled DB.
3. Frozen executable: next to the exe if writable, else `/var/lib/aegis-ics` (root), `$XDG_DATA_HOME/aegis-ics` (Linux user) or `%LOCALAPPDATA%\AegisICS` (Windows).
4. Dev: `<repo root>/aegis_v2.db`.

## Tables

### `users`
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| username | VARCHAR(50) UNIQUE NOT NULL | |
| password_hash | VARCHAR(255) NOT NULL | Werkzeug `generate_password_hash` (scrypt/pbkdf2 depending on version) |

Bootstrapped by `database._bootstrap_accounts()` (see `src/bootstrap.py`). `admin` is created with `ADMIN_PASSWORD`, or with a generated password written to `initial_admin_password.txt`. An `admin` still using the legacy default is rotated, and a legacy `noodles` account still using its default password is deleted. ⚠️ No roles column yet (RBAC is Phase 3).

### `audit_logs`
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| timestamp | DATETIME | default `datetime.now(timezone.utc)`; SQLite returns it **naive** |
| user_id | INTEGER FK → users.id, NULL | NULL = system action |
| action | VARCHAR(100) NOT NULL | free-form verb, e.g. `LOGIN_SUCCESS`, `AUTO_ISOLATION`, `CHANGE_SETPOINT` |
| location | VARCHAR(100) NOT NULL | operator "station coordinates" string from the login form |
| details | VARCHAR(255) | human-readable message; user-controlled parts are `bleach`-escaped, and the dashboard escapes again on render |
| is_simulated | BOOLEAN NOT NULL DEFAULT 0 | true for red-team drill entries (`SIMULATED_*`); excluded from PDF reports (added in v2.6, Alembic `b7d2e4a91c05`) |

Severity and NIST control are **derived at read time** from substrings of `action` (`app.py` `determine_severity`, `map_nist_control`).

Actions emitted by the code: `LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGOUT`, `CHANGE_SETPOINT`, `STALE_TELEMETRY_BLOCKED`, `SECURITY_VIOLATION_BLOCKED`, `AUTO_ISOLATION`, `MANUAL_ISOLATION`, `MANUAL_REJOIN`, `EMERGENCY_SHUTDOWN`, `DEVICE_PING_SENT`, `DEVICE_ALARMS_CLEARED`, `CONNECT_COM_PORT`, `DISCONNECT_COM_PORT`, `UPDATE_SAFETY_RULES`, `MODEL_RETRAINED_FROM_HARDWARE`, `ATTACK_SIMULATION_INJECTED`, `ATTACK_SIMULATION_RESET`. Also: `SETPOINT_NOT_DELIVERED` (no gateway), `SYSTEM_STARTUP` (every start, with version), `ACCOUNT_BOOTSTRAP`. Simulation-only (`is_simulated = true`): `SIMULATED_STUXNET_BLOCKED`, `SIMULATED_INJECTION_DETECTED`, `SIMULATED_PRIVILEGE_BLOCKED`. Databases created before v2.6 may still contain the six fabricated seed rows (`SYSTEM_BOOT`, `KEYRING_VALIDATED`, …); new installs don't create them.

### `telemetry_logs`
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| timestamp | FLOAT NOT NULL | epoch seconds; device-supplied if present, else server time |
| device_id | VARCHAR(50) NOT NULL | not a FK; not indexed ⚠️ (every dashboard query filters/sorts on it) |
| temperature, pressure, humidity, vibration, hall_effect, current, rssi | FLOAT NULL | units: °C, bar, %RH, g RMS, RPM, A, dBm |
| is_anomaly | BOOLEAN | rule/RF anomaly; always True for frames from isolated devices. Frames with invalid signatures are no longer stored (v2.6) |
| is_simulated | BOOLEAN | True for rows written by `/api/simulate-attack` and for all telemetry ingested while the software simulator is the active gateway |

No retention policy; the table grows unbounded (about 2 rows/s per node with the 500 ms firmware interval).

### `device_states`
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| device_id | VARCHAR(50) UNIQUE NOT NULL | ESP32_001–004 seeded |
| is_isolated | BOOLEAN | quarantine flag |
| updated_at | DATETIME | |

### `rules`
| key | default | meaning |
|---|---|---|
| temp_max | 60.0 | max temperature setpoint and anomaly threshold (°C) |
| temp_min | 0.0 | min temperature |
| pressure_max | 8.0 | max pressure (bar) |
| pressure_min | 0.0 | min pressure |

Editable via `POST /api/rules/update` (min must be < max). ⚠️ No upper cap: any operator can raise `temp_max` arbitrarily, leaving only the hard-coded 45 °C / 6 bar invariants in place.

## Migrations

- Runtime: `init_db()` → `migrate_sqlite_schema()` (one hand-written table rebuild for nullable sensor columns), then `Base.metadata.create_all()`.
- `src/alembic/` holds two revisions (`89c877d9e697` initial, `f1a4571c083c` device_states) but **nothing invokes Alembic**. The restructure plan makes Alembic the only migration path.

## Recommended indexes (not present)

```sql
CREATE INDEX ix_telemetry_device_ts ON telemetry_logs(device_id, timestamp DESC);
CREATE INDEX ix_audit_ts ON audit_logs(timestamp DESC);
```
