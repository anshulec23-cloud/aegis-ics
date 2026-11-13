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

Seeded at every start if absent: `admin` and `noodles`, both with `ADMIN_PASSWORD` (default `noodles`). ⚠️ No roles column.

### `audit_logs`
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| timestamp | DATETIME | default `datetime.now(timezone.utc)`; SQLite returns it **naive** |
| user_id | INTEGER FK → users.id, NULL | NULL = system action |
| action | VARCHAR(100) NOT NULL | free-form verb, e.g. `LOGIN_SUCCESS`, `AUTO_ISOLATION`, `CHANGE_SETPOINT` |
| location | VARCHAR(100) NOT NULL | operator "station coordinates" string from the login form |
| details | VARCHAR(255) | human-readable message (⚠️ may contain unescaped user input) |

Severity and NIST control are **derived at read time** from substrings of `action` (`app.py` `determine_severity`, `map_nist_control`).

Actions emitted by the code: `LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGOUT`, `CHANGE_SETPOINT`, `STALE_TELEMETRY_BLOCKED`, `SECURITY_VIOLATION_BLOCKED`, `AUTO_ISOLATION`, `MANUAL_ISOLATION`, `MANUAL_REJOIN`, `EMERGENCY_SHUTDOWN`, `DEVICE_PING_SENT`, `DEVICE_ALARMS_CLEARED`, `CONNECT_COM_PORT`, `DISCONNECT_COM_PORT`, `UPDATE_SAFETY_RULES`, `MODEL_RETRAINED_FROM_HARDWARE`, `ATTACK_SIMULATION_INJECTED`, `ATTACK_SIMULATION_RESET`. Simulation-only: `SECURITY_VIOLATION_STUXNET_BLOCKED`, `SECURITY_VIOLATION_AUTO_ISOLATION`, `SECURITY_VIOLATION_PRIVILEGE_BLOCKED`. Seeded at first start: `SYSTEM_BOOT`, `KEYRING_VALIDATED`, `SAFETY_INTERLOCKS_ENGAGED`, `ML_STATE_SPACE_BASELINE`, `STATION_GEOLOCATION_LOCKED`, `DATABASE_WAL_VERIFIED`.

### `telemetry_logs`
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| timestamp | FLOAT NOT NULL | epoch seconds; device-supplied if present, else server time |
| device_id | VARCHAR(50) NOT NULL | not a FK; not indexed ⚠️ (every dashboard query filters/sorts on it) |
| temperature, pressure, humidity, vibration, hall_effect, current, rssi | FLOAT NULL | units: °C, bar, %RH, g RMS, RPM, A, dBm |
| is_anomaly | BOOLEAN | `(not sig_valid) or rf/rule anomaly`; always True for frames from isolated devices |
| is_simulated | BOOLEAN | True only for rows written by `/api/simulate-attack` |

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
