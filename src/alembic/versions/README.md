# Alembic Database Migrations — Revision History

This directory stores historical schema migrations for the **Aegis ICS** SQLite database (`aegis_v2.db`).

---

## Migration Revisions

| Revision ID | Description | Changes Applied |
|---|---|---|
| `89c877d9e697` | Initial Schema | Creates base tables: `users`, `audit_logs`, `telemetry_logs`, and `rules`. |
| `f1a4571c083c` | Add Device States | Adds `device_states` table for tracking device quarantine and microsegmentation flags (`is_isolated`, `updated_at`). |
