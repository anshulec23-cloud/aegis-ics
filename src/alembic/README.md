# Aegis ICS — Database Migration Framework (Alembic)

This directory contains the database migration environment for **Aegis ICS**, powered by [Alembic](https://alembic.sqlalchemy.org/).

---

## Directory Structure

* `env.py`: Python script run whenever Alembic is invoked; connects to SQLAlchemy models in `database.py`.
* `script.py.mako`: Template file for generating new database migration revisions.
* [`versions/`](versions): Directory containing chronological migration version scripts.

---

## Usage

```powershell
# Create a new revision
alembic revision -m "description_of_change"

# Upgrade database to latest revision
alembic upgrade head

# Downgrade database by one revision
alembic downgrade -1
```
