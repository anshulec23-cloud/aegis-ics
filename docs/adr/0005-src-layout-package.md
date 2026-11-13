# 0005. Installable `aegis_ics` package with src layout and app factory

- **Status:** Proposed
- **Date:** 2026-11-13

## Context
`src/*.py` are loose modules imported via `sys.path` hacks (tests insert `src/` on the path; some modules try `from src.x import`). Importing `app` initialises the DB, loads models and creates secrets. `app.py` is 1,967 lines.

## Decision
Create a PEP 621 package `aegis_ics` in `src/aegis_ics/`, with layers `domain → services → web/gateway/desktop`, `persistence` behind repositories, and `create_app(settings)` as the only way to build the Flask app. Dependencies flow inward only (domain imports nothing from Flask or SQLAlchemy).

## Consequences
Enables `pip install -e .[dev]`, isolated tests, type checking per layer and a clean PyInstaller entry point (`python -m aegis_ics`). Migration is done slice by slice per [RESTRUCTURE_PLAN Phase 3](../08-roadmap/RESTRUCTURE_PLAN.md).
