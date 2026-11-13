# Contributing and engineering standards

## Workflow
1. Branch from `main`: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`, `refactor/<topic>`.
2. Use small, reviewable PRs (< 400 changed lines where possible). Each PR has a description, linked issue and test evidence.
3. Write [Conventional Commits](https://www.conventionalcommits.org/) messages (`fix(gateway): use per-device HMAC key`).
4. CI must be green: lint, type-check, tests and security scan.
5. Significant design changes get an ADR in [`docs/adr/`](../adr/).

## Code style
- Python: `ruff format` (Black-compatible, line length 100) and `ruff check` (rules E, F, I, B, UP, S, SIM). No `print` in library code; use `logging.getLogger(__name__)`.
- Type hints on all public functions; `mypy` on `core/`, `services/` and `protocol/`.
- No module-level side effects (DB init, model loading, thread start) at import time. Do these in the app factory or startup hooks.
- DB access goes through `with session_scope() as s:` or a repository; never open a session manually without a context manager.
- Configuration comes from one `Settings` object; no scattered `os.environ.get`.
- Security-relevant constants (limits, thresholds) live in one module and are referenced, not copied.
- Firmware: `clang-format` (Google style), no `String` in hot paths, protocol constants from the generated `protocol.h`.

## Definition of done
- [ ] Tests added or updated (unit + regression for bug fixes)
- [ ] Docs updated (this `docs/` tree, API reference if routes changed)
- [ ] No new default secrets or hard-coded keys
- [ ] `CHANGELOG.md` entry under *Unreleased*
- [ ] For safety-relevant changes: a note in the safety case or the debug report

## Versioning
Semantic Versioning, with a **single source of truth** for the version (`aegis_ics/__init__.py:__version__`, read by packaging, `/api/version`, firmware build flags and docs). Today the version is duplicated in more than eight places and they disagree (2.5.2 vs 2.5.3).
