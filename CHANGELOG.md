# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · Versioning: [SemVer](https://semver.org/).
The version number lives in exactly one place: `src/version.py`.

## [Unreleased] — 2.6.0

### Added
- `docs/` restructured into a full documentation tree (architecture, protocols, API, security model, runbook, ADRs, debug report, restructure plan).
- `src/version.py` as the single version source; build scripts and the Debian control file are stamped from it.
- `pyproject.toml` with project metadata, dependency pins and `desktop` / `ml` / `dev` extras; ruff and pytest configuration.
- `CHANGELOG.md`.

### Removed
- Unused dependencies `paho-mqtt` and `pandas`.

## [2.5.3-baseline] — 2026-11-13
Snapshot of the project before the restructure (git tag `v2.5.3-baseline`).
