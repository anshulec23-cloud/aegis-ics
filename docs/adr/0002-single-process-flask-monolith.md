# 0002. Single-process Flask monolith with in-process gateway thread

- **Status:** Accepted (retroactive, documents v2.x)
- **Date:** 2026-11-13

## Context
The system must run as a double-click desktop app on Windows and as a headless service on Debian, offline, on modest hardware, with a single developer maintaining it.

## Decision
Run everything (HTTP server, serial gateway, ML inference, PDF generation) in one Python process. Use Flask with the Werkzeug threaded server and SQLite in WAL mode. Package it with PyInstaller.

## Consequences
- **+** Trivial deployment, one artifact, no broker or DB server.
- **−** The gateway posts to its own HTTP endpoint (loopback), which forces `/api/telemetry` to be unauthenticated (see ADR 0003).
- **−** The Werkzeug dev server isn't hardened; SSE ties up one thread per client.
- **−** Module-level globals make testing and restarts fragile.

## Alternatives considered
Microservices with MQTT (paho-mqtt is in the requirements but unused): rejected at the time for complexity.
