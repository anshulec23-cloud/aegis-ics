# 0003. Hand telemetry to the ingest service in-process instead of loopback HTTP

- **Status:** Proposed
- **Date:** 2026-11-13

## Context
`serial_gateway` calls `requests.post("http://127.0.0.1:PORT/api/telemetry")` from inside the same process. To make that work, the endpoint is unauthenticated, CSRF-exempt and rate-limit-exempt. Any network client can therefore inject frames and trigger quarantines (debug report S1). It also adds avoidable latency and a dependency on `FLASK_PORT`.

## Decision
`GatewayWorker` calls `IngestService.ingest(frame)` directly. `/api/telemetry` remains only for **external** gateways. It's disabled by default, and when enabled it requires an API key (header) or mTLS and is rate limited.

## Consequences
- Removes the largest attack surface.
- The ingest logic must be free of Flask request context (it moves into `services/ingest.py`).
- Tests can ingest frames without HTTP.
