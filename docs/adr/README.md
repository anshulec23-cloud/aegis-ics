# Architecture Decision Records

Short documents recording **why** a significant technical decision was made. Format: [Michael Nygard's template](0000-template.md). Number them sequentially and never edit an accepted ADR; supersede it with a new one.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-single-process-flask-monolith.md) | Single-process Flask monolith with in-process gateway thread | Accepted (retroactive) |
| [0003](0003-in-process-ingestion-no-loopback-http.md) | Hand telemetry to the ingest service in-process instead of loopback HTTP | Proposed |
| [0004](0004-protocol-v1-seq-ack.md) | Protocol v1: sequence numbers, ACKs and verified commands | Proposed |
| [0005](0005-src-layout-package.md) | Installable `aegis_ics` package with src layout and app factory | Proposed |
| [0006](0006-zero-touch-enrollment.md) | Zero-touch device enrollment with one-click approval | Accepted |
