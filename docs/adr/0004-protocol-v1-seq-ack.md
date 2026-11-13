# 0004. Protocol v1: sequence numbers, ACKs and verified commands

- **Status:** Proposed
- **Date:** 2026-11-13

## Context
Protocol v0 frames carry no freshness data (replayable), commands aren't verified by firmware, there are no acknowledgements, and three hand-written canonicalisers have drifted (debug report S3, S5, F2).

## Decision
Define protocol v1 in JSON Schema under `src/aegis_ics/protocol/schema/`:
- every frame has `v:1`, `id`, `seq` (uint32, per sender, monotonic), `boot` (random per boot), `sig`;
- commands: `{"v":1,"type":"CMD","id":<target>,"seq":…,"cmd":"SETPOINT|ISOLATE|REARM|SHUTDOWN|PING|DISCOVER","args":{…},"ttl_ms":…,"sig":…}`;
- devices reply `{"v":1,"type":"ACK","id":…,"ack_seq":…,"result":"OK|REJECTED|EXPIRED","reason":…,"sig":…}`;
- receivers keep a sliding window of accepted `(boot, seq)` and reject duplicates or old values;
- canonicalisation rules and test vectors live in one place; `protocol.h` is generated from them.

## Consequences
Firmware must be reflashed (`legacy_protocol` flag accepts v0 for one release). Enables reliable command lifecycles and replay protection.
