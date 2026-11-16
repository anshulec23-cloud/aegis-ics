# Wire protocols

```
slave ESP32 ──RS-485 (115200, half-duplex, polled)── master ESP32 ──USB-CDC (115200)── host gateway thread ──in-process── ingestion
```

All framing is newline-delimited ASCII JSON. **Protocol v1** (v2.6+) is the normal protocol. **Protocol v0** (pre-shared keys compiled into firmware) is still accepted for legacy benches; see §6.

Source of truth: `src/protocol.py` (host and simulator), `src/enrollment.py` (key agreement), `firmware/esp32_slave_sensor` (device). Shared known-answer vectors: `tests/security/protocol_v1_vectors.json`. The contract is enforced by `tests/security/test_enrollment_v1.py` and `test_firmware_contract.py`.

---

## 1. Frames (v1)

Every frame carries `"v": 1` and a `type`.

| Type | Direction | Signed | Fields |
|---|---|---|---|
| `DISCOVER` | master → bus | – | `{}`: opens a discovery window |
| `POLL` | master → slave | – | `id`: "your turn to talk" |
| `HELLO` | slave → host | – | `id`, `pub` (X25519, 64 hex), `fw`, `boot`, `sensors[]`, `enrolled` |
| `WELCOME` | host → slave | ✓ (new key) | `id`, `hpub` (host X25519 public key) |
| `TEL` | slave → host | ✓ | `id`, `boot`, `seq`, sensor values, `faults[]`, `tripped`, optional `sp_t`/`sp_p` (applied setpoints) |
| `CMD` | host → slave | ✓ | `id`, `seq` (host sequence), `cmd`, `args{}` |
| `ACK` | slave → host | ✓ | `id`, `boot`, `seq`, `ack` (command seq; 0 = WELCOME), `result`, optional `reason` |

Commands: `SETPOINT {param: "temperature"|"pressure", value: "30.00"}`, `ISOLATE`, `REARM`, `SHUTDOWN`, `PING`.
ACK results: `OK`, `REJECTED` (e.g. outside the device envelope, relay tripped), `BAD_SIG`, `REPLAY`, `UNKNOWN_CMD`.

Example `TEL`:
```json
{"boot":2113870950,"current":"4.52","faults":[],"hall_effect":"0.00","id":"ESP32_C1DC7F","pressure":"4.21","seq":118,"sig":"9f…e1","sp_t":"32.00","temperature":"26.10","tripped":false,"type":"TEL","v":1,"vibration":"1.08"}
```

## 2. Canonical form and signatures

```
canonical = json.dumps(frame_without_sig, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
sig       = hex(HMAC-SHA256(key = session_key_hex_ascii, msg = canonical))
```

To make this byte-identical on the ESP32 (ArduinoJson keeps insertion order):
- real numbers are **never JSON floats**: they're strings with exactly two decimals (`"26.10"`);
- integers (`v`, `boot`, `seq`, `ack`) are plain JSON integers; booleans are `true`/`false`;
- the firmware inserts keys in sorted order;
- faulted sensors are **omitted** (and listed in `faults`), never sent as `null`.

## 3. Enrollment (ADR 0006)

```mermaid
sequenceDiagram
    participant S as Slave (new)
    participant M as Master
    participant H as Host
    participant O as Operator
    M->>S: DISCOVER (every 10 s)
    S->>M: HELLO {id, pub, sensors}  (random 0-300 ms slot)
    M->>H: HELLO
    H->>H: registry: status = pending, fingerprint
    O->>H: Approve (dashboard, Station 06)
    H->>H: key = HKDF(X25519(host_priv, dev_pub))
    H->>M: WELCOME {id, hpub, sig}
    M->>S: WELCOME
    S->>S: key = HKDF(X25519(dev_priv, hpub)); verify sig; store in NVS
    S->>M: ACK {ack: 0, result: OK, sig}
    M->>H: ACK → registry: enrollment_confirmed
    loop every poll cycle
        M->>S: POLL
        S->>M: TEL (signed)
        M->>H: TEL → ingestion
    end
```

Key derivation (`enrollment.derive_session_key`):
```
shared = X25519(own_priv, peer_pub)                             32 bytes, RFC 7748
PRK    = HMAC-SHA256(key = "aegis-ics-v1", msg = shared)
OKM    = HMAC-SHA256(key = PRK, msg = device_id | "|" | dev_pub | host_pub | 0x01)
key    = lowercase hex(OKM)                                     64 ASCII chars
```
Fingerprint = first 6 bytes of SHA-256(pub), as `XXXX-XXXX-XXXX`. It's shown on the dashboard and printed on the slave's USB console.

Special cases:
- An approved device announcing a **different public key** returns to `pending` (`DEVICE_KEY_CHANGED` audit) and must be approved again.
- An approved device that says `enrolled: false` (lost its key) gets the WELCOME again automatically.
- A device that confirms enrollment while **quarantined** is immediately sent `ISOLATE`.

## 4. Replay protection

- **Device → host:** each slave picks a random 31-bit `boot` at power-up and increments `seq` for every frame. The host keeps, per device, the current boot, the last seq and the last 32 boot ids. It rejects `seq ≤ last` within a boot and any frame from an earlier boot (409, `REPLAY_REJECTED` audit, at most once a minute per device).
- **Host → device:** every `CMD` carries the next per-device host `seq` (stored in `devices.host_seq`). The slave stores the last accepted value in NVS and answers `REPLAY` to anything not larger.
- **Host-side TTL:** queued frames older than `AEGIS_COMMAND_TTL_S` (5 s) are dropped (`command_log.status = EXPIRED`), never sent late.

## 5. Bus discipline (master)

The master polls each known slave in turn and forwards the reply. It opens a discovery window every 10 s, or when the host sends `DISCOVER`. Host frames are put on the bus between polls, and the addressed slave's ACK is forwarded back. Slaves transmit on RS-485 **only** when addressed, so there are no collisions. A slave wired directly to the PC's USB port (no master) streams on USB instead. The master also sends `BUS_TOPOLOGY {slaves[], slave_count}` every 3 s.

## 6. Legacy protocol v0

Frames without `"v"` follow the pre-2.6 format: long-name sensor floats, canonical values formatted to 2 decimals as strings, and an optional `timestamp`. They're verified with a pre-shared key from `DEVICE_KEY_<ID>` or `device_keys.json`. Replay defence for v0 is a 300 s duplicate-signature cache plus a ±60 s timestamp window. v0 commands are fire-and-forget (no ACK). The gateway drops unsigned v0 frames unless run with `--allow-unsigned` (bench only).

## 7. Host ingestion

In-process: the gateway thread calls `app.handle_device_frame` (v1) or `app.process_telemetry` (v0) directly. External gateway process: `POST /api/telemetry` with header `X-Aegis-Gateway-Token` (see [REST API](../03-api/rest-api.md)).

## 8. Server-Sent Events (host → browser)

`GET /api/stream`, one cycle per second: `telemetry` (new rows), `heartbeat` (`time`, `isolated[]`, `pending_devices`), `topology`, `error`.
