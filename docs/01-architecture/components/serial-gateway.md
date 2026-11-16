# Serial gateway — `src/serial_gateway.py`

## Responsibility
- Own the transport: a real serial port (pyserial, auto-reconnect) or the protocol-v1 **simulator** (`SimulatedBus`, `mock=True`).
- Read lines and route them. Protocol-v1 frames (`HELLO`/`TEL`/`ACK`) go to the in-process handler `app.handle_device_frame` (or are POSTed to `/api/telemetry` when running as a separate process). Legacy v0 frames go to `app.process_telemetry`. Bridge `BUS_TOPOLOGY` frames update the topology view.
- Write queued frames to the bus: signed v1 `CMD`/`WELCOME` frames from the registry, plus `DISCOVER`. Frames older than the TTL are dropped and their `command_log` rows marked `EXPIRED`.
- Keep dashboard state: raw packet ring buffer, active nodes, gateway health.
- Never sign frames on a device's behalf (unsigned v0 frames are dropped unless `--allow-unsigned`).

## Key functions
| Function | Purpose |
|---|---|
| `start_gateway(port, baud, mock, url, gateway_token, on_connect, sim_devices, ...)` | main loop; `on_connect` lets the app re-sync quarantine after every (re)connect |
| `stop_gateway()` / `is_connected()` / `is_mock_active()` | lifecycle; each run has its own stop event |
| `send_frame(frame, command_log_id)` | enqueue a signed v1 frame |
| `send_command(dict)` | enqueue a legacy v0 command (signed with the device's key) |
| `pop_ready_commands()` | drain unexpired items (tests / tooling) |
| `set_frame_handler(v1, v0)` | registered by `app.py` for in-process delivery |
| `get_simulated_bus()` | the active `SimulatedBus` (drills, tests) |
| `get_active_nodes()`, `get_gateway_health()`, `get_recent_raw_packets()` | dashboard state |

## Simulator (`src/simulator.py`)
Plays the master plus `AEGIS_SIM_DEVICES` slaves. Each simulated slave has its own X25519 identity and persists its "NVS" (identity, session key, host sequence, trip state, setpoints) in `<data dir>/simulator_devices.json`. It follows the same rules as the firmware: HELLO until enrolled, verified commands, signed ACKs, boot/seq, setpoint tracking, trip behaviour. Red-team drills (`inject_attack`) alter what one simulated slave sends (`stuxnet`, `hmac_tamper`, `replay`, `thermal_drift`, `fdi_spike`, `ddos`, `sensor_fault`); detection is left to the real pipeline.

## Known limitations
- The transport loop is synchronous (one thread); a slow handler delays reading. Moving to asyncio or a worker process is in restructure plan Phase 3.
- The serial port read timeout is 0.2 s; command latency is bounded by that plus the master's polling cycle.
