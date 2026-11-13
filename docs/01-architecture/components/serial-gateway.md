# Serial gateway — `src/serial_gateway.py`

## Responsibility
- Open a serial port (pyserial), read newline frames, auto-reconnect.
- Parse frames (JSON / CSV / key:value) and register bridge topology and node announcements.
- Sign unsigned frames and HTTP-POST them to `/api/telemetry`.
- Drain the outbound **command queue** to UART.
- Provide a **mock cluster simulator** (`mock=True`, port `MOCK*`/`SIM*`) and a red-team **attack injector**.
- Keep in-memory state for the dashboard: raw packet ring buffer (150), active nodes, master-bridge info, gateway state.

## Public functions
| Function | Used by | Purpose |
|---|---|---|
| `start_gateway(port, baud, mode, device_id, hmac_key, url, mock)` | `/api/com_ports/connect` (thread), CLI | blocking main loop |
| `stop_gateway()` | connect/disconnect routes | sets the module-global stop event |
| `send_command(dict)` | all control routes | sign if needed, enqueue |
| `sign_message`, `canonicalize_payload` | app, tests | HMAC helpers |
| `parse_serial_line(line)` | loop, tests | frame decoder |
| `get_active_nodes`, `get_gateway_health`, `get_gateway_state`, `get_active_port`, `get_master_bridge_info`, `get_recent_raw_packets` | read APIs, SSE | state snapshots |
| `find_esp32_ports()` | `/api/com_ports` | flags CP210x/CH340/FTDI-like ports |
| `inject_attack`, `reset_attacks`, `clear_device_attack`, `get_active_attacks` | red-team routes, analytics | simulator attack vectors: `stuxnet`, `hmac_tamper`, `thermal_drift`, `fdi_spike` (alias `injection`), `ddos` |
| `get_device_locations()` | `/api/devices/locations` | hard-coded plant coordinates |

## Main loop
```
connect (or mock) → enqueue DISCOVER
loop until stop_event:
    reconnect if port closed
    drain _command_queue → ser.write(json + "\n")
    line = mock_serial_stream() | ser.readline()   # readline timeout = 1 s; mock sleeps 0.5 s
    frame = parse_serial_line(line)
    bridge / announce frame → update topology, continue
    update _active_nodes
    if no signature: payload["signature"] = sign(payload, hmac_key or device key)
    requests.post(url, json=payload, timeout=3)
```

## Simulator
Round-robins the four nodes from `_sim_devices`, each with baselines matching `train_model.py` zones. Every seventh iteration it emits a `BUS_TOPOLOGY` frame. Attack vectors replace the packet values (e.g. `stuxnet`: vibration 4.9–6 g, RPM 3250–3550, temp +8–15 °C, spoofed normal pressure).

## Concurrency
- Module globals: `_gateway_stop_event`, `_active_port`, `_command_queue`, `_raw_packet_buffer`, `_active_nodes`, `_master_bridge_info`, `_gateway_state`, `_active_attacks`.
- `_buffer_lock` guards the packet buffer, nodes and bridge info, but not `_gateway_state`, `_active_port` or the attack dicts.
- ⚠️ Restart race: the connect route calls `stop_gateway()`, sleeps 0.2 s and starts a new thread that clears the **same** event, so the old thread may never stop (debug report F4).

## Known issues
F1 (single HMAC key for all nodes), F3 (stale command queue), F4 (thread race), S6 (host signs unsigned frames), F15 (fake locations).

## Target state
Separate `transport` (serial/mock), `codec` (versioned protocol), `command_bus` (TTL, seq, ACK tracking), `simulator` (own module, own DB flag). It runs as its own process, or as an asyncio task, and hands frames to the ingest service directly instead of over HTTP loopback.
