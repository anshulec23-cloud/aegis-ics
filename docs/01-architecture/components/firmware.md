# Firmware — `firmware/`

Arduino-framework C++ for ESP32-WROOM-32. Libraries: ArduinoJson (v6 API: `StaticJsonDocument`), mbedTLS (bundled with the ESP32 core). Detailed wiring and flashing guides: [`firmware/README.md`](../../../firmware/README.md) and the per-sketch READMEs.

## Master bridge — `esp32_master_bridge.ino`
| Item | Value |
|---|---|
| Links | USB `Serial` 115200 to host; `rs485` (UART2) on RX16/TX17, DE/RE GPIO4 |
| Slave table | up to N entries: id, sensor flags, last_seen; timeout 8 s |
| Upstream | forwards every `{…}` line from RS-485 verbatim; parses it to update the slave table |
| Downstream | `DISCOVER`/`GET_TOPOLOGY` → broadcast `{"command":"DISCOVER"}` + topology; `SHUTDOWN`+`ALL` → broadcast + `COMMAND_ACK`; anything else → broadcast verbatim |
| Heartbeat | `BUS_TOPOLOGY` every 3 s |

## Slave sensor node — `esp32_slave_sensor.ino`
Select the node at compile time with `#define NODE_CONFIG_ESP32_00x`. That sets `DEVICE_ID`, `PRE_SHARED_HMAC_KEY` and the baseline values.

| Pin | Function |
|---|---|
| 34 | Temperature ADC (LM35) |
| 35 | Pressure ADC (0.5–4.5 V transducer) |
| 32 | Vibration ADC |
| 33 | Hall-effect pulse interrupt (A3144) |
| 36 | Current ADC (ACS712) |
| 25 | Actuator / trip relay (HIGH = energised) |
| 2 | Status LED |
| 16/17/4 | RS-485 RX/TX/DE-RE |

Loop (non-blocking): read commands from RS-485 and USB → compute RPM every 1 s → every 500 ms read the ADCs, build the canonical string, HMAC-sign it, transmit on RS-485 (DE high) and mirror to USB.

## Known issues (see [debug report](../../07-reports/DEBUG_REPORT.md))
- S2: keys compiled into source. S3: commands not authenticated.
- F2: `SETPOINT` handler doesn't match what the host sends and doesn't actuate anything.
- F5: free-running transmit on a shared half-duplex bus means collisions.
- F7: a floating or broken sensor reports a random plausible value.
- No hardware watchdog. Isolation state isn't persisted: `setup()` drives GPIO25 **HIGH** (energised) on every boot, so a quarantined node that reboots or browns out **re-arms itself** until the host notices and re-sends `ISOLATE`.

## Target state
PlatformIO project (`platformio.ini`) with a shared `protocol.h` generated from the protocol spec, keys provisioned into NVS/eFuse (not source), command verification with sequence numbers, master-polled bus, sensor-fault flags, a hardware watchdog, and Unity unit tests for the canonicaliser using the same test vectors as pytest.
