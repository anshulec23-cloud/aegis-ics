# Aegis ICS — Slave Sensor Node Firmware

One image for **every** slave: no per-node configuration, no compiled-in keys.

- **Identity:** device ID from the chip MAC (`ESP32_A1B2C3`); X25519 key pair generated on first boot and kept in NVS.
- **Enrollment:** answers discovery with `HELLO`. After an operator approves it in the dashboard, it derives its session key from the host's `WELCOME` (X25519 + HKDF-SHA256) and confirms with a signed `ACK`.
- **Telemetry:** signed `TEL` frames with `boot`/`seq`. Faulted sensors are listed in `faults[]` and omitted; values are never faked.
- **Commands:** `SETPOINT`, `ISOLATE`, `REARM`, `SHUTDOWN`, `PING`. Each is verified (HMAC + host sequence number), envelope-checked, applied and acknowledged.
- **Fail-safe:** trip state persists in NVS (boots tripped if it was quarantined); 8 s task watchdog.
- **Bus discipline:** transmits on RS-485 only when the master addresses it. When wired directly to a PC over USB it streams on USB instead.

| Pin | Function |
|---|---|
| 16 / 17 / 4 | RS-485 RX / TX / DE+RE |
| 34 / 35 / 32 / 36 | Temperature / pressure / vibration / current ADC |
| 33 | Hall pulse input (RPM) |
| 25 | Trip relay (HIGH = energised) |
| 26 / 27 | Heater / pump PWM (setpoint actuators) |
| 2 | Status LED (on = tripped) |
| 0 (BOOT) | Hold at power-up ~3 s = factory reset (erase identity + key) |

Build: Arduino IDE or `arduino-cli compile --fqbn esp32:esp32:esp32 firmware/esp32_slave_sensor` (ESP32 core 3.x, ArduinoJson 7). Add `-DAEGIS_SELFTEST` to run the shared known-answer crypto test at boot. Full guide: [`../README.md`](../README.md).
