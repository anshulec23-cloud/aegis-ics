# Firmware — `firmware/`

Arduino-framework C++ for ESP32-WROOM-32 (core 2.x or 3.x). Libraries: ArduinoJson 6/7, mbedTLS and Preferences (both bundled with the core). Wiring, building and the bench checklist are in [`firmware/README.md`](../../../firmware/README.md).

## Slave sensor node — `esp32_slave_sensor.ino`

**One image for every slave.** There's nothing to configure per node and no key in the source.

| Concern | Implementation |
|---|---|
| Identity | `ESP32_` + last 3 bytes of the eFuse MAC; X25519 key pair generated with the hardware RNG on first boot and stored in NVS (`priv`, `pub`) |
| Enrollment | `HELLO` on discovery/poll while unenrolled; on `WELCOME`: `derive_session_key()` (X25519 + HKDF-SHA256), verify the frame, store `key` in NVS, `ACK ack=0` |
| Telemetry | `send_telemetry()`: signed `TEL` with `boot`/`seq`; keys inserted in sorted order; values as 2-decimal strings |
| Commands | `handle_command()`: verify HMAC, then `seq > host_seq` (NVS), then apply, then signed `ACK` |
| Setpoints | stored in NVS; proportional control of heater (GPIO 26) / pump (GPIO 27) PWM; zero output while tripped or when the feedback sensor is faulted; device envelope 0–60 °C / 0–8 bar |
| Faults | raw ADC ≤ 50 or ≥ 4090 means the sensor is omitted and named in `faults[]` |
| Fail-safe | trip state restored from NVS **first** in `setup()`; 8 s task watchdog; BOOT button at power-up = factory reset |
| Bus | transmits on RS-485 only when addressed (`POLL`, `CMD`, `WELCOME`, `DISCOVER` with a random 0–300 ms slot); free-runs on USB only when no master has polled it for 5 s |
| Self-test | `-DAEGIS_SELFTEST` runs the shared known-answer vector at boot and prints PASS/FAIL |

| Pin | Function |
|---|---|
| 16/17/4 | RS-485 RX/TX/DE-RE |
| 34, 35, 32, 36 | Temperature, pressure, vibration, current ADC |
| 33 | Hall pulse interrupt |
| 25 | Trip relay (HIGH = energised) |
| 26, 27 | Heater / pump PWM |
| 2 | Status LED (on = tripped) |
| 0 | BOOT button (factory reset) |

## Master bridge — `esp32_master_bridge.ino`

A scheduling relay with **no keys**. It polls known slaves round-robin (40 ms gap, 120 ms reply timeout) and runs a discovery window (450 ms) every 10 s or on the host's `DISCOVER`. Host frames are queued (8 deep) and sent between polls, followed by a 250 ms ACK wait. Up to 32 slaves; a slave silent for 20 s drops off the poll list until it's rediscovered. It sends a `BUS_TOPOLOGY` heartbeat every 3 s.

## Verification status

- The host/firmware contract is pinned by `tests/security/test_firmware_contract.py`: sorted canonical keys, verify-before-act, SETPOINT args, trip restore order, shared vectors, bus discipline, and no faked readings.
- The crypto is verified on the host with the shared known-answer vector. On hardware, run the `AEGIS_SELFTEST` build.
- ⚠️ The firmware hasn't been compiled in the project's CI yet (there's no ESP32 toolchain there). Adding `arduino-cli compile` to CI is the next step ([RESTRUCTURE_PLAN](../../08-roadmap/RESTRUCTURE_PLAN.md) P2.x).
