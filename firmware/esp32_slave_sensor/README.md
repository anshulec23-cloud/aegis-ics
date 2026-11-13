# Aegis ICS — Edge Slave Sensor Node Firmware

This directory contains the production C/C++ firmware sketch for the **Aegis ICS Edge Microcontroller Slave Sensor Nodes**.

---

## Role & Capabilities

Each slave node interfaces with physical plant transducers, acquires multi-sensor process signals, formats canonical JSON packets, generates cryptographic HMAC-SHA256 signatures via hardware-accelerated **mbedTLS**, and directly drives optocoupler isolation relays.

### Key Capabilities:
* **Canonical Cryptographic Signing**: Computes deterministic HMAC-SHA256 signatures matching the gateway's alphabetical JSON representation.
* **Physical Relay Actuation**: Controls an optocoupler relay on **GPIO 25**. Upon receiving an `ISOLATE` supervisory frame, the node instantly trips the relay to mechanically decouple motors or valves.
* **Non-Blocking Execution**: High-speed ring buffer line state machine ensures uninterrupted telemetry transmission without polling delays.

---

## Multi-Node Flashing Configuration Matrix

Before flashing, uncomment exactly **ONE** macro in `esp32_slave_sensor.ino`:

| Node Macro to Uncomment | Node ID | Industrial Unit Monitored | Pre-Shared HMAC-SHA256 Key |
|---|---|---|---|
| `#define NODE_CONFIG_ESP32_001` | `ESP32_001` | Catalytic Reactor 01 | `aegis_shared_esp32_001_secret_key_v2` |
| `#define NODE_CONFIG_ESP32_002` | `ESP32_002` | Centrifugal Pump 02 | `aegis_shared_esp32_002_secret_key_v2` |
| `#define NODE_CONFIG_ESP32_003` | `ESP32_003` | Cooling Cryo 03 | `aegis_shared_esp32_003_secret_key_v2` |
| `#define NODE_CONFIG_ESP32_004` | `ESP32_004` | Turbine Generator 04 | `aegis_shared_esp32_004_secret_key_v2` |

---

## Hardware Wiring & Pin Assignments

| Component / Sensor | Pin Function | ESP32 GPIO |
|---|---|---|
| **RS-485 Transceiver** | RX2 / TX2 / DE+RE | GPIO 16 (RX), GPIO 17 (TX), GPIO 4 (DIR) |
| **Temperature Sensor** | Analog LM35 / Thermocouple | GPIO 34 (ADC1_CH6) |
| **Pressure Transducer** | Industrial 0.5–4.5V Transducer | GPIO 35 (ADC1_CH7) |
| **Vibration Sensor** | Piezo Film / Accelerometer | GPIO 32 (ADC1_CH4) |
| **Hall Effect RPM** | A3144 Pulse Counter | GPIO 33 (Hardware Interrupt / Pullup) |
| **Current Sensor** | ACS712 Hall-Effect Transducer | GPIO 36 (SENSOR_VP) |
| **Actuator Relay** | Emergency Process Interlock | GPIO 25 (Digital Output) |
| **Status / Heartbeat LED** | Visual Alarm / Tamper | GPIO 2 (Digital Output) |

---

## Flashing Instructions

```bash
# PlatformIO
pio run -d firmware/esp32_slave_sensor -t upload

# Arduino IDE
# 1. Open esp32_slave_sensor.ino
# 2. Select: ESP32 Dev Module
# 3. Ensure ArduinoJson and mbedTLS are included
# 4. Flash to board at 115200 baud
```
