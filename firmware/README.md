# Aegis ICS — Edge Microcontroller Hardware & Firmware Engineering Guide

This directory contains production-ready C/C++ firmware sketches and hardware documentation for deploying real **ESP32 microcontrollers** in an industrial Master-Slave SCADA architecture compliant with **NIST SP 800-82 Rev 3** (Guide to Operational Technology Security) and **FIPS 198-1** (HMAC Message Authentication).

---

## 1. Directory Structure

```text
firmware/
├── esp32_slave_sensor/
│   └── esp32_slave_sensor.ino   # Edge Slave Node: Multi-sensor acquisition, mbedTLS HMAC-SHA256 & actuator control
├── esp32_master_bridge/
│   └── esp32_master_bridge.ino  # Master Concentrator: RS-485 to USB-UART Gateway Bridge with FIFO flush
└── README.md                    # This comprehensive hardware wiring & deployment guide
```

---

## 2. Hardware Bill of Materials (BOM)

| Component | Function | Recommended Part / Module | Operating Voltage | ESP32 Pin |
|---|---|---|---|---|
| **Microcontroller** | Master & Slaves | ESP32-WROOM-32 / ESP32-S3 DevKit v1 | 3.3V / 5V USB | All |
| **RS-485 Transceiver** | Differential Fieldbus Driver | MAX485, SP3485, or SN65HVD72 | 3.3V – 5.0V | RX: GPIO 16, TX: GPIO 17, DIR: GPIO 4 |
| **Temperature Sensor** | Exotherm Reactor Monitoring | LM35, TMP36, or MAX6675 Thermocouple | 3.3V / 5.0V | GPIO 34 (ADC1_CH6) |
| **Pressure Transducer** | Vessel Pressure (0–10 bar) | 0.5V – 4.5V Industrial Pressure Sensor | 5.0V (VCC), Resistor Divider to ADC | GPIO 35 (ADC1_CH7) |
| **Vibration Sensor** | Mechanical Resonance | Piezo Film Sensor or MPU6050 Accelerometer | 3.3V | GPIO 32 (ADC1_CH4) |
| **RPM Speed Sensor** | Rotor Speed Pulses | A3144 Hall Effect Magnetic Sensor | 3.3V / 5.0V | GPIO 33 (Interrupt / Pull-up) |
| **Current Sensor** | Motor Electrical Load | ACS712-05B / ACS712-20A Hall Current Sensor | 5.0V (VCC), Resistor Divider to ADC | GPIO 36 (ADC1_CH0 / SENSOR_VP) |
| **Actuator Relay** | Emergency Valve / Isolation | 1-Channel 5V Optocoupler Relay Module | 5.0V VCC / 3.3V Logic | GPIO 25 (Digital Output) |
| **Status LED** | Visual Alarm & Heartbeat | On-board LED or 3mm external LED | 3.3V | GPIO 2 (Digital Output) |
| **Terminating Resistors**| Differential Line Termination| 120Ω 1/4W Metal Film Resistors | N/A | Across Line A and Line B at endpoints |

---

## 3. Electrical Wiring & Pinout Specifications

### 3.1. ESP32 Master Concentrator Bridge Wiring

The Master ESP32 acts as the physical bridge between the differential RS-485 bus and the host PC running the Aegis ICS Edge Gateway over USB Serial.

```text
  ESP32 Master Concentrator                    MAX485 Module
┌───────────────────────────┐                ┌────────────────┐
│                   GPIO 16 │ (RX2) -------- │ RO  (Receiver) │
│                   GPIO 17 │ (TX2) -------- │ DI  (Driver)   │
│                   GPIO 04 │ (DIR) -------- │ DE + RE (Tied) │
│                      3.3V │ -------------- │ VCC            │
│                       GND │ -------------- │ GND            │
│                           │                │   A  (+) ──────┼──> RS-485 Line A (Twisted Pair)
│        MicroUSB / Type-C  │                │   B  (-) ──────┼──> RS-485 Line B (Twisted Pair)
└─────────────┬─────────────┘                └────────────────┘
              │
         Host PC USB
```

### 3.2. ESP32 Slave Sensor Node (`ESP32_001` through `ESP32_004`) Wiring

```text
  ESP32 Slave Sensor Node                      MAX485 Module & Sensors
┌───────────────────────────┐                ┌───────────────────────────────────┐
│                   GPIO 16 │ (RX2) -------- │ RO  (Receiver Output)             │
│                   GPIO 17 │ (TX2) -------- │ DI  (Driver Input)                │
│                   GPIO 04 │ (DIR) -------- │ DE + RE (Tied together)           │
│                   GPIO 34 │ (ADC) <------- │ LM35 / Temp Transducer OUT        │
│                   GPIO 35 │ (ADC) <------- │ Pressure Transducer OUT           │
│                   GPIO 32 │ (ADC) <------- │ Vibration Piezo OUT               │
│                   GPIO 33 │ (INT) <------- │ Hall Effect A3144 DO (Pullup)     │
│                   GPIO 36 │ (ADC) <------- │ ACS712 Current Sensor OUT         │
│                   GPIO 25 │ (OUT) -------> │ Relay IN (Actuator Trip Circuit)  │
│                   GPIO 02 │ (OUT) -------> │ Heartbeat / Isolation Status LED  │
│                      3.3V │ -------------- │ VCC (Transceiver & 3.3V Sensors)  │
│                       GND │ -------------- │ Common Ground (GND)               │
│                           │                │   A  (+) ───> RS-485 Line A       │
│                           │                │   B  (-) ───> RS-485 Line B       │
└───────────────────────────┘                └───────────────────────────────────┘
```

> [!WARNING]
> **Voltage Level Caution on 5V Industrial Sensors (Pressure & ACS712)**:
> - The ESP32 ADC inputs (GPIO 34, 35, 36) are rated for **0V to 3.3V**.
> - If powered from 5V, industrial pressure sensors output up to 4.5V. Use a simple voltage divider (e.g. 10kΩ and 20kΩ precision resistors) to step down 4.5V to ≤ 3.0V before entering the ESP32 ADC pin, or adjust linear scaling factors accordingly.
> - For MAX485 modules powered at 5V, place a 1kΩ / 2kΩ voltage divider on the `RO` pin before connecting to ESP32 GPIO 16, or use a 3.3V-native transceiver such as the **SP3485** or **MAX3485**.

### 3.3. RS-485 Differential Bus Topology & Grounding

```text
[Master Node]                [Slave Node 1]               [Slave Node 2]               [Slave Node 3/4]
  (Endpoint)                   (Mid-Bus)                    (Mid-Bus)                    (Endpoint)
┌───────────┐                ┌───────────┐                ┌───────────┐                ┌───────────┐
│  MAX485   │                │  MAX485   │                │  MAX485   │                │  MAX485   │
│   A   B   │                │   A   B   │                │   A   B   │                │   A   B   │
└───┬───┬───┘                └───┬───┬───┘                └───┬───┬───┘                └───┬───┬───┘
    │   │                        │   │                        │   │                        │   │
 [120Ω] │                        │   │                        │   │                     [120Ω] │
    │   │                        │   │                        │   │                        │   │
════╪═══╪════════════════════════╪═══╪════════════════════════╪═══╪════════════════════════╪═══╪════ RS-485 A (+)
════╪═══╧════════════════════════╪═══╧════════════════════════╪═══╧════════════════════════╪═══╧════ RS-485 B (-)
────┴────────────────────────────┴────────────────────────────┴────────────────────────────┴──── Common Signal Ground
```

- **Bus Topology**: Strict daisy-chain / bus topology. Avoid star or stub branches longer than 30 cm.
- **Termination**: Install a single **120Ω** terminating resistor across lines A and B at the Master Node and another **120Ω** resistor at the furthest Slave Node. Do not place terminating resistors on mid-bus nodes.
- **Cable**: Shielded twisted pair (STP), such as Belden 9841 or Category 5e/6. Connect the cable shield to Earth Ground at the Master Concentrator end only.

---

## 4. Multi-Node Flashing Matrix & Pre-Shared Cryptographic Keys

Each physical node must be flashed with its corresponding node macro in [`firmware/esp32_slave_sensor/esp32_slave_sensor.ino`](esp32_slave_sensor/esp32_slave_sensor.ino).

| Node Designation | Subsystem Monitored | Macro to Uncomment in Firmware | Device ID | Pre-Shared HMAC-SHA256 Key |
|---|---|---|---|---|
| **Node 1** | Catalytic Reactor 01 | `#define NODE_CONFIG_ESP32_001` | `ESP32_001` | `aegis_shared_esp32_001_secret_key_v2` |
| **Node 2** | Centrifugal Pump 02 | `#define NODE_CONFIG_ESP32_002` | `ESP32_002` | `aegis_shared_esp32_002_secret_key_v2` |
| **Node 3** | Cooling Cryo 03 | `#define NODE_CONFIG_ESP32_003` | `ESP32_003` | `aegis_shared_esp32_003_secret_key_v2` |
| **Node 4** | Turbine Generator 04 | `#define NODE_CONFIG_ESP32_004` | `ESP32_004` | `aegis_shared_esp32_004_secret_key_v2` |

> [!IMPORTANT]
> **Cryptographic Parity**:
> The HMAC keys defined in the firmware match the default keys in `src/security.py`. If you override keys in your host environment using `DEVICE_KEY_ESP32_001`, ensure the same key string is updated in the corresponding firmware macro before flashing.

---

## 5. Cryptographic Canonicalization Specification

Under NIST SP 800-82r3 Zero-Trust, every telemetry packet must be signed using **HMAC-SHA256**. The Python server strictly validates signatures by reconstructing a canonical string with **alphabetical key ordering** and **2-decimal formatted floats**.

The firmware implements this exact formula:
```c
char canonical_str[384];
snprintf(canonical_str, sizeof(canonical_str),
    "{\"current\":\"%.2f\",\"device_id\":\"%s\",\"hall_effect\":\"%.2f\",\"pressure\":\"%.2f\",\"temperature\":\"%.2f\",\"vibration\":\"%.2f\"}",
    current, DEVICE_ID, rpm, pressure, temperature, vibration
);
```

The resulting 64-character SHA-256 hex digest is calculated in hardware via the ESP32's built-in **mbedTLS** cryptographic engine and appended to the wire packet:
```json
{
  "current": 4.50,
  "device_id": "ESP32_001",
  "hall_effect": 0.00,
  "pressure": 4.20,
  "signature": "6ec06f534887315570075d658c14a2bb3bfa86144e5488429184518bf9776f82",
  "temperature": 26.00,
  "vibration": 1.10
}
```

---

## 6. Step-by-Step Flashing Guide

### Method A: Arduino IDE
1. Open Arduino IDE (version 2.x recommended).
2. Install the **ESP32 by Espressif Systems** board package (`Tools` -> `Board` -> `Boards Manager` -> search "esp32").
3. Install the **ArduinoJson** library by Benoit Blanchon (Library Manager -> search "ArduinoJson").
4. Select `Tools` -> `Board` -> `ESP32 Arduino` -> `ESP32 Dev Module`.
5. Configuration settings:
   - **Upload Speed**: `921600`
   - **CPU Frequency**: `240MHz`
   - **Flash Frequency**: `80MHz`
   - **Partition Scheme**: `Default 4MB with spiffs (1.2MB APP)`
   - **Core Debug Level**: `None` (or `Info` for debugging)
6. Open `firmware/esp32_master_bridge/esp32_master_bridge.ino` and flash to the Master ESP32.
7. Open `firmware/esp32_slave_sensor/esp32_slave_sensor.ino`, uncomment the target node (e.g. `NODE_CONFIG_ESP32_001`), and flash to Slave Node 1. Repeat for Nodes 2, 3, and 4.

### Method B: PlatformIO CLI
```bash
# Flash Master Bridge
pio run -d firmware/esp32_master_bridge -t upload

# Flash Slave Sensor Node
pio run -d firmware/esp32_slave_sensor -t upload
```

---

## 7. Benchtop Verification & Troubleshooting Checklist

1. **Serial Port Connection**:
   - Plug the Master ESP32 into the host PC. Note the COM port (e.g. `COM3` on Windows, `/dev/ttyUSB0` on Linux).
   - In Aegis ICS SCADA UI, select the COM port and click **Connect**.
2. **Master Heartbeat LED (GPIO 2)**:
   - Blinks briefly every time a telemetry packet is forwarded from RS-485 to USB Serial.
3. **Slave Activity**:
   - Telemetry packets transmit every 500 ms.
   - If `PIN_ACTUATOR_RELAY` (GPIO 25) is engaged, the relay remains closed (normally open circuit powered).
   - When an operator clicks **Isolate Node** on the SCADA UI, the supervisory interlock broadcasts an `ISOLATE` command: the relay de-energizes instantly and GPIO 2 turns solid ON.
4. **Fieldbus Diagnostics**:
   - If no packets are received: verify lines A and B are not swapped (A to A, B to B).
   - If packets have framing errors: check that `RS485_BAUD_RATE` is `115200` on both Master and Slaves.
   - If signatures fail: verify the `DEVICE_KEY_<ID>` in the host `.env` matches `PRE_SHARED_HMAC_KEY` in the firmware.

