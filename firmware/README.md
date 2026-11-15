# Aegis ICS — Edge Microcontroller Hardware & Firmware Engineering Guide

This directory contains production-ready C/C++ firmware sketches and hardware documentation for deploying real **ESP32 microcontrollers** in an industrial Master-Slave SCADA architecture compliant with **NIST SP 800-82 Rev 3** (Guide to Operational Technology Security) and **FIPS 198-1** (HMAC Message Authentication).

---

## 1. Directory Structure

```text
firmware/
├── esp32_slave_sensor/
│   └── esp32_slave_sensor.ino   # ONE image for every slave: sensors, X25519 enrollment, signed telemetry, verified commands
├── esp32_master_bridge/
│   └── esp32_master_bridge.ino  # Master: polls the RS-485 bus, discovers new slaves, relays host commands and ACKs
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

### 3.2. ESP32 Slave Sensor Node Wiring (same for every slave)

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
│                   GPIO 26 │ (PWM) -------> │ Heater driver (temp. setpoint)    │
│                   GPIO 27 │ (PWM) -------> │ Pump driver (pressure setpoint)   │
│                   GPIO 02 │ (OUT) -------> │ Heartbeat / Isolation Status LED  │
│           GPIO 00 (BOOT)  │ (IN)  <------- │ Hold at power-up = factory reset  │
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

## 4. Zero-touch deployment (no per-node configuration, no keys to copy)

Protocol v1 and [ADR 0006](../docs/adr/0006-zero-touch-enrollment.md). Every slave runs the **same binary**:

1. **Flash** `esp32_slave_sensor` to every slave and `esp32_master_bridge` to the master. Nothing to edit before flashing.
2. **First boot:** each slave derives its ID from its chip MAC (`ESP32_A1B2C3`), generates an X25519 key pair and stores it in NVS. The USB console prints the ID and a **fingerprint** (`6B7B-0FE8-B1BB`).
3. **Discovery:** the master opens a discovery window every 10 s. Unenrolled slaves answer with `HELLO` (ID, public key, sensors), and the master adds every ID it hears to its poll list. There's no fixed number of slaves (up to `MAX_SLAVES` = 32 per bridge).
4. **Approve:** in the dashboard (Station 06 → Field device enrollment) the new slave shows as **PENDING** with the same fingerprint. Compare it, optionally name the device, and click **APPROVE**.
5. **Key agreement:** the host sends `WELCOME` with its public key. Both sides compute `X25519` + `HKDF-SHA256`, so the key never travels over the bus. The slave verifies the WELCOME, stores the key in NVS and confirms with a signed `ACK`. From then on it answers polls with signed `TEL` frames.

Replacing a board: the new board has a new ID/key and appears as a new pending device. Revoke the old one in the dashboard.
Re-deploying a board elsewhere: **factory reset** by holding BOOT (GPIO 0) at power-up for ~3 s; this erases its identity and key.

---

## 5. Wire protocol v1 (summary)

Full spec: [`docs/01-architecture/protocols.md`](../docs/01-architecture/protocols.md). All frames are one JSON line with `"v":1`.

| Frame | Direction | Signed | Purpose |
|---|---|---|---|
| `DISCOVER` | master → bus | no | open a discovery window |
| `POLL {id}` | master → slave | no | "your turn": the slave answers with `TEL` (or `HELLO` if not enrolled) |
| `HELLO {id, pub, sensors, fw, boot, enrolled}` | slave → host | no | announce / request enrollment |
| `WELCOME {id, hpub, sig}` | host → slave | yes (new key) | deliver the host key after approval |
| `TEL {id, boot, seq, <sensors>, faults, tripped, sp_t?, sp_p?, sig}` | slave → host | yes | telemetry |
| `CMD {id, seq, cmd, args, sig}` | host → slave | yes | `SETPOINT`, `ISOLATE`, `REARM`, `SHUTDOWN`, `PING` |
| `ACK {id, boot, seq, ack, result, reason?, sig}` | slave → host | yes | result of a command (`OK`, `REJECTED`, `BAD_SIG`, `REPLAY`, `UNKNOWN_CMD`) |

**Canonical signing string:** the frame without `sig`, with keys sorted and no spaces. Real numbers are always strings with two decimals (`"26.10"`), so the ESP32 and Python produce byte-identical JSON. The firmware inserts keys in sorted order, and `tests/security/test_firmware_contract.py` enforces that.

**Replay protection:** each slave picks a random `boot` id at power-up and increments `seq` per frame; the host rejects anything already seen. Host commands carry a per-device `seq` that the slave stores in NVS and never accepts twice.

**Fail-safe behaviour:**
- Trip state is kept in NVS: a quarantined node **boots tripped**.
- Floating or shorted sensors (raw ADC ≤ 50 or ≥ 4090) are reported in `faults[]` and omitted, never faked.
- A task watchdog (8 s) resets a hung node.
- Setpoints drive the PWM outputs (GPIO 26/27) only while the relay is energised and the feedback sensor is healthy.

---

## 6. Building and flashing

**Arduino IDE 2.x**
1. Boards Manager → install **esp32 by Espressif Systems** (core 2.x or 3.x).
2. Library Manager → install **ArduinoJson** (6.x or 7.x).
3. Open `esp32_slave_sensor/esp32_slave_sensor.ino` → board **ESP32 Dev Module** → Upload. Repeat for every slave (same sketch).
4. Open `esp32_master_bridge/esp32_master_bridge.ino` → Upload to the master.

**arduino-cli**
```bash
arduino-cli core install esp32:esp32
arduino-cli lib install ArduinoJson
arduino-cli compile --fqbn esp32:esp32:esp32 firmware/esp32_slave_sensor
arduino-cli upload  --fqbn esp32:esp32:esp32 -p COM5 firmware/esp32_slave_sensor
```

**Crypto self-test on real hardware:** compile the slave with `-DAEGIS_SELFTEST` (or add `#define AEGIS_SELFTEST` at the top). At boot the USB console prints `[SELFTEST] protocol v1 key agreement + signature: PASS` if the ESP32 reproduces the host's known-answer vector (`tests/security/protocol_v1_vectors.json`).

---

## 7. Bench checklist

| Check | Expected |
|---|---|
| Slave USB console after reset | `[AEGIS] ESP32_xxxxxx firmware 2.6.0 fingerprint XXXX-XXXX-XXXX AWAITING APPROVAL relay ENERGISED` |
| Master USB console | `{"system":"Aegis Master Concentrator",...,"protocol":1}` then `BUS_TOPOLOGY` every 3 s |
| Dashboard Station 06 | each slave listed as PENDING within ~10 s; fingerprints match the consoles |
| After APPROVE | slave console prints `[ENROLL] ... Device enrolled.`; telemetry appears in Station 01 |
| ISOLATE from dashboard | relay drops; dashboard shows the device ACK; node stays tripped after a power cycle |
| Unplug a sensor | its value disappears and `faults` lists it; the device is flagged anomalous |

A single slave can also be wired straight to the PC over USB (no master): it then streams on USB only, and the host enrolls it the same way.
