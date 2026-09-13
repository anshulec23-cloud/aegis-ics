# Aegis ICS — Master Concentrator Bridge Firmware

This folder contains the production C/C++ firmware sketch for the **ESP32 Master Concentrator Node**.

---

## 🎯 Role & Functionality

The Master Concentrator node acts as the physical, high-speed bridge between:
1. **RS-485 Differential Fieldbus**: Interrogates and receives signed sensor frames from multi-node slave units (`ESP32_001` through `ESP32_004`).
2. **Host PC USB-CDC Serial**: Forwards verified wire frames to the Aegis ICS Edge Gateway server over UART at **115200 baud**.
3. **Bi-directional Actuator Dispatch**: Relays supervisory control frames (`ISOLATE`, `REARM`, `setpoint`, `ping`) from the host computer down to field slaves.

---

## 🔌 Electrical Connections & Pinout

```text
  ESP32 Master Concentrator                    MAX485 Module
┌───────────────────────────┐                ┌────────────────┐
│                   GPIO 16 │ (RX2) -------- │ RO  (Receiver) │
│                   GPIO 17 │ (TX2) -------- │ DI  (Driver)   │
│                   GPIO 04 │ (DIR) -------- │ DE + RE (Tied) │
│                      3.3V │ -------------- │ VCC            │
│                       GND │ -------------- │ GND            │
│                           │                │   A  (+) ──────┼──> RS-485 Line A
│        MicroUSB / Type-C  │                │   B  (-) ──────┼──> RS-485 Line B
└─────────────┬─────────────┘                └────────────────┘
              │
         Host PC USB
```

* **Heartbeat Indicator (GPIO 2)**: Blinks briefly each time a telemetry frame is forwarded across the bridge.
* **Termination Resistor**: Place a single 120Ω resistor across lines A and B at this endpoint.

---

## ⚡ Flashing Instructions

### Arduino IDE
1. Select board: `ESP32 Dev Module`.
2. Open `esp32_master_bridge.ino`.
3. Set Upload Speed: `921600`, Baud Rate: `115200`.
4. Click **Upload**.

### PlatformIO CLI
```bash
pio run -d firmware/esp32_master_bridge -t upload
```
