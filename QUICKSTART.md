# Quickstart Guide — Aegis ICS v2.5.2

This quickstart guide helps you set up, verify, and run the Aegis ICS Industrial Security Gateway on Windows or Linux.

---

## 1. Prerequisites & Environment Setup

Ensure you have **Python 3.12+** installed.

```powershell
# 1. Set up a virtual environment
python -m venv .venv

# 2. Activate the virtual environment
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# 3. Install required dependencies
pip install -r src/requirements.txt
```

---

## 2. Configuration (`.env`)

Copy the template configuration file:

```powershell
copy .env.example .env
```

Key environment variables:
* `FLASK_SECRET_KEY`: Random 64-character hex secret for operator sessions.
* `DEVICE_KEY_ESP32_001`: Pre-shared HMAC-SHA256 key for ESP32 edge microcontroller 001.
* `ADMIN_PASSWORD`: Custom master administrator password (defaults to `noodles` in local dev).

---

## 3. Run the Automated Test Suite

Execute the complete 46-module pytest test suite:

```powershell
python -m pytest tests/ -v
```

This verifies HMAC cryptographic signatures, Stuxnet multi-variable safety rules, financial analytics modeling, PDF report generation, serial gateway parsers, air-gapped asset availability, 5-feature ML anomaly inference, SSE streaming, and multi-threaded stress concurrency.

---

## 4. Launching Aegis ICS

### Mode A: Web Gateway & SCADA Dashboard (Recommended for Servers)

```powershell
python src/app.py
```

Open your browser and navigate to `http://127.0.0.1:5000`.
* **Default Operator ID**: `noodles`
* **Default Access Token**: `noodles`
* **Station Coordinates**: Enter your 3D terminal location (e.g. `X: 12.4, Y: -48.1, Z: 3.5`).

---

### Mode B: Standalone Native Desktop Application

```powershell
# Windows:
python src/main.py

# Linux / MX Linux:
python3 src/main.py

# Or run the standalone compiled binary:
./dist/AegisICS
```

Launches the native PyWebView window with anti-debugging protections, ephemeral port allocation, system tray integration (`pystray`), and background GitHub update checking.

### Mode C: Headless Linux Server / Daemon Mode (MX Linux)

```bash
# Launch as a background SCADA server:
./dist/AegisICS --server --port 5000 --host 0.0.0.0

# Or via MX Linux SysVinit service:
sudo service aegis-ics start
```

---

## 5. Connecting Edge Hardware (ESP32 / PLC)

Connect your physical ESP32 or PLC via USB/Serial cable.

### Option 1: Via SCADA Dashboard
1. Log in to the dashboard.
2. In the **Hardware Connection** card, click **Scan Ports**.
3. Select your COM port (e.g., `COM3`, `COM4`) and baud rate (default: `115200`).
4. Click **Connect**.

### Option 2: Via Standalone Edge Gateway Driver CLI

```powershell
# Real Hardware on COM3:
python src/serial_gateway.py --port COM3 --baud 115200 --mode plc

# Software Emulation (No hardware required):
python src/serial_gateway.py --mock --mode plc
```

---

## 6. What To Expect

* **Zero-Trust Telemetry Ingestion**: Live waveforms of temperature, pressure, vibration, current, and RPM streaming in real-time.
* **Autonomous Micro-Segmentation**: Any device sending invalid HMAC signatures or anomalous sensor signals is automatically quarantined (`is_isolated = True`).
* **Stuxnet Prevention**: Attempting to raise temperature setpoints while pressure is elevated is blocked with an immediate security audit alarm.
* **Instant Incident PDF Reports**: One-click download of formal, Chicago/Harvard-style security audit documentation.
