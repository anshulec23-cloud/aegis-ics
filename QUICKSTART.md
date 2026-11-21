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
* Device keys are **not** configured by hand: each ESP32 derives a unique session key at enrollment (X25519 + HKDF-SHA256) and the operator approves it with one click.
* `ADMIN_PASSWORD`: Administrator password (minimum 12 characters). Optional - if unset, the app starts in setup mode and you create the password at `/setup`. There is no default password.

---

## 3. Run the Automated Test Suite

Execute the complete pytest suite (174 passing, 1 xfailed):

```powershell
python -m pytest tests -q
```

This verifies HMAC cryptographic signatures, Stuxnet multi-variable safety rules, financial analytics modeling, PDF report generation, serial gateway parsers, physical Master Concentrator bridge detection, 5-transducer dynamic profiling, and multi-threaded stress concurrency.

---

## 4. Launching Aegis ICS

### Mode A: Web Gateway & SCADA Dashboard (Recommended for Servers)

```powershell
python src/app.py
```

Open your browser and navigate to `http://127.0.0.1:5000`.
* **First run**: there are no default credentials. You are redirected to `/setup` to create the `admin` password; the one-time setup token is printed in the startup log (or `setup_token.txt` in the data directory).
* **Station Coordinates**: Enter your 3D terminal location (e.g. `X: 12.4, Y: -48.1, Z: 3.5`).

---

### Mode B: Standalone Native Desktop Application

```powershell
# Windows:
python src/main.py

# Linux / MX Linux:
python3 src/main.py

# Or launch the standalone compiled binaries:
# Windows:
.\dist\AegisICS.exe

# Linux:
./dist/linux/AegisICS
```

---

## 5. Physical Hardware Connection (ESP32 Master Concentrator)

1. Connect the **ESP32 Master Concentrator** to your PC via USB.
2. Launch Aegis ICS and navigate to **Station 06 (Gateway)**.
3. In the **Hardware COM Port** dropdown, choose the port marked with `★ [ESP32 DETECTED]` (e.g. `COM3` or `/dev/ttyUSB0`).
4. Select `115200` baud and click **CONNECT GATEWAY**.
5. Switch to **Station 01 (Monitor)**: verify the **Cluster Topology Ribbon** shows detected nodes, total active transducers (`5/5`), and live telemetry waveforms.

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
