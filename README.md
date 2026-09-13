# Aegis ICS - Industrial Zero-Trust Security Gateway & Physical Enforcer

[![Release Version](https://img.shields.io/badge/release-v2.5.2-blue.svg)](https://github.com/anshulec23-cloud/aegis-ics/releases/tag/v2.5.2)
[![Application Status](https://img.shields.io/badge/status-functioning_software_application-success.svg)](#software-application-overview)
[![Tests Status](https://img.shields.io/badge/tests-39%2F39%20passing-brightgreen.svg)](#quality-assurance--testing)
[![Python Version](https://img.shields.io/badge/python-3.12%2B-informational.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **Official Software Application Release (v2.5.2 — Final Production Release)**: Aegis ICS is a fully functioning, production-ready zero-trust security gateway, physical safety enforcer, and real-time SCADA monitoring application built for Industrial Control Systems (ICS) and Operational Technology (OT) environments. Concludes the v2.x architecture cycle, subject to future LTS maintenance or security updates as needed.

---

## Table of Contents
- [Executive Summary & Software Application Overview](#software-application-overview)
- [The Problem Aegis ICS Solves](#the-problem-aegis-ics-solves)
- [Key Features & Capabilities](#key-features--capabilities)
- [System Architecture & Workflow](#system-architecture--workflow)
- [Installation & Quickstart Guide](#installation--quickstart-guide)
- [Hardware & Serial Integration](#hardware--serial-integration)
- [Quality Assurance & Testing](#quality-assurance--testing)
- [REST API Reference](#rest-api-reference)
- [Repository Structure](#repository-structure)
- [Release Notes & Version 2.5.0 Updates](#release-notes--version-250-updates)
- [Authors & Contact](#authors--contact)

---

## Software Application Overview

**Aegis ICS** is a complete industrial cybersecurity solution engineered to bridge physical edge devices (such as ESP32 microcontrollers, PLCs, and field sensors) with zero-trust security policies and physical safety enforcement rules.

Unlike traditional Intrusion Detection Systems (IDS) that passively observe cyberattacks after malicious commands reach physical machinery, **Aegis ICS functions as an active enforcer gateway**. It intercepts telemetry and control commands in real-time, verifying payload HMAC signatures, enforcing cross-parameter physical stress boundaries (preventing Stuxnet-style physical destruction), auditing operator actions with 3D spatial coordinates (`X, Y, Z`), and micro-segmenting compromised devices automatically.

Aegis ICS is distributed as both a standalone desktop application (`AegisICS.exe`) powered by PyWebView and an enterprise Flask web gateway with real-time SCADA interactive dashboards.

---

## The Problem Aegis ICS Solves

1. **Stuxnet-Style Coordinated Physical Stress Attacks**: Cyber-adversaries often send individual commands (e.g., raising temperature or pressure) that appear benign when viewed in isolation, but result in physical destruction when executed concurrently under specific operating states. Aegis ICS evaluates **multi-variable stress vectors** to block dangerous combinations before execution.
2. **Field Device Compromise**: If an edge device or broker credential is hijacked, plain network traffic allows unauthorized command injection. Aegis ICS enforces **HMAC-SHA256 payload signing** on every telemetry packet and command response.
3. **Lack of Spatial & Insider Auditability**: Industrial sabotage often originates from rogue internal operators or compromised credentials. Aegis ICS cryptographically logs operator logins, setpoint changes, and safety violations tagged with the physical 3D location coordinates (`X, Y, Z`) of the control terminal.
4. **Uncontained Blast Radius**: Aegis ICS continuously scores device trust metrics. When anomaly thresholds or HMAC violations occur, the system triggers **automated micro-segmentation**, isolating the rogue device from the control network while maintaining local fail-safe operation.

---

## Key Features & Capabilities

- **Zero-Trust Telemetry Ingestion**: Every sensor transmission is validated for schema structure, timestamp freshness, and HMAC-SHA256 cryptographic signature integrity.
- **Stuxnet-Proof Physical Safety Enforcer**: Evaluates mathematical physical limits across temperature, pressure, vibration, current, and RPM variables to reject hazardous operator setpoints.
- **Hardware Serial & COM Gateway**: Built-in PySerial communication layer supporting direct USB/Serial connection to ESP32 microcontrollers and industrial PLCs with custom RTS/DTR reset loop prevention.
- **Real-Time Interactive SCADA Dashboard**: Built with dynamic Chart.js graphing, live telemetry streaming, device quarantine toggles, and safety rule configuration controls.
- **Financial Risk & Threat Index Engine**: Quantifies potential financial loss, prevented asset damage, telemetry noise index, and sensor drift risk in real time.
- **Automated PDF & CSV Security Reporting**: Uses ReportLab to dynamically build comprehensive security incident reports complete with operator location metadata and violation logs.
- **Standalone Executable Deployment**: Bundled via PyInstaller into a standalone executable (`AegisICS.exe`) requiring zero pre-installed Python dependencies for deployment.

---

## System Architecture & Workflow

### Zero-Trust Telemetry & Enforcer Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Field as ESP32 / Industrial PLC
    participant Serial as Aegis Serial Gateway
    participant Server as Aegis Gateway Server
    participant Enforcer as Physical Safety Enforcer
    participant Audit as SQLite Audit Engine
    participant GUI as SCADA Dashboard

    Field->>Serial: Publish Telemetry Payload (JSON/CSV) + HMAC Signature
    Serial->>Server: Forward Raw Data Stream
    Server->>Server: Verify HMAC-SHA256 Signature & Timestamp
    alt HMAC Signature Valid
        Server->>Enforcer: Evaluate Physical Stress Vector (Temp vs. Pressure)
        alt Enforcer Approves
            Server->>Audit: Commit Telemetry Log & Update Trust Score
            Server->>GUI: Update Live Charts & Telemetry Stream
        else Coordinated Hazard Detected (Stuxnet Rule)
            Server->>Server: Block Action & Micro-segment Device
            Server->>Audit: Log Security Violation (Operator ID & 3D Coordinates)
            Server->>GUI: Raise Critical Alarm & Highlight Violation
        end
    else HMAC Signature Invalid
        Server->>Server: Quarantine Device (State = ISOLATED)
        Server->>Audit: Log Cryptographic Violation Event
        Server->>GUI: Display Invalid Signature Alert
    end
```

---

## Installation & Quickstart Guide

### Option A: Running Standalone Executable (Windows)

1. Download the latest `AegisICS.exe` executable from the [Releases](https://github.com/anshulec23-cloud/aegis-ics/releases) page.
2. Double-click `AegisICS.exe` to start the standalone desktop application.
3. The desktop application window will open automatically with the embedded SCADA dashboard interface.

### Option B: Debian Package & Linux Distribution (MX Linux / Debian)

1. Download the Debian package `aegis-ics_2.5.0_amd64.deb` or portable tarball `aegis-ics-2.5.0-linux-x86_64.tar.gz`.
2. Install via `dpkg` or MX Package Installer / GDebi:
   ```bash
   sudo dpkg -i aegis-ics_2.5.0_amd64.deb
   sudo usermod -a -G dialout $USER   # Allow USB/Serial hardware COM access
   ```
3. Run as Desktop Application:
   ```bash
   aegis-ics
   ```
4. Or run as 24/7 background service:
   * **MX Linux SysVinit**: `sudo service aegis-ics start`
   * **systemd**: `sudo systemctl start aegis-ics`

For full details, see [docs/linux_deployment.md](docs/linux_deployment.md).

### Option C: Running from Source Code (Developer Mode)

#### Prerequisites
- **Python 3.12+**
- Git

#### Installation Steps

```powershell
# 1. Clone the repository
git clone https://github.com/anshulec23-cloud/aegis-ics.git
cd aegis-ics

# 2. Set up virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install required dependencies
pip install -r requirements.txt

# 4. Initialize SQLite Database & Launch Server
python src/app.py
```

After starting `app.py`, navigate to `http://127.0.0.1:5000` in your web browser.

---

## Hardware & Serial Integration

Aegis ICS supports direct physical connection with hardware devices (e.g. ESP32, Arduino, industrial sensors):

1. Connect your ESP32 device via USB/Serial to your system.
2. In the Aegis SCADA Dashboard, navigate to the **Hardware Connection** tab.
3. Click **Scan Ports** to detect available COM ports (e.g., `COM3`, `COM4`).
4. Select your baud rate (default: `115200`) and click **Connect**.
5. The gateway will establish a non-resetting serial stream (disabling DTR/RTS) and ingest signed sensor telemetry live.

---

## Quality Assurance & Testing

Aegis ICS includes a comprehensive automated test suite covering unit logic, HMAC cryptography, physical safety rules, stress concurrency, fuzzing, and PDF generation.

To run the complete test suite:

```powershell
.venv\Scripts\python.exe -m pytest tests/
```

### Test Coverage Highlights
- **Database & User Authentication**: User creation, hashed credentials, and spatial audit log verification.
- **Cryptographic HMAC Security**: Key derivation, canonical payload serialization, and signature matching.
- **Stuxnet Safety Rules**: Single-parameter boundary enforcement and multi-variable coordinated hazard prevention.
- **Financial & Threat Index**: Asset loss calculation, noise ratio, and sensor drift risk metrics.
- **Incident Report Generation**: PDF creation and structural validation via ReportLab.
- **Serial Parser**: Multi-format parsing (JSON, CSV, Key-Value) with error tolerance.
- **Stress & Concurrency**: Multi-threaded client API requests under heavy load.
- **Payload Fuzzing**: Malformed inputs, SQL injection attempts, XSS payloads, and boundary conditions.

---

## REST API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/data` | `GET` | Fetches live telemetry, financial risk analytics, and recent spatial audit logs. |
| `/api/telemetry` | `POST` | Ingests sensor payload with HMAC-SHA256 signature verification. |
| `/api/setpoint` | `POST` | Issues a SCADA setpoint command subject to Physical Safety Enforcer validation. |
| `/api/rules/update` | `POST` | Configures safety threshold boundaries (max/min temperature and pressure). |
| `/api/simulate-attack` | `POST` | Triggers simulated attacks (`stuxnet`, `injection`, `privilege`) for security testing. |
| `/api/device/isolate` | `POST` | Manually puts the active field device into isolated quarantine. |
| `/api/device/rejoin` | `POST` | Clears device quarantine and restores network connectivity. |
| `/api/report/download` | `GET` | Generates and downloads the official incident audit PDF report. |
| `/api/serial/ports` | `GET` | Lists available COM serial ports on the host system. |
| `/api/serial/connect` | `POST` | Initiates serial gateway data ingestion from a specified COM port. |

---

## Repository Structure

```text
aegis-ics/
├── build/                 # PyInstaller build artifacts
├── dist/                  # Compiled standalone AegisICS.exe executable
├── docs/                  # Architectural specs and trust scoring documentation
├── src/                   # Core application source code
│   ├── analytics.py       # Financial exposure & threat index engine
│   ├── app.py             # Flask web application & REST API gateway
│   ├── database.py        # SQLAlchemy models & SQLite spatial audit engine
│   ├── launcher.py        # Desktop wrapper entrypoint
│   ├── reporting.py       # ReportLab PDF report generation engine
│   ├── safety_enforcer.py # Stuxnet-proof physical safety rule validator
│   ├── security.py        # HMAC-SHA256 signature & key management
│   ├── serial_gateway.py  # PySerial hardware connection manager
│   ├── simulator.py       # Hardware device telemetry simulator
│   └── templates/         # SCADA dashboard frontend HTML/JS/CSS
├── tests/                 # Comprehensive pytest test suite
├── .env.example           # Environment template configuration
├── pyproject.toml         # Python project configuration
├── README.md              # Project documentation & release overview
└── release_notes.txt      # Release changelog details
```

---

## Release Notes & Version 2.5.2 Updates

**Version 2.5.2 Final Production Release Summary**:
- **Cross-Platform Linux & Windows Deliverables**: Self-contained standalone binaries for Linux 64-bit ELF (`dist/linux/AegisICS`), Debian package (`dist/linux/aegis-ics_2.5.0_amd64.deb`), portable tarball (`dist/linux/aegis-ics-2.5.0-linux-x86_64.tar.gz`), and Windows desktop executable (`dist/AegisICS.exe`).
- **MX Linux XFCE Specialization**: Native SysVinit service management (`/etc/init.d/aegis-ics`), systemd unit alternative, XFCE desktop launcher and panel icons, dialout serial port permissions, and automatic headless fallback.
- **Universal Documentation Coverage**: 100% of all repository folders (17/17) contain clear, dedicated `README.md` guides.
- **100% Air-Gapped Offline Deployment**: Fully bundled standalone vendor static assets (`src/static/vendor/chart.umd.js` and `tailwind.min.css`) eliminating external CDN dependencies.
- **Retrained 5-Feature ML Pipeline**: Multi-variable Random Forest anomaly detection model over `[temperature, pressure, vibration, hall_effect, current]` achieving 1.0000 ROC-AUC.
- **Server-Sent Events (SSE) Live Stream**: Sub-second push telemetry endpoint (`/api/stream`) for low-latency SCADA updates with automatic polling fallback.
- **Interactive 2D Plant Digital Twin**: Vector-based spatial plant layout with animated process flow lines, sector grid coordinates, and node selection/telemetry inspector.
- **Forensic "Black Box" Time Scrubber**: Interactive timeline scrubbing, freeze-frame playback, one-click jump-to-incident, and resume-to-live streaming.
- **Gamified Cyber Defense Arena**: NIST SP 800-61 incident response challenge arena with 3 timed simulation scenarios (Stuxnet, Rogue HMAC, Thermal Creep) and defense scoring.
- **100% Test Suite Coverage**: 39/39 passing automated unit and integration tests covering all critical paths across both Linux and Windows runtimes.

For a full list of historical release changes, see [release_notes.txt](release_notes.txt).

---

## Development & Maintenance Team

- **Aegis ICS Core Engineering & Security Team**
  - **Organization**: Industrial Zero-Trust Working Group
  - **Email**: `security@aegis-ics.internal` / `support@aegis-ics.org`
  - **Repository**: [github.com/anshulec23-cloud/aegis-ics](https://github.com/anshulec23-cloud/aegis-ics)

---
*Aegis ICS - Safeguard Industrial Operations through Zero-Trust Engineering.*
