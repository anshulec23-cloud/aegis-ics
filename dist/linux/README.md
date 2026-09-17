# Aegis ICS v2.5.0 — Linux Application Release & Operations Guide

Welcome to the official Linux distribution directory for **Aegis ICS v2.5.0**. This directory contains production-ready, standalone release deliverables engineered specifically for **Debian-based Linux distributions**, with dedicated optimizations and hardening for **MX Linux (XFCE Edition)**.

---

## What is Aegis ICS?

**Aegis ICS** is an industrial zero-trust security gateway, cyber-physical safety enforcer, and real-time SCADA supervisory system. It bridges physical field edge devices (such as ESP32 microcontrollers, RTUs, and industrial PLCs) across **Purdue Model Levels 0, 1, and 2** with cryptographic authentication, multi-variable safety rules, and autonomous hardware microsegmentation.

### Core Capabilities:
* **Zero-Trust Telemetry Ingestion**: Every sensor transmission is cryptographically validated using canonical HMAC-SHA256 signatures with per-node key isolation.
* **Stuxnet-Proof Physical Safety Enforcer**: Evaluates mathematical physical stress boundaries across temperature, pressure, vibration, rotor RPM, and stator current to block dangerous setpoint combinations before execution.
* **Dual-Engine AI/ML Pipeline**: 5-feature Random Forest model running local real-time inference with 0.9755 ROC-AUC (5-fold CV F1: 0.9623) alongside a 6D Deep Neural Safety Policy Network (NSPN) achieving 96.08% validation accuracy and 0.025 ms vectorized inference.
* **Autonomous Microsegmentation**: Sub-second transition to `ISOLATED` state upon anomaly detection, returning HTTP 403 and dispatching physical optocoupler relay trip commands over serial UART within 12.74 ms.
* **100% Air-Gapped Operation**: Bundled offline Chart.js and Tailwind CSS assets requiring zero internet connectivity.
* **Authentic 1980s DEC VT-220 SCADA Dashboard**: Green phosphor CRT interface with interactive 2D Plant Digital Twin, forensic "Black Box" time scrubber, and gamified NIST SP 800-61 operator defense drills.

---

## File Inventory in this Directory

| File Name | Format | Size | Description |
|---|---|---|---|
| `AegisICS` | ELF 64-bit Executable | **92.14 MB** | Standalone native Linux binary. Statically bundles Python 3 runtime, Flask web gateway, Scikit-Learn ML pipeline, SQLite WAL database, and UI assets. Requires **no** external Python libraries. |
| `aegis-ics_2.5.0_amd64.deb` | Debian Package | **91.27 MB** | Native installer for MX Linux (MX-21 / MX-23) and Debian (Bullseye / Bookworm). Integrates with GDebi, MX Package Installer, and `dpkg`. Configures XFCE menu shortcuts, SysVinit script, and systemd service. |
| `aegis-ics-2.5.0-linux-x86_64.tar.gz` | Portable Tarball | **91.45 MB** | Self-contained portable archive for non-root environments or running directly from a USB flash drive. Includes `run.sh` and `install.sh`. |

---

## Quickstart Commands for Any Linux Environment

### Method 1: Run the Standalone Binary Directly (Fastest)

Ensure the binary has executable permissions and run:

```bash
# 1. Grant execute permissions
chmod +x AegisICS

# 2. Verify binary integrity
./AegisICS --version
./AegisICS --check

# 3A. Launch in Desktop GUI Mode (XFCE / GNOME / KDE / X11)
./AegisICS

# 3B. Launch in 24/7 Headless SCADA Server Mode (Localhost port 5000)
./AegisICS --server --port 5000

# 3C. Launch for Remote Network Workstations (All interfaces 0.0.0.0)
./AegisICS --server --host 0.0.0.0 --port 5000
```

Open a web browser on any networked workstation and navigate to:
`http://<SERVER_IP>:5000`

---

### Method 2: Install via Debian Package (`.deb`) — Recommended for MX Linux

The `.deb` package installs Aegis ICS into `/opt/aegis-ics/`, creates system symlinks (`/usr/local/bin/aegis-ics`), registers desktop entries in the **MX Linux XFCE Application Menu**, configures icons, and deploys SysVinit and systemd service scripts.

```bash
# 1. Install via dpkg
sudo dpkg -i aegis-ics_2.5.0_amd64.deb

# 2. Resolve any optional desktop GUI dependencies (WebKitGTK)
sudo apt-get install -f

# 3. Grant hardware USB/Serial port access for ESP32/PLC field units
sudo usermod -a -G dialout $USER
newgrp dialout

# 4. Launch from XFCE Application Menu (under System / Security) or run:
aegis-ics
```

*Note for MX Linux users*: You can also right-click `aegis-ics_2.5.0_amd64.deb` in the file manager and choose **Open with GDebi Package Installer** or use the **MX Package Installer**.

---

### Method 3: 24/7 Background Service (SysVinit & systemd)

#### SysVinit (MX Linux Default Init System)
```bash
# Start the Aegis ICS gateway service
sudo service aegis-ics start

# Check running status & PID
sudo service aegis-ics status

# View live daemon logs
tail -f /var/log/aegis-ics.log

# Stop or restart service
sudo service aegis-ics restart
sudo service aegis-ics stop
```

#### systemd (Alternative on MX Linux / Standard Debian)
```bash
# Enable at system startup
sudo systemctl enable aegis-ics.service

# Start the service
sudo systemctl start aegis-ics.service

# Check service health
sudo systemctl status aegis-ics.service

# View live systemd journal logs
sudo journalctl -u aegis-ics.service -f
```

---

### Method 4: Portable USB / Non-Root Execution (`.tar.gz`)

Ideal when root/sudo privileges are restricted:

```bash
# 1. Extract the tarball
tar -zxvf aegis-ics-2.5.0-linux-x86_64.tar.gz
cd aegis-ics-2.5.0/

# 2. Run portably in-place (stores database in current directory)
./run.sh

# 3. Or install for the current user into ~/.local/bin:
./install.sh
```

---

## Hardware USB/Serial Configuration (ESP32 / Industrial PLC)

To allow Aegis ICS to communicate with edge microcontrollers over USB/Serial (`/dev/ttyUSB0`, `/dev/ttyACM0`):

```bash
# 1. Add your user account to the dialout group
sudo usermod -a -G dialout $USER

# 2. Apply group change immediately without logging out
newgrp dialout

# 3. Verify connected serial devices
ls -l /dev/ttyUSB* /dev/ttyACM*
```

In the SCADA Dashboard, navigate to **Hardware Connection**, click **Scan Ports**, select your port (e.g., `/dev/ttyUSB0`), select baud rate `115200`, and click **Connect**.

---

## CLI Options Reference

| Flag | Argument | Default | Description |
|---|---|---|---|
| `--server`, `-s` | None | N/A | Forces headless SCADA web gateway mode (disables desktop GUI window). |
| `--port`, `-p` | `<port_number>` | `5000` (server) / ephemeral (GUI) | Port number to bind the Flask WSGI server. |
| `--host`, `-h` | `<ip_address>` | `127.0.0.1` | Network interface to bind (`0.0.0.0` for all interfaces). |
| `--version` | None | N/A | Prints application version string (`Aegis ICS v2.5.0`) and exits cleanly. |
| `--check` | None | N/A | Performs internal health and self-test checks and exits with status 0. |

---

## Default Credentials & Access

* **Operator Username**: `admin`
* **Operator Password**: `admin` (or configured via `ADMIN_PASSWORD` environment variable)
* **Cartesian Station Geolocation**: Input terminal coordinates upon login (e.g., `X: 12.40, Y: -48.10, Z: 3.50`).

---

## Troubleshooting

1. **GUI Window fails to open on minimal server**:
   - Install WebKitGTK: `sudo apt-get install -y libwebkit2gtk-4.1-0 gir1.2-webkit2-4.1 libgtk-3-0`
   - Or launch with `--server` to access via browser: `./AegisICS --server --port 5000`
2. **Permission denied opening `/dev/ttyUSB0`**:
   - Ensure user is in `dialout` group: `sudo usermod -a -G dialout $USER` and run `newgrp dialout`.
3. **Port 5000 already in use**:
   - Specify a custom port: `./AegisICS --server --port 8080`
