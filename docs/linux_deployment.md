# Aegis ICS: Linux (Debian & MX Linux) Deployment & Operations Guide

## 1. Overview & Compatibility

**Aegis ICS v2.5.2** is fully optimized for **Debian-based Linux distributions**, with dedicated support for **MX Linux** (MX-21 / MX-23, Debian Bullseye / Bookworm / Trixie).

Aegis ICS supports both of MX Linux's operating modes:
* **Standalone Desktop GUI Application**: Native desktop window powered by PyWebView and WebKitGTK with system tray integration.
* **Continuous Headless SCADA Gateway Daemon**: 24/7 background service for edge industrial PCs and servers running either **SysVinit** (default on MX Linux) or **systemd**.

---

## 2. Installation Methods

### Method A: Debian Package (`.deb`) — Recommended for MX Linux

The `.deb` package installs Aegis ICS into `/opt/aegis-ics/`, creates system symlinks, registers the desktop entry in the MX Linux Application Menu (XFCE / KDE / Fluxbox), configures scalable icons, and sets up SysVinit and systemd service scripts.

```bash
# 1. Download or locate the package
cd dist/

# 2. Install via dpkg
sudo dpkg -i aegis-ics_2.5.0_amd64.deb

# 3. Resolve any optional desktop GUI dependencies (WebKitGTK)
sudo apt-get install -f
```

*Note for MX Linux users*: You can also right-click `aegis-ics_2.5.0_amd64.deb` in the file manager and select **Open with GDebi Package Installer** or use the **MX Package Installer**.

---

### Method B: Portable Tarball (`.tar.gz`) — Non-Root / Portable Mode

Ideal for environments where root access is restricted or for running from a portable USB drive:

```bash
# 1. Extract the tarball
tar -xvf aegis-ics-2.5.0-linux-x86_64.tar.gz
cd aegis-ics-2.5.0/

# 2. Run portably in-place (keeps SQLite database in current folder)
./run.sh

# 3. Or install for the current user without root:
./install.sh
```

---

## 3. Hardware & Serial Port Access (ESP32 / PLC)

On Debian and MX Linux, physical USB/Serial devices (e.g., `/dev/ttyUSB0`, `/dev/ttyACM0`) are restricted to the `dialout` system group.

### Granting Access
To allow Aegis ICS to read and write telemetry frames to field hardware:

```bash
# Add your user account to the dialout group
sudo usermod -a -G dialout $USER

# Log out and log back in, or activate group in current shell:
newgrp dialout
```

### Checking Connected Devices
```bash
ls -l /dev/ttyUSB* /dev/ttyACM*
```

---

## 4. Running Aegis ICS

### 4.1 Desktop GUI Mode
Run from terminal or launch **Aegis ICS** from the MX Linux application menu:

```bash
aegis-ics
```

*Prerequisites for Desktop GUI*:
```bash
sudo apt-get install -y libwebkit2gtk-4.1-0 gir1.2-webkit2-4.1 libgtk-3-0
```

### 4.2 Headless SCADA Gateway Server Mode
If running on an industrial edge PC without a display monitor, over SSH, or inside a container:

```bash
# Listen on localhost port 5000:
aegis-ics --server --port 5000

# Listen on all network interfaces for remote SCADA access:
aegis-ics --server --host 0.0.0.0 --port 5000
```

Open a web browser on any network workstation and navigate to:
`http://<SERVER_IP>:5000`

---

## 5. Background Service Management

Aegis ICS includes support for both **SysVinit** (MX Linux default) and **systemd**.

### 5.1 SysVinit (MX Linux Default)
```bash
# Start the Aegis ICS gateway service
sudo service aegis-ics start

# Check status
sudo service aegis-ics status

# Stop service
sudo service aegis-ics stop

# Restart service
sudo service aegis-ics restart

# View logs
tail -f /var/log/aegis-ics.log
```

### 5.2 systemd (Optional on MX Linux)
```bash
# Enable service at boot
sudo systemctl enable aegis-ics.service

# Start the service
sudo systemctl start aegis-ics.service

# Check service status
sudo systemctl status aegis-ics.service

# View live systemd logs
sudo journalctl -u aegis-ics.service -f
```

---

## 6. Building the Linux Package from Source

To build the standalone executable, `.deb` package, and portable tarball from source on Debian or MX Linux:

```bash
# 1. Install build tools and Python environment
sudo apt update
sudo apt install -y python3 python3-pip python3-venv binutils dpkg-dev

# 2. Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r src/requirements.txt
pip install pyinstaller

# 3. Execute the automated Linux build pipeline
python3 build_scripts/build_linux.py
```

Generated deliverables will be placed in `dist/` and `dist/linux/`:
* `dist/linux/AegisICS` (Standalone ELF executable)
* `dist/linux/aegis-ics_2.5.0_amd64.deb` (Debian package)
* `dist/linux/aegis-ics-2.5.0-linux-x86_64.tar.gz` (Portable archive)
* `dist/linux/README.md` (Quickstart & operations guide)

