# Aegis ICS — Compilation, Packaging & Release Pipeline Architecture

This document details the complete build, compilation, and packaging architecture for **Aegis ICS v2.5.2** across both **Linux (Debian / MX Linux)** and **Windows**.

---

## 1. Build Pipeline Overview

Aegis ICS produces self-contained, standalone release deliverables that embed the entire application runtime, eliminating any requirement for target machines to have pre-installed Python interpreters or third-party libraries.

```text
               Source Tree (src/, debian/, firmware/)
                                │
               ┌────────────────┴────────────────┐
               │                                 │
     [ Linux Build Pipeline ]         [ Windows Build Pipeline ]
     (build_scripts/build_linux.py)    (build_scripts/build.py)
               │                                 │
     PyInstaller (ELF 64-bit)          PyInstaller (PE32+ EXE)
               │                                 │
       ┌───────┴───────┐                         │
       │               │                         │
  [ dpkg-deb ]   [ tarfile ]                     │
       │               │                         │
       ▼               ▼                         ▼
   aegis-ics.deb    aegis-ics.tar.gz          AegisICS.exe
   (85.32 MB)       (85.49 MB)                (348.97 MB)
```

---

## 2. Linux Deliverables & Packaging Architecture

### 2.1 Standalone ELF Binary (`dist/linux/AegisICS`)
* **Specification**: [`build_scripts/AegisICS_linux.spec`](../build_scripts/AegisICS_linux.spec)
* **Entrypoint**: `src/main.py`
* **Static Assets Bundled**:
  * `src/templates/` -> `templates` (SCADA dashboard, login terminal)
  * `src/static/` -> `static` (`terminal.css`, `vendor/chart.umd.js`, `vendor/tailwind.min.css`, brand icons)
  * `src/model/` -> `model` (`rf_model.pkl`, `neural_safety_policy.pt`, `neural_safety_policy.npz`, `training_metrics.json`)
  * `aegis_v2.db` -> `.` (seed database schema)
* **Dynamic Linking**: Statically links required Python bytecode and shared C-extensions; dynamically links system `libc.so.6` (compatible with `libc6 >= 2.31`).

### 2.2 Debian Package (`dist/linux/aegis-ics_2.5.2_amd64.deb`)
* **Builder**: [`build_scripts/package_deb.py`](../build_scripts/package_deb.py)
* **Assembler**: Uses `dpkg-deb --build --root-owner-group` with automatic pure-Python `ar` archive fallback.
* **Target Layout**:
  * `/opt/aegis-ics/AegisICS`: Executable binary
  * `/opt/aegis-ics/aegis-ics.init`: SysVinit service script
  * `/usr/local/bin/aegis-ics`: Symlink for path access
  * `/usr/share/applications/aegis-ics.desktop`: XFCE / desktop menu entry
  * `/usr/share/icons/hicolor/scalable/apps/aegis-ics.svg`: SVG icon
  * `/usr/share/pixmaps/aegis-ics.png`: PNG pixmap
  * `/lib/systemd/system/aegis-ics.service`: systemd unit definition
  * `/var/lib/aegis-ics/`: Persistent database and WAL directory

### 2.3 Portable Tarball (`dist/linux/aegis-ics-2.5.2-linux-x86_64.tar.gz`)
* **Builder**: [`build_scripts/package_tarball.py`](../build_scripts/package_tarball.py)
* **Contents**:
  * `AegisICS`: Executable binary
  * `run.sh`: Zero-configuration portable launcher setting `AEGIS_DATA_DIR` to current directory
  * `install.sh`: Shell script supporting system-wide (`sudo`) or user-local (`~/.local/`) installation
  * `README.txt`, `aegis-ics.desktop`, `aegis-ics.svg`, `aegis-ics.png`

---

## 3. Step-by-Step Compilation Guide

### Building on Linux / MX Linux / WSL:
```bash
# 1. Install prerequisites
sudo apt update
sudo apt install -y python3 python3-pip python3-venv binutils dpkg-dev

# 2. Prepare virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r src/requirements.txt pyinstaller

# 3. Run automated Linux build
python3 build_scripts/build_linux.py
```

### Building on Windows:
```powershell
# 1. Prepare environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r src/requirements.txt pyinstaller

# 2. Run automated Windows build
python build_scripts/build.py
```

---

## 4. Verification & Validation Procedures

Every compiled binary must be validated through the two-phase verification check:

```bash
# Phase 1: Semantic Version Check
./dist/linux/AegisICS --version
# Expected Output: Aegis ICS v2.5.2

# Phase 2: Internal Self-Test
./dist/linux/AegisICS --check
# Expected Output: Aegis ICS v2.5.2 [SELF-TEST OK]
```
