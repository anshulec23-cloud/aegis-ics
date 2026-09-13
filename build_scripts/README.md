# Aegis ICS — Automated Compilation & Packaging Suite

This directory contains the automated build specifications, compilation scripts, and packaging utilities for building standalone executables and distribution packages for both **Linux** and **Windows**.

---

## File Manifest

| File | Target OS | Purpose |
|---|---|---|
| `AegisICS.spec` | Windows | PyInstaller specification file for compiling the standalone Windows binary (`dist/AegisICS.exe`) with embedded PyWebView, pystray, models, and UI assets. |
| `AegisICS_linux.spec` | Linux | PyInstaller specification file for compiling the standalone 64-bit ELF binary (`dist/AegisICS`) with Linux dynamic linking, WebKitGTK hooks, and offline assets. |
| `build.py` | Windows | Automated build runner for Windows. Terminates running instances, purges previous build caches, and compiles `AegisICS.exe`. |
| `build_linux.py` | Linux | Master Linux build pipeline runner. Compiles `dist/AegisICS`, executes self-verification tests, and invokes `package_deb.py` and `package_tarball.py`. |
| `build_linux.sh` | Linux | Shell wrapper for `build_linux.py`. Detects Python 3, validates PyInstaller installation, and launches the build runner. |
| `package_deb.py` | Linux | Assembles a native Debian binary package (`aegis-ics_2.5.0_amd64.deb`) with XDG desktop shortcuts, icons, SysVinit service script, and systemd unit. |
| `package_tarball.py` | Linux | Bundles the standalone ELF executable, launcher scripts (`run.sh`, `install.sh`), icons, and documentation into a portable `.tar.gz` archive. |

---

## How to Build

### Compiling on Linux (Debian / MX Linux / WSL):
```bash
# 1. Install prerequisites
sudo apt update && sudo apt install -y python3 python3-pip python3-venv binutils dpkg-dev

# 2. Run the automated Linux pipeline
python3 build_scripts/build_linux.py
```
Outputs are generated in [`dist/`](../dist) and [`dist/linux/`](../dist/linux).

### Compiling on Windows:
```powershell
# 1. Ensure Python 3.12+ and PyInstaller are installed
pip install -r src/requirements.txt pyinstaller

# 2. Run Windows build script
python build_scripts/build.py
```
Output executable is generated at [`dist/AegisICS.exe`](../dist/AegisICS.exe).
