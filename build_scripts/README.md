# Aegis ICS — Automated Compilation & Packaging Suite

This directory contains the automated build specifications, compilation scripts, and packaging utilities for building standalone executables and distribution packages for both **Linux** and **Windows**.

---

## File Manifest

| File | Target OS | Purpose |
|---|---|---|
| `build.py` | Multi-Platform | Universal build dispatcher. Detects host OS and automatically delegates to `build_windows.py` or `build_linux.py`. Supports `--windows` and `--linux` flags. |
| `build_windows.py` | Windows | Automated production build pipeline for Windows. Terminates running instances, purges staging cache, and compiles `dist/AegisICS.exe`. |
| `build_linux.py` | Linux | Master Linux build pipeline runner. Compiles `dist/linux/AegisICS`, executes self-verification tests, and invokes packaging routines. |
| `build_linux.sh` | Linux | Shell wrapper for `build_linux.py`. Detects Python 3, validates PyInstaller installation, and launches the build runner. |
| `AegisICS.spec` | Windows | PyInstaller specification file for compiling the standalone Windows binary (`dist/AegisICS.exe`) with embedded assets, firmware, models, and dependencies. |
| `AegisICS_linux.spec` | Linux | PyInstaller specification file for compiling the standalone 64-bit ELF binary (`dist/linux/AegisICS`) with Linux dynamic linking and offline assets. |
| `package_deb.py` | Linux | Assembles a native Debian binary package (`aegis-ics_2.5.2_amd64.deb`) with XDG desktop shortcuts, icons, SysVinit service script, and systemd unit. |
| `package_tarball.py` | Linux | Bundles the standalone ELF executable, launcher scripts (`run.sh`, `install.sh`), icons, and documentation into a portable `.tar.gz` archive. |

---

## How to Build

### Universal Build Command:
```bash
# Automatically detects OS and compiles appropriate target:
python build_scripts/build.py
```

### Compiling Specifically on Windows:
```powershell
# 1. Ensure Python 3.12+ and PyInstaller are installed
pip install -r src/requirements.txt pyinstaller

# 2. Run Windows build pipeline
python build_scripts/build_windows.py
```
Output executable is generated at [`dist/AegisICS.exe`](../dist/AegisICS.exe).

### Compiling Specifically on Linux (Debian / MX Linux / Ubuntu / WSL):
```bash
# 1. Install prerequisites
sudo apt update && sudo apt install -y python3 python3-pip python3-venv binutils dpkg-dev

# 2. Run the automated Linux pipeline
python3 build_scripts/build_linux.py
```
Outputs are generated in [`dist/`](../dist) and [`dist/linux/`](../dist/linux).
