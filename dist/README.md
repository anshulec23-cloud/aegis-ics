# Aegis ICS v2.5.2 — Release Distribution Directory

This directory contains the production release artifacts and compiled standalone deliverables for **Aegis ICS v2.5.2**.

---

## Directory Structure & Deliverables

```text
dist/
├── linux/                                  # Dedicated Linux application distribution
│   ├── AegisICS                            # Standalone 64-bit ELF binary
│   ├── aegis-ics_2.5.2_amd64.deb           # Debian package for MX Linux / Debian
│   ├── aegis-ics-2.5.2-linux-x86_64.tar.gz # Portable standalone tarball
│   └── README.md                           # Comprehensive Linux operations & quickstart guide
│
├── AegisICS                                # Direct symlink/copy of standalone Linux ELF binary
├── AegisICS.exe                            # Standalone Windows desktop executable
├── aegis-ics_2.5.2_amd64.deb               # Direct copy of Debian package
├── aegis-ics-2.5.2-linux-x86_64.tar.gz     # Direct copy of Linux portable tarball
└── README.md                               # This release distribution guide
```

---

## Operating System Quickstart

### For Linux Users (MX Linux / Debian / Ubuntu):
Navigate to the dedicated [`dist/linux/`](linux) folder and consult [`dist/linux/README.md`](linux/README.md):
```bash
# 1. Direct standalone execution
chmod +x dist/linux/AegisICS
./dist/linux/AegisICS

# 2. Or install Debian package:
sudo dpkg -i dist/linux/aegis-ics_2.5.2_amd64.deb
```

### For Windows Users:
Double-click [`dist/AegisICS.exe`](AegisICS.exe) to start the standalone native desktop application. The embedded PyWebView window and system tray icon will initialize automatically.

---

## Cryptographic Integrity & Offline Readiness
All binaries in this directory are 100% self-contained and pre-bundled with:
* Local vendor static assets (`chart.umd.js`, `tailwind.min.css`) in `src/static/vendor/`
* Scikit-Learn 5-feature Random Forest classifier (`rf_model.pkl`)
* Seed SQLite database schema (`aegis_v2.db`)
* ReportLab PDF generation engine
