# Aegis ICS — Debian & MX Linux Packaging Configuration

This directory contains Debian packaging metadata, desktop launcher files, maintainer hook scripts, and init service scripts used to build the official `aegis-ics_2.5.0_amd64.deb` package for **MX Linux** and **Debian**.

---

## 📁 File Manifest

| File | Type | Purpose |
|---|---|---|
| `control` | Debian Control | Package metadata: name (`aegis-ics`), version (`2.5.0`), architecture (`amd64`), and package dependencies (`libc6 >= 2.31`, recommends WebKitGTK 4.0 / 4.1). |
| `aegis-ics.desktop` | XDG Desktop Entry | Registers Aegis ICS in the **XFCE Application Menu** under *System* and *Security*, binding to `/usr/local/bin/aegis-ics` and system icons. |
| `aegis-ics.init` | SysVinit Script | 24/7 background service management script for **MX Linux** (which defaults to SysVinit). Installed into `/etc/init.d/aegis-ics`. |
| `aegis-ics.service` | systemd Unit | Service configuration file for systemd-booted environments, managing daemon execution and auto-restart. |
| `postinst` | Shell Script | Post-installation hook: creates `/var/lib/aegis-ics`, symlinks `/usr/local/bin/aegis-ics`, updates desktop databases, and prompts for `dialout` group membership. |
| `prerm` | Shell Script | Pre-removal hook: safely terminates running SysVinit or systemd services before uninstallation. |
| `postrm` | Shell Script | Post-removal hook: cleans symlinks and refreshes desktop icon caches upon package purge. |

---

## 📦 Target Filesystem Layout upon `.deb` Installation

When `aegis-ics_2.5.0_amd64.deb` is installed via `dpkg -i`, files are placed in standard Linux directories:
* `/opt/aegis-ics/AegisICS`: Main executable binary
* `/opt/aegis-ics/aegis-ics.init`: SysVinit service template
* `/usr/local/bin/aegis-ics`: Symlink for terminal execution
* `/usr/share/applications/aegis-ics.desktop`: Application menu entry
* `/usr/share/icons/hicolor/scalable/apps/aegis-ics.svg`: Scalable vector icon
* `/usr/share/pixmaps/aegis-ics.png`: Application pixmap icon
* `/lib/systemd/system/aegis-ics.service`: systemd service definition
* `/etc/init.d/aegis-ics`: Active SysVinit control script
* `/var/lib/aegis-ics/`: Persistent database and runtime storage
