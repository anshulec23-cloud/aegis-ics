# Aegis ICS — Frontend Static Assets & SCADA Styling

This directory contains static styling, visual assets, application branding icons, and offline vendor bundles for the **Aegis ICS SCADA Dashboard**.

---

## File Manifest

| File | Purpose |
|---|---|
| [`terminal.css`](terminal.css) | **Authentic 1980s DEC VT-220 / IBM 3270 CRT Stylesheet**: Custom CSS providing P1 green phosphor color tokens (`#22c55e`, `#4ade80`), pitch-black backgrounds (`#000000`), subtle scanline overlays, eye-strain bloom calibration, and annunciator animations. |
| `achilles_icon.svg` | Scalable vector graphic badge for Aegis ICS, installed to system icon themes on Linux (`/usr/share/icons/hicolor/scalable/apps/aegis-ics.svg`). |
| `icon.png` | High-resolution 256x256 application icon used by the system tray and XFCE desktop panel (`/usr/share/pixmaps/aegis-ics.png`). |
| `Achilles.ico` | Multi-resolution Windows icon asset used for PyInstaller desktop packaging. |

---

## Subdirectories

* [`vendor/`](vendor): Contains fully air-gapped, offline vendor JavaScript and CSS bundles (`chart.umd.js` and `tailwind.min.css`), eliminating any external CDN dependency.
