# Aegis ICS — SCADA User Interface Templates

This directory contains the Jinja2 HTML/JavaScript templates for the **Aegis ICS Supervisory Control and Data Acquisition (SCADA)** interface.

---

## Template Manifest

### 1. [`dashboard.html`](dashboard.html) (239 KB)
The primary operator console for plant monitoring and active defense enforcement:
* **Authentic 1980s DEC VT-220 CRT Design**: Green monochrome phosphor layout with scanline toggles, UTC mission clock, and auditory annunciator controls.
* **Interactive 2D Plant Digital Twin**: Vector SVG plant schematic with animated process flow lines, sector grid coordinates, and node status inspector cards.
* **Forensic "Black Box" Time Scrubber**: Interactive timeline slider that slices historical telemetry buffers, dynamically recalculates physical metrics, and supports one-click seeking to safety trips (`is_anomaly === 1`).
* **Operator Defense Challenge Arena (NIST SP 800-61)**: Interactive gamified scenarios (*Stuxnet Resonance*, *Rogue HMAC Spoofing*, *Stealth Thermal Creep*) with real-time countdown timers and scoring.
* **Aegis Incident Advisor**: Slide-over drawer providing situational root-cause diagnosis and containment SOP guidance.
* **Real-Time Telemetry Charts**: Chart.js monotone cubic spline charts tracking temperature, pressure, vibration, Hall RPM, and loop current.
* **Red Team Attack Injection Suite**: Live simulation of cyber-physical attack profiles.
* **Live NIST SP 800-53 Audit Trail**: Append-only streaming security log with control mappings.

### 2. [`login.html`](login.html)
Terminal login screen enforcing cryptographic credential verification and physical spatial attribution:
* **Spatial Coordinate Capture**: Requires input of physical 3D terminal coordinates (`X, Y, Z`) or GPS geolocation (`Lat, Lon, Elev`).
* **CSRF Token Verification**: Protects against cross-site request forgery.
* **DEC VT-220 CRT Styling**: Matches the green phosphor terminal aesthetic.
