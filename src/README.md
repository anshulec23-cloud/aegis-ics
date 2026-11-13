# Aegis ICS — Core Application Architecture & Modules

This directory contains the primary backend application source code, security enforcement algorithms, machine learning models, and database engine for **Aegis ICS v2.5.2**.

---

## Source Code Modules & Responsibilities

| Module | Primary Responsibility |
|---|---|
| [`app.py`](app.py) | **Central REST API & Web Gateway**: Flask application managing HTTP routes, CSRF token validation, rate-limiting, Server-Sent Events (`/api/stream`), spatial coordinate logins, and telemetry ingestion. |
| [`safety_enforcer.py`](safety_enforcer.py) | **Stuxnet Physical Safety Enforcer**: Evaluates operator setpoints (`set_temp`, `set_pressure`) against cross-variable physical boundaries to block coordinated destructive attacks. |
| [`trust_engine.py`](trust_engine.py) | **Continuous Mathematical Trust Calculator**: Computes normalized $T_{\text{final}} \in [0.0, 1.0]$ based on anomaly probability, HMAC validity, rolling mean deviation, and signal stability. |
| [`analytics.py`](analytics.py) | **Cyber-Financial Governance Engine**: Implements FAIR quantitative risk modeling, SLE/ALE/ARO loss calculations, hourly outage liabilities, statutory fines (EPA, NERC CIP, NIS2), and 12-point Monte Carlo loss distributions. |
| [`database.py`](database.py) | **State Persistence & Spatial Audit Engine**: SQLAlchemy models for users, telemetry logs, device states, and audit logs tagged with 3D Cartesian terminal coordinates (`X, Y, Z`). Configured with SQLite Write-Ahead Logging (WAL). |
| [`reporting.py`](reporting.py) | **NIST SP 800-82 Compliance PDF Generator**: ReportLab engine dynamically compiling a publication-grade 10-section security audit and incident documentation PDF. |
| [`security.py`](security.py) | **Cryptographic Security & Anti-Debug**: Per-node HMAC-SHA256 key management, ephemeral port allocation, resource path resolution for frozen builds, and debugger detection. |
| [`serial_gateway.py`](serial_gateway.py) | **Hardware RS-485 / COM Port Gateway**: PySerial communication layer with DTR/RTS anti-reset protection, multi-format parsing (JSON, CSV, KV), mock multi-node simulation, and UART command queues. |
| [`main.py`](main.py) | **Application Desktop Launcher**: Manages lifecycle, ephemeral port binding, system tray (`pystray`), PyWebView embedded window, and automatic fallback to headless server mode. |
| [`train_model.py`](train_model.py) | **ML Training Pipeline**: Synthesizes 5-feature multi-variable industrial telemetry datasets and exports the optimized Random Forest classifier (`rf_model.pkl`). |
| [`tray.py`](tray.py) | **System Tray Integration**: Native taskbar/system tray menu for Windows and Linux with minimize-to-tray and background service status. |
| [`updater.py`](updater.py) | **Release Update Checker**: Background worker checking GitHub API for new semver release tags and notifying the operator dashboard. |

---

## Subdirectories in `src/`

* [`model/`](model): Contains the trained Scikit-Learn Random Forest anomaly detection model (`rf_model.pkl`).
* [`static/`](static): Contains terminal styling (`terminal.css`), application icons, and offline vendor libraries (`src/static/vendor/`).
* [`templates/`](templates): Contains the Jinja2 SCADA dashboard interface (`dashboard.html`) and login terminal (`login.html`).
* [`alembic/`](alembic): Contains Alembic database migration environment and version scripts.
