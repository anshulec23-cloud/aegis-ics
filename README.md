# Aegis ICS - Simulation & V2.1.0 Snapshot Branch (`sim`)

Welcome to the `sim` branch of the Aegis ICS project. This branch serves as a historical snapshot and active simulation environment for the v2.1.0 architecture before the major v3.0 codebase restructuring and PyInstaller packaging.

## Branch Overview

This branch contains the foundational components of the Aegis ICS system across its evolutionary stages:

1. **`version-two/` (V2 Monolithic Architecture)**
   - The original Flask-based web application backend before it was bundled into a desktop executable.
   - Contains the initial SQLAlchemy models (`database.py`) and Alembic migration scripts.
   - Handles the basic serial port ingestion and the early SCADA dashboard UI (`templates/dashboard.html`).

2. **`server/` & `policies/` (V1 Distributed Architecture)**
   - The legacy distributed architecture utilizing an MQTT broker for communication.
   - JSON-based device policies and a policy engine to enforce safe operational ranges.
   - Contains the early AI integration for trust scoring (`server/ai_engine/`).

3. **`esp32_sim/` (Hardware Simulation)**
   - A critical software-based simulator designed to mimic ESP32 hardware sensors.
   - Includes anomaly injection (`anomaly_injector.py`) to simulate cyber-physical attacks and generate synthetic telemetry data for training the Machine Learning models.

## Usage

This branch is primarily preserved for running the **ESP32 Simulator** to generate synthetic data, and for testing the legacy V1 MQTT architecture or the raw V2 Flask backend without the desktop application wrapper.

To run the codebase from this branch, navigate to either `version-two/` or `server/` and use the respective `requirements.txt` to set up your virtual environment.
