# ESP32 Simulator

This folder simulates physical ESP32 field devices.

## Files
- `simulator.py` - main script for one simulated device.
- `anomaly_injector.py` - creates spikes, drift, flatline, and noise bursts.
- `device_policy.py` - blocks unsafe server commands.
- `device_config.json` - per-device settings and safe operating ranges.
- `requirements.txt` - Python dependencies for the simulator.
- `__init__.py` - marks the folder as a Python package.

## What It Does
It generates telemetry, signs it with HMAC, publishes it to MQTT, and refuses commands outside the local rules.
