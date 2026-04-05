# Policies

This folder contains the rules that limit what the server and each device are allowed to do.

## Files
- `__init__.py` - marks `policies` as a Python package.
- `server_policy.json` - the server-side command limits.
- `policy_engine.py` - checks outgoing commands before they are sent.
- `device_policies/<DEVICE_ID>.json` - per-device allowed ranges mirrored by the simulator.

## What It Does
These rules stop unsafe server commands, block privilege escalation, and keep isolated devices separated until re-authenticated.
