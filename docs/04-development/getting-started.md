# Getting started

## Using the packaged app (no Python needed)

1. Run `AegisICS.exe` (Windows) or install the `.deb` (Linux).
2. **First launch** opens the *First-run setup* screen. Choose the administrator password (minimum 12 characters); you're signed in straight away. There's no default password and nothing to type in a console.
3. **Station 06 → Hardware gateway:** pick the master bridge's COM port (or **SOFTWARE EMULATOR** to try it without hardware) and click **CONNECT GATEWAY**.
4. Slaves on the bus appear under **Field device enrollment** as **PENDING**, each with a fingerprint. Compare the fingerprint with the slave's USB console if you like, give it a name, and click **APPROVE**. It starts streaming within seconds. Add more slaves at any time; they show up the same way.

All data (database, host identity key, session key, simulator state) lives in a per-user data folder: `%LOCALAPPDATA%\AegisICS` on Windows, `~/.local/share/aegis-ics` on Linux, `/var/lib/aegis-ics` for the system service. To keep data next to the exe instead (portable mode), put an empty file named `aegis_portable` beside it.

## Developer setup

### Prerequisites
- Python 3.11 or 3.12
- Optional: PyTorch (only to retrain the NSPN), Arduino IDE / `arduino-cli` (firmware), ESP32 + MAX485 boards (hardware loop)

### Install
```bash
git clone https://github.com/anshulec23-cloud/aegis-ics.git
cd aegis-ics
python -m venv .venv
# Windows: .\.venv\Scripts\Activate.ps1     Linux/macOS: source .venv/bin/activate
pip install -r src/requirements.txt
```

### Run

| Goal | Command | URL |
|---|---|---|
| Web dev server | `python src/app.py` | http://127.0.0.1:5000 |
| Desktop window | `python src/main.py` | opens a window on the setup page / dashboard |
| Headless like production | `python src/main.py --server --port 5000` | http://127.0.0.1:5000 (the setup link is printed in the log) |

In development the data directory defaults to the repository root (`aegis_v2.db` etc.). Point it elsewhere with `AEGIS_DATA_DIR`. For scripted setups, set `ADMIN_PASSWORD` (≥ 12 characters) to skip the setup screen.

### Data without hardware
Connect **SOFTWARE EMULATOR** in Station 06. The simulator plays the master plus `AEGIS_SIM_DEVICES` slaves (default 4). Each simulated slave has its own X25519 identity and goes through the same enrollment, signing, ACK and replay rules as the firmware. Approve them like real devices. Their telemetry is stored with `is_simulated = true` and excluded from PDF reports. The red-team drills in Station 04 inject attacks into simulated slaves only.

To run the gateway as a separate process instead, share a gateway token:
```bash
export AEGIS_GATEWAY_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
python src/app.py &
python src/serial_gateway.py --mock --sim-devices 6 --url http://127.0.0.1:5000/api/telemetry
```

### Tests
```bash
python -m pytest tests -q
```
See [testing.md](testing.md).

### Hardware loop
Flash the **same** `firmware/esp32_slave_sensor` image to every slave and `firmware/esp32_master_bridge` to the master. There's nothing to configure and no keys to generate. Wire the RS-485 bus, plug the master into USB, connect its COM port in Station 06 and approve the slaves. See [`firmware/README.md`](../../firmware/README.md).

### Repository map
See [ARCHITECTURE §4](../01-architecture/ARCHITECTURE.md#4-source-layout).
