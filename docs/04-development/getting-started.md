# Getting started (developers)

## Prerequisites
- Python 3.11 or 3.12 (3.11 is the oldest tested; `pyproject.toml` targets py310 for Black)
- Git
- Optional: PyTorch (only to retrain the NSPN), Arduino IDE or PlatformIO (firmware), an ESP32 + MAX485 kit (hardware loop)

## 1. Install
```bash
git clone https://github.com/anshulec23-cloud/aegis-ics.git
cd aegis-ics
python -m venv .venv
# Windows: .\.venv\Scripts\Activate.ps1     Linux/macOS: source .venv/bin/activate
pip install -r src/requirements.txt
```
`src/requirements.txt` includes desktop-only packages (`pywebview`, `pystray`, `pillow`). On headless Linux, `pywebview` may need GTK/Qt system libraries. The server runs without it.

## 2. Configure
The app reads environment variables only. It does **not** load `.env` automatically, so export them or use your IDE's env support. Template: [`.env.example`](../../.env.example).

```bash
# 1. Device keys (there are no built-in keys; devices without one are rejected)
python src/device_keys.py generate ESP32_001 ESP32_002 ESP32_003 ESP32_004 --out device_keys.json
export AEGIS_DEVICE_KEYS_FILE="$PWD/device_keys.json"

# 2. Admin password (optional: if unset, one is generated and printed on first start)
export ADMIN_PASSWORD='choose-a-strong-one-12+'
export FLASK_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"
```
All variables: [configuration.md](configuration.md).

## 3. Run

| Goal | Command | URL |
|---|---|---|
| Web dev server | `python src/app.py` | http://127.0.0.1:5000 |
| Desktop window | `python src/main.py` | opens a window (random port) |
| Headless like production | `python src/main.py --server --port 5000` | http://127.0.0.1:5000 |

Log in as `admin` with your `ADMIN_PASSWORD`. If you didn't set one, use the generated password printed in the console, which is also saved to `initial_admin_password.txt` next to the database.

## 4. Get data flowing without hardware
In the dashboard go to **Station 06 → Hardware gateway**, choose **SOFTWARE EMULATOR (Mock Driver)** and connect. This starts the simulator thread. It plays the four field devices and signs each frame with that device's own key. Telemetry it produces is stored with `is_simulated = true` and excluded from PDF reports.

To run the simulator as a separate process instead, give both processes the same gateway token:
```bash
export AEGIS_GATEWAY_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
python src/app.py &
python src/serial_gateway.py --mock --url http://127.0.0.1:5000/api/telemetry
```

## 5. Run the tests
```bash
python -m pytest tests -q
```
See [testing.md](testing.md).

## 6. Hardware loop
Generate the firmware key header (`--firmware-header firmware/esp32_slave_sensor/aegis_secrets.h`, see step 2), then flash `firmware/esp32_slave_sensor` (one `NODE_CONFIG_ESP32_00x` per board) and `firmware/esp32_master_bridge`, wire the RS-485 transceivers, plug the master into USB, then select its COM port in Station 06. Wiring: [`firmware/README.md`](../../firmware/README.md).

## 7. Repository map
See [ARCHITECTURE §4](../01-architecture/ARCHITECTURE.md#4-source-layout).
