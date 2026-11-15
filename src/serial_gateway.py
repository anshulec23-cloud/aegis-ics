"""
Aegis ICS V2 — Production Serial COM Port Telemetry Gateway Driver

Listens to the designated serial COM port (USB connection from the ESP32),
parses the sensor readings, and forwards **device-signed** frames to the Aegis
ingestion API. The gateway never signs telemetry on a device's behalf (unless
explicitly run with ``--allow-unsigned`` for bench testing): a frame without a
device signature is dropped.

Outbound commands are queued with a time-to-live; commands older than
``COMMAND_TTL_SECONDS`` are discarded instead of being replayed later.
"""

import sys
import os
import time
import json
import hmac
import hashlib
import argparse
import requests

try:
    import serial

    serial_available = True
except ImportError:
    serial_available = False

import secrets
import queue

import protocol

try:
    from security import get_device_key
except ImportError:
    from src.security import get_device_key

DEFAULT_GATEWAY_URL = "http://127.0.0.1:5000/api/telemetry"
GATEWAY_TOKEN_HEADER = "X-Aegis-Gateway-Token"

# Commands older than this are dropped rather than written to the bus (debug report F3).
COMMAND_TTL_SECONDS = float(os.environ.get("AEGIS_COMMAND_TTL_S", "5"))

import threading  # noqa: E402
import collections  # noqa: E402

# One stop event per gateway run: stop_gateway() sets the *current* run's event, and a
# new run gets a fresh event, so an old thread can never be revived (debug report F4).
_gateway_stop_event = threading.Event()
_gateway_stop_event.set()
_active_port = None
_command_queue = queue.Queue()
_raw_packet_buffer = collections.deque(maxlen=150)
_buffer_lock = threading.Lock()

_active_nodes = {}
_master_bridge_info = {"status": "OFFLINE", "last_seen": None, "details": None}
_gateway_state = "DISCONNECTED"


def stop_gateway():
    global _gateway_state
    _gateway_stop_event.set()
    _gateway_state = "DISCONNECTED"


def is_connected() -> bool:
    """True when a gateway run is active and its transport is connected."""
    return (not _gateway_stop_event.is_set()) and _gateway_state == "CONNECTED"


def is_mock_active() -> bool:
    """True while the software simulator (not real hardware) is feeding telemetry."""
    return (
        (not _gateway_stop_event.is_set())
        and bool(_active_port)
        and str(_active_port).upper().startswith(("SIM", "MOCK"))
    )


def get_active_port():
    return _active_port if not _gateway_stop_event.is_set() else None


def get_gateway_state():
    return _gateway_state


def get_master_bridge_info():
    with _buffer_lock:
        return dict(_master_bridge_info)


def get_active_nodes():
    """Returns detected active slave nodes and their sensor profiles."""
    now = time.time()
    with _buffer_lock:
        result = {}
        for dev_id, info in _active_nodes.items():
            sensors_list = sorted(list(info.get("sensors", [])))
            result[dev_id] = {
                "device_id": dev_id,
                "first_seen": info.get("first_seen"),
                "last_seen": info.get("last_seen"),
                "packet_count": info.get("packet_count", 0),
                "sensors": sensors_list,
                "active_sensors_count": len(sensors_list),
                "is_online": (now - info.get("last_seen", 0)) <= 10.0,
                "latest_values": dict(info.get("latest_values", {})),
            }
        return result


def get_gateway_health():
    """Returns comprehensive gateway health and bus topology status."""
    active = get_active_nodes()
    total_sensors = sum(n["active_sensors_count"] for n in active.values())
    online_nodes = sum(1 for n in active.values() if n["is_online"])
    return {
        "state": _gateway_state,
        "active_port": _active_port,
        "active_nodes_count": len(active),
        "online_nodes_count": online_nodes,
        "total_active_sensors": total_sensors,
        "master_bridge": get_master_bridge_info(),
    }


def find_esp32_ports():
    """Scans and returns serial ports with ESP32 / USB-UART hardware flags."""
    if not serial_available:
        return []
    try:
        from serial.tools import list_ports

        results = []
        # Common USB-UART bridge identifiers used with ESP32 boards
        esp_keywords = [
            "CP210",
            "CH340",
            "CH341",
            "FTDI",
            "UART",
            "ESP32",
            "USB SERIAL",
            "USB-SERIAL",
        ]
        for p in list_ports.comports():
            desc = p.description or ""
            hwid = getattr(p, "hwid", "") or ""
            is_esp = any(k in desc.upper() or k in hwid.upper() for k in esp_keywords)
            results.append(
                {
                    "device": p.device,
                    "description": desc,
                    "hwid": hwid,
                    "is_esp32_candidate": is_esp,
                }
            )
        return results
    except Exception as e:
        print(f"[Gateway] Error enumerating ports: {e}")
        return []


def send_command(payload_dict):
    """Sign (with the target device's key) and enqueue a command for the serial bus.

    Broadcast commands (target ``ALL``) are sent unsigned until protocol v1 adds a bus key
    (restructure plan P2.1). Raises ``ValueError`` if a unicast target has no key.
    """
    if not isinstance(payload_dict, dict):
        raise TypeError("command must be a dict")
    cmd = {k: v for k, v in payload_dict.items() if not k.startswith("_")}
    target_device = cmd.get("target_device") or cmd.get("device_id") or "ALL"
    if not cmd.get("signature") and target_device != "ALL":
        key = get_device_key(target_device)
        if not key:
            raise ValueError(f"No HMAC key provisioned for {target_device}; command not sent.")
        cmd["signature"] = sign_message({k: v for k, v in cmd.items() if k != "signature"}, key)
    cmd["_enqueued_at"] = time.time()
    _command_queue.put(cmd)
    return cmd


def send_frame(frame: dict, command_log_id=None):
    """Enqueue an already-signed protocol-v1 frame (CMD / WELCOME) for the bus."""
    item = dict(frame)
    item["_enqueued_at"] = time.time()
    if command_log_id is not None:
        item["_log_id"] = command_log_id
    _command_queue.put(item)
    return item


def _pop_ready_with_meta(now=None):
    """Drain the queue: ``[(clean_frame, command_log_id_or_None)]``; expired items are dropped
    (and their command-log rows marked EXPIRED)."""
    now = time.time() if now is None else now
    ready = []
    while True:
        try:
            cmd = _command_queue.get_nowait()
        except queue.Empty:
            break
        age = now - float(cmd.get("_enqueued_at", now))
        log_id = cmd.get("_log_id")
        if age > COMMAND_TTL_SECONDS:
            name = cmd.get("cmd") or cmd.get("type") or cmd.get("command") or cmd.get("action")
            print(f"[Gateway] Dropping expired command ({age:.1f}s old): {name}")
            if log_id is not None:
                try:
                    import registry

                    registry.mark_command(log_id, "EXPIRED", "not delivered within TTL")
                except Exception:
                    pass
            continue
        ready.append(({k: v for k, v in cmd.items() if not k.startswith("_")}, log_id))
    return ready


def pop_ready_commands(now=None):
    """Drain the queue, returning unexpired commands/frames with internal fields removed."""
    return [item for item, _ in _pop_ready_with_meta(now)]


def purge_command_queue():
    """Discard everything queued (used when a new gateway run starts)."""
    while True:
        try:
            _command_queue.get_nowait()
        except queue.Empty:
            return


def get_recent_raw_packets(limit=50):
    with _buffer_lock:
        return list(_raw_packet_buffer)[-limit:]


def log_raw_wire_packet(line: str, parsed: bool = True, target_id: str = "ESP32_001"):
    with _buffer_lock:
        _raw_packet_buffer.append(
            {
                "timestamp": time.time(),
                "line": line.strip(),
                "parsed": parsed,
                "device_id": target_id,
            }
        )


def canonicalize_payload(payload: dict) -> dict:
    """The one canonical form used for signing AND verification (see docs/01-architecture/protocols.md).

    Sensor values -> strings with 2 decimals; ``timestamp`` -> 3 decimals (or the original
    string if it is not numeric, e.g. ISO-8601); ``None`` values are omitted.
    """
    canonical = {}
    for k, v in payload.items():
        if v is None:
            continue
        if k in (
            "temperature",
            "pressure",
            "humidity",
            "rssi",
            "vibration",
            "hall_effect",
            "current",
        ):
            canonical[k] = f"{float(v):.2f}"
        elif k == "timestamp":
            try:
                canonical[k] = f"{float(v):.3f}"
            except (ValueError, TypeError):
                canonical[k] = str(v)
        else:
            canonical[k] = v
    return canonical


def sign_message(payload: dict, key: str) -> str:
    if not key:
        raise ValueError("Cannot sign: no HMAC key")
    canonical_payload = canonicalize_payload(payload)
    canonical = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def parse_serial_line(line: str, mode: str = "production"):
    line = line.strip()
    if not line:
        return None

    import re

    json_match = re.search(r'(\{.*\})', line)
    if json_match:
        try:
            data = json.loads(json_match.group(1))
            # Intercept and register Master Concentrator Bridge status and topology frames
            if (
                "system" in data
                and (
                    "Concentrator" in str(data.get("system", ""))
                    or "Master" in str(data.get("system", ""))
                )
            ) or data.get("type") == "BUS_TOPOLOGY":
                with _buffer_lock:
                    _master_bridge_info["status"] = data.get("status", "ONLINE")
                    _master_bridge_info["last_seen"] = time.time()
                    _master_bridge_info["details"] = data
                    _master_bridge_info["bridge_id"] = data.get("bridge_id", "MASTER_CONCENTRATOR")
                    _master_bridge_info["firmware"] = data.get(
                        "firmware", data.get("version", "unknown")
                    )
                    if "slave_count" in data:
                        _master_bridge_info["slave_count"] = int(data.get("slave_count"))
                    if "slaves" in data and isinstance(data["slaves"], list):
                        now_ts = time.time()
                        for slave_id in data["slaves"]:
                            if slave_id not in _active_nodes:
                                _active_nodes[slave_id] = {
                                    "first_seen": now_ts,
                                    "packet_count": 1,
                                    "sensors": set(),
                                }
                            _active_nodes[slave_id]["last_seen"] = now_ts
                            sensors_for_slave = data.get("sensors", {}).get(slave_id, [])
                            if sensors_for_slave:
                                _active_nodes[slave_id]["sensors"].update(sensors_for_slave)
                return {
                    "_is_bridge_msg": True,
                    "bridge_data": data,
                    "type": data.get("type", "MASTER_ANNOUNCEMENT"),
                    "bridge_id": data.get("bridge_id", "MASTER_CONCENTRATOR"),
                }

            # Intercept Slave Node dynamic announcement frame
            if data.get("type") == "NODE_ANNOUNCE" and ("device_id" in data or "id" in data):
                dev_id = str(data.get("device_id", data.get("id")))
                now_ts = time.time()
                with _buffer_lock:
                    if dev_id not in _active_nodes:
                        _active_nodes[dev_id] = {
                            "first_seen": now_ts,
                            "packet_count": 1,
                            "sensors": set(),
                        }
                    _active_nodes[dev_id]["last_seen"] = now_ts
                    if "sensors" in data and isinstance(data["sensors"], list):
                        _active_nodes[dev_id]["sensors"].update(data["sensors"])
                return {
                    "_is_bridge_msg": True,
                    "bridge_data": data,
                    "type": "NODE_ANNOUNCE",
                    "device_id": dev_id,
                }

            res = {}
            if "device_id" in data or "id" in data or "slave_id" in data:
                res["device_id"] = str(data.get("device_id", data.get("id", data.get("slave_id"))))
            if "signature" in data:
                res["signature"] = str(data.get("signature"))
            if "temp" in data or "temperature" in data:
                res["temperature"] = float(data.get("temp", data.get("temperature")))
            if "pres" in data or "pressure" in data:
                res["pressure"] = float(data.get("pres", data.get("pressure")))
            if "vib" in data or "vibration" in data:
                res["vibration"] = float(data.get("vib", data.get("vibration")))
            if "hall" in data or "hall_effect" in data or "rpm" in data:
                res["hall_effect"] = float(
                    data.get("hall", data.get("hall_effect", data.get("rpm", 0.0)))
                )
            if "curr" in data or "current" in data:
                res["current"] = float(data.get("curr", data.get("current")))
            if "hum" in data or "humidity" in data:
                res["humidity"] = float(data.get("hum", data.get("humidity")))
            if "rssi" in data:
                res["rssi"] = float(data.get("rssi"))
            return res
        except Exception:
            pass

    try:
        parts = [p.strip() for p in line.split(",")]

        if len(parts) >= 5:
            return {
                "temperature": float(parts[0]),
                "pressure": float(parts[1]),
                "vibration": float(parts[2]),
                "hall_effect": float(parts[3]),
                "current": float(parts[4]),
            }

        elif len(parts) == 1:
            return {"temperature": float(parts[0])}

        elif len(parts) == 2:
            return {"temperature": float(parts[0]), "pressure": float(parts[1])}
    except Exception as e:
        pass

    # Key-Value fallback parsing (e.g., "TEMP:42.5", "T:42.5", "temp=42.5", "P:4.2")
    kv_res = {}
    for item in line.replace('=', ':').split(','):
        if ':' in item:
            k, v = item.split(':', 1)
            k = k.strip().lower()
            try:
                val = float(v.strip())
                if k in ('t', 'temp', 'temperature'):
                    kv_res['temperature'] = val
                elif k in ('p', 'pres', 'pressure'):
                    kv_res['pressure'] = val
                elif k in ('v', 'vib', 'vibration'):
                    kv_res['vibration'] = val
                elif k in ('h', 'hall', 'hall_effect'):
                    kv_res['hall_effect'] = val
                elif k in ('c', 'curr', 'current'):
                    kv_res['current'] = val
            except ValueError:
                pass
    if kv_res:
        return kv_res

    print(f"[Gateway] Could not parse serial line: '{line}'")
    return None


# --------------------------------------------------------------------------------
# Simulator compatibility: drills live in simulator.py, re-exported for existing callers.
# --------------------------------------------------------------------------------
from simulator import (  # noqa: E402,F401
    clear_device_attack,
    get_active_attacks,
    inject_attack,
    reset_attacks,
)

_sim_bus = None  # SimulatedBus of the current simulator run (None for real hardware)


def get_simulated_bus():
    return _sim_bus


def get_device_locations():
    """Plant layout positions for the digital twin.

    There is no real geolocation data from field devices (the previous fixed GPS coordinates
    were invented -- debug report F15), so devices get an automatic grid position; operators
    see them by name/ID. Physical coordinates will be operator-entered in a later phase.
    """
    import registry

    ids = sorted(set(registry.approved_device_ids()) | set(get_active_nodes()))
    cols = max(1, min(4, len(ids)))
    out = []
    for i, dev_id in enumerate(ids):
        info = registry.device_info(dev_id) or {}
        out.append(
            {
                "device_id": dev_id,
                "name": info.get("name") or dev_id,
                "zone": "Unassigned",
                "grid": f"Slot {i + 1}",
                "latitude": None,
                "longitude": None,
                "elevation_m": None,
                "grid_x": (i % cols) * 25.0,
                "grid_y": (i // cols) * 25.0,
                "grid_z": 0.0,
                "location_source": "auto-layout",
            }
        )
    return out


FORWARDED_FIELDS = (
    "temperature",
    "pressure",
    "vibration",
    "hall_effect",
    "current",
    "humidity",
    "rssi",
)


def build_forward_payload(
    raw_data: dict, allow_unsigned: bool = False, bench_key=None, default_device_id=None
):
    """Build the protocol-v0 ingestion body from a parsed legacy frame.

    Returns ``None`` for frames without a device signature: the gateway is not a signing
    authority (debug report S6). ``allow_unsigned`` exists only for bench testing with
    sensors that cannot sign; it signs with ``bench_key`` or the device's own key.
    """
    device_id = raw_data.get("device_id") or default_device_id
    if not device_id:
        return None
    payload = {"device_id": device_id}
    if "timestamp" in raw_data:
        payload["timestamp"] = raw_data["timestamp"]
    for k in FORWARDED_FIELDS:
        if k in raw_data:
            payload[k] = raw_data[k]
    if raw_data.get("signature"):
        payload["signature"] = raw_data["signature"]
        return payload
    if not allow_unsigned:
        return None
    key = bench_key or get_device_key(device_id)
    if not key:
        return None
    payload.setdefault("timestamp", time.time())
    payload["signature"] = sign_message(payload, key)
    return payload


# In-process frame handlers registered by app.py (ADR 0003). When the gateway runs as a
# separate process they are unset and frames are POSTed to /api/telemetry instead.
_frame_handler_v1 = None
_frame_handler_v0 = None


def set_frame_handler(v1_handler, v0_handler=None):
    global _frame_handler_v1, _frame_handler_v0
    _frame_handler_v1 = v1_handler
    _frame_handler_v0 = v0_handler


def _note_node(device_id: str, sensors=None, values=None):
    with _buffer_lock:
        node = _active_nodes.setdefault(
            device_id, {"first_seen": time.time(), "packet_count": 0, "sensors": set()}
        )
        node["last_seen"] = time.time()
        node["packet_count"] = node.get("packet_count", 0) + 1
        if sensors:
            node["sensors"].update(sensors)
        if values is not None:
            node["latest_values"] = values


def _deliver(kind: str, body: dict, url: str, headers: dict):
    """Hand a frame to ingestion: in-process when available, else HTTP."""
    handler = _frame_handler_v1 if kind == "v1" else _frame_handler_v0
    if handler is not None:
        ok, status, message = handler(body)
        return status, message
    resp = requests.post(url, json=body, headers=headers, timeout=3)
    return resp.status_code, resp.text


def _handle_v1_line(frame: dict, line: str, url: str, headers: dict) -> None:
    device_id = str(frame.get("id"))
    ftype = frame.get("type")
    log_raw_wire_packet(line, parsed=True, target_id=device_id)
    if ftype == "HELLO":
        _note_node(device_id, sensors=frame.get("sensors") or [])
    elif ftype == "TEL":
        values = {k: frame.get(k) for k in FORWARDED_FIELDS[:5] if frame.get(k) is not None}
        _note_node(device_id, sensors=list(values), values=values)
    elif ftype in ("POLL", "DISCOVER", "WELCOME", "CMD"):
        return  # bus echo of host/master traffic
    status, message = _deliver("v1", frame, url, headers)
    if status not in (200,):
        print(f"[Gateway] [{device_id}] {ftype} -> {status}: {message}")


def _write_frames(write_line):
    """Write every unexpired queued frame/command via ``write_line(str)``."""
    import registry

    for item, log_id in _pop_ready_with_meta():
        line = protocol.encode(item) if protocol.is_v1(item) else json.dumps(item)
        write_line(line)
        if log_id is not None:
            registry.mark_command(log_id, "SENT")


def start_gateway(
    port="COM3",
    baud=115200,
    mode="plc",
    device_id=None,
    hmac_key=None,
    url=DEFAULT_GATEWAY_URL,
    mock=False,
    allow_unsigned=False,
    gateway_token=None,
    on_connect=None,
    sim_devices=None,
):
    """Run the gateway loop until stop_gateway() is called.

    ``mock=True`` runs the protocol-v1 plant simulator (``AEGIS_SIM_DEVICES`` slaves) instead
    of a serial port. ``on_connect`` is called once the link is up (the app uses it to re-send
    ISOLATE to quarantined nodes). ``hmac_key``/``allow_unsigned`` are for bench testing of
    legacy unsigned sensors only. ``gateway_token`` authenticates HTTP delivery when the
    gateway runs as a separate process (defaults to ``AEGIS_GATEWAY_TOKEN``).
    """
    global _active_port, _gateway_state, _gateway_stop_event, _sim_bus

    stop_event = threading.Event()
    _gateway_stop_event = stop_event
    purge_command_queue()
    _active_port = (port if port else "SIM_CLUSTER") if mock else port
    token = gateway_token or os.environ.get("AEGIS_GATEWAY_TOKEN", "")
    post_headers = {"Content-Type": "application/json", GATEWAY_TOKEN_HEADER: token}
    default_dev_id = device_id

    print("=" * 60)
    print(" Aegis Edge Serial Gateway")
    print(f" Port         : {_active_port} (@ {baud} baud){'  [SIMULATOR]' if mock else ''}")
    print(f" Delivery     : {'in-process' if _frame_handler_v1 else url}")
    print("=" * 60)

    ser = None
    if mock:
        import simulator
        from database import DATA_DIR

        _sim_bus = simulator.SimulatedBus(DATA_DIR, sim_devices)
    else:
        _sim_bus = None

    def _try_connect():
        nonlocal ser
        global _gateway_state
        if mock:
            _gateway_state = "CONNECTED"
            return True
        if not serial_available:
            print("[CRITICAL] PySerial not installed. Install it or run with mock=True.")
            _gateway_state = "DISCONNECTED"
            return False
        try:
            ser = serial.Serial(port, baudrate=baud, timeout=0.2)
            ser.setDTR(False)
            ser.setRTS(False)
            ser.reset_input_buffer()
            ser.reset_output_buffer()
            print(f"[Gateway] Connected to COM port: {port} @ {baud} baud (Buffers Cleared)")
            _gateway_state = "CONNECTED"
            return True
        except Exception as e:
            print(f"[Gateway] Could not connect to COM port {port}: {e}")
            ser = None
            _gateway_state = "RECONNECTING" if not stop_event.is_set() else "DISCONNECTED"
            return False

    def _after_connect():
        send_command(
            {
                "command": "DISCOVER",
                "action": "DISCOVER",
                "target_device": "ALL",
                "timestamp": time.time(),
            }
        )
        if on_connect is not None:
            try:
                on_connect()
            except Exception as err:
                print(f"[Gateway] on_connect hook failed: {err}")

    if _try_connect():
        _after_connect()
    else:
        print(f"[Gateway] Initial connection to {port} failed. Retrying in background.")

    def _write_line(line: str):
        if mock:
            _sim_bus.write(line)
        elif ser and ser.is_open:
            ser.write((line + "\n").encode("utf-8"))
            ser.flush()

    while not stop_event.is_set():
        try:
            if not mock and (ser is None or not ser.is_open):
                _gateway_state = "RECONNECTING"
                if not _try_connect():
                    for _ in range(10):
                        if stop_event.is_set():
                            break
                        time.sleep(0.2)
                    continue
                _after_connect()

            _write_frames(_write_line)

            if mock:
                line = _sim_bus.readline(stop_event)
            else:
                line = ser.readline().decode("utf-8", errors="ignore")
            if stop_event.is_set():
                break
            if not line or not line.strip():
                continue

            stripped = line.strip()
            frame = None
            if stripped.startswith("{"):
                try:
                    frame = json.loads(stripped)
                except ValueError:
                    frame = None
            if protocol.is_v1(frame):
                _handle_v1_line(frame, stripped, url, post_headers)
                continue

            # ---- protocol v0 (legacy firmware) and bridge status frames ----
            raw_data = parse_serial_line(line, mode)
            if not raw_data:
                log_raw_wire_packet(line, parsed=False, target_id="UNKNOWN")
                continue
            if raw_data.get("_is_bridge_msg"):
                log_raw_wire_packet(line, parsed=True, target_id="MASTER_BRIDGE")
                continue

            target_device_id = raw_data.get("device_id") or default_dev_id or "UNKNOWN"
            log_raw_wire_packet(line, parsed=True, target_id=target_device_id)
            detected = [s for s in FORWARDED_FIELDS[:5] if raw_data.get(s) is not None]
            _note_node(
                target_device_id, sensors=detected, values={k: raw_data[k] for k in detected}
            )

            payload = build_forward_payload(
                raw_data,
                allow_unsigned=allow_unsigned,
                bench_key=hmac_key,
                default_device_id=default_dev_id,
            )
            if payload is None:
                print(
                    f"[Gateway] [{target_device_id}] Dropped unsigned frame (device signature required)."
                )
                continue
            status, message = _deliver("v0", payload, url, post_headers)
            if status not in (200,):
                print(f"[Gateway] [{target_device_id}] -> {status}: {message}")

        except Exception as e:
            print(f"[Gateway] Telemetry acquisition exception: {e}")
            if stop_event.is_set():
                break
            if not mock and ser is not None:
                try:
                    ser.close()
                except Exception:
                    pass
                ser = None
            time.sleep(1)

    if ser and ser.is_open:
        try:
            ser.close()
            print(f"[Gateway] COM port {port} closed safely.")
        except Exception as e:
            print(f"[Gateway] Error closing COM port: {e}")
    # Only reset shared state if no newer gateway run has started in the meantime.
    if _gateway_stop_event is stop_event:
        _active_port = None
        _gateway_state = "DISCONNECTED"
        _sim_bus = None
    print("[Gateway] Shutdown complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aegis ICS — Edge Serial Gateway Driver")
    parser.add_argument("--port", type=str, default="COM3", help="Serial port (COM3, /dev/ttyUSB0)")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--mode", type=str, choices=["plc", "non-plc"], default="plc")
    parser.add_argument(
        "--device-id", type=str, default=None, help="Device id for legacy CSV sensors"
    )
    parser.add_argument(
        "--key", type=str, default=None, help="Bench-test HMAC key (only with --allow-unsigned)"
    )
    parser.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="BENCH TESTING ONLY: sign frames from legacy sensors that cannot sign themselves",
    )
    parser.add_argument("--url", type=str, default=DEFAULT_GATEWAY_URL, help="Aegis ingestion URL")
    parser.add_argument("--mock", action="store_true", help="Run the protocol-v1 plant simulator")
    parser.add_argument("--sim-devices", type=int, default=None, help="Number of simulated slaves")
    args = parser.parse_args()
    start_gateway(
        port=args.port,
        baud=args.baud,
        mode=args.mode,
        device_id=args.device_id,
        hmac_key=args.key,
        url=args.url,
        mock=args.mock,
        allow_unsigned=args.allow_unsigned,
        sim_devices=args.sim_devices,
    )
