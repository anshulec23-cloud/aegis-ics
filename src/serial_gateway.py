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


def pop_ready_commands(now=None):
    """Drain the queue, returning unexpired commands with internal fields removed."""
    now = time.time() if now is None else now
    ready = []
    while True:
        try:
            cmd = _command_queue.get_nowait()
        except queue.Empty:
            break
        age = now - float(cmd.get("_enqueued_at", now))
        if age > COMMAND_TTL_SECONDS:
            print(
                f"[Gateway] Dropping expired command ({age:.1f}s old): {cmd.get('command') or cmd.get('action')}"
            )
            continue
        ready.append({k: v for k, v in cmd.items() if not k.startswith("_")})
    return ready


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


_sim_device_index = 0
_sim_devices = [
    {
        "id": "ESP32_001",
        "name": "Catalytic Reactor 01",
        "zone": "Reactor Bay North",
        "grid": "Grid R-01",
        "lat": 37.774929,
        "lon": -122.419416,
        "elev": 18.5,
        "grid_x": 12.40,
        "grid_y": -48.10,
        "grid_z": 3.50,
        "temp_base": 26.0,
        "pres_base": 4.2,
        "vib_base": 1.1,
        "hall_base": 0.0,
        "curr_base": 4.5,
        "sensors": ["temp", "pres", "vib", "curr"],
    },
    {
        "id": "ESP32_002",
        "name": "Centrifugal Pump 02",
        "zone": "Pumping Station East",
        "grid": "Grid P-04",
        "lat": 37.775180,
        "lon": -122.418900,
        "elev": 12.0,
        "grid_x": 45.80,
        "grid_y": -14.20,
        "grid_z": 1.20,
        "temp_base": 41.0,
        "pres_base": 5.4,
        "vib_base": 1.8,
        "hall_base": 1500.0,
        "curr_base": 5.2,
        "sensors": ["vib", "hall", "curr", "temp"],
    },
    {
        "id": "ESP32_003",
        "name": "Cooling Cryo 03",
        "zone": "Cryogenics Vault Sub-1",
        "grid": "Grid C-02",
        "lat": 37.774410,
        "lon": -122.419850,
        "elev": 8.2,
        "grid_x": -22.10,
        "grid_y": -65.40,
        "grid_z": -4.80,
        "temp_base": 18.5,
        "pres_base": 2.2,
        "vib_base": 0.6,
        "hall_base": 0.0,
        "curr_base": 2.8,
        "sensors": ["temp", "pres", "curr"],
    },
    {
        "id": "ESP32_004",
        "name": "Turbine Generator 04",
        "zone": "Turbine Hall South",
        "grid": "Grid T-09",
        "lat": 37.775550,
        "lon": -122.420120,
        "elev": 24.0,
        "grid_x": -35.60,
        "grid_y": 28.90,
        "grid_z": 6.00,
        "temp_base": 33.0,
        "pres_base": 3.8,
        "vib_base": 2.2,
        "hall_base": 2200.0,
        "curr_base": 7.1,
        "sensors": ["temp", "pres", "vib", "hall", "curr"],
    },
]


def get_device_locations():
    """Returns real GPS and facility plant coordinates reported by edge hardware."""
    return [
        {
            "device_id": dev["id"],
            "name": dev["name"],
            "zone": dev["zone"],
            "grid": dev["grid"],
            "latitude": dev["lat"],
            "longitude": dev["lon"],
            "elevation_m": dev["elev"],
            "grid_x": dev["grid_x"],
            "grid_y": dev["grid_y"],
            "grid_z": dev["grid_z"],
        }
        for dev in _sim_devices
    ]


_active_attacks = {}
_thermal_drift_offsets = {}


def inject_attack(device_id: str, attack_type: str):
    """Dynamically activates an ICS cyber-physical attack vector on a simulated device node."""
    global _active_attacks, _thermal_drift_offsets
    if attack_type == "injection":
        attack_type = "fdi_spike"
    valid_attacks = {"stuxnet", "hmac_tamper", "thermal_drift", "fdi_spike", "ddos"}
    if attack_type not in valid_attacks:
        return {
            "success": False,
            "error": f"Invalid attack type '{attack_type}'. Choose from: {list(valid_attacks)}",
        }
    _active_attacks[device_id] = attack_type
    if attack_type == "thermal_drift":
        _thermal_drift_offsets[device_id] = 0.0
    print(f"[Attack Suite] INJECTED vector '{attack_type}' onto {device_id}")
    return {"success": True, "device_id": device_id, "attack": attack_type}


def reset_attacks():
    """Clears all active cyber-physical attack simulations."""
    global _active_attacks, _thermal_drift_offsets
    _active_attacks.clear()
    _thermal_drift_offsets.clear()
    print("[Attack Suite] Reset all attack vectors to clean baseline.")
    return {"success": True, "message": "All attack vectors reset to normal"}


def clear_device_attack(device_id: str):
    """Clears active attack on a specific device."""
    global _active_attacks, _thermal_drift_offsets
    if device_id in _active_attacks:
        del _active_attacks[device_id]
    if device_id in _thermal_drift_offsets:
        del _thermal_drift_offsets[device_id]
    return {"success": True, "device_id": device_id}


def get_active_attacks():
    """Returns currently active attack vectors per device."""
    return dict(_active_attacks)


def mock_serial_stream(mode):
    global _sim_device_index, _active_attacks, _thermal_drift_offsets
    import random

    time.sleep(0.5)
    dev = _sim_devices[_sim_device_index % len(_sim_devices)]
    _sim_device_index += 1
    dev_id = dev["id"]

    packet = {"device_id": dev_id, "rssi": round(-65.0 + random.uniform(-6, 6), 1)}

    attack = _active_attacks.get(dev_id)

    if attack == "stuxnet":
        # Stuxnet resonance vector: Severe vibration and Hall RPM overspeed, while reporting spoofed baseline pressure
        packet["vib"] = round(4.8 + random.uniform(0.1, 1.2), 2)
        packet["hall"] = 3250.0 + random.choice([0, 150, 300])
        packet["temp"] = round(dev["temp_base"] + random.uniform(8.0, 15.0), 2)
        packet["pres"] = round(dev["pres_base"] + random.uniform(-0.1, 0.1), 2)
        packet["curr"] = round(dev["curr_base"] + random.uniform(2.5, 4.0), 2)
    elif attack == "hmac_tamper":
        # Cryptographic tamper vector: Valid sensors but deliberately corrupted HMAC signature
        active_sensors = dev["sensors"]
        if "temp" in active_sensors:
            packet["temp"] = dev["temp_base"]
        if "pres" in active_sensors:
            packet["pres"] = dev["pres_base"]
        if "vib" in active_sensors:
            packet["vib"] = dev["vib_base"]
        if "hall" in active_sensors and dev["hall_base"] > 0:
            packet["hall"] = dev["hall_base"]
        if "curr" in active_sensors:
            packet["curr"] = dev["curr_base"]
        packet["_tampered"] = True
    elif attack == "thermal_drift":
        # Stealth thermal drift: Creeps temperature upward progressively to test rolling deviation / variance
        _thermal_drift_offsets[dev_id] = _thermal_drift_offsets.get(dev_id, 0.0) + 0.65
        drift_val = _thermal_drift_offsets[dev_id]
        packet["temp"] = round(dev["temp_base"] + drift_val, 2)
        packet["pres"] = round(dev["pres_base"] + (drift_val * 0.08), 2)
        packet["vib"] = dev["vib_base"]
        if dev["hall_base"] > 0:
            packet["hall"] = dev["hall_base"]
        packet["curr"] = dev["curr_base"]
    elif attack == "fdi_spike":
        # False Data Injection: Extreme critical out-of-boundary spike
        packet["temp"] = 96.8
        packet["pres"] = 12.4
        packet["vib"] = 5.8
        if dev["hall_base"] > 0:
            packet["hall"] = 3500.0
        packet["curr"] = 19.2
    elif attack == "ddos":
        # Denial of Service: High bus latency, buffer saturation, signal degradation
        packet["temp"] = round(dev["temp_base"] + random.uniform(-0.5, 0.5), 2)
        packet["pres"] = round(dev["pres_base"] + random.uniform(-0.1, 0.1), 2)
        packet["vib"] = dev["vib_base"]
        packet["rssi"] = -98.0
    else:
        # Normal baseline telemetry
        active_sensors = dev["sensors"]
        if "temp" in active_sensors or random.random() < 0.2:
            packet["temp"] = round(dev["temp_base"] + random.uniform(-1.2, 1.2), 2)
        if "pres" in active_sensors or random.random() < 0.2:
            packet["pres"] = round(dev["pres_base"] + random.uniform(-0.25, 0.25), 2)
        if "vib" in active_sensors or random.random() < 0.2:
            packet["vib"] = round(dev["vib_base"] + random.uniform(-0.15, 0.15), 2)
        if "hall" in active_sensors and dev["hall_base"] > 0:
            packet["hall"] = dev["hall_base"] + random.choice([-100, 0, 100])
        if "curr" in active_sensors or random.random() < 0.2:
            packet["curr"] = round(dev["curr_base"] + random.uniform(-0.25, 0.25), 2)

    # Periodically emit Master Concentrator BUS_TOPOLOGY frame every 7 iterations
    if _sim_device_index % 7 == 0:
        topo_frame = {
            "system": "Aegis Master Concentrator",
            "type": "BUS_TOPOLOGY",
            "status": "ONLINE",
            "version": "simulator",
            "slave_count": len(_sim_devices),
            "slaves": [d["id"] for d in _sim_devices],
            "sensors": {
                d["id"]: ["temperature", "pressure", "vibration", "current"]
                + (["hall_effect"] if d["hall_base"] > 0 else [])
                for d in _sim_devices
            },
        }
        return json.dumps(topo_frame) + "\n"

    return json.dumps(_sign_simulated_packet(packet)) + "\n"


_SIM_KEY_MAP = {
    "temp": "temperature",
    "pres": "pressure",
    "vib": "vibration",
    "hall": "hall_effect",
    "curr": "current",
}
_warned_unkeyed_sim_devices = set()


def _sign_simulated_packet(packet: dict) -> dict:
    """Emit a frame exactly as a provisioned device would: long field names + its own HMAC.

    The simulator plays the role of the field devices, so it signs with each device's own
    key (never one shared key -- debug report F1). The ``hmac_tamper`` drill emits a
    deliberately corrupted signature.
    """
    tampered = packet.pop("_tampered", False)
    frame = {_SIM_KEY_MAP.get(k, k): v for k, v in packet.items()}
    if tampered:
        frame["signature"] = "BAD_HMAC_SIGNATURE_TAMPERED_" + "0" * 36
        return frame
    key = get_device_key(frame["device_id"])
    if not key:
        if frame["device_id"] not in _warned_unkeyed_sim_devices:
            _warned_unkeyed_sim_devices.add(frame["device_id"])
            print(
                f"[Simulator] No key provisioned for {frame['device_id']}; its frames will be rejected."
            )
        return frame
    frame["signature"] = sign_message(frame, key)
    return frame


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
    """Build the JSON body sent to /api/telemetry from a parsed frame.

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
    initial_commands=None,
):
    """Run the gateway loop until stop_gateway() is called.

    ``hmac_key`` is only used together with ``allow_unsigned`` (bench testing).
    ``gateway_token`` is sent as the ``X-Aegis-Gateway-Token`` header; defaults to the
    ``AEGIS_GATEWAY_TOKEN`` environment variable. ``initial_commands`` are queued right
    after DISCOVER on every (re)start, e.g. ISOLATE re-sync for quarantined nodes.
    """
    global _active_port, _gateway_state, _gateway_stop_event

    stop_event = threading.Event()
    _gateway_stop_event = stop_event
    purge_command_queue()
    _active_port = (port if port else "SIM_CLUSTER") if mock else port
    token = gateway_token or os.environ.get("AEGIS_GATEWAY_TOKEN", "")
    post_headers = {"Content-Type": "application/json", GATEWAY_TOKEN_HEADER: token}

    default_dev_id = device_id or ("ESP32_001" if mode == "plc" else "ESP32_002")

    print("=" * 60)
    print(f" Aegis Edge Serial Gateway: Master Gateway Node")
    print(f" Port         : {port} (@ {baud} baud)")
    print(f" Mode Profile : {mode.upper()}")
    print(f" Ingestion URL: {url}")
    print("=" * 60)

    ser = None

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
            ser = serial.Serial(port, baudrate=baud, timeout=1)
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

    if not mock:
        connected = _try_connect()
        if not connected:
            print(
                f"[Gateway] Initial connection to {port} failed. Gateway will attempt auto-recovery in background."
            )
        else:
            send_command(
                {
                    "command": "DISCOVER",
                    "action": "DISCOVER",
                    "target_device": "ALL",
                    "timestamp": time.time(),
                }
            )
    else:
        _try_connect()  # simulator: marks the run CONNECTED
        send_command(
            {
                "command": "DISCOVER",
                "action": "DISCOVER",
                "target_device": "ALL",
                "timestamp": time.time(),
            }
        )

    for cmd in initial_commands or []:
        try:
            send_command(dict(cmd, timestamp=time.time()))
        except ValueError as err:
            print(f"[Gateway] Initial command skipped: {err}")

    while not stop_event.is_set():
        try:
            # Auto-reconnect if physical serial connection was lost or interrupted
            if not mock and (ser is None or not ser.is_open):
                print(f"[Gateway] Attempting auto-reconnect to {port}...")
                _gateway_state = "RECONNECTING"
                if not _try_connect():
                    for _ in range(10):
                        if stop_event.is_set():
                            break
                        time.sleep(0.2)
                    continue

            for cmd in pop_ready_commands():
                if not mock and ser and ser.is_open:
                    ser.write((json.dumps(cmd) + "\n").encode("utf-8"))
                    ser.flush()
                    print(f"[Gateway] Wrote command to UART: {cmd}")
                elif mock:
                    print(f"[Gateway MOCK] Wrote command: {cmd}")

            if mock:
                line = mock_serial_stream(mode)
                if stop_event.is_set():
                    break
            else:
                line = ser.readline().decode("utf-8", errors="ignore")
                if not line:
                    continue

            raw_data = parse_serial_line(line, mode)
            if not raw_data:
                log_raw_wire_packet(line, parsed=False, target_id="UNKNOWN")
                continue

            # Check if this frame is a Master Concentrator announcement
            if raw_data.get("_is_bridge_msg"):
                log_raw_wire_packet(line, parsed=True, target_id="MASTER_BRIDGE")
                print(
                    f"[Gateway] Master Concentrator Bridge verified: {raw_data.get('bridge_data')}"
                )
                continue

            target_device_id = raw_data.get("device_id") or default_dev_id
            log_raw_wire_packet(line, parsed=True, target_id=target_device_id)

            # Update active nodes & sensor detection registry
            detected_sensors = []
            for s_name in ("temperature", "pressure", "vibration", "hall_effect", "current"):
                if s_name in raw_data and raw_data[s_name] is not None:
                    detected_sensors.append(s_name)

            with _buffer_lock:
                if target_device_id not in _active_nodes:
                    _active_nodes[target_device_id] = {
                        "first_seen": time.time(),
                        "packet_count": 0,
                        "sensors": set(),
                    }
                _active_nodes[target_device_id]["last_seen"] = time.time()
                _active_nodes[target_device_id]["packet_count"] += 1
                _active_nodes[target_device_id]["sensors"].update(detected_sensors)
                _active_nodes[target_device_id]["latest_values"] = {
                    k: raw_data[k] for k in detected_sensors
                }

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

            resp = requests.post(url, json=payload, headers=post_headers, timeout=3)

            if resp.status_code == 200:
                print(f"[Gateway] [{target_device_id}] Success -> {raw_data}")
            elif resp.status_code == 403:
                print(
                    f"[Gateway] [{target_device_id}] ACCESS DENIED: Device is isolated by Gateway."
                )
            else:
                print(
                    f"[Gateway] [{target_device_id}] Error status {resp.status_code}: {resp.text}"
                )

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
    print("[Gateway] Shutdown complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aegis ICS V2 — Edge Serial Gateway Driver")
    parser.add_argument(
        "--port", type=str, default="COM3", help="Serial COM port name (e.g. COM3 or /dev/ttyUSB0)"
    )
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate (115200, 9600, etc.)")
    parser.add_argument(
        "--mode",
        type=str,
        choices=["plc", "non-plc"],
        default="plc",
        help="Machine Profile Profile",
    )
    parser.add_argument("--device-id", type=str, default=None, help="Device ID override")
    parser.add_argument(
        "--key", type=str, default=None, help="Bench-test HMAC key (only with --allow-unsigned)"
    )
    parser.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="BENCH TESTING ONLY: sign frames from sensors that cannot sign themselves",
    )
    parser.add_argument(
        "--url", type=str, default=DEFAULT_GATEWAY_URL, help="Aegis REST Telemetry Ingest URL"
    )
    parser.add_argument(
        "--mock", action="store_true", help="Emulate serial input (no COM port required)"
    )

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
    )
