"""Software plant simulator speaking protocol v1 (restructure plan P2.8).

It stands in for the master bridge plus N slave ESP32s, so the dashboard, enrollment,
command ACKs and the attack drills can be exercised without hardware. Each simulated slave
behaves like the real firmware (firmware/esp32_slave_sensor):

* owns an X25519 identity (persisted in ``<data dir>/simulator_devices.json`` so approvals
  survive restarts), announces ``HELLO`` until enrolled, derives the session key from the
  host's ``WELCOME`` and confirms with a signed ``ACK``;
* answers polls with signed ``TEL`` frames carrying ``boot``/``seq`` and sensor faults;
* verifies every ``CMD`` (signature + host sequence) and replies with an ``ACK``;
* applies setpoints (temperature/pressure track the target), trips its relay on
  ``ISOLATE``/``SHUTDOWN`` and re-arms on ``REARM``.

The number of slaves comes from ``AEGIS_SIM_DEVICES`` (default 4). Everything the simulator
produces is stored with ``is_simulated = true``.
"""

from __future__ import annotations

import collections
import json
import os
import random
import secrets
import threading
import time
from typing import Deque, Dict, List, Optional

import enrollment
import protocol

PROFILES = [
    {"role": "reactor", "temp": 26.0, "pres": 4.2, "vib": 1.1, "rpm": 0.0, "curr": 4.5},
    {"role": "pump", "temp": 41.0, "pres": 5.4, "vib": 1.8, "rpm": 1500.0, "curr": 5.2},
    {"role": "chiller", "temp": 18.5, "pres": 2.2, "vib": 0.6, "rpm": 0.0, "curr": 2.8},
    {"role": "turbine", "temp": 33.0, "pres": 3.8, "vib": 2.2, "rpm": 2200.0, "curr": 7.1},
]
SENSORS = ["temperature", "pressure", "vibration", "hall_effect", "current"]
FIRMWARE = "sim-2.6"
VALID_ATTACKS = {"stuxnet", "hmac_tamper", "thermal_drift", "fdi_spike", "ddos", "sensor_fault"}

# Red-team drill state, keyed by simulated device id.
_active_attacks: Dict[str, str] = {}
_drift: Dict[str, float] = {}
_attack_lock = threading.Lock()


def inject_attack(device_id: str, attack_type: str) -> dict:
    """Activate an attack vector on a simulated device (drill only)."""
    if attack_type == "injection":
        attack_type = "fdi_spike"
    if attack_type not in VALID_ATTACKS:
        return {
            "success": False,
            "error": f"Invalid attack type '{attack_type}'. Choose from: {sorted(VALID_ATTACKS)}",
        }
    with _attack_lock:
        _active_attacks[device_id] = attack_type
        _drift[device_id] = 0.0
    print(f"[Simulator] Drill: injected '{attack_type}' on {device_id}")
    return {"success": True, "device_id": device_id, "attack": attack_type}


def reset_attacks() -> dict:
    with _attack_lock:
        _active_attacks.clear()
        _drift.clear()
    return {"success": True, "message": "All attack vectors reset to normal"}


def clear_device_attack(device_id: str) -> dict:
    with _attack_lock:
        _active_attacks.pop(device_id, None)
        _drift.pop(device_id, None)
    return {"success": True, "device_id": device_id}


def get_active_attacks() -> dict:
    with _attack_lock:
        return dict(_active_attacks)


class SimDevice:
    def __init__(self, device_id: str, private_hex: str, profile: dict):
        self.id = device_id
        self.priv = enrollment.private_from_hex(private_hex)
        self.pub = enrollment.public_hex(self.priv)
        self.profile = profile
        self.boot = secrets.randbits(31)
        self.seq = 0
        self.key: Optional[str] = None
        self.last_host_seq = 0
        self.tripped = False
        self.sp_t: Optional[float] = None
        self.sp_p: Optional[float] = None
        self.temp = profile["temp"]
        self.pres = profile["pres"]
        self.last_hello = 0.0

    # --- frames -----------------------------------------------------------------
    def _next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def hello(self) -> dict:
        self.last_hello = time.time()
        return {
            "v": 1,
            "type": "HELLO",
            "id": self.id,
            "pub": self.pub,
            "fw": FIRMWARE,
            "boot": self.boot,
            "sensors": list(SENSORS),
            "enrolled": self.key is not None,
        }

    def telemetry(self) -> Optional[dict]:
        if self.key is None:
            return None
        with _attack_lock:
            attack = _active_attacks.get(self.id)
            if attack == "thermal_drift":
                _drift[self.id] = _drift.get(self.id, 0.0) + 0.65
            drift = _drift.get(self.id, 0.0)
        if attack == "ddos" and random.random() < 0.6:
            return None  # frames lost on a saturated bus

        p = self.profile
        # First-order tracking of applied setpoints (what a real control loop would do).
        target_t = self.sp_t if self.sp_t is not None else p["temp"]
        target_p = self.sp_p if self.sp_p is not None else p["pres"]
        self.temp += 0.15 * (target_t - self.temp)
        self.pres += 0.15 * (target_p - self.pres)
        reading = {
            "temperature": self.temp + random.uniform(-0.6, 0.6),
            "pressure": self.pres + random.uniform(-0.12, 0.12),
            "vibration": p["vib"] + random.uniform(-0.12, 0.12),
            "hall_effect": (p["rpm"] + random.choice([-60, 0, 60])) if p["rpm"] else 0.0,
            "current": p["curr"] + random.uniform(-0.2, 0.2),
        }
        faults: List[str] = []
        if attack == "stuxnet":
            reading.update(
                vibration=4.8 + random.uniform(0.1, 1.2),
                hall_effect=3250.0 + random.choice([0, 150, 300]),
                temperature=p["temp"] + random.uniform(8, 15),
                current=p["curr"] + random.uniform(2.5, 4.0),
            )
        elif attack == "fdi_spike":
            reading.update(
                temperature=96.8,
                pressure=12.4,
                vibration=5.8,
                current=19.2,
                hall_effect=3500.0 if p["rpm"] else 0.0,
            )
        elif attack == "thermal_drift":
            reading["temperature"] = p["temp"] + drift
            reading["pressure"] = p["pres"] + drift * 0.08
        elif attack == "sensor_fault":
            faults.append("temperature")
        if self.tripped:
            reading.update(pressure=0.0, hall_effect=0.0, current=0.1)

        frame = {
            "v": 1,
            "type": "TEL",
            "id": self.id,
            "boot": self.boot,
            "seq": self._next_seq(),
            "faults": faults,
            "tripped": self.tripped,
            "rssi": protocol.fmt2(-62 + random.uniform(-5, 5)),
        }
        for name, value in reading.items():
            if name not in faults:
                frame[name] = protocol.fmt2(max(0.0, value))
        if self.sp_t is not None:
            frame["sp_t"] = protocol.fmt2(self.sp_t)
        if self.sp_p is not None:
            frame["sp_p"] = protocol.fmt2(self.sp_p)
        signed = protocol.sign(frame, self.key)
        if attack == "hmac_tamper":
            signed["sig"] = "0" * 64
        return signed

    def _ack(self, ack_seq: int, result: str, reason: str = "") -> dict:
        frame = {
            "v": 1,
            "type": "ACK",
            "id": self.id,
            "boot": self.boot,
            "seq": self._next_seq(),
            "ack": ack_seq,
            "result": result,
        }
        if reason:
            frame["reason"] = reason
        return protocol.sign(frame, self.key)

    # --- host -> device -------------------------------------------------------------
    def on_welcome(self, frame: dict) -> Optional[dict]:
        hpub = frame.get("hpub")
        if not enrollment.is_valid_public_hex(hpub):
            return None
        key = enrollment.derive_session_key(self.priv, hpub, self.id, self.pub, hpub)
        if not protocol.verify(frame, key):
            print(f"[Simulator] {self.id}: WELCOME signature mismatch, ignoring")
            return None
        self.key = key
        self.last_host_seq = 0
        print(f"[Simulator] {self.id}: enrolled (session key derived)")
        return self._ack(0, "OK")

    def on_command(self, frame: dict) -> Optional[dict]:
        if self.key is None:
            return None
        cmd_seq = frame.get("seq")
        if not isinstance(cmd_seq, int):
            return None
        if not protocol.verify(frame, self.key):
            return self._ack(cmd_seq, "BAD_SIG", "signature check failed")
        if cmd_seq <= self.last_host_seq:
            return self._ack(cmd_seq, "REPLAY", "sequence already used")
        self.last_host_seq = cmd_seq
        cmd, args = frame.get("cmd"), frame.get("args") or {}
        if cmd == "ISOLATE" or cmd == "SHUTDOWN":
            self.tripped = True
            return self._ack(cmd_seq, "OK", "relay tripped")
        if cmd == "REARM":
            self.tripped = False
            return self._ack(cmd_seq, "OK", "relay energised")
        if cmd == "PING":
            return self._ack(cmd_seq, "OK", "pong")
        if cmd == "SETPOINT":
            param = args.get("param")
            try:
                value = float(args.get("value"))
            except (TypeError, ValueError):
                return self._ack(cmd_seq, "REJECTED", "invalid value")
            limits = {"temperature": (0.0, 60.0), "pressure": (0.0, 8.0)}
            if param not in limits:
                return self._ack(cmd_seq, "REJECTED", "unknown parameter")
            lo, hi = limits[param]
            if not lo <= value <= hi:
                return self._ack(cmd_seq, "REJECTED", f"outside device envelope [{lo:g}, {hi:g}]")
            if self.tripped:
                return self._ack(cmd_seq, "REJECTED", "relay tripped")
            if param == "temperature":
                self.sp_t = value
            else:
                self.sp_p = value
            return self._ack(cmd_seq, "OK", f"{param} setpoint {value:.2f} applied")
        return self._ack(cmd_seq, "UNKNOWN_CMD", str(cmd)[:20])


class SimulatedBus:
    """Master bridge + N slaves. Same interface as a serial port: ``readline`` / ``write``."""

    DISCOVERY_INTERVAL_S = 10.0
    HELLO_RETRY_S = 5.0
    LINE_INTERVAL_S = 0.25

    def __init__(self, data_dir: str, count: Optional[int] = None):
        count = count if count is not None else int(os.environ.get("AEGIS_SIM_DEVICES", "4"))
        self.devices = self._load_devices(data_dir, max(1, min(count, 64)))
        self._out: Deque[str] = collections.deque()
        self._poll_index = 0
        self._last_discovery = 0.0
        self._lock = threading.Lock()

    @staticmethod
    def _load_devices(data_dir: str, count: int) -> List[SimDevice]:
        path = os.path.join(data_dir, "simulator_devices.json")
        try:
            with open(path, "r", encoding="utf-8") as fh:
                stored = json.load(fh)
        except (OSError, ValueError):
            stored = {}
        ids = list(stored)
        while len(ids) < count:
            new_id = "ESP32_" + secrets.token_hex(3).upper()
            if new_id not in stored:
                stored[new_id] = enrollment.private_to_hex(enrollment.generate_keypair()[0])
                ids.append(new_id)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(stored, fh, indent=2)
        except OSError as exc:
            print(f"[Simulator] Could not persist simulator identities: {exc}")
        return [
            SimDevice(dev_id, stored[dev_id], PROFILES[i % len(PROFILES)])
            for i, dev_id in enumerate(ids[:count])
        ]

    def device(self, device_id: str) -> Optional[SimDevice]:
        return next((d for d in self.devices if d.id == device_id), None)

    # --- serial-port interface ------------------------------------------------------
    def write(self, line: str) -> None:
        try:
            frame = json.loads(line)
        except ValueError:
            return
        if not isinstance(frame, dict):
            return
        reply = None
        with self._lock:
            if frame.get("command") == "DISCOVER" or frame.get("type") == "DISCOVER":
                self._discovery()
                return
            dev = self.device(frame.get("id") or frame.get("device_id") or "")
            if dev is None:
                return
            if frame.get("type") == "WELCOME":
                reply = dev.on_welcome(frame)
            elif frame.get("type") == "CMD":
                reply = dev.on_command(frame)
            if reply is not None:
                self._out.append(protocol.encode(reply))

    def readline(self, stop_event: Optional[threading.Event] = None) -> str:
        deadline = time.time() + self.LINE_INTERVAL_S
        while time.time() < deadline:
            if stop_event is not None and stop_event.is_set():
                return ""
            with self._lock:
                if self._out:
                    return self._out.popleft() + "\n"
            time.sleep(0.02)
        with self._lock:
            self._tick()
            return (self._out.popleft() + "\n") if self._out else ""

    # --- master behaviour -------------------------------------------------------------
    def _discovery(self) -> None:
        self._last_discovery = time.time()
        for dev in self.devices:
            self._out.append(protocol.encode(dev.hello()))
        topo = {
            "system": "Aegis Master Concentrator (simulated)",
            "type": "BUS_TOPOLOGY",
            "status": "ONLINE",
            "version": FIRMWARE,
            "slave_count": len(self.devices),
            "slaves": [d.id for d in self.devices],
            "sensors": {d.id: list(SENSORS) for d in self.devices},
        }
        self._out.append(json.dumps(topo))

    def _tick(self) -> None:
        now = time.time()
        if now - self._last_discovery > self.DISCOVERY_INTERVAL_S:
            self._discovery()
            return
        dev = self.devices[self._poll_index % len(self.devices)]
        self._poll_index += 1
        if dev.key is None:
            if now - dev.last_hello > self.HELLO_RETRY_S:
                self._out.append(protocol.encode(dev.hello()))
            return
        frame = dev.telemetry()
        if frame is not None:
            self._out.append(protocol.encode(frame))
