"""Aegis wire protocol v1 (docs/01-architecture/protocols.md, ADR 0004/0006).

Every frame is one line of JSON with ``"v": 1`` and a ``type``:

  slave -> host   HELLO    {id, pub, fw, boot, sensors[], enrolled}            unsigned
                  TEL      {id, boot, seq, <sensor>: "12.34", faults[], tripped, sp_t?, sp_p?, sig}
                  ACK      {id, boot, seq, ack, result, reason?, sig}
  host -> slave   WELCOME  {id, hpub, sig}                                      signed with the new key
                  CMD      {id, seq, cmd, args{}, sig}
  master <-> bus  POLL     {id}  /  DISCOVER {}                                 unsigned, no authority

Canonical form for signing: the frame without ``sig``, serialised with sorted keys and
compact separators (``json.dumps(..., sort_keys=True, separators=(",", ":"))``).
To make that byte-identical on the ESP32 (ArduinoJson), protocol v1 never carries JSON
floats: every real number is a string with exactly two decimals ("26.10"). Integers
(``boot``, ``seq``, ``ack``, ``v``) are plain JSON integers; booleans are true/false;
all strings are ASCII.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict, Optional

VERSION = 1
SENSOR_FIELDS = (
    "temperature",
    "pressure",
    "vibration",
    "hall_effect",
    "current",
    "humidity",
    "rssi",
)
COMMANDS = ("SETPOINT", "ISOLATE", "REARM", "SHUTDOWN", "PING")
ACK_RESULTS = ("OK", "REJECTED", "BAD_SIG", "REPLAY", "UNKNOWN_CMD")
SETPOINT_PARAMS = {"set_temp": "temperature", "set_pressure": "pressure"}


def is_v1(frame: Any) -> bool:
    return (
        isinstance(frame, dict) and frame.get("v") == VERSION and isinstance(frame.get("type"), str)
    )


def fmt2(value: float) -> str:
    return f"{float(value):.2f}"


def canonical(frame: Dict[str, Any]) -> str:
    body = {k: v for k, v in frame.items() if k != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sign(frame: Dict[str, Any], key: str) -> Dict[str, Any]:
    """Return a copy of ``frame`` with ``sig`` set (HMAC-SHA256 over the canonical form)."""
    if not key:
        raise ValueError("Cannot sign: no key")
    out = {k: v for k, v in frame.items() if k != "sig"}
    out["sig"] = hmac.new(
        key.encode("ascii"), canonical(out).encode("ascii"), hashlib.sha256
    ).hexdigest()
    return out


def verify(frame: Dict[str, Any], key: Optional[str]) -> bool:
    sig = frame.get("sig")
    if not key or not isinstance(sig, str):
        return False
    try:
        expected = hmac.new(
            key.encode("ascii"), canonical(frame).encode("ascii"), hashlib.sha256
        ).hexdigest()
    except (TypeError, ValueError, UnicodeEncodeError):
        return False
    return hmac.compare_digest(expected, sig)


def encode(frame: Dict[str, Any]) -> str:
    """Wire encoding (sorted keys, so the receiver can re-serialise to the canonical form)."""
    return json.dumps(frame, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


# ------------------------------------------------------------------ builders ---


def build_cmd(
    device_id: str, seq: int, cmd: str, args: Optional[Dict[str, str]], key: str
) -> Dict[str, Any]:
    if cmd not in COMMANDS:
        raise ValueError(f"unknown command {cmd}")
    frame = {
        "v": VERSION,
        "type": "CMD",
        "id": device_id,
        "seq": int(seq),
        "cmd": cmd,
        "args": dict(args or {}),
    }
    return sign(frame, key)


def build_welcome(device_id: str, host_pub_hex: str, key: str) -> Dict[str, Any]:
    return sign({"v": VERSION, "type": "WELCOME", "id": device_id, "hpub": host_pub_hex}, key)


def telemetry_fields(frame: Dict[str, Any]) -> Dict[str, Optional[float]]:
    """Sensor readings of a TEL frame as floats (missing/faulted sensors -> None)."""
    out: Dict[str, Optional[float]] = {}
    for name in SENSOR_FIELDS:
        raw = frame.get(name)
        try:
            out[name] = float(raw) if raw is not None else None
        except (TypeError, ValueError):
            out[name] = None
    return out
