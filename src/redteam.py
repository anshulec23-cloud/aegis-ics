"""Red-team drill engine — the target side of the portable attack harness.

The owner's design: a script on a USB stick is run on the machine hosting Aegis, attacks the
software in a staged sequence, and the software defends in real time while the loss engine
puts a dollar figure on each incident. This module is the in-app half:

* **Perimeter stages** are run by the portable script itself against the HTTP surface with no
  credentials (unauthenticated ingestion, CSRF-less control, auth bypass, login brute force).
  They are *supposed* to be rejected; the script checks the status codes.
* **Physical-process stages** need bus-level access, so the script asks this module (over a
  localhost-only, token-authenticated endpoint) to inject the malicious telemetry *as if from a
  compromised field device*. The real ingestion pipeline then detects it, quarantines the node,
  and the loss engine quantifies the impact. Nothing is faked: the same detection and trust
  logic that protects real hardware runs here.

A one-time ``redteam_token.txt`` in the data directory authorises the physical stages, so only
a program on the same machine (which can read the data dir) can drive them.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional

import attacks
import protocol

TOKEN_FILE = "redteam_token.txt"
RUNTIME_FILE = "redteam_runtime.json"
# Malicious telemetry per attack (values that an attacker would push to damage the plant).
_MALICIOUS = {
    "fdi_spike": {"temperature": 96.8, "pressure": 12.4, "vibration": 5.8, "hall_effect": 3500.0, "current": 19.2},
    "stuxnet": {"temperature": 55.0, "pressure": 7.8, "vibration": 6.9, "hall_effect": 3250.0, "current": 8.6},
    "thermal_drift": {"temperature": 61.0, "pressure": 8.4, "vibration": 2.4, "hall_effect": 1200.0, "current": 6.8},
}


def _data_dir() -> str:
    from database import DATA_DIR

    return DATA_DIR


def ensure_token() -> str:
    """Return the one-time red-team token, creating (and announcing) it on first use."""
    path = os.path.join(_data_dir(), TOKEN_FILE)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("token: "):
                    return line.split(": ", 1)[1].strip()
    except OSError:
        pass
    token = secrets.token_urlsafe(24)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(
            "Aegis ICS red-team drill token.\n"
            "The portable attack harness reads this to run the physical-process stages.\n"
            f"token: {token}\n"
        )
    return token


def check_token(candidate: Optional[str]) -> bool:
    if not candidate:
        return False
    return secrets.compare_digest(ensure_token(), str(candidate))


def write_runtime_info(port: int) -> None:
    """Publish the live base URL to the data dir so the portable harness can find this app.

    Only a program on this same machine can read the data dir, which is exactly the trust
    boundary we want for the USB drill. Also materialises the drill token on first server start.
    """
    try:
        ensure_token()
        path = os.path.join(_data_dir(), RUNTIME_FILE)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"port": int(port), "base_url": f"http://127.0.0.1:{int(port)}"}, fh)
    except OSError:
        pass


# ------------------------------------------------------------------ targeting ---


def _target_device(db, device_id: Optional[str]) -> Optional[str]:
    """Choose a device to attack: the requested one, else the first approved registry device."""
    import registry

    if device_id and registry.get_key(device_id):
        return device_id
    approved = registry.approved_device_ids()
    return approved[0] if approved else None


def _is_isolated(db, device_id: str) -> bool:
    from database import DeviceState

    st = db.query(DeviceState).filter_by(device_id=device_id).first()
    return bool(st and st.is_isolated)


def _sign_tel(device_id: str, key: str, boot: int, seq: int, values: Dict[str, float]) -> Dict[str, Any]:
    frame = {"v": 1, "type": "TEL", "id": device_id, "boot": boot, "seq": seq, "faults": [], "tripped": False}
    for name, val in values.items():
        frame[name] = protocol.fmt2(val)
    return protocol.sign(frame, key)


# ------------------------------------------------------------------- stages ---


def run_physical_attack(attack: str, device_id: Optional[str] = None) -> Dict[str, Any]:
    """Inject a malicious-telemetry attack from a 'compromised' device and report the defense."""
    import app as app_module
    import registry
    from database import SessionLocal

    key_name = attacks.canonical(attack)
    db = SessionLocal()
    try:
        target = _target_device(db, device_id)
    finally:
        db.close()
    if target is None:
        return {"attack": key_name, "ok": False, "error": "No approved device to target. Connect the simulator and approve a device."}

    key = registry.get_key(target)
    boot = secrets.randbits(31)
    started = time.time()
    statuses: List[int] = []

    if key_name == "hmac_tamper":
        # Forged signatures: the pipeline rejects each and quarantines after repeated failures.
        for seq in range(1, 6):
            frame = _sign_tel(target, key, boot, seq, {"temperature": 25.0, "pressure": 4.0})
            frame["sig"] = "0" * 64
            ok, status, _ = app_module.handle_device_frame(frame)
            statuses.append(status)
    elif key_name == "replay":
        # Capture one valid frame, then resend it: boot/seq replay protection must reject the copy.
        frame = _sign_tel(target, key, boot, 10, {"temperature": 26.0, "pressure": 4.1, "vibration": 1.1, "current": 4.5})
        statuses.append(app_module.handle_device_frame(frame)[1])
        for _ in range(4):
            statuses.append(app_module.handle_device_frame(dict(frame))[1])
    else:
        # Malicious process values (FDI / Stuxnet / drift): detection + trust collapse -> quarantine.
        values = _MALICIOUS.get(key_name, _MALICIOUS["fdi_spike"])
        for seq in range(1, 16):
            frame = _sign_tel(target, key, boot, seq, values)
            ok, status, _ = app_module.handle_device_frame(frame)
            statuses.append(status)
            if _is_isolated_quick(target):
                break

    db = SessionLocal()
    try:
        import loss_engine

        isolated = _is_isolated(db, target)
        incident = loss_engine.assess(db, detections={target: {"attack_type": key_name}})
    finally:
        db.close()

    rejected = sum(1 for s in statuses if s in (401, 403, 409))
    defended = isolated or rejected > 0
    action = (
        "device quarantined (micro-segmented)"
        if isolated
        else ("frames rejected at ingestion" if rejected else "no defensive action")
    )
    this_incident = next((i for i in incident["incidents"] if i["device_id"] == target), None)
    return {
        "attack": key_name,
        "attack_label": attacks.info(key_name)["label"],
        "target": target,
        "ok": True,
        "defended": defended,
        "action": action,
        "frames_sent": len(statuses),
        "frames_rejected": rejected,
        "quarantined": isolated,
        "elapsed_ms": round((time.time() - started) * 1000, 1),
        "incident": this_incident,
        "totals": incident["totals"],
    }


def _is_isolated_quick(device_id: str) -> bool:
    from database import DeviceState, SessionLocal

    db = SessionLocal()
    try:
        st = db.query(DeviceState).filter_by(device_id=device_id).first()
        return bool(st and st.is_isolated)
    finally:
        db.close()


def run_perimeter_selftest(stage_id: str) -> Dict[str, Any]:
    """Exercise a perimeter stage from inside the app (loopback), the way the USB tool would
    from outside, and report whether the HTTP surface rejected it."""
    import app as app_module

    client = app_module.app.test_client()
    bad = {"device_id": "ESP32_EVIL", "temperature": 999}

    if stage_id == "perimeter_flood":
        codes = [client.post("/api/telemetry", json=bad).status_code for _ in range(12)]
        defended = bool(codes) and all(c == 401 for c in codes)
        detail = f"12 unauthenticated frames rejected {sorted(set(codes))} — gateway token required"
    elif stage_id == "perimeter_forged":
        c = client.post(
            "/api/telemetry", json=bad, headers={app_module.GATEWAY_TOKEN_HEADER: "forged" + "x" * 32}
        ).status_code
        defended = c == 401
        detail = f"forged gateway token rejected (HTTP {c})"
    elif stage_id == "perimeter_csrf":
        c = client.post("/api/device/isolate", json={"device_id": "ESP32_EVIL"}).status_code
        defended = c in (400, 401, 403, 302)
        detail = f"control command without a session/CSRF token rejected (HTTP {c})"
    elif stage_id == "perimeter_bruteforce":
        with client.session_transaction() as sess:
            sess["csrf_token"] = "drill"
        codes = []
        for i in range(6):
            r = client.post(
                "/login",
                data={"username": "admin", "password": f"guess{i}", "csrf_token": "drill"},
            )
            codes.append(r.status_code)
        defended = bool(codes) and all(c in (401, 400, 429) for c in codes)
        detail = f"6 wrong-password logins rejected {sorted(set(codes))} — no default password exists"
    else:
        return {"ok": False, "error": f"Unknown perimeter stage '{stage_id}'."}

    return {"ok": True, "defended": defended, "action": "rejected at the perimeter", "detail": detail}


def run_stage(stage_id: str, device_id: Optional[str] = None) -> Dict[str, Any]:
    """Run one campaign stage (perimeter self-test or physical injection) and tag it with the
    campaign metadata so the dashboard and the portable tool render identically."""
    stage = next((s for s in CAMPAIGN if s["id"] == stage_id), None)
    if stage is None:
        return {"ok": False, "error": f"Unknown stage '{stage_id}'."}
    if stage["kind"] == "perimeter":
        res = run_perimeter_selftest(stage_id)
    else:
        res = run_physical_attack(stage_id, device_id)
    res.update({"id": stage_id, "name": stage["name"], "kind": stage["kind"], "expect": stage["expect"]})
    return res


def reset(user_id: Optional[int] = None) -> Dict[str, Any]:
    """Clear drill state and rejoin every device the campaign quarantined."""
    import app as app_module
    from database import AuditLog, DeviceState, SessionLocal

    rejoined = []
    db = SessionLocal()
    try:
        for st in db.query(DeviceState).filter_by(is_isolated=True).all():
            st.is_isolated = False
            rejoined.append(st.device_id)
        db.add(
            AuditLog(
                user_id=user_id,
                action="REDTEAM_CAMPAIGN_RESET",
                location="RED_TEAM",
                details=f"Red-team campaign reset; rejoined {len(rejoined)} node(s).",
            )
        )
        db.commit()
    finally:
        db.close()
    try:
        import simulator

        simulator.reset_attacks()
    except Exception:
        pass
    for dev in rejoined:
        try:
            app_module.send_device_command(dev, "REARM", reason="red-team campaign reset")
        except Exception:
            pass
    return {"ok": True, "rejoined": rejoined}


# The campaign plan — shared by the portable runner and the dashboard so both show the same stages.
CAMPAIGN: List[Dict[str, Any]] = [
    {"id": "perimeter_flood", "kind": "perimeter", "name": "Unauthenticated telemetry flood",
     "expect": "Rejected: ingestion requires the gateway token (401) and is rate limited."},
    {"id": "perimeter_forged", "kind": "perimeter", "name": "Forged-token telemetry injection",
     "expect": "Rejected: wrong gateway token (401)."},
    {"id": "perimeter_csrf", "kind": "perimeter", "name": "Control command without a session/CSRF",
     "expect": "Rejected: login + CSRF required (302/400)."},
    {"id": "perimeter_bruteforce", "kind": "perimeter", "name": "Operator credential brute force",
     "expect": "Rejected: no default password, failed logins audited and rate limited (401)."},
    {"id": "replay", "kind": "physical", "name": "Replay / stale-frame attack",
     "expect": "Rejected: protocol v1 boot/sequence numbers drop the replayed frame (409)."},
    {"id": "hmac_tamper", "kind": "physical", "name": "Signature tampering / spoofing",
     "expect": "Rejected and, after repeated failures, the node is quarantined."},
    {"id": "fdi_spike", "kind": "physical", "name": "False data injection (out-of-envelope spike)",
     "expect": "Detected and micro-segmented; catastrophe prevented, downtime cost incurred."},
    {"id": "stuxnet", "kind": "physical", "name": "Coordinated multi-variable (Stuxnet-style)",
     "expect": "Detected and micro-segmented; largest prevented loss."},
]
