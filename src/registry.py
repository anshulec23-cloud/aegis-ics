"""Device registry and protocol-v1 session handling (ADR 0006).

Responsibilities:
* HELLO handling: discover new devices (-> ``pending``), detect key changes, re-send
  WELCOME to approved devices that lost their key.
* Operator approval / rejection / revocation (key derivation via ``enrollment``).
* Replay protection for device frames (``boot`` + ``seq``).
* Command lifecycle for v1 devices: per-device host sequence numbers, ``command_log`` rows,
  and waiting for the device's ACK.

This module holds no Flask state; ``app.py`` exposes it over HTTP and ``serial_gateway`` feeds
it frames.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import enrollment
import protocol
from database import AuditLog, CommandLog, DATA_DIR, Device, DeviceState, SessionLocal

MAX_REMEMBERED_BOOTS = 32

_lock = threading.RLock()
_host_private = None
_key_cache: Dict[str, str] = {}
_ack_events: Dict[int, threading.Event] = {}


def _now():
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------ identity ---


def host_private():
    global _host_private
    with _lock:
        if _host_private is None:
            _host_private = enrollment.load_or_create_host_identity(DATA_DIR)
        return _host_private


def host_public_hex() -> str:
    return enrollment.public_hex(host_private())


def host_fingerprint() -> str:
    return enrollment.fingerprint(host_public_hex())


# ----------------------------------------------------------------- lookups ---


def get_key(device_id: str) -> Optional[str]:
    """HMAC key of an approved v1 device (cached), else ``None``."""
    with _lock:
        if device_id in _key_cache:
            return _key_cache[device_id]
    db = SessionLocal()
    try:
        dev = db.query(Device).filter_by(device_id=device_id, status="approved").first()
        key = dev.hmac_key if dev else None
    finally:
        db.close()
    with _lock:
        if key:
            _key_cache[device_id] = key
    return key


def _invalidate(device_id: str) -> None:
    with _lock:
        _key_cache.pop(device_id, None)


def is_v1_device(device_id: str) -> bool:
    db = SessionLocal()
    try:
        return (
            db.query(Device).filter_by(device_id=device_id, status="approved").first() is not None
        )
    finally:
        db.close()


def approved_device_ids() -> List[str]:
    db = SessionLocal()
    try:
        return [d.device_id for d in db.query(Device).filter_by(status="approved").all()]
    finally:
        db.close()


def _device_dict(d: Device) -> Dict[str, Any]:
    return {
        "device_id": d.device_id,
        "name": d.name,
        "status": d.status,
        "fingerprint": d.fingerprint,
        "firmware": d.firmware,
        "sensors": json.loads(d.sensors) if d.sensors else [],
        "protocol": d.protocol,
        "first_seen": enrollment_ts(d.first_seen),
        "last_seen": enrollment_ts(d.last_seen),
        "approved_at": enrollment_ts(d.approved_at),
        "enrollment_confirmed": bool(d.enrollment_confirmed),
        "relay_tripped": d.relay_tripped,
    }


def enrollment_ts(dt) -> Optional[float]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def list_devices(status: Optional[str] = None) -> List[Dict[str, Any]]:
    db = SessionLocal()
    try:
        q = db.query(Device)
        if status:
            q = q.filter_by(status=status)
        return [_device_dict(d) for d in q.order_by(Device.first_seen.asc()).all()]
    finally:
        db.close()


def device_info(device_id: str) -> Optional[Dict[str, Any]]:
    db = SessionLocal()
    try:
        d = db.query(Device).filter_by(device_id=device_id).first()
        return _device_dict(d) if d else None
    finally:
        db.close()


# ------------------------------------------------------------------- HELLO ---


def handle_hello(frame: Dict[str, Any]) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Process a HELLO. Returns ``(outcome, reply_frame_or_None)``.

    outcomes: ``pending_new``, ``pending``, ``key_changed``, ``welcome``, ``known``,
    ``revoked``, ``invalid``.
    """
    from device_keys import is_valid_device_id

    device_id = frame.get("id")
    pub = frame.get("pub")
    if not is_valid_device_id(device_id) or not enrollment.is_valid_public_hex(pub):
        return "invalid", None
    sensors = [s for s in frame.get("sensors", []) if isinstance(s, str)][:16]
    firmware = str(frame.get("fw", ""))[:32]
    enrolled = bool(frame.get("enrolled"))

    db = SessionLocal()
    try:
        dev = db.query(Device).filter_by(device_id=device_id).first()
        if dev is None:
            dev = Device(
                device_id=device_id,
                status="pending",
                public_key=pub,
                fingerprint=enrollment.fingerprint(pub),
                firmware=firmware,
                sensors=json.dumps(sensors),
                last_seen=_now(),
            )
            db.add(dev)
            db.add(
                AuditLog(
                    user_id=None,
                    action="DEVICE_DISCOVERED",
                    location="FIELD_BUS",
                    details=f"New device {device_id} requests enrollment (fingerprint {dev.fingerprint}, sensors: {', '.join(sensors) or 'none'}).",
                )
            )
            db.commit()
            print(f"[Registry] New device {device_id} pending approval ({dev.fingerprint})")
            return "pending_new", None

        dev.last_seen = _now()
        dev.firmware = firmware or dev.firmware
        if sensors:
            dev.sensors = json.dumps(sensors)

        if dev.status == "revoked":
            db.commit()
            return "revoked", None

        if dev.public_key != pub:
            previous = dev.status
            dev.public_key = pub
            dev.fingerprint = enrollment.fingerprint(pub)
            dev.status = "pending"
            dev.hmac_key = None
            dev.enrollment_confirmed = False
            dev.last_boot = dev.last_seq = None
            dev.seen_boots = None
            db.add(
                AuditLog(
                    user_id=None,
                    action="DEVICE_KEY_CHANGED",
                    location="FIELD_BUS",
                    details=f"Device {device_id} announced a different public key (new fingerprint {dev.fingerprint}); "
                    f"status {previous} -> pending. Re-approval required.",
                )
            )
            db.commit()
            _invalidate(device_id)
            return "key_changed", None

        if dev.status == "approved":
            if enrolled and dev.enrollment_confirmed:
                db.commit()
                return "known", None
            reply = protocol.build_welcome(device_id, host_public_hex(), dev.hmac_key)
            db.commit()
            return "welcome", reply

        db.commit()
        return "pending", None
    finally:
        db.close()


# ------------------------------------------------------------- approvals ---


def approve(
    device_id: str, user_id: Optional[int], name: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Approve a pending device: derive its key and return the WELCOME frame to send."""
    db = SessionLocal()
    try:
        dev = db.query(Device).filter_by(device_id=device_id).first()
        if dev is None or dev.status != "pending" or not dev.public_key:
            return None
        host_pub = host_public_hex()
        dev.hmac_key = enrollment.derive_session_key(
            host_private(), dev.public_key, device_id, dev.public_key, host_pub
        )
        dev.status = "approved"
        dev.approved_at = _now()
        dev.approved_by = user_id
        dev.enrollment_confirmed = False
        dev.host_seq = 0
        if name:
            dev.name = name[:80]
        if not db.query(DeviceState).filter_by(device_id=device_id).first():
            db.add(DeviceState(device_id=device_id, is_isolated=False))
        db.add(
            AuditLog(
                user_id=user_id,
                action="DEVICE_APPROVED",
                location="REGISTRY",
                details=f"Approved device {device_id} (fingerprint {dev.fingerprint}); session key derived.",
            )
        )
        db.commit()
        welcome = protocol.build_welcome(device_id, host_pub, dev.hmac_key)
    finally:
        db.close()
    _invalidate(device_id)
    return welcome


def reject(device_id: str, user_id: Optional[int], action: str = "DEVICE_REJECTED") -> bool:
    """Reject a pending device or revoke an approved one (status -> revoked, key erased)."""
    db = SessionLocal()
    try:
        dev = db.query(Device).filter_by(device_id=device_id).first()
        if dev is None:
            return False
        dev.status = "revoked"
        dev.hmac_key = None
        dev.enrollment_confirmed = False
        db.add(
            AuditLog(
                user_id=user_id,
                action=action,
                location="REGISTRY",
                details=f"{'Revoked' if action == 'DEVICE_REVOKED' else 'Rejected'} device {device_id} (fingerprint {dev.fingerprint}).",
            )
        )
        db.commit()
    finally:
        db.close()
    _invalidate(device_id)
    return True


def forget(device_id: str, user_id: Optional[int]) -> bool:
    """Delete a revoked/pending entry so the device can be discovered again from scratch."""
    db = SessionLocal()
    try:
        dev = db.query(Device).filter_by(device_id=device_id).first()
        if dev is None or dev.status == "approved":
            return False
        db.delete(dev)
        db.add(
            AuditLog(
                user_id=user_id,
                action="DEVICE_FORGOTTEN",
                location="REGISTRY",
                details=f"Removed registry entry for {device_id}.",
            )
        )
        db.commit()
    finally:
        db.close()
    _invalidate(device_id)
    return True


def rename(device_id: str, name: str, user_id: Optional[int]) -> bool:
    db = SessionLocal()
    try:
        dev = db.query(Device).filter_by(device_id=device_id).first()
        if dev is None:
            return False
        dev.name = name[:80]
        db.add(
            AuditLog(
                user_id=user_id,
                action="DEVICE_RENAMED",
                location="REGISTRY",
                details=f"Device {device_id} renamed to '{name[:80]}'.",
            )
        )
        db.commit()
        return True
    finally:
        db.close()


# ------------------------------------------------------- frame authentication ---


def authenticate_frame(frame: Dict[str, Any]) -> Tuple[bool, str]:
    """Verify a signed v1 frame (TEL / ACK): key, signature, then boot/seq freshness.

    Returns ``(ok, reason)``; reason is one of ``ok``, ``unknown_device``, ``bad_sig``,
    ``replay``, ``bad_seq``.
    """
    device_id = frame.get("id")
    key = get_key(device_id) if isinstance(device_id, str) else None
    if not key:
        return False, "unknown_device"
    if not protocol.verify(frame, key):
        return False, "bad_sig"
    boot, seq = frame.get("boot"), frame.get("seq")
    if not isinstance(boot, int) or not isinstance(seq, int) or isinstance(boot, bool) or seq < 0:
        return False, "bad_seq"

    db = SessionLocal()
    try:
        with _lock:
            dev = db.query(Device).filter_by(device_id=device_id).first()
            seen = json.loads(dev.seen_boots) if dev.seen_boots else []
            if dev.last_boot == boot:
                if dev.last_seq is not None and seq <= dev.last_seq:
                    return False, "replay"
            elif boot in seen:
                return False, "replay"  # frame from an earlier boot of this device
            else:
                seen = (seen + [boot])[-MAX_REMEMBERED_BOOTS:]
                dev.seen_boots = json.dumps(seen)
                dev.last_boot = boot
            dev.last_seq = seq
            dev.last_seen = _now()
            if "tripped" in frame:
                dev.relay_tripped = bool(frame.get("tripped"))
            db.commit()
    finally:
        db.close()
    return True, "ok"


# ------------------------------------------------------------- commands ---


def create_command(
    device_id: str, cmd: str, args: Optional[Dict[str, str]], user_id: Optional[int]
) -> Tuple[int, Dict[str, Any]]:
    """Allocate the next host sequence number, log the command and return ``(log_id, frame)``."""
    db = SessionLocal()
    try:
        with _lock:
            dev = db.query(Device).filter_by(device_id=device_id, status="approved").first()
            if dev is None or not dev.hmac_key:
                raise ValueError(f"{device_id} is not an approved protocol-v1 device")
            dev.host_seq = (dev.host_seq or 0) + 1
            seq = dev.host_seq
            frame = protocol.build_cmd(device_id, seq, cmd, args, dev.hmac_key)
            row = CommandLog(
                device_id=device_id,
                seq=seq,
                command=cmd,
                args=json.dumps(args or {}),
                user_id=user_id,
            )
            db.add(row)
            db.commit()
            log_id = row.id
            _ack_events[log_id] = threading.Event()
    finally:
        db.close()
    return log_id, frame


def mark_command(log_id: int, status: str, result: Optional[str] = None) -> None:
    db = SessionLocal()
    try:
        row = db.get(CommandLog, log_id)
        if row is None or row.status in ("ACKED", "REJECTED"):
            return
        row.status = status
        if result:
            row.result = result[:120]
        if status == "SENT":
            row.sent_at = _now()
        db.commit()
    finally:
        db.close()
    if status in ("EXPIRED", "FAILED"):
        ev = _ack_events.pop(log_id, None)
        if ev:
            ev.set()


def handle_ack(frame: Dict[str, Any]) -> Optional[int]:
    """Apply an authenticated ACK frame to the command log. Returns the command log id."""
    device_id, ack_seq = frame.get("id"), frame.get("ack")
    if not isinstance(ack_seq, int):
        return None
    result = str(frame.get("result", ""))[:16]
    reason = str(frame.get("reason", ""))[:100]

    if ack_seq == 0:  # acknowledgement of WELCOME: enrollment complete on the device
        db = SessionLocal()
        try:
            dev = db.query(Device).filter_by(device_id=device_id).first()
            if dev and result == "OK" and not dev.enrollment_confirmed:
                dev.enrollment_confirmed = True
                db.add(
                    AuditLog(
                        user_id=None,
                        action="DEVICE_ENROLLED",
                        location="FIELD_BUS",
                        details=f"Device {device_id} confirmed its session key.",
                    )
                )
                db.commit()
        finally:
            db.close()
        return None

    db = SessionLocal()
    try:
        row = (
            db.query(CommandLog)
            .filter_by(device_id=device_id, seq=ack_seq)
            .order_by(CommandLog.id.desc())
            .first()
        )
        if row is None:
            return None
        row.status = "ACKED" if result == "OK" else "REJECTED"
        row.result = f"{result}: {reason}".strip(": ") if reason else result
        row.acked_at = _now()
        db.commit()
        log_id = row.id
    finally:
        db.close()
    ev = _ack_events.pop(log_id, None)
    if ev:
        ev.set()
    return log_id


def wait_for_ack(log_id: int, timeout: float) -> Dict[str, Any]:
    ev = _ack_events.get(log_id)
    if ev is not None:
        ev.wait(timeout)
    db = SessionLocal()
    try:
        row = db.get(CommandLog, log_id)
        return {
            "command_id": log_id,
            "status": row.status if row else "UNKNOWN",
            "result": row.result if row else None,
            "seq": row.seq if row else None,
        }
    finally:
        db.close()
