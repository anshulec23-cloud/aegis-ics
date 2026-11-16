import os
import sys
import time
import json
import math
import functools
import threading
import secrets
import bleach
from typing import Optional
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    send_file,
    Response,
    stream_with_context,
)
from werkzeug.security import check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from database import (
    init_db,
    SessionLocal,
    User,
    AuditLog,
    TelemetryLog,
    Rule,
    DeviceState,
    to_utc_epoch,
    setup_required,
    DATA_DIR,
)
from safety_enforcer import validate_command
from sqlalchemy.orm import joinedload
from io import BytesIO

from analytics import (
    calculate_financial_analytics,
    calculate_monte_carlo_distribution,
    get_subsystem_financial_breakdown,
    get_subsystem_profile,
)
from reporting import generate_incident_report_pdf


def _resource_path(relative_path: str) -> str:
    """Resolve file path for both dev and frozen PyInstaller builds."""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)


from security import require_webview_token, get_device_key


init_db()

app = Flask(
    __name__,
    template_folder=_resource_path('templates'),
    static_folder=_resource_path('static'),
)


def _load_or_generate_session_token() -> str:
    env_token = os.environ.get("FLASK_SECRET_KEY")
    if env_token:
        return env_token
    # Stored in the data directory: inside a PyInstaller bundle the source directory is a
    # temporary folder that changes on every launch (sessions would never survive a restart).
    token_path = os.path.join(DATA_DIR, ".aegis_session_key")
    if os.path.exists(token_path):
        try:
            with open(token_path, "r", encoding="utf-8") as tf:
                existing = tf.read().strip()
                if existing:
                    return existing
        except OSError:
            pass
    import secrets as _s

    raw_entropy = _s.token_hex(32)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600
        fd = os.open(token_path, flags, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as tf:
            tf.write(raw_entropy)
    except OSError:
        pass  # Read-only filesystem; entropy held in memory only
    return raw_entropy


app.secret_key = _load_or_generate_session_token()


limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[]
    if os.environ.get("AEGIS_DESKTOP_MODE")
    else ["10000 per hour", "200 per minute"],
    storage_uri="memory://",
)


app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get("FLASK_SESSION_SECURE", "False").lower() in (
    "true",
    "1",
)


# Shared secret between the serial gateway and /api/telemetry. The ingestion endpoint is
# CSRF-exempt (machines post to it), so it must authenticate callers some other way
# (debug report S1). Set AEGIS_GATEWAY_TOKEN when running serial_gateway.py as a
# separate process; otherwise a random per-process token is used by the in-process thread.
GATEWAY_TOKEN = os.environ.get("AEGIS_GATEWAY_TOKEN") or secrets.token_urlsafe(32)
GATEWAY_TOKEN_HEADER = "X-Aegis-Gateway-Token"

from device_keys import is_valid_device_id  # noqa: E402


def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


app.jinja_env.globals.update(csrf_token=generate_csrf_token)


@app.before_request
def csrf_protect():
    # Rate limits are disabled under TESTING (stress tests); security checks are NOT.
    if app.config.get("TESTING"):
        limiter.enabled = False

    if request.path == "/api/telemetry":
        return  # authenticated by gateway token + per-device HMAC instead

    if request.path.startswith("/api/redteam/"):
        return  # localhost-only + one-time drill token instead (see _redteam_guard)

    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        token = (
            request.form.get("csrf_token")
            or request.headers.get("X-CSRF-Token")
            or request.headers.get("X-CSRFToken")
        )

        if not token and request.is_json:
            try:
                token = (request.get_json(silent=True) or {}).get("csrf_token")
            except Exception:
                pass

        session_token = session.get("csrf_token")

        if (
            not session_token
            or not token
            or not secrets.compare_digest(str(session_token), str(token))
        ):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "CSRF token missing or invalid."}), 400
            return render_template(
                "login.html", error="CSRF validation failed. Please authenticate again."
            ), 400


# Content-Security-Policy: inline scripts/styles are still required by dashboard.html
# (they move to static modules in restructure plan Phase 3), but every external origin,
# framing and plugin content is blocked.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self' data:; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


@app.after_request
def set_security_headers(response):
    response.headers.setdefault("Content-Security-Policy", _CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


from trust_engine import compute_device_trust_score  # noqa: E402
from serial_gateway import canonicalize_payload  # noqa: E402


def verify_signature(payload: dict) -> bool:
    """Verify a frame's HMAC with the sending device's own key. Unknown devices fail."""
    import hmac
    import hashlib

    device_id = payload.get("device_id")
    key = get_device_key(device_id) if is_valid_device_id(device_id) else None
    sig = payload.get("signature")
    if not key or not sig:
        return False
    body = {k: v for k, v in payload.items() if k != "signature"}
    try:
        canonical = json.dumps(canonicalize_payload(body), sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return False
    expected = hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, str(sig))


import pickle


class LocalRFModel:
    def __init__(self, model_path=None):
        if model_path is None:
            model_path = _resource_path("model/rf_model.pkl")
        self.model_path = model_path
        self.model = None
        self.fast_trees = None
        self.reload()

    def reload(self) -> bool:
        try:
            if os.path.exists(self.model_path):
                # Verify cryptographic SHA-256 integrity prior to unpickling
                hash_path = self.model_path + ".sha256"
                if os.path.exists(hash_path):
                    import hashlib
                    import hmac

                    with open(hash_path, "r", encoding="utf-8") as hf:
                        expected_hash = hf.read().strip()
                    with open(self.model_path, "rb") as mf:
                        actual_hash = hashlib.sha256(mf.read()).hexdigest()
                    if not hmac.compare_digest(expected_hash, actual_hash):
                        print(
                            f"[Security Error] Model integrity verification failed for {self.model_path}! Expected {expected_hash}, got {actual_hash}. Unpickling blocked."
                        )
                        return False
                with open(self.model_path, "rb") as f:
                    self.model = pickle.load(f)
                if hasattr(self.model, "estimators_"):
                    self.fast_trees = [t.tree_ for t in self.model.estimators_]
                print(
                    f"[Server] Loaded Random Forest model from {self.model_path} ({len(self.fast_trees) if self.fast_trees else 0} trees)"
                )
                return True
        except Exception as e:
            print(f"[Server] Failed to load Random Forest model: {e}")
        return False

    def predict_anomaly(self, telemetry: dict, db_session=None) -> bool:
        if not telemetry or not isinstance(telemetry, dict):
            return False
        temp_val = telemetry.get("temperature")
        pres_val = telemetry.get("pressure")
        vib_val = telemetry.get("vibration")
        hall_val = telemetry.get("hall_effect")
        curr_val = telemetry.get("current")
        hum_val = telemetry.get("humidity")

        temp_max = 60.0
        temp_min = 0.0
        pressure_max = 8.0
        pressure_min = 0.0

        if db_session is not None:
            try:
                from database import Rule

                rules = db_session.query(Rule).all()
                rule_dict = {r.key: r.value for r in rules}
                temp_max = float(rule_dict.get("temp_max", 60.0))
                temp_min = float(rule_dict.get("temp_min", 0.0))
                pressure_max = float(rule_dict.get("pressure_max", 8.0))
                pressure_min = float(rule_dict.get("pressure_min", 0.0))
            except Exception:
                pass

        anomaly = 0.0

        # Safety threshold check against dynamic database rules
        if temp_val is not None:
            try:
                temp = float(temp_val)
                if math.isnan(temp) or math.isinf(temp) or temp < temp_min or temp > temp_max:
                    anomaly += 0.6
            except (ValueError, TypeError):
                anomaly += 0.6
        if pres_val is not None:
            try:
                pres = float(pres_val)
                if (
                    math.isnan(pres)
                    or math.isinf(pres)
                    or pres < pressure_min
                    or pres > pressure_max
                ):
                    anomaly += 0.6
            except (ValueError, TypeError):
                anomaly += 0.6
        if vib_val is not None:
            try:
                if float(vib_val) > 6.0:
                    anomaly += 0.6
            except (ValueError, TypeError):
                anomaly += 0.6
        # Device-specific Hall-effect RPM limits:
        # ESP32_004 (Turbine Generator) has a normal operating baseline of 2200.0 RPM, with overspeed trip at 3000.0 RPM.
        # Pump and auxiliary nodes (ESP32_002) have baseline of 1500.0 RPM, with overspeed trip at 2000.0 RPM.
        dev_id_val = str(telemetry.get("device_id", ""))
        # Global overspeed limit (per-device limits arrive with the device profile editor).
        hall_max = float(os.environ.get("AEGIS_RPM_MAX", "3000"))
        if hall_val is not None:
            try:
                if float(hall_val) > hall_max:
                    anomaly += 0.6
            except (ValueError, TypeError):
                anomaly += 0.6
        if curr_val is not None:
            try:
                if float(curr_val) > 8.0:
                    anomaly += 0.6
            except (ValueError, TypeError):
                anomaly += 0.6

        # Only execute 5D Random Forest ML model if all core metrics are provided in payload
        all_features_present = (
            temp_val is not None
            and pres_val is not None
            and vib_val is not None
            and curr_val is not None
        )
        if all_features_present and (self.fast_trees or self.model is not None):
            try:
                feat_vec = [
                    float(temp_val),
                    float(pres_val),
                    float(vib_val),
                    float(hall_val) if hall_val is not None else 0.0,
                    float(curr_val),
                ]
                if self.fast_trees:
                    p_sum = 0.0
                    for t in self.fast_trees:
                        node = 0
                        while t.children_left[node] != t.children_right[node]:
                            if feat_vec[t.feature[node]] <= t.threshold[node]:
                                node = t.children_left[node]
                            else:
                                node = t.children_right[node]
                        val = t.value[node][0]
                        p_sum += val[1] / (val[0] + val[1])
                    rf_prob = p_sum / len(self.fast_trees)
                else:
                    import numpy as np

                    rf_prob = float(self.model.predict_proba(np.array([feat_vec]))[0][1])

                if rf_prob > 0.5:
                    anomaly += 0.6
            except Exception:
                pass

        return anomaly > 0.5


rf_model = LocalRFModel(_resource_path(os.path.join("model", "rf_model.pkl")))


# --- Ingestion guards -------------------------------------------------------------------
# A single unauthenticated frame must never be able to quarantine a node and trip its
# relay (debug report S1). Signature failures are counted per device in a sliding window;
# only SIG_FAILURE_THRESHOLD failures within SIG_FAILURE_WINDOW_S trigger quarantine.
SIG_FAILURE_THRESHOLD = int(os.environ.get("AEGIS_SIG_FAILURE_THRESHOLD", "3"))
SIG_FAILURE_WINDOW_S = float(os.environ.get("AEGIS_SIG_FAILURE_WINDOW_S", "60"))
# Identical signed frames seen again within this window are rejected as replays (S5).
# Firmware v2.5 frames carry no sequence number yet (protocol v1, plan P2.1), so this
# duplicate-signature cache is the interim replay defence.
REPLAY_WINDOW_S = float(os.environ.get("AEGIS_REPLAY_WINDOW_S", "300"))
MAX_TIMESTAMP_SKEW_S = 60.0

_ingest_lock = threading.Lock()
_sig_failures: "defaultdict[str, list]" = defaultdict(list)
_seen_signatures: "dict[tuple, float]" = {}


def _record_signature_failure(device_id: str, now: float) -> int:
    with _ingest_lock:
        window = [t for t in _sig_failures[device_id] if now - t <= SIG_FAILURE_WINDOW_S]
        window.append(now)
        _sig_failures[device_id] = window
        return len(window)


def _is_replay(device_id: str, signature: str, now: float) -> bool:
    with _ingest_lock:
        if len(_seen_signatures) > 50_000:
            for key, seen in list(_seen_signatures.items()):
                if now - seen > REPLAY_WINDOW_S:
                    del _seen_signatures[key]
        key = (device_id, signature)
        seen = _seen_signatures.get(key)
        if seen is not None and now - seen <= REPLAY_WINDOW_S:
            return True
        _seen_signatures[key] = now
        return False


def _parse_timestamp(t_val):
    """Return epoch seconds for a numeric or ISO-8601 timestamp (raises ValueError)."""
    if isinstance(t_val, bool):
        raise ValueError("boolean timestamp")
    if isinstance(t_val, (int, float)):
        value = float(t_val)
    elif isinstance(t_val, str):
        try:
            value = float(t_val)
        except ValueError:
            parsed = datetime.fromisoformat(t_val.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            value = parsed.timestamp()
    else:
        raise ValueError("unsupported timestamp type")
    if math.isnan(value) or math.isinf(value):
        raise ValueError("non-finite timestamp")
    return value


def _quarantine_device(db, device_id: str, reason: str) -> None:
    """Mark a device isolated, audit it, and send ISOLATE to its relay."""
    now_utc = datetime.now(timezone.utc)
    state = db.query(DeviceState).filter_by(device_id=device_id).first()
    if not state:
        db.add(DeviceState(device_id=device_id, is_isolated=True, updated_at=now_utc))
    else:
        state.is_isolated = True
        state.updated_at = now_utc
    db.add(
        AuditLog(
            user_id=None,
            action="AUTO_ISOLATION",
            location="SYSTEM",
            details=f"System automatically isolated device {device_id} due to {reason}."[:255],
        )
    )
    db.commit()
    print(f"[SYSTEM] AUTOMATIC ISOLATION TRIGGERED FOR DEVICE {device_id} ({reason})")
    send_device_command(device_id, "ISOLATE", reason=reason)


V0_COMMAND_NAMES = {"ISOLATE": "ISOLATE", "REARM": "REARM", "SHUTDOWN": "SHUTDOWN", "PING": "ping"}


def send_device_command(
    device_id: str,
    cmd: str,
    args: Optional[dict] = None,
    user_id: Optional[int] = None,
    wait_ack_s: float = 0.0,
    reason: Optional[str] = None,
) -> dict:
    """Send a command to one device over the gateway.

    Protocol-v1 devices (enrolled via the registry) get a signed ``CMD`` with a fresh host
    sequence number, tracked in ``command_log``; with ``wait_ack_s`` the call waits for the
    device's ACK. Legacy v0 devices get the old JSON command. Returns a status dict with
    ``sent`` plus, for v1, ``command_id`` / ``status`` / ``result``.
    """
    import registry
    import serial_gateway

    if not serial_gateway.is_connected():
        print(f"[Server] No gateway connected; {cmd} for {device_id} not sent to hardware.")
        return {"sent": False, "status": "NO_GATEWAY"}

    if device_id != "ALL" and registry.is_v1_device(device_id):
        try:
            log_id, frame = registry.create_command(device_id, cmd, args, user_id)
        except ValueError as err:
            print(f"[Server] Command not sent: {err}")
            return {"sent": False, "status": "FAILED", "result": str(err)}
        serial_gateway.send_frame(frame, command_log_id=log_id)
        if wait_ack_s > 0:
            outcome = registry.wait_for_ack(log_id, wait_ack_s)
            if outcome["status"] in ("QUEUED", "SENT"):
                outcome["status"] = "PENDING_ACK"
            return {"sent": True, **outcome}
        return {"sent": True, "command_id": log_id, "status": "SENT", "result": None}

    legacy = {
        "command": V0_COMMAND_NAMES.get(cmd, cmd),
        "action": V0_COMMAND_NAMES.get(cmd, cmd),
        "device_id": device_id,
        "target_device": device_id,
        "timestamp": time.time(),
    }
    if cmd == "PING":
        legacy["target"] = device_id
    if reason:
        legacy["reason"] = reason
    if args:
        legacy.update(args)
    try:
        serial_gateway.send_command(legacy)
        return {"sent": True, "status": "SENT"}
    except ValueError as err:
        print(f"[Server] Command not sent: {err}")
        return {"sent": False, "status": "FAILED", "result": str(err)}


def _dispatch_command(cmd: dict) -> bool:
    """Back-compat wrapper used by routes that build v0-style command dicts."""
    name = str(cmd.get("command") or cmd.get("action") or "").upper()
    target = cmd.get("device_id") or cmd.get("target_device") or "ALL"
    if name == "DISCOVER":
        import serial_gateway

        if not serial_gateway.is_connected():
            return False
        serial_gateway.send_command(cmd)
        return True
    if target == "ALL" and name == "SHUTDOWN":
        sent = False
        for dev in _known_device_ids():
            sent = send_device_command(dev, "SHUTDOWN")["sent"] or sent
        return sent
    return send_device_command(target, name, reason=cmd.get("reason"))["sent"]


def _known_device_ids() -> list:
    """Every device the host knows about: approved registry entries, legacy provisioned
    (env / key file) devices, devices with state rows and devices that sent telemetry.
    Replaces the old hard-coded ESP32_001..004 lists."""
    import registry
    from device_keys import provisioned_devices

    db = SessionLocal()
    try:
        ids = set(registry.approved_device_ids()) | provisioned_devices()
        ids |= {r.device_id for r in db.query(DeviceState).all() if r.device_id}
        ids |= {r[0] for r in db.query(TelemetryLog.device_id).distinct().all() if r[0]}
    finally:
        db.close()
    return sorted(ids)


def _ingest_authenticated(device_id: str, fields: dict, stored_ts: float, faults=None):
    """Store an authenticated reading, score trust and apply the quarantine policy."""
    import serial_gateway

    is_simulated = serial_gateway.is_mock_active()
    faults = [f for f in (faults or []) if isinstance(f, str)][:8]
    fault_str = ",".join(faults) or None
    db = SessionLocal()
    try:
        state = db.query(DeviceState).filter_by(device_id=device_id).first()
        if state is None:
            state = DeviceState(device_id=device_id, is_isolated=False)
            db.add(state)
            db.flush()
        if state.is_isolated:
            # Keep authenticated post-trip telemetry so operators can verify de-energisation.
            db.add(
                TelemetryLog(
                    timestamp=stored_ts,
                    device_id=device_id,
                    is_anomaly=True,
                    is_simulated=is_simulated,
                    faults=fault_str,
                    **fields,
                )
            )
            db.commit()
            return (
                False,
                403,
                f"Access Denied: Device {device_id} is quarantined by Zero-Trust microsegmentation policy.",
            )

        payload = dict(fields, device_id=device_id)
        # A faulted sensor is an anomaly: the plant can't be verified as safe (debug report F7).
        ml_anomaly = rf_model.predict_anomaly(payload, db_session=db) or bool(faults)
        db.add(
            TelemetryLog(
                timestamp=stored_ts,
                device_id=device_id,
                is_anomaly=ml_anomaly,
                is_simulated=is_simulated,
                faults=fault_str,
                **fields,
            )
        )
        db.commit()

        trust_info = compute_device_trust_score(
            device_id, db, latest_is_anomaly=ml_anomaly, latest_sig_valid=True
        )
        trust_score = trust_info.get("trust_score", 1.0)

        # Autonomous quarantine: trust collapse (< 0.40) or anomaly while degraded (< 0.50).
        if trust_score < 0.40 or (ml_anomaly and trust_score < 0.50):
            if trust_score < 0.40:
                reason = (
                    f"continuous trust collapsed to {trust_score:.2f} (<0.40 quarantine threshold)"
                )
            else:
                reason = "safeguard boundary violation / behavioral anomaly detection"
            _quarantine_device(db, device_id, reason)

        return True, 200, "Telemetry ingested successfully."
    except Exception as e:
        db.rollback()
        print(f"[Server] Database write failed: {e}")
        return False, 500, "Database write operation failed."
    finally:
        db.close()


_audit_throttle: dict = {}
AUDIT_THROTTLE_S = 60.0


def _audit_throttled(device_id: str, action: str, details: str) -> None:
    """Record a security event at most once per device/action per minute (no log flooding)."""
    now = time.time()
    with _ingest_lock:
        last = _audit_throttle.get((device_id, action), 0.0)
        if now - last < AUDIT_THROTTLE_S:
            return
        _audit_throttle[(device_id, action)] = now
    db = SessionLocal()
    try:
        db.add(AuditLog(user_id=None, action=action, location="FIELD_BUS", details=details[:255]))
        db.commit()
    finally:
        db.close()


def _signature_failure(device_id: str, now: float) -> None:
    _audit_throttled(
        device_id,
        "SIGNATURE_REJECTED",
        f"Rejected frame(s) with an invalid HMAC signature from {device_id}.",
    )
    failures = _record_signature_failure(device_id, now)
    print(
        f"[Server] Invalid signature from {device_id} ({failures}/{SIG_FAILURE_THRESHOLD} in window)"
    )
    if failures >= SIG_FAILURE_THRESHOLD:
        db = SessionLocal()
        try:
            state = db.query(DeviceState).filter_by(device_id=device_id).first()
            if not (state and state.is_isolated):
                _quarantine_device(
                    db,
                    device_id,
                    f"{failures} invalid HMAC signatures within {SIG_FAILURE_WINDOW_S:.0f}s",
                )
        finally:
            db.close()


def handle_device_frame(frame: dict) -> tuple[bool, int, str]:
    """Entry point for protocol-v1 frames (in-process from the gateway, or via /api/telemetry).

    HELLO -> registry (discovery / WELCOME); TEL -> authenticated ingestion; ACK -> command log.
    """
    import protocol
    import registry
    import serial_gateway

    ftype = frame.get("type")
    device_id = frame.get("id")
    if not is_valid_device_id(device_id):
        return False, 400, "Rejected: invalid device id."

    if ftype == "HELLO":
        outcome, reply = registry.handle_hello(frame)
        if reply is not None and serial_gateway.is_connected():
            serial_gateway.send_frame(reply)
        return outcome != "invalid", 200 if outcome != "invalid" else 400, f"HELLO: {outcome}"

    if ftype not in ("TEL", "ACK"):
        return False, 400, f"Rejected: unsupported frame type {ftype!r}."

    ok, reason = registry.authenticate_frame(frame)
    if not ok:
        if reason == "unknown_device":
            return False, 403, f"Rejected: device {device_id} is not enrolled."
        if reason == "bad_sig":
            _signature_failure(device_id, time.time())
            return False, 401, "Rejected: invalid signature."
        if reason == "replay":
            _audit_throttled(
                device_id,
                "REPLAY_REJECTED",
                f"Rejected replayed frame(s) from {device_id} (boot/seq already seen).",
            )
            return False, 409, "Rejected: replayed frame (boot/seq already seen)."
        return False, 400, "Rejected: malformed sequence fields."

    if ftype == "ACK":
        registry.handle_ack(frame)
        if frame.get("ack") == 0 and frame.get("result") == "OK":
            # A device that (re-)enrolls while quarantined is tripped again immediately:
            # it may have lost its trip state (flash wiped / replaced board).
            db = SessionLocal()
            try:
                state = db.query(DeviceState).filter_by(device_id=device_id).first()
                quarantined = bool(state and state.is_isolated)
            finally:
                db.close()
            if quarantined:
                send_device_command(
                    device_id, "ISOLATE", reason="quarantine re-sync after enrollment"
                )
        return True, 200, "ACK recorded."

    fields = protocol.telemetry_fields(frame)
    return _ingest_authenticated(device_id, fields, time.time(), frame.get("faults"))


def process_telemetry(payload: dict) -> tuple[bool, int, str]:
    """Protocol-v0 telemetry (legacy firmware with pre-provisioned keys)."""
    now = time.time()
    device_id = payload.get("device_id")
    if not is_valid_device_id(device_id):
        return False, 400, "Rejected: invalid device_id."
    if not get_device_key(device_id):
        print(f"[Server] Telemetry REJECTED from unprovisioned device: {device_id}")
        return False, 403, f"Rejected: device {device_id} is not provisioned."

    # 1. Freshness window (applies in every mode, including tests).
    numeric_ts = None
    if payload.get("timestamp") is not None:
        try:
            numeric_ts = _parse_timestamp(payload["timestamp"])
        except (ValueError, TypeError):
            return False, 400, "Rejected: Invalid telemetry timestamp format."
        skew = abs(now - numeric_ts)
        if skew > MAX_TIMESTAMP_SKEW_S:
            return False, 400, f"Rejected: Telemetry timestamp expired (skew={skew:.1f}s)."

    # 2. Authenticate before anything is stored or acted on.
    if not verify_signature(payload):
        _signature_failure(device_id, now)
        return False, 401, "Rejected: invalid signature."

    # 3. Replay protection.
    if _is_replay(device_id, str(payload.get("signature")), now):
        return False, 409, "Rejected: duplicate frame (possible replay)."

    fields = {
        k: payload.get(k)
        for k in (
            "temperature",
            "pressure",
            "humidity",
            "vibration",
            "hall_effect",
            "current",
            "rssi",
        )
    }
    return _ingest_authenticated(device_id, fields, numeric_ts if numeric_ts is not None else now)


def login_required(f):
    @functools.wraps(f)
    def decorator(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorator


# --- First-run setup ------------------------------------------------------------------
_SETUP_STATE = {"required": None}
_SETUP_OPEN_PATHS = ("/setup", "/static/", "/health", "/api/version")


def is_setup_required() -> bool:
    if _SETUP_STATE["required"] is None:
        _SETUP_STATE["required"] = setup_required()
    return _SETUP_STATE["required"]


def refresh_setup_state() -> None:
    _SETUP_STATE["required"] = None


def setup_url() -> str:
    """Path (with one-time token) the desktop shell opens when setup is pending, else ``/``."""
    from bootstrap import ensure_setup_token

    if not is_setup_required():
        return "/"
    return f"/setup?token={ensure_setup_token(DATA_DIR)}"


@app.before_request
def require_first_run_setup():
    if not is_setup_required():
        return None
    if request.path.startswith(_SETUP_OPEN_PATHS) or request.path == "/api/telemetry":
        return None
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "First-run setup required.", "setup": True}), 503
    return redirect(url_for("first_run_setup"))


@app.route("/setup", methods=["GET", "POST"])
@limiter.limit("20 per minute")
def first_run_setup():
    from bootstrap import (
        MIN_PASSWORD_LENGTH,
        check_setup_token,
        clear_setup_token,
        ensure_setup_token,
        password_problem,
    )
    from werkzeug.security import generate_password_hash

    if not is_setup_required():
        return redirect(url_for("login"))
    ensure_setup_token(DATA_DIR)  # make sure a token exists (and is announced) on first visit

    token = request.values.get("token", "")
    token_ok = check_setup_token(DATA_DIR, token)
    context = {
        "token": token if token_ok else "",
        "token_ok": token_ok,
        "min_length": MIN_PASSWORD_LENGTH,
        "data_dir": DATA_DIR,
    }
    if request.method == "GET":
        return render_template("setup.html", **context)

    if not token_ok:
        return render_template("setup.html", error="Invalid or expired setup link.", **context), 403
    password = request.form.get("password", "")
    if password != request.form.get("confirm", ""):
        return render_template("setup.html", error="Passwords do not match.", **context), 400
    problem = password_problem(password)
    if problem:
        return render_template("setup.html", error=f"Password {problem}.", **context), 400

    db = SessionLocal()
    try:
        admin = db.query(User).filter_by(username="admin").first()
        if admin is None:
            admin = User(username="admin", password_hash=generate_password_hash(password))
            db.add(admin)
        else:
            admin.password_hash = generate_password_hash(password)
        db.flush()
        db.add(
            AuditLog(
                user_id=admin.id,
                action="ADMIN_ACCOUNT_CREATED",
                location="FIRST_RUN_SETUP",
                details=f"Administrator password set via first-run setup (Client IP: {request.remote_addr or 'unknown'}).",
            )
        )
        db.commit()
        admin_id = admin.id
    finally:
        db.close()

    clear_setup_token(DATA_DIR)
    refresh_setup_state()
    session.clear()
    session.permanent = True
    session["user_id"] = admin_id
    session["username"] = "admin"
    session["location"] = "FIRST_RUN_SETUP"
    return redirect(url_for("index"))


@app.route("/")
@login_required
def index():
    return render_template(
        "dashboard.html", username=session.get("username"), location=session.get("location")
    )


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("120 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        location_coords = request.form.get("location_coords")
        latitude = request.form.get("latitude")
        longitude = request.form.get("longitude")
        elevation = request.form.get("elevation")

        if location_coords:
            location_str = bleach.clean(str(location_coords))
        elif latitude and longitude:
            try:
                lat_f = float(latitude)
                lon_f = float(longitude)
                elev_f = float(elevation or 0.0)
                location_str = f"Lat: {lat_f:.5f}, Lon: {lon_f:.5f}, Elev: {elev_f:.1f}m"
            except ValueError:
                location_str = "Control Station (Sector-4, Lat: 37.77490, Lon: -122.41940)"
        else:
            coord_x = request.form.get("coord_x")
            coord_y = request.form.get("coord_y")
            coord_z = request.form.get("coord_z")
            if coord_x is not None and coord_y is not None:
                try:
                    cx = float(coord_x)
                    cy = float(coord_y)
                    cz = float(coord_z or 0.0)
                    location_str = f"X={cx:.2f}, Y={cy:.2f}, Z={cz:.2f}"
                except ValueError:
                    location_str = (
                        "Terminal GPS: Lat 37.77490, Lon -122.41940, Elev 18.5m [Grid H-01]"
                    )
            else:
                location_str = "Terminal GPS: Lat 37.77490, Lon -122.41940, Elev 18.5m [Grid H-01]"

        # X-Forwarded-For is client-controlled and is not trusted for audit records (S13).
        client_ip = request.remote_addr or "unknown"
        # The username is attacker-controlled on failed logins and is rendered in the
        # audit view: store an escaped, length-limited copy (debug report S7).
        safe_username = bleach.clean(str(username or ""))[:50]
        db = SessionLocal()
        user = db.query(User).filter_by(username=username).first() if username else None

        if user and password and check_password_hash(user.password_hash, password):
            session.clear()  # new session on privilege change (prevents session fixation)
            session.permanent = True
            session["user_id"] = user.id
            session["username"] = user.username
            session["location"] = location_str

            audit = AuditLog(
                user_id=user.id,
                action="LOGIN_SUCCESS",
                location=location_str,
                details=f"Operator '{safe_username}' successfully authenticated (Client IP: {client_ip}).",
            )
            db.add(audit)
            db.commit()
            db.close()
            return redirect(url_for("index"))

        # Record failed login attempt in Security Audit Log (NIST AU-2 / IA-2 compliance)
        audit_failed = AuditLog(
            user_id=user.id if user else None,
            action="LOGIN_FAILED",
            location=location_str,
            details=f"Authentication rejected: invalid credentials for '{safe_username}' (Client IP: {client_ip}).",
        )
        db.add(audit_failed)
        db.commit()
        db.close()
        return render_template("login.html", error="Invalid credentials."), 401

    return render_template("login.html")


@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    location = session.get("location", "Unknown")
    username = session.get("username", "Unknown")
    client_ip = request.remote_addr or "unknown"

    if user_id:
        db = SessionLocal()
        audit = AuditLog(
            user_id=user_id,
            action="LOGOUT",
            location=location,
            details=f"Operator '{username}' logged out (Client IP: {client_ip}).",
        )
        db.add(audit)
        db.commit()
        db.close()

    session.clear()
    return redirect(url_for("login"))


@app.route("/api/setpoint", methods=["POST"])
@login_required
@require_webview_token
@limiter.limit("30 per minute")
def setpoint():
    payload = request.json or {}
    cmd_type = bleach.clean(str(payload.get("type", "")))
    try:
        val_input = payload.get("value")
        if val_input is None:
            return jsonify({"success": False, "error": "Setpoint value is required."}), 400
        if isinstance(val_input, bool):
            return jsonify(
                {"success": False, "error": "Command setpoint value must be numeric."}
            ), 400
        value = float(val_input)
        if math.isnan(value) or math.isinf(value):
            return jsonify(
                {
                    "success": False,
                    "error": "Command setpoint value must be a finite numeric value.",
                }
            ), 400
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid numeric value."}), 400

    db = SessionLocal()

    target_device = bleach.clean(
        str(payload.get("target_device") or payload.get("device_id") or "")
    )
    if not is_valid_device_id(target_device):
        db.close()
        return jsonify({"success": False, "error": "A valid target_device is required."}), 400
    state = db.query(DeviceState).filter_by(device_id=target_device).first()
    if state and state.is_isolated:
        db.close()
        return jsonify(
            {
                "success": False,
                "error": f"Blocked: Control loop commands rejected because device {target_device} is currently isolated.",
            }
        ), 403

    allowed, reason = validate_command(
        {"type": cmd_type, "value": value}, db, target_device=target_device
    )

    user_id = session["user_id"]
    location = session["location"]

    if not allowed:
        act_name = (
            "STALE_TELEMETRY_BLOCKED"
            if "Stale Telemetry" in reason
            else "SECURITY_VIOLATION_BLOCKED"
        )
        audit = AuditLog(
            user_id=user_id,
            action=act_name,
            location=location,
            details=f"Blocked attempt to set {cmd_type} to {value} on {target_device}. Reason: {reason}",
        )
        db.add(audit)
        db.commit()
        db.close()
        return jsonify({"success": False, "error": reason}), 403

    import serial_gateway

    if not serial_gateway.is_connected():
        # Never queue a setpoint for "later": it would be replayed on the next connection
        # with stale context (debug report F3).
        db.add(
            AuditLog(
                user_id=user_id,
                action="SETPOINT_NOT_DELIVERED",
                location=location,
                details=f"Setpoint {cmd_type}={value} for {target_device} approved but not sent: no hardware gateway connected.",
            )
        )
        db.commit()
        db.close()
        return jsonify(
            {
                "success": False,
                "error": "No hardware gateway connected. Connect a COM port (or the simulator) and retry.",
            }
        ), 503

    import protocol
    import registry

    if registry.is_v1_device(target_device):
        outcome = send_device_command(
            target_device,
            "SETPOINT",
            {"param": protocol.SETPOINT_PARAMS[cmd_type], "value": protocol.fmt2(value)},
            user_id=user_id,
            wait_ack_s=3.0,
        )
        status = outcome.get("status")
        if status == "REJECTED":
            db.add(
                AuditLog(
                    user_id=user_id,
                    action="SETPOINT_REJECTED_BY_DEVICE",
                    location=location,
                    details=f"{target_device} rejected {cmd_type}={value}: {outcome.get('result')}",
                )
            )
            db.commit()
            db.close()
            return jsonify(
                {
                    "success": False,
                    "error": f"Device rejected the setpoint: {outcome.get('result')}",
                    "command": outcome,
                }
            ), 409
        if status != "ACKED":
            db.add(
                AuditLog(
                    user_id=user_id,
                    action="SETPOINT_NOT_CONFIRMED",
                    location=location,
                    details=f"{cmd_type}={value} sent to {target_device} but not acknowledged ({status}).",
                )
            )
            db.commit()
            db.close()
            return jsonify(
                {
                    "success": False,
                    "error": f"Setpoint sent but the device did not acknowledge it ({status}).",
                    "command": outcome,
                }
            ), 504
        db.add(
            AuditLog(
                user_id=user_id,
                action="CHANGE_SETPOINT",
                location=location,
                details=f"Changed {cmd_type} to {value} on {target_device} (device ACK seq {outcome.get('seq')}).",
            )
        )
        db.commit()
        db.close()
        return jsonify(
            {
                "success": True,
                "details": f"Setpoint {value} applied and acknowledged by {target_device}.",
                "command": outcome,
            }
        )

    # Legacy v0 firmware: fire-and-forget (no acknowledgement in protocol v0).
    command_body = {
        "command": "setpoint",
        "device_id": target_device,
        "target": cmd_type,
        "value": value,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        serial_gateway.send_command(command_body)
        print(f"[Server] Dispatched control command: {cmd_type}={value} -> {target_device}")
    except Exception as e:
        db.close()
        print(f"[Server] UART publish failed: {e}")
        return jsonify(
            {"success": False, "error": "UART publish failed. Target controller unreachable."}
        ), 500

    audit = AuditLog(
        user_id=user_id,
        action="CHANGE_SETPOINT",
        location=location,
        details=f"Changed {cmd_type} to {value} on {target_device}.",
    )
    db.add(audit)
    db.commit()
    db.close()

    return jsonify(
        {
            "success": True,
            "details": f"Setpoint {value} sent to {target_device} (protocol v0: no device acknowledgement yet).",
        }
    )


@app.route("/api/neural_policy/status", methods=["GET"])
@login_required
@require_webview_token
def neural_policy_status():
    try:
        from neural_policy import get_neural_policy

        policy = get_neural_policy()
        latency_val = 0.019
        try:
            metrics_path = _resource_path(os.path.join("model", "training_metrics.json"))
            if os.path.exists(metrics_path):
                with open(metrics_path, "r") as mf:
                    m_data = json.load(mf)
                    latency_val = float(
                        m_data.get("nspn", {}).get("inference_latency_numpy_ms", 0.019)
                    )
        except Exception:
            pass

        return jsonify(
            {
                "success": True,
                "status": "ACTIVE" if policy.weights_loaded else "HEURISTIC_FALLBACK",
                "weights_loaded": policy.weights_loaded,
                "architecture": "6 -> 64 -> 32 -> 16 -> 1",
                "activations": "LeakyReLU(0.1), Sigmoid",
                "device": "CPU (Local / Offline)",
                "empirical_latency_ms": round(latency_val, 4),
            }
        )
    except Exception as e:
        print(f"[Neural Policy Status Error] {e}")
        return jsonify({"success": False, "error": "Unable to query neural policy status."}), 500


@app.route("/api/com_ports", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def list_com_ports():
    try:
        import serial_gateway

        ports = serial_gateway.find_esp32_ports()
        if not ports:
            from serial.tools import list_ports

            ports = [
                {
                    "device": p.device,
                    "description": p.description or "Hardware Serial Interface",
                    "hwid": getattr(p, "hwid", "") or "UART",
                    "is_esp32_candidate": False,
                }
                for p in list_ports.comports()
            ]
        return jsonify({"success": True, "ports": ports})
    except Exception as e:
        print(f"[COM Ports Query Error] {e}")
        return jsonify(
            {"success": False, "error": "Failed to enumerate COM ports.", "ports": []}
        ), 500


@app.route("/api/gateway/raw_packets", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def gateway_raw_packets():
    try:
        import serial_gateway

        packets = serial_gateway.get_recent_raw_packets(limit=60)
        return jsonify({"success": True, "packets": packets})
    except Exception as e:
        print(f"[Raw Packets Query Error] {e}")
        return jsonify(
            {"success": False, "error": "Failed to retrieve gateway packets.", "packets": []}
        ), 500


@app.route("/api/com_ports/status", methods=["GET"])
@login_required
@require_webview_token
def com_port_status():
    try:
        import serial_gateway

        port = serial_gateway.get_active_port()
        state = serial_gateway.get_gateway_state()
        health = serial_gateway.get_gateway_health()
        return jsonify({"success": True, "port": port, "state": state, "health": health})
    except Exception as e:
        print(f"[COM Status Query Error] {e}")
        return jsonify({"success": False, "error": "Failed to read gateway status."}), 500


@app.route("/api/cluster/topology", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def cluster_topology():
    """
    Returns the real-time physical cluster topology:
    - Master Concentrator Bridge connection status
    - Total detected ESP32 slave nodes
    - Total active sensor transducers across the cluster
    - Per-node breakdown of all 5 physical sensors (Temp, Pres, Vib, RPM, Curr)
    """
    try:
        import serial_gateway

        health = serial_gateway.get_gateway_health()
        active_nodes = serial_gateway.get_active_nodes()

        db = SessionLocal()
        try:
            t_devs = [r[0] for r in db.query(TelemetryLog.device_id).distinct().all() if r[0]]
            s_devs = [r.device_id for r in db.query(DeviceState).all() if r.device_id]
            all_dev_ids = sorted(set(_known_device_ids()) | set(active_nodes.keys()))

            nodes = []
            now_ts = time.time()
            total_sensors = 0

            for dev_id in all_dev_ids:
                state = db.query(DeviceState).filter_by(device_id=dev_id).first()
                is_isolated = state.is_isolated if state else False
                last_log = (
                    db.query(TelemetryLog)
                    .filter_by(device_id=dev_id)
                    .order_by(TelemetryLog.timestamp.desc())
                    .first()
                )
                trust = compute_device_trust_score(dev_id, db)
                profile = get_subsystem_profile(dev_id, db)

                # Detect which of the 5 sensors are active on this node
                gateway_node = active_nodes.get(dev_id, {})
                sensors = gateway_node.get("sensors", [])
                if not sensors and last_log:
                    s_detected = []
                    if last_log.temperature is not None:
                        s_detected.append("temperature")
                    if last_log.pressure is not None:
                        s_detected.append("pressure")
                    if last_log.vibration is not None:
                        s_detected.append("vibration")
                    if last_log.hall_effect is not None:
                        s_detected.append("hall_effect")
                    if last_log.current is not None:
                        s_detected.append("current")
                    sensors = s_detected

                sensor_count = len(sensors)
                total_sensors += sensor_count

                last_ts = last_log.timestamp if last_log else gateway_node.get("last_seen")
                is_active = bool(
                    last_ts is not None and (now_ts - last_ts) <= 10.0 and not is_isolated
                )

                nodes.append(
                    {
                        "device_id": dev_id,
                        "name": profile.get("name", f"Industrial Node {dev_id}"),
                        "zone": profile.get("zone", "Fieldbus Segment"),
                        "criticality": profile.get("criticality", "TIER-2 HIGH"),
                        "is_isolated": is_isolated,
                        "is_active": is_active,
                        "trust_score": trust["trust_score"],
                        "trust_percentage": trust["trust_percentage"],
                        "status": trust["status"],
                        "last_seen": last_ts,
                        "sensors": sensors,
                        "active_sensors_count": sensor_count,
                        "latest_readings": {
                            "temperature": last_log.temperature if last_log else None,
                            "pressure": last_log.pressure if last_log else None,
                            "vibration": last_log.vibration if last_log else None,
                            "hall_effect": last_log.hall_effect if last_log else None,
                            "current": last_log.current if last_log else None,
                        },
                    }
                )

            return jsonify(
                {
                    "success": True,
                    "master_bridge": health.get("master_bridge", {}),
                    "gateway_state": health.get("state", "DISCONNECTED"),
                    "active_port": health.get("active_port"),
                    "total_nodes_count": len(nodes),
                    "online_nodes_count": sum(1 for n in nodes if n["is_active"]),
                    "total_active_sensors": total_sensors,
                    "nodes": nodes,
                }
            )
        finally:
            db.close()
    except Exception as e:
        print(f"[Cluster Topology Error] {e}")
        return jsonify({"success": False, "error": "Failed to retrieve cluster topology."}), 500


def _resync_quarantine():
    """Re-send ISOLATE to every quarantined node (called by the gateway after connecting)."""
    db = SessionLocal()
    try:
        isolated = [d.device_id for d in db.query(DeviceState).filter_by(is_isolated=True).all()]
    finally:
        db.close()
    for dev in isolated:
        send_device_command(dev, "ISOLATE", reason="quarantine re-sync on gateway connect")
    return isolated


def _install_gateway_frame_handler():
    """Frames from the in-process gateway go straight to ingestion (ADR 0003); no loopback HTTP."""
    import serial_gateway

    serial_gateway.set_frame_handler(handle_device_frame, process_telemetry)


_install_gateway_frame_handler()


def _spawn_gateway_thread(**kwargs):
    """Start serial_gateway.start_gateway on a daemon thread (patched in tests)."""
    import serial_gateway

    thread = threading.Thread(
        target=serial_gateway.start_gateway, kwargs=kwargs, daemon=True, name="serial-gateway"
    )
    thread.start()
    return thread


@app.route("/api/com_ports/connect", methods=["POST"])
@login_required
@require_webview_token
def connect_com_port():
    payload = request.json or {}
    port = payload.get("port")
    try:
        baud = int(payload.get("baud", 115200))
    except (ValueError, TypeError):
        baud = 115200
    if not port:
        return jsonify({"success": False, "error": "No port specified."})
    try:
        import serial_gateway
        import threading

        serial_gateway.stop_gateway()
        time.sleep(0.2)

        flask_port = os.environ.get("FLASK_PORT", "5000")
        url = f"http://127.0.0.1:{flask_port}/api/telemetry"

        mock = port.upper().startswith("MOCK") or port.upper().startswith("SIM")

        db = SessionLocal()
        isolated = [d.device_id for d in db.query(DeviceState).filter_by(is_isolated=True).all()]

        # Each frame is verified with its own device's key: no shared hmac_key (F1).
        # Quarantine survives reconnects (S8): once the link is up the gateway calls
        # _resync_quarantine(), which re-sends ISOLATE to every quarantined node.
        _install_gateway_frame_handler()
        _spawn_gateway_thread(
            port=port if not mock else None,
            baud=baud,
            mock=mock,
            url=url,
            gateway_token=GATEWAY_TOKEN,
            on_connect=_resync_quarantine,
        )

        audit = AuditLog(
            user_id=session.get("user_id"),
            action="CONNECT_COM_PORT",
            location=session.get("location"),
            details=f"Connected hardware gateway to port {bleach.clean(str(port))[:40]}; "
            f"re-sent ISOLATE to {len(isolated)} quarantined node(s).",
        )
        db.add(audit)
        db.commit()
        db.close()

        return jsonify({"success": True, "details": f"Gateway connecting to {port}."})
    except Exception as e:
        print(f"[COM Connect Error] {e}")
        return jsonify({"success": False, "error": "Failed to connect to specified COM port."}), 500


@app.route("/api/com_ports/disconnect", methods=["POST"])
@login_required
@require_webview_token
def disconnect_com_port():
    try:
        import serial_gateway

        serial_gateway.stop_gateway()

        db = SessionLocal()
        audit = AuditLog(
            user_id=session.get("user_id"),
            action="DISCONNECT_COM_PORT",
            location=session.get("location"),
            details="Disconnected hardware gateway manually.",
        )
        db.add(audit)
        db.commit()
        db.close()

        return jsonify({"success": True, "details": "Disconnected COM port successfully."})
    except Exception as e:
        print(f"[COM Disconnect Error] {e}")
        return jsonify({"success": False, "error": "Failed to disconnect COM port."}), 500


@app.route("/api/devices", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def list_all_devices():
    db = SessionLocal()
    try:
        import serial_gateway

        active_nodes = serial_gateway.get_active_nodes()

        t_devs = [r[0] for r in db.query(TelemetryLog.device_id).distinct().all() if r[0]]
        s_devs = [r.device_id for r in db.query(DeviceState).all() if r.device_id]
        all_dev_ids = sorted(set(_known_device_ids()) | set(active_nodes.keys()))

        now_ts = time.time()
        results = []
        for dev_id in all_dev_ids:
            state = db.query(DeviceState).filter_by(device_id=dev_id).first()
            is_isolated = state.is_isolated if state else False
            last_log = (
                db.query(TelemetryLog)
                .filter_by(device_id=dev_id)
                .order_by(TelemetryLog.timestamp.desc())
                .first()
            )
            trust = compute_device_trust_score(dev_id, db)
            profile = get_subsystem_profile(dev_id, db)

            # Detect sensors for this node
            gateway_node = active_nodes.get(dev_id, {})
            sensors = gateway_node.get("sensors", [])
            if not sensors and last_log:
                s_detected = []
                if last_log.temperature is not None:
                    s_detected.append("temperature")
                if last_log.pressure is not None:
                    s_detected.append("pressure")
                if last_log.vibration is not None:
                    s_detected.append("vibration")
                if last_log.hall_effect is not None:
                    s_detected.append("hall_effect")
                if last_log.current is not None:
                    s_detected.append("current")
                sensors = s_detected

            last_ts = last_log.timestamp if last_log else gateway_node.get("last_seen")
            # Hardware is actively communicating if telemetry was received within the last 10 seconds
            is_active = bool(last_ts is not None and (now_ts - last_ts) <= 10.0 and not is_isolated)

            results.append(
                {
                    "device_id": dev_id,
                    "name": profile.get("name", f"Industrial Node {dev_id}"),
                    "zone": profile.get("zone", "Auxiliary Field Bus"),
                    "criticality": profile.get("criticality", "STANDARD"),
                    "is_isolated": is_isolated,
                    "is_active": is_active,
                    "trust_score": trust["trust_score"],
                    "trust_percentage": trust["trust_percentage"],
                    "status": trust["status"],
                    "last_seen": last_ts,
                    "sensors": sensors,
                    "active_sensors_count": len(sensors),
                    "latest_temp": last_log.temperature if last_log else None,
                    "latest_pres": last_log.pressure if last_log else None,
                    "latest_vib": last_log.vibration if last_log else None,
                    "latest_curr": last_log.current if last_log else None,
                    "latest_hall": last_log.hall_effect if last_log else None,
                    "latest_hum": last_log.humidity if last_log else None,
                }
            )
        return jsonify({"success": True, "devices": results})
    finally:
        db.close()


# --- Device registry (zero-touch enrollment, ADR 0006) -------------------------------------


@app.route("/api/registry", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def registry_list():
    import registry

    devices = registry.list_devices()
    return jsonify(
        {
            "success": True,
            "host_fingerprint": registry.host_fingerprint(),
            "pending_count": sum(1 for d in devices if d["status"] == "pending"),
            "devices": devices,
        }
    )


def _registry_target(device_id: str):
    import registry

    if not is_valid_device_id(device_id):
        return None, (jsonify({"success": False, "error": "Invalid device id."}), 400)
    info = registry.device_info(device_id)
    if info is None:
        return None, (jsonify({"success": False, "error": "Unknown device."}), 404)
    return info, None


@app.route("/api/registry/<device_id>/approve", methods=["POST"])
@login_required
@require_webview_token
def registry_approve(device_id):
    import registry
    import serial_gateway

    info, error = _registry_target(device_id)
    if error:
        return error
    if info["status"] != "pending":
        return jsonify(
            {"success": False, "error": f"Device is {info['status']}, not pending."}
        ), 409
    import financials

    payload = request.get_json(silent=True) or {}
    name = bleach.clean(str(payload.get("name", "")))[:80] or None
    try:
        fin = financials.normalize_input(payload.get("financials"))
    except ValueError as err:
        return jsonify({"success": False, "error": f"Financial profile: {err}"}), 400
    welcome = registry.approve(device_id, session.get("user_id"), name=name, financials=fin)
    if welcome is None:
        return jsonify({"success": False, "error": "Approval failed."}), 409
    delivered = serial_gateway.is_connected()
    if delivered:
        serial_gateway.send_frame(welcome)
    return jsonify(
        {
            "success": True,
            "details": f"{device_id} approved."
            + (
                ""
                if delivered
                else " The key will be delivered when the device next announces itself."
            ),
            "device": registry.device_info(device_id),
        }
    )


@app.route("/api/registry/<device_id>/reject", methods=["POST"])
@login_required
@require_webview_token
def registry_reject(device_id):
    import registry

    info, error = _registry_target(device_id)
    if error:
        return error
    action = "DEVICE_REVOKED" if info["status"] == "approved" else "DEVICE_REJECTED"
    registry.reject(device_id, session.get("user_id"), action=action)
    if action == "DEVICE_REVOKED":
        send_device_command(device_id, "ISOLATE", reason="device revoked")  # best effort
    return jsonify(
        {
            "success": True,
            "details": f"{device_id} {'revoked' if action == 'DEVICE_REVOKED' else 'rejected'}.",
        }
    )


@app.route("/api/registry/<device_id>/forget", methods=["POST"])
@login_required
@require_webview_token
def registry_forget(device_id):
    import registry

    info, error = _registry_target(device_id)
    if error:
        return error
    if not registry.forget(device_id, session.get("user_id")):
        return jsonify({"success": False, "error": "Revoke the device before removing it."}), 409
    return jsonify(
        {
            "success": True,
            "details": f"{device_id} removed; it will reappear as pending if it announces again.",
        }
    )


@app.route("/api/registry/roles", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def registry_roles():
    import financials

    return jsonify(
        {
            "success": True,
            "roles": financials.role_choices(),
            "criticality": financials.CRITICALITY_CHOICES,
        }
    )


@app.route("/api/registry/<device_id>/financials", methods=["POST"])
@login_required
@require_webview_token
def registry_financials(device_id):
    import financials
    import registry

    info, error = _registry_target(device_id)
    if error:
        return error
    try:
        fin = financials.normalize_input(request.get_json(silent=True) or {})
    except ValueError as err:
        return jsonify({"success": False, "error": f"Financial profile: {err}"}), 400
    registry.set_financials(device_id, fin, session.get("user_id"))
    return jsonify({"success": True, "device": registry.device_info(device_id)})


@app.route("/api/registry/<device_id>/rename", methods=["POST"])
@login_required
@require_webview_token
def registry_rename(device_id):
    import registry

    info, error = _registry_target(device_id)
    if error:
        return error
    name = bleach.clean(str((request.get_json(silent=True) or {}).get("name", ""))).strip()[:80]
    if not name:
        return jsonify({"success": False, "error": "Name required."}), 400
    registry.rename(device_id, name, session.get("user_id"))
    return jsonify({"success": True, "device": registry.device_info(device_id)})


@app.route("/api/device/status", methods=["GET"])
@login_required
@require_webview_token
def device_status():
    device_id = request.args.get("device_id", "")
    db = SessionLocal()
    state = db.query(DeviceState).filter_by(device_id=device_id).first()
    is_isolated = state.is_isolated if state else False
    trust = compute_device_trust_score(device_id, db)
    db.close()
    return jsonify({"device_id": device_id, "is_isolated": is_isolated, "trust": trust})


@app.route("/api/device/isolate", methods=["POST"])
@login_required
@require_webview_token
def isolate_device_v2():
    payload = request.json or {}
    device_id = str(payload.get("device_id", ""))
    if not is_valid_device_id(device_id):
        return jsonify({"success": False, "error": "Invalid device_id."}), 400
    db = SessionLocal()
    state = db.query(DeviceState).filter_by(device_id=device_id).first()
    now_utc = datetime.now(timezone.utc)
    if not state:
        state = DeviceState(device_id=device_id, is_isolated=True, updated_at=now_utc)
        db.add(state)
    else:
        state.is_isolated = True
        state.updated_at = now_utc

    audit = AuditLog(
        user_id=session.get("user_id"),
        action="MANUAL_ISOLATION",
        location=session.get("location", "SYSTEM"),
        details=f"Operator manually isolated device {device_id} from control loop.",
    )
    db.add(audit)
    db.commit()
    db.close()

    outcome = send_device_command(
        device_id, "ISOLATE", user_id=session.get("user_id"), wait_ack_s=2.0
    )
    sent = outcome["sent"]
    note = "" if sent else " No gateway connected: ISOLATE will be re-sent when one connects."
    if outcome.get("status") == "ACKED":
        note = " Device confirmed: relay tripped."
    return jsonify(
        {
            "success": True,
            "hardware_command_sent": sent,
            "command": outcome,
            "details": f"Device {device_id} successfully isolated.{note}",
        }
    )


@app.route("/api/device/rejoin", methods=["POST"])
@login_required
@require_webview_token
def rejoin_device_v2():
    payload = request.json or {}
    device_id = str(payload.get("device_id", ""))
    if not is_valid_device_id(device_id):
        return jsonify({"success": False, "error": "Invalid device_id."}), 400
    db = SessionLocal()
    state = db.query(DeviceState).filter_by(device_id=device_id).first()
    now_utc = datetime.now(timezone.utc)
    if not state:
        state = DeviceState(device_id=device_id, is_isolated=False, updated_at=now_utc)
        db.add(state)
    else:
        state.is_isolated = False
        state.updated_at = now_utc

    audit = AuditLog(
        user_id=session.get("user_id"),
        action="MANUAL_REJOIN",
        location=session.get("location", "SYSTEM"),
        details=f"Operator manually rejoined device {device_id} to control loop.",
    )
    db.add(audit)
    db.commit()
    db.close()

    outcome = send_device_command(
        device_id, "REARM", user_id=session.get("user_id"), wait_ack_s=2.0
    )
    sent = outcome["sent"]
    note = "" if sent else " No gateway connected: relay state unchanged until REARM is sent."
    if outcome.get("status") == "ACKED":
        note = " Device confirmed: relay re-energised."
    return jsonify(
        {
            "success": True,
            "hardware_command_sent": sent,
            "command": outcome,
            "details": f"Device {device_id} successfully rejoined to control loop.{note}",
        }
    )


@app.route("/api/device/shutdown", methods=["POST"])
@login_required
@require_webview_token
def shutdown_device():
    payload = request.json or {}
    device_id = str(payload.get("device_id", "ALL"))
    if device_id != "ALL" and not is_valid_device_id(device_id):
        return jsonify({"success": False, "error": "Invalid device_id."}), 400
    db = SessionLocal()
    try:
        now_utc = datetime.now(timezone.utc)
        if device_id == "ALL":
            from device_keys import provisioned_devices

            targets = {d.device_id for d in db.query(DeviceState).all()} | provisioned_devices()
        else:
            targets = {device_id}
        for target in targets:
            state = db.query(DeviceState).filter_by(device_id=target).first()
            if not state:
                db.add(DeviceState(device_id=target, is_isolated=True, updated_at=now_utc))
            else:
                state.is_isolated = True
                state.updated_at = now_utc

        audit = AuditLog(
            user_id=session.get("user_id"),
            action="EMERGENCY_SHUTDOWN",
            location=session.get("location", "SYSTEM"),
            details=f"Operator executed emergency shutdown instruction on target: {device_id}.",
        )
        db.add(audit)
        db.commit()

        sent = _dispatch_command(
            {
                "command": "SHUTDOWN",
                "action": "SHUTDOWN",
                "device_id": device_id,
                "target_device": device_id,
                "timestamp": time.time(),
            }
        )
        note = "" if sent else " WARNING: no gateway connected -- confirm relays physically."
        return jsonify(
            {
                "success": True,
                "hardware_command_sent": sent,
                "details": f"Emergency shutdown instruction dispatched to {device_id}.{note}",
            }
        )
    except Exception as e:
        print(f"[Emergency Shutdown Error] {e}")
        return jsonify({"success": False, "error": "Emergency shutdown execution failed."}), 500
    finally:
        db.close()


@app.route("/api/cluster/discover", methods=["POST", "GET"])
@limiter.exempt
@login_required
@require_webview_token
def discover_cluster():
    try:
        import serial_gateway

        _dispatch_command(
            {
                "command": "DISCOVER",
                "action": "DISCOVER",
                "target_device": "ALL",
                "timestamp": time.time(),
            }
        )
        health = serial_gateway.get_gateway_health()
        active_nodes = serial_gateway.get_active_nodes()
        return jsonify(
            {
                "success": True,
                "message": "Discovery probe dispatched to Master Concentrator",
                "health": health,
                "active_nodes": active_nodes,
            }
        )
    except Exception as e:
        print(f"[Cluster Discover Error] {e}")
        return jsonify(
            {"success": False, "error": "Failed to dispatch cluster discovery probe."}
        ), 500


@app.route("/api/device/ping", methods=["POST"])
@login_required
@require_webview_token
def ping_device():
    """Send a ping frame. Firmware v2.5 does not answer pings, so no latency is reported
    (the previous fixed 14.2 ms value was fabricated -- debug report F14)."""
    payload = request.json or {}
    device_id = str(payload.get("device_id", ""))
    if not is_valid_device_id(device_id):
        return jsonify({"success": False, "error": "Invalid device_id."}), 400
    db = SessionLocal()
    try:
        started = time.perf_counter()
        outcome = send_device_command(
            device_id, "PING", user_id=session.get("user_id"), wait_ack_s=2.0
        )
        rtt_ms = (
            round((time.perf_counter() - started) * 1000.0, 1)
            if outcome.get("status") == "ACKED"
            else None
        )
        sent = outcome["sent"]
        audit = AuditLog(
            user_id=session.get("user_id"),
            action="DEVICE_PING_SENT",
            location=session.get("location", "SYSTEM"),
            details=f"Ping frame {'sent' if sent else 'NOT sent (no gateway)'} to device {device_id}.",
        )
        db.add(audit)
        db.commit()
        return jsonify(
            {
                "success": True,
                "device_id": device_id,
                "hardware_command_sent": sent,
                "latency_ms": rtt_ms,
                "details": (
                    f"Ping acknowledged by {device_id} (measured RTT {rtt_ms} ms)."
                    if rtt_ms is not None
                    else f"Ping frame sent to {device_id}; no acknowledgement "
                    "(legacy v0 firmware does not answer pings)."
                    if sent
                    else f"Ping not sent to {device_id}: no hardware gateway connected."
                ),
            }
        )
    finally:
        db.close()


@app.route("/api/device/clear", methods=["POST"])
@login_required
@require_webview_token
def clear_device_alarms():
    payload = request.json or {}
    device_id = bleach.clean(str(payload.get("device_id", "ALL")))
    db = SessionLocal()
    try:
        audit = AuditLog(
            user_id=session.get("user_id"),
            action="DEVICE_ALARMS_CLEARED",
            location=session.get("location", "SYSTEM"),
            details=f"Operator cleared security alarms and warning flags for {device_id}.",
        )
        db.add(audit)
        db.commit()
        try:
            import serial_gateway

            if device_id == "ALL":
                serial_gateway.reset_attacks()
            else:
                serial_gateway.clear_device_attack(device_id)
        except Exception:
            pass

        return jsonify(
            {
                "success": True,
                "device_id": device_id,
                "details": f"Alarms and warning states cleared for {device_id}.",
            }
        )
    finally:
        db.close()


@app.route("/api/device/<device_id>/trust_breakdown", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def device_trust_breakdown(device_id):
    clean_id = bleach.clean(str(device_id))
    db = SessionLocal()
    try:
        from trust_engine import get_trust_breakdown

        breakdown = get_trust_breakdown(clean_id, db)
        return jsonify({"success": True, "data": breakdown})
    except Exception as e:
        print(f"[Trust Breakdown Error] {e}")
        return jsonify({"success": False, "error": "Failed to compute trust breakdown."}), 500
    finally:
        db.close()


@app.route("/api/simulate/attack", methods=["POST"])
@login_required
@require_webview_token
def simulate_attack_endpoint():
    payload = request.json or {}
    device_id = bleach.clean(str(payload.get("device_id", "")))
    attack_type = bleach.clean(str(payload.get("attack_type", "stuxnet")))
    try:
        import serial_gateway

        # Drills only ever run on the software simulator, never on real field devices.
        bus = serial_gateway.get_simulated_bus()
        if not serial_gateway.is_mock_active() or bus is None:
            return jsonify(
                {
                    "success": False,
                    "error": "Drills need the software simulator: connect SOFTWARE EMULATOR in Station 06.",
                }
            ), 409
        if bus.device(device_id) is None:
            return jsonify(
                {"success": False, "error": f"{device_id} is not a simulated device."}
            ), 409

        res = serial_gateway.inject_attack(device_id, attack_type)
        if res.get("success"):
            db = SessionLocal()
            audit = AuditLog(
                user_id=session.get("user_id"),
                action="ATTACK_SIMULATION_INJECTED",
                location=session.get("location", "SYSTEM"),
                details=f"[RED TEAM] Injected attack vector '{attack_type}' onto {device_id}.",
            )
            db.add(audit)
            db.commit()
            db.close()
        return jsonify(res)
    except Exception as e:
        print(f"[Simulation Step Error] {e}")
        return jsonify({"success": False, "error": "Simulation step execution failed."}), 500


@app.route("/api/simulate/reset", methods=["POST"])
@login_required
@require_webview_token
def simulate_reset_endpoint():
    try:
        import serial_gateway

        res = serial_gateway.reset_attacks()
        db = SessionLocal()
        audit = AuditLog(
            user_id=session.get("user_id"),
            action="ATTACK_SIMULATION_RESET",
            location=session.get("location", "SYSTEM"),
            details="[RED TEAM] Cleared all active cyber-physical attack simulation vectors.",
        )
        db.add(audit)
        db.commit()
        db.close()
        return jsonify(res)
    except Exception as e:
        print(f"[Simulation Reset Error] {e}")
        return jsonify({"success": False, "error": "Failed to reset simulation state."}), 500


@app.route("/api/audit/logs", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def get_audit_logs():
    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(limit, 300))
    category = request.args.get("category", "ALL").upper()
    operator_filter = request.args.get("operator", "").strip()
    search_term = request.args.get("search", "").strip().lower()

    db = SessionLocal()
    try:
        query = db.query(AuditLog).options(joinedload(AuditLog.user))

        if operator_filter and operator_filter != "ALL":
            if operator_filter.lower() == "system":
                query = query.filter(AuditLog.user_id == None)
            else:
                query = query.join(User).filter(User.username == operator_filter)

        logs = query.order_by(AuditLog.timestamp.desc()).limit(limit * 2).all()

        def map_nist_control(action: str) -> str:
            act = (action or "").upper()
            if "ISOLAT" in act or "QUARANTINE" in act:
                return "NIST SC-7 (Boundary Protection / Microsegmentation)"
            elif "REJECT" in act or "SETPOINT" in act or "STUXNET" in act:
                return "NIST AC-4 (Information Flow Enforcement)"
            elif "ANOMALY" in act or "ATTACK" in act or "INJECT" in act:
                return "NIST SI-4 (Information System Monitoring)"
            elif "LOGIN" in act or "AUTH" in act:
                return "NIST IA-2 (Identification & Authentication)"
            elif "MODEL" in act or "CALIBRAT" in act:
                return "NIST SI-7 (Software & Information Integrity)"
            else:
                return "NIST AU-2 / AU-12 (Audit & Accountability)"

        def determine_severity(action: str) -> str:
            act = (action or "").upper()
            if any(
                w in act
                for w in (
                    "VIOLATION",
                    "ATTACK",
                    "BLOCKED",
                    "FAILED",
                    "QUARANTINE",
                    "REPLAY",
                    "SIGNATURE_REJECTED",
                    "KEY_CHANGED",
                )
            ):
                return "CRITICAL"
            elif any(
                w in act for w in ("SETPOINT", "ISOLAT", "RECONNECT", "DISCONNECT", "WARNING")
            ):
                return "WARNING"
            return "INFO"

        data = []
        for log in logs:
            act = (log.action or "").upper()
            if category == "AUTH" and not any(k in act for k in ("LOGIN", "LOGOUT", "AUTH")):
                continue
            elif category == "SETPOINT" and "SETPOINT" not in act:
                continue
            elif category == "QUARANTINE" and not any(k in act for k in ("ISOLAT", "QUARANTINE")):
                continue
            elif category == "VIOLATION" and "VIOLATION" not in act:
                continue
            elif category == "GATEWAY" and not any(k in act for k in ("COM_PORT", "GATEWAY")):
                continue
            elif category == "MODEL" and not any(
                k in act for k in ("MODEL", "BASELINE", "CALIBRAT")
            ):
                continue

            op_name = (
                log.user.username
                if log.user
                else ("System" if log.user_id is None else f"User#{log.user_id}")
            )
            det = log.details or ""
            loc = log.location or "Local Terminal"

            if search_term and (
                search_term not in act.lower()
                and search_term not in det.lower()
                and search_term not in op_name.lower()
                and search_term not in loc.lower()
            ):
                continue

            ts_epoch = to_utc_epoch(log.timestamp)
            ts_str = (
                log.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                if hasattr(log.timestamp, "strftime")
                else str(log.timestamp or "")
            )

            data.append(
                {
                    "id": log.id,
                    "timestamp": ts_str,
                    "timestamp_epoch": ts_epoch,
                    "operator": op_name,
                    "action": log.action,
                    "location": loc,
                    "details": det,
                    "severity": "SIMULATED" if log.is_simulated else determine_severity(log.action),
                    "nist_control": map_nist_control(log.action),
                    "is_simulated": bool(log.is_simulated),
                }
            )
            if len(data) >= limit:
                break

        return jsonify({"success": True, "logs": data})
    except Exception as e:
        print(f"[Audit Logs Error] {e}")
        return jsonify({"success": False, "error": "Failed to retrieve audit log records."}), 500
    finally:
        db.close()


@app.route("/api/model/retrain", methods=["POST"])
@login_required
@require_webview_token
@limiter.limit("10 per minute")
def api_retrain_model():
    db = SessionLocal()
    try:
        from train_model import retrain_from_hardware_telemetry

        res = retrain_from_hardware_telemetry(db)
        rf_model.reload()

        user_id = session.get("user_id")
        location = session.get("location", "Local Terminal")
        username = session.get("username", "System")
        audit = AuditLog(
            user_id=user_id,
            action="MODEL_RETRAINED_FROM_HARDWARE",
            location=location,
            details=f"Operator '{username}' calibrated Random Forest model with {res.get('hardware_samples_used', 0)} hardware COM frames (Accuracy: {res.get('accuracy', 0) * 100:.1f}%).",
        )
        db.add(audit)
        db.commit()
        return jsonify({"success": True, "metrics": res})
    except Exception as e:
        print(f"[Financial Metrics Error] {e}")
        return jsonify({"success": False, "error": "Failed to execute model retraining."}), 500
    finally:
        db.close()


def _json_safe(obj):
    """Recursively replace non-finite floats (inf/-inf/nan) with None.

    sklearn's roc_curve sets thresholds[0] to +inf; json.load accepts it, but jsonify then
    emits the literal token ``Infinity``, which is invalid JSON and makes browsers throw a
    SyntaxError when parsing /api/model/status. Sanitize before serializing.
    """
    import math

    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    return obj


@app.route("/api/model/status", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def api_model_status():
    db = SessionLocal()
    try:
        real_samples_count = db.query(TelemetryLog).filter_by(is_simulated=False).count()
        metrics_path = _resource_path(os.path.join("model", "training_metrics.json"))
        metrics = {}
        if os.path.exists(metrics_path):
            try:
                with open(metrics_path, "r") as mf:
                    metrics = _json_safe(json.load(mf))
            except Exception:
                pass
        try:
            import detection

            classifier = detection.status()
        except Exception:
            classifier = {"available": False}
        return jsonify(
            {
                "success": True,
                "real_samples_count": real_samples_count,
                "trees_count": len(rf_model.fast_trees) if rf_model.fast_trees else 0,
                "enforcement_status": "ACTIVE_ZERO_TRUST",
                "metrics": metrics,
                "attack_classifier": classifier,
            }
        )
    except Exception as e:
        print(f"[Dashboard Analytics Error] {e}")
        return jsonify(
            {"success": False, "error": "Failed to retrieve model telemetry metrics."}
        ), 500
    finally:
        db.close()


@app.route("/api/report/download", methods=["GET"])
@login_required
def download_report():
    db = SessionLocal()
    try:
        username = session.get("username", "admin")
        location = session.get("location", "X:+12.40, Y:-48.10, Z:+3.50")
        pdf_data = generate_incident_report_pdf(db, username, location, detections=_current_detections(db))
        filename = f"aegis_scada_nist800_report_{int(time.time())}.pdf"
        response = send_file(
            BytesIO(pdf_data),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename,
            max_age=0,
        )
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        response.headers["Content-Length"] = len(pdf_data)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    except Exception as e:
        print(f"[Report Generation Error] {e}")
        return jsonify(
            {"success": False, "error": "Automated security report generation failed."}
        ), 500
    finally:
        db.close()


@app.route("/api/report/view", methods=["GET"])
@login_required
def view_report():
    """Renders the NIST SP 800-82 incident report PDF inline for direct browser inspection."""
    db = SessionLocal()
    try:
        username = session.get("username", "admin")
        location = session.get("location", "X:+12.40, Y:-48.10, Z:+3.50")
        pdf_data = generate_incident_report_pdf(db, username, location, detections=_current_detections(db))
        filename = f"aegis_scada_nist800_report_{int(time.time())}.pdf"
        response = send_file(
            BytesIO(pdf_data),
            mimetype="application/pdf",
            as_attachment=False,
            download_name=filename,
            max_age=0,
        )
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f'inline; filename="{filename}"'
        response.headers["Content-Length"] = len(pdf_data)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    except Exception as e:
        print(f"[Report View Error] {e}")
        return jsonify({"success": False, "error": "Failed to render security report."}), 500
    finally:
        db.close()


@app.route("/api/report/save_dialog", methods=["POST", "GET"])
@login_required
def save_report_dialog():
    db = SessionLocal()
    try:
        # A native (Tk) save dialog only makes sense in the desktop app, where the server and
        # the operator share a screen. In web/headless mode it would open on the *server*
        # and block a worker thread, so ?native=1 is ignored there (debug report S11).
        if not os.environ.get("AEGIS_DESKTOP_MODE"):
            return jsonify(
                {
                    "success": True,
                    "download_url": "/api/report/download",
                    "message": "Report generated. Use direct download endpoint in web mode.",
                }
            ), 200

        username = session.get("username", "admin")
        location = session.get("location", "X:+12.40, Y:-48.10, Z:+3.50")
        pdf_data = generate_incident_report_pdf(db, username, location, detections=_current_detections(db))

        default_filename = f"aegis_scada_nist800_report_{int(time.time())}.pdf"

        # Open native Windows save file dialog using Tkinter
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)

        file_path = filedialog.asksaveasfilename(
            title="Save Incident Report PDF",
            initialfile=default_filename,
            defaultextension=".pdf",
            filetypes=[("PDF Documents (*.pdf)", "*.pdf"), ("All Files (*.*)", "*.*")],
        )
        root.destroy()

        if not file_path:
            return jsonify(
                {"success": False, "cancelled": True, "message": "Save cancelled by user."}
            )

        with open(file_path, "wb") as f:
            f.write(pdf_data)

        return jsonify(
            {
                "success": True,
                "saved_path": file_path,
                "message": f"Report saved successfully to {os.path.basename(file_path)}",
            }
        )
    except Exception as e:
        print(f"[Report Save Dialog Fallback] {e}")
        return jsonify(
            {
                "success": True,
                "download_url": "/api/report/download",
                "message": "Native save dialog unavailable. Initiating direct download.",
            }
        )
    finally:
        db.close()


@app.route("/api/financial/analytics", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def get_financial_analytics():
    device_id = request.args.get("device_id")
    target_dev = device_id if (device_id and device_id != "ALL" and device_id != "all") else None
    db = SessionLocal()
    try:
        import loss_engine

        data = calculate_financial_analytics(db, device_id=target_dev)
        # Live incident loss picture (actual / projected / time-to-fix / restabilization / where).
        data["incident"] = loss_engine.assess(db, detections=_current_detections(db))
        return jsonify({"success": True, "financials": data})
    except Exception as e:
        print(f"[Financial Analytics Error] {e}")
        return jsonify({"success": False, "error": "Failed to calculate financial analytics."}), 500
    finally:
        db.close()


@app.route("/api/financial/incident", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def get_incident_losses():
    """Live incident loss accounting on its own (drives the financial tab's incident panel)."""
    db = SessionLocal()
    try:
        import loss_engine

        return jsonify(
            {
                "success": True,
                "incident": loss_engine.assess(db, detections=_current_detections(db)),
            }
        )
    except Exception as e:
        print(f"[Incident Loss Error] {e}")
        return jsonify({"success": False, "error": "Failed to compute incident losses."}), 500
    finally:
        db.close()


def _current_detections(db):
    """Assemble the current attack detections for the loss engine.

    The trained offline classifier (detection.py) names the physical-process attack behind each
    quarantined / anomalous node from its telemetry. Where it is confident, its label (and
    confidence) feed the loss engine so the incident is priced by the real attack type; where it
    abstains (protocol attacks leave no malicious telemetry), the loss engine falls back to the
    deterministic/audit view. Best-effort: never let detection break the financial read.
    """
    try:
        import detection
        from database import DeviceState, TelemetryLog

        if not detection.model_available():
            return None

        candidates = {s.device_id for s in db.query(DeviceState).filter_by(is_isolated=True).all()}
        recent_anom = (
            db.query(TelemetryLog.device_id)
            .filter(TelemetryLog.is_anomaly == True)  # noqa: E712
            .order_by(TelemetryLog.timestamp.desc())
            .limit(50)
            .all()
        )
        candidates.update(row[0] for row in recent_anom)

        detections = {}
        for device_id in candidates:
            hit = detection.detect_device(db, device_id)
            if hit:
                detections[device_id] = hit
        return detections or None
    except Exception as e:  # pragma: no cover - defensive
        print(f"[Detection] _current_detections failed, using deterministic view: {e}")
        return None


@app.route("/api/financial/loss_distribution", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def get_loss_distribution():
    device_id = request.args.get("device_id")
    target_dev = device_id if (device_id and device_id != "ALL" and device_id != "all") else None
    db = SessionLocal()
    try:
        curve = calculate_monte_carlo_distribution(db, device_id=target_dev)
        return jsonify({"success": True, "distribution": curve})
    except Exception as e:
        print(f"[Monte Carlo Distribution Error] {e}")
        return jsonify(
            {"success": False, "error": "Failed to compute Monte Carlo risk distribution."}
        ), 500
    finally:
        db.close()


@app.route("/api/financial/subsystems", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def get_subsystems_financial():
    db = SessionLocal()
    try:
        breakdown = get_subsystem_financial_breakdown(db)
        return jsonify({"success": True, "subsystems": breakdown})
    except Exception as e:
        print(f"[Subsystem Breakdown Error] {e}")
        return jsonify(
            {"success": False, "error": "Failed to compute subsystem financial breakdown."}
        ), 500
    finally:
        db.close()


# --------------------------------------------------------------------- red team ---
# The portable USB attack harness drives the physical-process stages through these.
# They are machine-to-machine (no operator session), so they are CSRF-exempt and
# guarded two ways instead: the caller must be on the loopback interface AND present
# the one-time drill token from the data directory (only a program on this same
# machine can read it). See src/redteam.py and tools/redteam/aegis_redteam.py.
REDTEAM_TOKEN_HEADER = "X-Aegis-Redteam-Token"


def _redteam_guard():
    """Return an error ``(json, status)`` tuple if the red-team call is not allowed, else None."""
    import redteam

    remote = request.remote_addr or ""
    if remote not in ("127.0.0.1", "::1", "localhost"):
        return jsonify({"success": False, "error": "Red-team drills are localhost-only."}), 403
    token = request.headers.get(REDTEAM_TOKEN_HEADER, "") or (
        (request.get_json(silent=True) or {}).get("token") if request.is_json else ""
    )
    if not redteam.check_token(token):
        return jsonify({"success": False, "error": "Invalid or missing red-team drill token."}), 401
    return None


@app.route("/api/redteam/plan", methods=["GET"])
@limiter.exempt
def api_redteam_plan():
    guard = _redteam_guard()
    if guard is not None:
        return guard
    import redteam

    return jsonify({"success": True, "campaign": redteam.CAMPAIGN})


@app.route("/api/redteam/inject", methods=["POST"])
@limiter.exempt
def api_redteam_inject():
    guard = _redteam_guard()
    if guard is not None:
        return guard
    import redteam

    body = request.get_json(silent=True) or {}
    attack = str(body.get("attack", "")).strip()
    if not attack:
        return jsonify({"success": False, "error": "Missing 'attack'."}), 400
    try:
        result = redteam.run_physical_attack(attack, body.get("device_id"))
    except Exception as e:
        print(f"[RedTeam Inject Error] {e}")
        return jsonify({"success": False, "error": "Red-team injection failed."}), 500
    return jsonify({"success": result.get("ok", False), "result": result})


@app.route("/api/redteam/reset", methods=["POST"])
@limiter.exempt
def api_redteam_reset():
    guard = _redteam_guard()
    if guard is not None:
        return guard
    import redteam

    return jsonify({"success": True, "result": redteam.reset()})


@app.route("/api/redteam/status", methods=["GET"])
@limiter.exempt
def api_redteam_status():
    guard = _redteam_guard()
    if guard is not None:
        return guard
    import loss_engine

    db = SessionLocal()
    try:
        return jsonify({"success": True, "incident": loss_engine.assess(db)})
    finally:
        db.close()


# Operator-facing campaign control (dashboard Station 04). Unlike /api/redteam/* (machine,
# token-guarded for the USB tool), these are driven by the logged-in operator, so they use the
# normal login + CSRF protection and are NOT in the /api/redteam/ CSRF exemption.
@app.route("/api/campaign/plan", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def api_campaign_plan():
    import redteam

    return jsonify({"success": True, "campaign": redteam.CAMPAIGN})


@app.route("/api/campaign/stage", methods=["POST"])
@login_required
@require_webview_token
def api_campaign_stage():
    import redteam

    body = request.get_json(silent=True) or {}
    stage_id = str(body.get("id", "")).strip()
    if not stage_id:
        return jsonify({"success": False, "error": "Missing stage 'id'."}), 400
    try:
        result = redteam.run_stage(stage_id, body.get("device_id"))
    except Exception as e:
        print(f"[Campaign Stage Error] {e}")
        return jsonify({"success": False, "error": "Campaign stage failed to run."}), 500
    return jsonify({"success": result.get("ok", False), "result": result})


@app.route("/api/campaign/reset", methods=["POST"])
@login_required
@require_webview_token
def api_campaign_reset():
    import redteam

    return jsonify({"success": True, "result": redteam.reset(session.get("user_id"))})


@app.route("/api/devices/locations", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def get_devices_locations():
    try:
        import serial_gateway

        locations = serial_gateway.get_device_locations()
        db = SessionLocal()
        try:
            states = {d.device_id: d for d in db.query(DeviceState).all()}
            for loc in locations:
                dev_state = states.get(loc["device_id"])
                loc["is_isolated"] = dev_state.is_isolated if dev_state else False
                loc["is_active"] = not loc["is_isolated"]
        finally:
            db.close()
        return jsonify({"success": True, "locations": locations})
    except Exception as e:
        print(f"[Device Locations Error] {e}")
        return jsonify(
            {"success": False, "error": "Failed to retrieve device geographic topology."}
        ), 500


@app.route("/api/rules", methods=["GET"])
@login_required
@require_webview_token
def get_rules():
    db = SessionLocal()
    rules = db.query(Rule).all()
    res = {r.key: r.value for r in rules}
    db.close()
    return jsonify({"success": True, "rules": res})


@app.route("/api/rules/update", methods=["POST"])
@login_required
@require_webview_token
def update_rules():
    payload = request.json or {}
    db = SessionLocal()
    try:
        # 1. Fetch current rules
        current_rules = {r.key: r.value for r in db.query(Rule).all()}
        new_rules = dict(current_rules)

        for key, val in payload.items():
            if key in ("temp_max", "temp_min", "pressure_max", "pressure_min"):
                if isinstance(val, bool):
                    return jsonify(
                        {"success": False, "error": f"Rule '{key}' value must be numeric."}
                    ), 400
                try:
                    fval = float(val)
                    if math.isnan(fval) or math.isinf(fval):
                        return jsonify(
                            {
                                "success": False,
                                "error": f"Rule '{key}' must be a finite numeric value.",
                            }
                        ), 400
                    new_rules[key] = fval
                except (ValueError, TypeError):
                    return jsonify(
                        {"success": False, "error": f"Invalid numeric value for '{key}'."}
                    ), 400

        # 2. Validate non-inverted boundaries
        if new_rules.get("temp_min", 0.0) >= new_rules.get("temp_max", 60.0):
            return jsonify(
                {
                    "success": False,
                    "error": "Minimum temperature threshold must be strictly less than maximum temperature.",
                }
            ), 400

        if new_rules.get("pressure_min", 0.0) >= new_rules.get("pressure_max", 8.0):
            return jsonify(
                {
                    "success": False,
                    "error": "Minimum pressure threshold must be strictly less than maximum pressure.",
                }
            ), 400

        # 3. Apply updates to database
        for key, fval in new_rules.items():
            rule = db.query(Rule).filter_by(key=key).first()
            if rule:
                rule.value = fval

        # 4. Commit AuditLog record for NIST SP 800-82 / 800-53 AU-2 compliance
        audit = AuditLog(
            user_id=session.get("user_id"),
            action="UPDATE_SAFETY_RULES",
            location=session.get("location", "SYSTEM"),
            details=(
                f"Updated safety thresholds: temp=[{new_rules.get('temp_min')}°C, {new_rules.get('temp_max')}°C], "
                f"pressure=[{new_rules.get('pressure_min')} bar, {new_rules.get('pressure_max')} bar]."
            ),
        )
        db.add(audit)
        db.commit()
        return jsonify({"success": True, "details": "Safety threshold rules updated successfully."})
    except Exception as e:
        db.rollback()
        print(f"[Rules Update Error] {e}")
        return jsonify({"success": False, "error": "Failed to update safety threshold rules."}), 500
    finally:
        db.close()


@app.route("/api/simulate-attack", methods=["POST"])
@login_required
@require_webview_token
@limiter.limit("30 per minute")
def simulate_attack():
    payload = request.json or {}
    attack_type = bleach.clean(str(payload.get("type", "")))
    requested = str(payload.get("device_id", ""))
    known = _known_device_ids()
    drill_device = (
        requested if is_valid_device_id(requested) else (known[0] if known else "DRILL_NODE")
    )

    db = SessionLocal()
    user_id = session.get("user_id")
    location = session.get("location", "X:+12.40, Y:-48.10, Z:+3.50")
    now_ts = time.time()
    print(f"[AttackEngine] Executing attack simulation profile: '{attack_type}' for user {user_id}")

    if attack_type == "stuxnet":
        # Simulate Stuxnet Coordinated Stress Attack: Telemetry pressure & temp stress surge
        for offset, (t_val, p_val, vib_val, curr_val) in enumerate(
            [(48.0, 6.8, 4.5, 6.2), (52.0, 7.4, 5.8, 7.5), (55.0, 7.8, 6.9, 8.4)]
        ):
            log = TelemetryLog(
                timestamp=now_ts - (2 - offset) * 2,
                device_id=drill_device,
                temperature=t_val,
                pressure=p_val,
                humidity=45.0,
                vibration=vib_val,
                hall_effect=2400.0,
                current=curr_val,
                is_anomaly=True,
                is_simulated=True,
            )
            db.add(log)

        audit = AuditLog(
            user_id=user_id,
            action="SIMULATED_STUXNET_BLOCKED",
            location=location,
            details="[SIMULATION] Drill: coordinated temp setpoint (55.0°C) under high pressure (7.8 bar) would be blocked by the Stuxnet interlock.",
            is_simulated=True,
        )
        db.add(audit)
        db.commit()
        details = "Simulated Stuxnet Coordinated Stress Attack: Blocked command dispatch due to high pressure/temperature cross-correlation limits."

    elif attack_type == "injection":
        # Simulate Telemetry Injection / HMAC Spoofing Attack
        for offset, (t_val, p_val, vib_val) in enumerate([(42.0, 5.0, 3.1), (58.0, 6.2, 7.5)]):
            log = TelemetryLog(
                timestamp=now_ts - (1 - offset) * 2,
                device_id=drill_device,
                temperature=t_val,
                pressure=p_val,
                humidity=50.0,
                vibration=vib_val,
                hall_effect=1800.0,
                current=8.8,
                is_anomaly=True,
                is_simulated=True,
            )
            db.add(log)

        # A drill must not change real quarantine state (it would desynchronise the DB
        # from the physical relay, which never receives a command) -- debug report R1.
        audit = AuditLog(
            user_id=user_id,
            action="SIMULATED_INJECTION_DETECTED",
            location=location,
            details="[SIMULATION] Drill: spoofed telemetry with an invalid HMAC would be rejected and, after repeated failures, the target node quarantined.",
            is_simulated=True,
        )
        db.add(audit)
        db.commit()
        details = "Simulated Telemetry Injection Attack: drill telemetry recorded (flagged simulated); real device state unchanged."

    elif attack_type == "privilege":
        # Simulate Privilege Escalation Attempt
        audit = AuditLog(
            user_id=user_id,
            action="SIMULATED_PRIVILEGE_BLOCKED",
            location=location,
            details="[SIMULATION] Drill: unauthorised attempt to set temp_max to 100.0°C. (Role-based access control arrives in v3.0.)",
            is_simulated=True,
        )
        db.add(audit)
        db.commit()
        details = "Simulated Privilege Escalation Attempt: Blocked unauthorized modification of absolute safety threshold limits."

    else:
        db.close()
        return jsonify({"success": False, "error": "Unknown attack type."}), 400

    db.close()
    return jsonify({"success": True, "details": details})


@app.route("/api/data")
@limiter.exempt
@login_required
@require_webview_token
def get_data():
    db = SessionLocal()

    data_mode = request.args.get("mode", "all")
    device_id = request.args.get("device_id")
    query = db.query(TelemetryLog)
    if device_id and device_id != "all":
        query = query.filter_by(device_id=device_id)
    if data_mode == "real":
        query = query.filter(TelemetryLog.is_simulated == False)
    telemetry = query.order_by(TelemetryLog.timestamp.desc()).limit(100).all()

    # Dedicated per-node telemetry streams for 4-node multi-grid
    node_ids = _known_device_ids()
    telemetry_by_node = {}
    for nid in node_ids:
        n_query = db.query(TelemetryLog).filter_by(device_id=nid)
        if data_mode == "real":
            n_query = n_query.filter(TelemetryLog.is_simulated == False)
        n_logs = n_query.order_by(TelemetryLog.timestamp.desc()).limit(30).all()
        telemetry_by_node[nid] = [
            {
                "timestamp": t.timestamp,
                "device_id": t.device_id,
                "temperature": t.temperature,
                "pressure": t.pressure,
                "humidity": t.humidity,
                "vibration": t.vibration,
                "hall_effect": t.hall_effect,
                "current": t.current,
                "rssi": t.rssi,
                "is_anomaly": t.is_anomaly,
            }
            for t in reversed(n_logs)
        ]

    audit_logs = (
        db.query(AuditLog)
        .options(joinedload(AuditLog.user))
        .order_by(AuditLog.timestamp.desc())
        .limit(30)
        .all()
    )

    telemetry_data = [
        {
            "timestamp": t.timestamp,
            "device_id": t.device_id,
            "temperature": t.temperature,
            "pressure": t.pressure,
            "humidity": t.humidity,
            "vibration": t.vibration,
            "hall_effect": t.hall_effect,
            "current": t.current,
            "rssi": t.rssi,
            "is_anomaly": t.is_anomaly,
        }
        for t in reversed(telemetry)
    ]

    def _audit_sev(action: str) -> str:
        act = (action or "").upper()
        if any(
            w in act
            for w in (
                "VIOLATION",
                "ATTACK",
                "BLOCKED",
                "FAILED",
                "QUARANTINE",
                "REPLAY",
                "SIGNATURE_REJECTED",
                "KEY_CHANGED",
            )
        ):
            return "CRITICAL"
        elif any(w in act for w in ("SETPOINT", "ISOLAT", "RECONNECT", "DISCONNECT", "WARNING")):
            return "WARNING"
        return "INFO"

    def _audit_nist(action: str) -> str:
        act = (action or "").upper()
        if "ISOLAT" in act or "QUARANTINE" in act:
            return "NIST SC-7"
        elif "REJECT" in act or "SETPOINT" in act or "STUXNET" in act:
            return "NIST AC-4"
        elif "ANOMALY" in act or "ATTACK" in act or "INJECT" in act:
            return "NIST SI-4"
        elif "LOGIN" in act or "AUTH" in act:
            return "NIST IA-2"
        elif "MODEL" in act or "CALIBRAT" in act:
            return "NIST SI-7"
        return "NIST AU-2"

    audit_data = [
        {
            "id": a.id,
            "timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            if hasattr(a.timestamp, "strftime")
            else str(a.timestamp or ""),
            "timestamp_epoch": to_utc_epoch(a.timestamp),
            "operator": a.user.username
            if a.user
            else ("System" if a.user_id is None else f"User#{a.user_id}"),
            "username": a.user.username if a.user else "System",
            "action": a.action,
            "location": a.location or "Local Terminal",
            "severity": "SIMULATED" if a.is_simulated else _audit_sev(a.action),
            "nist_control": _audit_nist(a.action),
            "details": a.details,
            "is_simulated": bool(a.is_simulated),
        }
        for a in audit_logs
    ]

    target_dev = device_id if (device_id and device_id != "all") else None
    financials = calculate_financial_analytics(db, device_id=target_dev)
    target_trust_dev = (
        device_id if (device_id and device_id != "all") else (node_ids[0] if node_ids else None)
    )
    trust = compute_device_trust_score(target_trust_dev, db)

    db.close()
    return jsonify(
        {
            "telemetry": telemetry_data,
            "telemetry_by_node": telemetry_by_node,
            "audit_logs": audit_data,
            "financials": financials,
            "trust": trust,
        }
    )


@app.route("/api/stream", methods=["GET"])
@limiter.exempt
@login_required
@require_webview_token
def api_stream():
    """
    Server-Sent Events (SSE) push stream delivering sub-second telemetry,
    continuous trust scores, and security alarms directly to the SCADA dashboard.
    """

    def generate():
        last_seen_ts = time.time() - 3.0
        while True:
            db = SessionLocal()
            try:
                new_logs = (
                    db.query(TelemetryLog)
                    .filter(TelemetryLog.timestamp > last_seen_ts)
                    .order_by(TelemetryLog.timestamp.asc())
                    .limit(20)
                    .all()
                )
                if new_logs:
                    last_seen_ts = max(t.timestamp for t in new_logs)
                    payload = [
                        {
                            "timestamp": t.timestamp,
                            "device_id": t.device_id,
                            "temperature": t.temperature,
                            "pressure": t.pressure,
                            "humidity": t.humidity,
                            "vibration": t.vibration,
                            "hall_effect": t.hall_effect,
                            "current": t.current,
                            "rssi": t.rssi,
                            "is_anomaly": t.is_anomaly,
                        }
                        for t in new_logs
                    ]
                    yield f"event: telemetry\ndata: {json.dumps(payload)}\n\n"

                isolated_devs = [
                    d.device_id for d in db.query(DeviceState).filter_by(is_isolated=True).all()
                ]
                from database import Device as _Device

                pending_count = db.query(_Device).filter_by(status="pending").count()
                yield f"event: heartbeat\ndata: {json.dumps({'time': time.time(), 'isolated': isolated_devs, 'pending_devices': pending_count})}\n\n"

                try:
                    import serial_gateway

                    health = serial_gateway.get_gateway_health()
                    active_nodes = serial_gateway.get_active_nodes()
                    topology_payload = {
                        "total_nodes_count": max(len(active_nodes), 4),
                        "online_nodes_count": health.get("online_nodes_count", 0),
                        "total_active_sensors": health.get("total_active_sensors", 0),
                        "gateway_state": health.get("state", "DISCONNECTED"),
                        "active_port": health.get("active_port"),
                        "master_bridge": health.get("master_bridge", {}),
                    }
                    yield f"event: topology\ndata: {json.dumps(topology_payload)}\n\n"
                except Exception:
                    pass
            except Exception as e:
                print(f"[Telemetry SSE Stream Error] {e}")
                yield f"event: error\ndata: {json.dumps({'error': 'Telemetry stream interrupted.'})}\n\n"
            finally:
                db.close()
            time.sleep(1.0)

    res = Response(stream_with_context(generate()), mimetype="text/event-stream")
    res.headers["Cache-Control"] = "no-cache, no-transform"
    res.headers["X-Accel-Buffering"] = "no"
    return res


@app.route("/api/telemetry", methods=["POST"])
@limiter.exempt
def api_telemetry():
    """Machine-to-machine ingestion. Requires the gateway token (S1) and a valid per-device
    HMAC; CSRF does not apply. Exempt from per-IP rate limits because all frames arrive
    from the local gateway; abuse is bounded by the token."""
    token = request.headers.get(GATEWAY_TOKEN_HEADER, "")
    if not token or not secrets.compare_digest(token, GATEWAY_TOKEN):
        return jsonify({"success": False, "error": "Gateway authentication required."}), 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"success": False, "error": "JSON object body required."}), 400

    import protocol

    if protocol.is_v1(payload):
        success, status_code, message = handle_device_frame(payload)
        if success:
            return jsonify({"success": True, "message": message}), status_code
        return jsonify({"success": False, "error": message}), status_code

    device_id = payload.get("device_id")
    if not device_id:
        return jsonify({"success": False, "error": "Missing device_id"}), 400

    success, status_code, message = process_telemetry(payload)
    if success:
        return jsonify({"success": True, "message": message}), status_code
    return jsonify({"success": False, "error": message}), status_code


@app.route("/health", methods=["GET"])
def health():
    try:
        db = SessionLocal()
        db.query(User).first()
        db.close()
        return jsonify(
            {"status": "healthy", "service": "aegis-ics", "components": {"database": "connected"}}
        ), 200
    except Exception as e:
        print(f"[Health Check Error] {e}")
        return jsonify({"status": "unhealthy", "error": "Database connection check failed."}), 500


@app.route("/api/version", methods=["GET"])
def api_version():
    """Returns the current application version. Used by the auto-updater."""
    from version import __version__ as version

    return jsonify({"version": version, "name": "Aegis ICS"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"[*] Starting Aegis ICS Web Gateway on http://{host}:{port}")
    try:
        import redteam

        redteam.write_runtime_info(port)
    except Exception:
        pass
    app.run(host=host, port=port, debug=False)
