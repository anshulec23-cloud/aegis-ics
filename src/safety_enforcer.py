"""
safety_enforcer.py - SCADA Command Validation & Neural Safety Policy Enforcement
================================================================================
Evaluates supervisory control setpoint commands against:
1. Static database physical boundary rules (Rule table)
2. 6D Local Neural Safety Policy Network (NSPN)
3. Hard physical invariant overrides to prevent coordinated Stuxnet exploits.
"""

import math
import time
from typing import Tuple, Optional
from sqlalchemy.orm import Session
from database import Rule, TelemetryLog

try:
    from neural_policy import get_neural_policy
except ImportError:
    try:
        from src.neural_policy import get_neural_policy
    except Exception:
        get_neural_policy = None


def validate_command(
    command: dict,
    db: Session,
    target_device: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Validates a SCADA setpoint command against safety rules and Neural Safety Policy.
    Scopes multi-variable physical correlation checks to the target field device.
    """
    cmd_type = command.get("type")
    value = command.get("value")
    device_id = target_device or command.get("target_device") or command.get("device_id")

    # 1. Command Syntax & Type Validation
    if cmd_type not in ("set_temp", "set_pressure"):
        return False, f"Denied: Unknown command type '{cmd_type}'. Only 'set_temp' and 'set_pressure' are permitted."

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False, "Command setpoint value must be numeric."

    if math.isnan(value) or math.isinf(value):
        return False, "Command setpoint value must be a finite numeric value."

    # 2. Database Outer Boundary Hard Rules
    if cmd_type == "set_temp":
        temp_max_rule = db.query(Rule).filter_by(key="temp_max").first()
        temp_min_rule = db.query(Rule).filter_by(key="temp_min").first()

        t_max = temp_max_rule.value if temp_max_rule else 60.0
        t_min = temp_min_rule.value if temp_min_rule else 0.0

        if not (t_min <= value <= t_max):
            return False, f"Rule violation: Temperature setpoint {value}C exceeds boundaries ({t_min}-{t_max}C)."

    elif cmd_type == "set_pressure":
        pres_max_rule = db.query(Rule).filter_by(key="pressure_max").first()
        pres_min_rule = db.query(Rule).filter_by(key="pressure_min").first()

        p_max = pres_max_rule.value if pres_max_rule else 8.0
        p_min = pres_min_rule.value if pres_min_rule else 0.0

        if not (p_min <= value <= p_max):
            return False, f"Rule violation: Pressure setpoint {value} bar exceeds boundaries ({p_min}-{p_max} bar)."

    # 3. Telemetry Freshness & Device Scoping
    telemetry_query = db.query(TelemetryLog)
    if device_id:
        telemetry_query = telemetry_query.filter_by(device_id=device_id)
    latest_telemetry = telemetry_query.order_by(TelemetryLog.timestamp.desc()).first()

    dev_label = f" on {device_id}" if device_id else ""

    # Telemetry Freshness Check: requires active telemetry within 120s
    is_fresh = bool(
        latest_telemetry
        and latest_telemetry.timestamp is not None
        and abs(time.time() - latest_telemetry.timestamp) <= 120.0
    )

    # 4. Neural Safety Policy & Coordinated Stuxnet Interlock Evaluation
    if is_fresh and latest_telemetry:
        telemetry_dict = {
            "temperature": latest_telemetry.temperature,
            "pressure": latest_telemetry.pressure,
            "vibration": latest_telemetry.vibration,
            "hall_effect": latest_telemetry.hall_effect,
            "current": latest_telemetry.current,
        }

        # Evaluate via Local Neural Safety Policy Network
        if get_neural_policy is not None:
            try:
                policy = get_neural_policy()
                is_safe, prob, diag = policy.evaluate_safety(
                    telemetry_dict, cmd_type, value, device_id=device_id
                )
                if not is_safe:
                    return False, diag
            except Exception as e:
                # V5 FIX: Fail-closed on neural policy errors
                return False, (
                    f"SAFETY INTERLOCK BLOCK: Neural Safety Policy evaluation failed ({e}). "
                    f"Command blocked as precautionary measure. System requires maintenance."
                )

        # Deterministic Physics-Informed Hard Invariant Interlocks (Redundant Defense-in-Depth)
        if cmd_type == "set_temp" and value >= 45.0:
            if latest_telemetry.pressure is not None and latest_telemetry.pressure >= 6.0:
                return False, (
                    f"SAFETY INTERLOCK BLOCK (Stuxnet Prevention & Neural Safety Policy): "
                    f"Blocked raising Temperature to {value}C{dev_label} because live Pressure is {latest_telemetry.pressure} bar. "
                    "Coordinated high-temperature/high-pressure damage profile detected."
                )

        if cmd_type == "set_pressure" and value >= 6.0:
            if latest_telemetry.temperature is not None and latest_telemetry.temperature >= 45.0:
                return False, (
                    f"SAFETY INTERLOCK BLOCK (Stuxnet Prevention & Neural Safety Policy): "
                    f"Blocked raising Pressure to {value} bar{dev_label} because live Temperature is {latest_telemetry.temperature}C. "
                    "Coordinated high-temperature/high-pressure damage profile detected."
                )
    else:
        # V1 FIX: Fail-closed when telemetry is stale or unavailable
        # Block high-risk setpoints when we cannot verify cross-variable safety
        if cmd_type == "set_temp" and value >= 45.0:
            return False, (
                f"SAFETY INTERLOCK BLOCK (Stale Telemetry): "
                f"Blocked raising Temperature to {value}C{dev_label}. "
                f"Fresh telemetry required for high-risk setpoints (T >= 45°C) but last reading is "
                f"{'older than 120s' if latest_telemetry else 'unavailable'}. "
                f"Cannot verify cross-variable safety without live sensor data."
            )
        if cmd_type == "set_pressure" and value >= 6.0:
            return False, (
                f"SAFETY INTERLOCK BLOCK (Stale Telemetry): "
                f"Blocked raising Pressure to {value} bar{dev_label}. "
                f"Fresh telemetry required for high-risk setpoints (P >= 6.0 bar) but last reading is "
                f"{'older than 120s' if latest_telemetry else 'unavailable'}. "
                f"Cannot verify cross-variable safety without live sensor data."
            )
        if latest_telemetry and not is_fresh:
            print(f"[SafetyEnforcer] Warning: Stale telemetry for{dev_label}. Low-risk command allowed.")
        elif not latest_telemetry:
            print(f"[SafetyEnforcer] Warning: No telemetry history for{dev_label}. Low-risk command allowed.")

    return True, "Approved"
