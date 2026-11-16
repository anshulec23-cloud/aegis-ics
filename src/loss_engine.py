"""Live incident loss engine (domain layer).

Turns the current security state of the plant into money, the way the owner described the
financial tab: for every node under attack or quarantine, how much have we **actually** lost,
how much would we lose **if we don't fix it**, how long will the fix take, what will it cost to
**restabilize**, and **where** it is happening. The deterministic rules and (later) the ML
classifier say *what* the attack is; this module says what it *costs*.

Per-incident formulas (all per device, per its operator-set financial profile):

* ``burn``                = downtime_rate_per_hour                      (production $/h while down)
* ``duration_h``          = hours since the node was isolated / attacked
* ``actual_loss``         = burn * duration_h                          (incurred so far)
* ``mttr_h``              = attack.mttr_hours * criticality_multiplier (time to fix)
* ``projected_loss``      = burn * mttr_h  +  (base_sle * severity if damages_equipment)
                            — what we would still lose if nothing were done
* ``prevented_loss``      = base_sle * severity   if the node is isolated and the attack
                            would otherwise reach the actuator (the catastrophe we avoided)
* ``restabilization_cost``= cleanup_cost * severity * 0.3  +  mttr_h * LABOR_RATE
* ``regulatory_exposure`` = profile regulatory exposure   if the attack is reportable
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

import attacks
import financials

LABOR_RATE_PER_HOUR = 180.0  # OT incident-response labour, blended ($/h)
MIN_DURATION_H = 1.0 / 60.0  # show at least one minute so a fresh incident isn't $0


def _epoch(dt) -> Optional[float]:
    if dt is None:
        return None
    try:
        from database import to_utc_epoch

        return to_utc_epoch(dt)
    except Exception:
        return None


def _active_drills() -> Dict[str, str]:
    try:
        import serial_gateway

        return serial_gateway.get_active_attacks() or {}
    except Exception:
        return {}


def _attack_from_audit(db, device_id: str) -> str:
    """Best-effort attack classification from the most recent security audit entry."""
    try:
        from database import AuditLog

        rows = (
            db.query(AuditLog)
            .filter(AuditLog.details.like(f"%{device_id}%"))
            .order_by(AuditLog.id.desc())
            .limit(6)
            .all()
        )
    except Exception:
        return "unknown"
    for row in rows:
        action = (row.action or "").upper()
        details = (row.details or "").lower()
        if "REPLAY" in action:
            return "replay"
        if "SIGNATURE_REJECTED" in action or "signature" in details:
            return "hmac_tamper"
        if "STUXNET" in action or "coordinated" in details:
            return "stuxnet"
        if "injection" in details or "false data" in details:
            return "fdi_spike"
        if "privilege" in details or "unauthor" in details:
            return "privilege"
    return "unknown"


def _incident_for(db, device_id: str, attack_key: str, now: float) -> Dict[str, Any]:
    from database import DeviceState

    profile = financials.profile_for(device_id, db=db)
    state = db.query(DeviceState).filter_by(device_id=device_id).first()
    is_isolated = bool(state and state.is_isolated)
    started = _epoch(state.updated_at) if (state and is_isolated) else now
    duration_h = max(MIN_DURATION_H, (now - (started or now)) / 3600.0)

    atk = attacks.info(attack_key)
    severity = float(atk["severity"])
    mult = attacks.criticality_multiplier(profile["criticality"])
    mttr_h = round(atk["mttr_hours"] * mult, 2)

    burn = float(profile["downtime_rate_per_hour"])
    base_sle = float(profile["base_sle"])

    actual_loss = round(burn * duration_h, 2)
    equipment_at_risk = base_sle * severity if atk["damages_equipment"] else 0.0
    projected_loss = round(burn * mttr_h + equipment_at_risk, 2)
    prevented_loss = round(
        equipment_at_risk if (is_isolated and atk["damages_equipment"]) else 0.0, 2
    )
    restabilization_cost = round(
        float(profile["cleanup_remediation"]) * severity * 0.3 + mttr_h * LABOR_RATE_PER_HOUR, 2
    )
    regulatory_exposure = round(
        float(profile["regulatory_exposure"]) if atk["reportable"] else 0.0, 2
    )

    status = "ISOLATED" if is_isolated else "UNDER ATTACK"
    return {
        "device_id": device_id,
        "name": profile["name"],
        "role": profile["role"],
        "zone": profile["zone"],
        "criticality": profile["criticality"],
        "attack_type": atk["key"],
        "attack_label": atk["label"],
        "severity": round(severity, 2),
        "mitre": atk["mitre"],
        "status": status,
        "is_isolated": is_isolated,
        "started_at": started,
        "duration_hours": round(duration_h, 3),
        "downtime_rate_per_hour": burn,
        "actual_loss": actual_loss,
        "projected_loss": projected_loss,
        "prevented_loss": prevented_loss,
        "time_to_fix_hours": mttr_h,
        "restabilization_cost": restabilization_cost,
        "regulatory_exposure": regulatory_exposure,
        "mitigation": atk["mitigation"],
        "nist_controls": atk["nist_controls"],
    }


def affected_devices(db, detections: Optional[Dict[str, Dict]] = None) -> Dict[str, str]:
    """Return {device_id: attack_key} for every node under attack or quarantine right now."""
    from database import DeviceState

    result: Dict[str, str] = {}
    # 1. Explicit detections (ML classifier / caller supplied).
    for dev, info in (detections or {}).items():
        result[dev] = attacks.canonical((info or {}).get("attack_type", "unknown"))
    # 2. Active red-team drills (simulator).
    for dev, drill in _active_drills().items():
        result.setdefault(dev, attacks.canonical(drill))
    # 3. Quarantined devices with no explicit detection: infer from the audit trail.
    for state in db.query(DeviceState).filter_by(is_isolated=True).all():
        if state.device_id not in result:
            result[state.device_id] = _attack_from_audit(db, state.device_id)
    return result


def assess(db, detections: Optional[Dict[str, Dict]] = None) -> Dict[str, Any]:
    """Full live financial picture of the current security posture."""
    now = time.time()
    affected = affected_devices(db, detections)
    incidents: List[Dict[str, Any]] = [
        _incident_for(db, dev, key, now) for dev, key in sorted(affected.items())
    ]

    def total(field: str) -> float:
        return round(sum(i[field] for i in incidents), 2)

    actual = total("actual_loss")
    prevented = total("prevented_loss")
    projected = total("projected_loss")
    exposure_ceiling = round(
        sum(financials.profile_for(i["device_id"], db=db)["base_sle"] for i in incidents), 2
    )
    denom = prevented + actual + projected
    net_reduction = round(100.0 * prevented / denom, 1) if denom > 0 else 0.0

    return {
        "generated_at": now,
        "incident_active": bool(incidents),
        "affected_count": len(incidents),
        "incidents": incidents,
        "totals": {
            "actual_loss": actual,
            "projected_loss": projected,
            "prevented_loss": prevented,
            "restabilization_cost": total("restabilization_cost"),
            "regulatory_exposure": total("regulatory_exposure"),
            "downtime_rate_per_hour": total("downtime_rate_per_hour"),
            "exposure_ceiling": exposure_ceiling,
            "net_risk_reduction_pct": net_reduction,
            "total_time_to_fix_hours": round(
                max([0.0] + [i["time_to_fix_hours"] for i in incidents]), 2
            ),
        },
    }


def snapshot_json(db, detections: Optional[Dict[str, Dict]] = None) -> str:
    return json.dumps(assess(db, detections), default=str)
