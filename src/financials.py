"""Per-device financial profiles (domain layer).

Devices now have auto-generated IDs (``ESP32_A1B2C3``), so the old hard-coded
ESP32_001..004 dollar figures are meaningless. Instead, the operator sets a device's
financial profile **when approving it** (ADR 0006 enrollment). Each device carries:

* ``role``        — picks sensible defaults (reactor, pump, chiller, turbine, ...)
* ``criticality`` — TIER-1 / TIER-2 / TIER-3
* ``equipment_value``         — replacement cost of the equipment this node controls ($)
* ``downtime_rate_per_hour``  — production value lost per hour while this node is down ($/h)
* ``cleanup_cost``            — environmental / remediation cost of a failure ($)
* ``regulatory_exposure``     — regulatory fine exposure (EPA / NERC-CIP / NIS2) ($)

The Single Loss Expectancy (SLE) used by the FAIR model is derived:
``base_sle = equipment_value + cleanup_cost + regulatory_exposure``.

This module is the single source of truth for a device's money. ``analytics.py`` (FAIR
risk), the live incident loss engine, and the NIST report all read profiles from here.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# Role -> default profile. Dollar figures are illustrative starting points an operator edits.
ROLE_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "reactor": {
        "label": "Reactor / exothermic unit",
        "zone": "Reaction unit",
        "criticality": "TIER-1 CRITICAL",
        "equipment_value": 450000.0,
        "downtime_rate_per_hour": 22500.0,
        "cleanup_cost": 120000.0,
        "regulatory_exposure": 400000.0,
    },
    "turbine": {
        "label": "Turbine / generator",
        "zone": "Power generation",
        "criticality": "TIER-1 CRITICAL",
        "equipment_value": 650000.0,
        "downtime_rate_per_hour": 31000.0,
        "cleanup_cost": 150000.0,
        "regulatory_exposure": 400000.0,
    },
    "compressor": {
        "label": "Compressor",
        "zone": "Gas handling",
        "criticality": "TIER-2 HIGH",
        "equipment_value": 380000.0,
        "downtime_rate_per_hour": 18000.0,
        "cleanup_cost": 70000.0,
        "regulatory_exposure": 150000.0,
    },
    "pump": {
        "label": "Pump / feed booster",
        "zone": "Fluid transfer",
        "criticality": "TIER-2 HIGH",
        "equipment_value": 280000.0,
        "downtime_rate_per_hour": 14000.0,
        "cleanup_cost": 60000.0,
        "regulatory_exposure": 150000.0,
    },
    "chiller": {
        "label": "Chiller / cryogenic exchanger",
        "zone": "Cooling",
        "criticality": "TIER-2 HIGH",
        "equipment_value": 190000.0,
        "downtime_rate_per_hour": 9500.0,
        "cleanup_cost": 45000.0,
        "regulatory_exposure": 155000.0,
    },
    "sensor_node": {
        "label": "Instrumentation / sensor node",
        "zone": "Field bus",
        "criticality": "TIER-3 STANDARD",
        "equipment_value": 60000.0,
        "downtime_rate_per_hour": 3000.0,
        "cleanup_cost": 10000.0,
        "regulatory_exposure": 20000.0,
    },
    "generic": {
        "label": "Generic industrial node",
        "zone": "Auxiliary segment",
        "criticality": "TIER-2 HIGH",
        "equipment_value": 250000.0,
        "downtime_rate_per_hour": 12500.0,
        "cleanup_cost": 50000.0,
        "regulatory_exposure": 150000.0,
    },
}

CRITICALITY_CHOICES = ["TIER-1 CRITICAL", "TIER-2 HIGH", "TIER-3 STANDARD"]
# Financial columns stored on the Device row (operator-set when not None).
_MONEY_FIELDS = ("equipment_value", "downtime_rate_per_hour", "cleanup_cost", "regulatory_exposure")


def role_choices() -> List[Dict[str, str]]:
    """Roles for the approval dropdown, each with its label and default figures."""
    return [
        {
            "key": key,
            "label": spec["label"],
            **{k: spec[k] for k in _MONEY_FIELDS},
            "criticality": spec["criticality"],
        }
        for key, spec in ROLE_DEFAULTS.items()
    ]


def defaults_for_role(role: Optional[str]) -> Dict[str, Any]:
    return dict(ROLE_DEFAULTS.get((role or "generic").lower(), ROLE_DEFAULTS["generic"]))


def normalize_input(data: Optional[dict]) -> Dict[str, Any]:
    """Validate operator-supplied financials (from the approval form). Missing money fields
    fall back to the chosen role's defaults. Raises ValueError on bad numbers."""
    data = data or {}
    role = str(data.get("role", "generic")).lower()
    if role not in ROLE_DEFAULTS:
        role = "generic"
    base = ROLE_DEFAULTS[role]
    criticality = str(data.get("criticality") or base["criticality"])
    if criticality not in CRITICALITY_CHOICES:
        criticality = base["criticality"]
    out: Dict[str, Any] = {
        "role": role,
        "criticality": criticality,
        "zone": (str(data.get("zone")).strip()[:80] if data.get("zone") else base["zone"]),
    }
    for field in _MONEY_FIELDS:
        raw = data.get(field)
        if raw in (None, ""):
            out[field] = float(base[field])
            continue
        try:
            value = float(raw)
        except (TypeError, ValueError):
            raise ValueError(f"'{field}' must be a number")
        if value < 0 or value != value or value in (float("inf"), float("-inf")):
            raise ValueError(f"'{field}' must be a non-negative, finite number")
        out[field] = round(value, 2)
    return out


def _effective(device_row) -> Dict[str, Any]:
    """Resolve a device's financial figures: operator-set columns win, else role defaults."""
    role = getattr(device_row, "role", None) if device_row is not None else None
    base = defaults_for_role(role)
    result = {
        "role": (role or "generic"),
        "criticality": getattr(device_row, "criticality", None) or base["criticality"],
        "zone": getattr(device_row, "zone", None) or base["zone"],
    }
    is_custom = False
    for field in _MONEY_FIELDS:
        stored = (
            getattr(device_row, field if field != "cleanup_cost" else "cleanup_cost", None)
            if device_row is not None
            else None
        )
        if stored is not None:
            is_custom = True
            result[field] = float(stored)
        else:
            result[field] = float(base[field])
    result["is_custom"] = is_custom
    return result


def profile_for(device_id: str, db=None, device_row=None) -> Dict[str, Any]:
    """Full financial profile for a device, in the shape the FAIR engine and report expect.

    ``base_sle``, ``epa_fines`` and ``nerc_cip_fines`` are derived so existing analytics math
    is unchanged; the operator only ever sets the four money fields above plus role/criticality.
    """
    if device_row is None and db is not None:
        try:
            from database import Device

            device_row = db.query(Device).filter_by(device_id=device_id).first()
        except Exception:
            device_row = None
    eff = _effective(device_row)
    name = getattr(device_row, "name", None) if device_row is not None else None
    regulatory = eff["regulatory_exposure"]
    base_sle = eff["equipment_value"] + eff["cleanup_cost"] + regulatory
    return {
        "device_id": device_id,
        "name": name or f"Industrial node {device_id}",
        "role": eff["role"],
        "zone": eff["zone"],
        "criticality": eff["criticality"],
        "equipment_value": eff["equipment_value"],
        "downtime_rate_per_hour": eff["downtime_rate_per_hour"],
        "cleanup_remediation": eff["cleanup_cost"],
        "regulatory_exposure": regulatory,
        # Derived, for the FAIR model (kept so analytics math is untouched):
        "base_sle": base_sle,
        "epa_fines": round(regulatory * 0.5, 2),
        "nerc_cip_fines": round(regulatory * 0.5, 2),
        "is_custom": eff["is_custom"],
    }
