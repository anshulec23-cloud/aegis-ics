"""Attack taxonomy — the single source of truth for what each attack is and costs.

Used by the live loss engine (``loss_engine.py``), the ML attack classifier
(``detection.py``), the red-team drills (``simulator.py``) and the NIST report
(``reporting.py``). Each entry carries:

* ``label``             — human name for the UI and report
* ``severity``          — 0..1, scales projected damage
* ``mttr_hours``        — baseline mean time to remediate (before criticality scaling)
* ``damages_equipment`` — True if, unmitigated, it reaches the actuator and damages plant
* ``reportable``        — True if it is a reportable security incident (regulatory exposure)
* ``mitre``             — closest MITRE ATT&CK for ICS technique id
* ``nist_controls``     — NIST SP 800-82 / 800-53 controls that bear on it
* ``mitigation``        — what to do about it (goes into the report's mitigation section)
"""

from __future__ import annotations

from typing import Dict

CATALOG: Dict[str, Dict] = {
    "stuxnet": {
        "label": "Coordinated multi-variable stress (Stuxnet-style)",
        "severity": 0.95,
        "mttr_hours": 8.0,
        "damages_equipment": True,
        "reportable": True,
        "mitre": "T0831 (Manipulation of Control)",
        "nist_controls": ["SI-4", "SC-7", "AC-4"],
        "mitigation": (
            "Keep the node micro-segmented until the coupled setpoints are verified safe. "
            "Audit the last supervisory commands for the cross-variable signature (high "
            "temperature with high pressure), rotate the device key, and re-baseline the "
            "process model before rejoining."
        ),
    },
    "fdi_spike": {
        "label": "False data injection (out-of-envelope spike)",
        "severity": 0.88,
        "mttr_hours": 4.0,
        "damages_equipment": True,
        "reportable": True,
        "mitre": "T0856 (Spoof Reporting Message)",
        "nist_controls": ["SI-10", "SI-4", "SC-8"],
        "mitigation": (
            "Reject the forged frames (already enforced by signature + range checks), confirm "
            "the physical sensor against a second instrument, and rotate the device key if the "
            "injection carried a valid signature."
        ),
    },
    "replay": {
        "label": "Replay / stale-frame attack",
        "severity": 0.60,
        "mttr_hours": 2.0,
        "damages_equipment": False,
        "reportable": False,
        "mitre": "T0858 (Change Operating Mode)",
        "nist_controls": ["SC-8", "SI-4"],
        "mitigation": (
            "Protocol v1 boot/sequence numbers already drop replayed frames. Verify the master "
            "bridge is not buffering and re-emitting frames, and check for an unauthorized tap "
            "on the RS-485 bus."
        ),
    },
    "hmac_tamper": {
        "label": "Signature tampering / telemetry spoofing",
        "severity": 0.75,
        "mttr_hours": 3.0,
        "damages_equipment": False,
        "reportable": True,
        "mitre": "T0856 (Spoof Reporting Message)",
        "nist_controls": ["SC-8", "IA-3", "SI-7"],
        "mitigation": (
            "Signature failures are rejected and counted; after repeated failures the node is "
            "quarantined. Physically inspect the bus for a rogue transmitter, then re-enroll the "
            "device so a fresh session key is derived."
        ),
    },
    "ddos": {
        "label": "Denial of service / bus flooding",
        "severity": 0.70,
        "mttr_hours": 2.0,
        "damages_equipment": False,
        "reportable": False,
        "mitre": "T0814 (Denial of Service)",
        "nist_controls": ["SC-5", "SI-4"],
        "mitigation": (
            "Rate-limit ingestion, isolate the flooding source from the bus, and fail the "
            "affected loops to their safe local state until throughput recovers."
        ),
    },
    "thermal_drift": {
        "label": "Stealth setpoint / thermal drift",
        "severity": 0.55,
        "mttr_hours": 3.0,
        "damages_equipment": True,
        "reportable": False,
        "mitre": "T0836 (Modify Parameter)",
        "nist_controls": ["SI-4", "AC-4"],
        "mitigation": (
            "Compare the drifting variable with its historical baseline, revert the setpoint, "
            "and review who issued the gradual changes. Tighten the rate-of-change limit."
        ),
    },
    "sensor_fault": {
        "label": "Sensor fault / tamper",
        "severity": 0.40,
        "mttr_hours": 1.5,
        "damages_equipment": False,
        "reportable": False,
        "mitre": "T0806 (Brute Force I/O)",
        "nist_controls": ["SI-4", "MA-2"],
        "mitigation": (
            "The firmware reports faulted channels instead of faking values. Dispatch "
            "maintenance to reseat or replace the transducer; cross-check with redundant sensors."
        ),
    },
    "privilege": {
        "label": "Unauthorized control / privilege escalation attempt",
        "severity": 0.80,
        "mttr_hours": 2.0,
        "damages_equipment": False,
        "reportable": True,
        "mitre": "T0859 (Valid Accounts)",
        "nist_controls": ["AC-6", "IA-2", "AU-2"],
        "mitigation": (
            "Block the out-of-policy command (enforced by the safety envelope), review the "
            "operator session and audit trail, and require two-person approval for limit changes."
        ),
    },
    "unknown": {
        "label": "Unclassified anomaly",
        "severity": 0.50,
        "mttr_hours": 3.0,
        "damages_equipment": True,
        "reportable": False,
        "mitre": "—",
        "nist_controls": ["SI-4"],
        "mitigation": (
            "Hold the node in quarantine while an analyst reviews the telemetry and audit trail "
            "to classify the event; treat as potentially damaging until ruled out."
        ),
    },
}

# Drill / detector names that map onto catalog keys.
ALIASES = {
    "injection": "fdi_spike",
    "tamper": "hmac_tamper",
    "fdi": "fdi_spike",
    "dos": "ddos",
    "flood": "ddos",
    "spoof": "hmac_tamper",
}

# Criticality scales how long remediation takes and how much a loss hurts.
CRITICALITY_MULTIPLIER = {
    "TIER-1 CRITICAL": 1.3,
    "TIER-2 HIGH": 1.0,
    "TIER-3 STANDARD": 0.8,
}


def canonical(name: str) -> str:
    """Map any drill/detector label to a catalog key."""
    key = (name or "unknown").strip().lower()
    key = ALIASES.get(key, key)
    return key if key in CATALOG else "unknown"


def info(name: str) -> Dict:
    """Catalog entry for an attack name (always returns a dict; unknown -> 'unknown')."""
    entry = dict(CATALOG[canonical(name)])
    entry["key"] = canonical(name)
    return entry


def criticality_multiplier(criticality: str) -> float:
    return CRITICALITY_MULTIPLIER.get(criticality, 1.0)
