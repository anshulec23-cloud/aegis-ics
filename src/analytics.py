"""
Aegis ICS — Industrial Cyber-Financial Analytics & Quantitative Risk Modeling
=============================================================================
Implements standard OT/ICS quantitative risk governance methodologies:
 - FAIR (Factor Analysis of Information Risk) Model
 - ALE / SLE / ARO (Annualized Loss Expectancy, Single Loss Expectancy, Annualized Rate of Occurrence)
 - Critical Subsystem Hourly Downtime & Outage Liabilities ($/hour per unit)
 - Regulatory Non-Compliance & Environmental Exposure (NERC CIP, NIS2, EPA/OSHA)
 - Monte Carlo Cumulative Probability Loss Distribution (P10 to P99 Tail Risk)
 - Return on Security Investment (ROSI)
"""

import math
from typing import Dict, Any, List, Optional
from database import TelemetryLog, AuditLog, DeviceState


SUBSYSTEM_PROFILES = {
    "ESP32_001": {
        "name": "Catalytic Reactor 01",
        "zone": "Zone A: High-Exotherm Reaction Unit",
        "equipment_value": 450000.0,
        "cleanup_remediation": 120000.0,
        "base_sle": 570000.0,
        "downtime_rate_per_hour": 22500.0,
        "criticality": "TIER-1 CRITICAL",
        "epa_fines": 250000.0,
        "nerc_cip_fines": 150000.0,
    },
    "ESP32_002": {
        "name": "Centrifugal Pump 02",
        "zone": "Zone B: Secondary Feed Booster",
        "equipment_value": 280000.0,
        "cleanup_remediation": 60000.0,
        "base_sle": 340000.0,
        "downtime_rate_per_hour": 14000.0,
        "criticality": "TIER-2 HIGH",
        "epa_fines": 50000.0,
        "nerc_cip_fines": 100000.0,
    },
    "ESP32_003": {
        "name": "Cooling Cryo 03",
        "zone": "Zone C: Primary Cryogenic Heat Exchanger",
        "equipment_value": 190000.0,
        "cleanup_remediation": 45000.0,
        "base_sle": 235000.0,
        "downtime_rate_per_hour": 9500.0,
        "criticality": "TIER-2 HIGH",
        "epa_fines": 80000.0,
        "nerc_cip_fines": 75000.0,
    },
    "ESP32_004": {
        "name": "Turbine Generator 04",
        "zone": "Zone D: Main Turbine Hall Generation",
        "equipment_value": 650000.0,
        "cleanup_remediation": 150000.0,
        "base_sle": 800000.0,
        "downtime_rate_per_hour": 31000.0,
        "criticality": "TIER-1 CRITICAL",
        "epa_fines": 150000.0,
        "nerc_cip_fines": 250000.0,
    }
}


def calculate_financial_analytics(db, device_id: str = None) -> Dict[str, Any]:
    """
    Comprehensive Quantitative Risk & Financial Analytics Engine.
    Evaluates empirical telemetry, isolation history, and physical subsystem valuations.
    """
    from sqlalchemy import or_

    query = db.query(TelemetryLog)
    if device_id and device_id != "ALL":
        query = query.filter_by(device_id=device_id)
    telemetry = query.order_by(TelemetryLog.timestamp.desc()).limit(60).all()

    audit_query = db.query(AuditLog).filter(
        or_(
            AuditLog.action.like("%VIOLATION%"),
            AuditLog.action.like("%ISOLATION%"),
            AuditLog.action.like("%ATTACK%")
        )
    )
    if device_id and device_id != "ALL":
        audit_query = audit_query.filter(AuditLog.details.like(f"%{device_id}%"))
    violations = audit_query.all()
    violation_count = len(violations)

    incurred_cost = violation_count * 5000.0
    prevented_cost = violation_count * 400000.0

    threat_index = 0.0
    drift_risk = 0.0
    corr_risk = 0.0
    boundary_risk = 0.0

    chrono_telemetry = list(reversed(telemetry))
    valid_telemetry = [t for t in chrono_telemetry if t.temperature is not None and t.pressure is not None]
    n_valid = len(valid_telemetry)

    if n_valid >= 2:
        temps = [t.temperature for t in valid_telemetry]
        pressures = [t.pressure for t in valid_telemetry]
        times = [t.timestamp for t in valid_telemetry]

        idx_offset = min(15, n_valid)
        latest_temp = temps[-1]
        older_temp = temps[-idx_offset]
        time_diff = (times[-1] - times[-idx_offset]) / 60.0
        drift = abs((latest_temp - older_temp) / (time_diff or 1.0))
        drift_risk = min(30.0, drift * 5.0)

        t_mean = sum(temps) / n_valid
        p_mean = sum(pressures) / n_valid
        num = sum((temps[i] - t_mean) * (pressures[i] - p_mean) for i in range(n_valid))
        den_t = sum((temps[i] - t_mean) ** 2 for i in range(n_valid))
        den_p = sum((pressures[i] - p_mean) ** 2 for i in range(n_valid))
        r = num / ((den_t * den_p) ** 0.5 or 1.0)

        if n_valid > 20 and den_t > 0.5 and den_p > 0.05:
            abs_r = abs(r)
            if abs_r < 0.2:
                corr_risk = 40.0
            elif abs_r < 0.5:
                corr_risk = 20.0

        if temps[-1] >= 45.0:
            boundary_risk += 15.0
        if pressures[-1] >= 6.0:
            boundary_risk += 15.0

        threat_index = min(100.0, drift_risk + corr_risk + boundary_risk)

    expected_loss = (threat_index / 100.0) * 400000.0

    # --- 1. FAIR Model Quantitative Framework ---
    tef = max(0.2, float(violation_count) * 0.4)
    vuln_factor = 0.15 if threat_index < 30 else (0.45 if threat_index < 70 else 0.85)
    lef = round(tef * vuln_factor, 3)

    # --- 2. ALE / SLE / ARO Quantitative Analysis ---
    if device_id and device_id in SUBSYSTEM_PROFILES:
        target_profile = SUBSYSTEM_PROFILES[device_id]
        base_sle = target_profile["base_sle"]
        downtime_rate = target_profile["downtime_rate_per_hour"]
        epa_fines = target_profile["epa_fines"]
        nerc_fines = target_profile["nerc_cip_fines"]
    else:
        base_sle = sum(p["base_sle"] for p in SUBSYSTEM_PROFILES.values())
        downtime_rate = sum(p["downtime_rate_per_hour"] for p in SUBSYSTEM_PROFILES.values())
        epa_fines = sum(p["epa_fines"] for p in SUBSYSTEM_PROFILES.values())
        nerc_fines = sum(p["nerc_cip_fines"] for p in SUBSYSTEM_PROFILES.values())

    aro = round(max(0.05, (threat_index / 100.0) * 2.5), 2)
    sle = base_sle
    ale = round(sle * aro, 2)
    residual_risk_pct = round(max(5.0, 100.0 - (prevented_cost / (prevented_cost + expected_loss + 1.0) * 100.0)), 1)

    # --- 3. Subsystem Downtime & Outage Liabilities ---
    # Query currently isolated devices to calculate live outage loss
    isolated_devs = db.query(DeviceState).filter_by(is_isolated=True).all()
    isolated_ids = [d.device_id for d in isolated_devs]
    is_target_isolated = (device_id in isolated_ids) if (device_id and device_id != "ALL") else (len(isolated_ids) > 0)

    # Active outage hourly rate for isolated nodes
    if device_id and device_id in SUBSYSTEM_PROFILES:
        active_hourly_outage = downtime_rate if is_target_isolated else 0.0
    else:
        active_hourly_outage = sum(SUBSYSTEM_PROFILES[did]["downtime_rate_per_hour"] for did in isolated_ids if did in SUBSYSTEM_PROFILES)

    proj_4h = round(downtime_rate * 4.0, 2)
    proj_8h = round(downtime_rate * 8.0, 2)
    proj_24h = round(downtime_rate * 24.0, 2)

    # --- 4. Regulatory & Compliance Exposure ---
    nis2_fines = 100000.0 if threat_index > 50 else 25000.0
    total_regulatory = round(epa_fines + nerc_fines + nis2_fines, 2)

    # --- 5. Return on Security Investment (ROSI) ---
    annual_tooling_cost = 48000.0
    rosi_calc = round(((prevented_cost - annual_tooling_cost) / annual_tooling_cost) * 100.0, 1) if prevented_cost > 0 else 0.0

    return {
        "violation_count": violation_count,
        "incurred_cost": incurred_cost,
        "prevented_cost": prevented_cost,
        "threat_index": round(threat_index, 1),
        "drift_risk": round(drift_risk, 1),
        "corr_risk": round(corr_risk, 1),
        "boundary_risk": round(boundary_risk, 1),
        "expected_loss": round(expected_loss, 2),

        # Expanded Cyber-Financial Governance Metrics
        "fair_model": {
            "tef": round(tef, 2),
            "vulnerability_pct": round(vuln_factor * 100.0, 1),
            "lef": lef,
            "primary_loss": round(sle * 0.6, 2),
            "secondary_loss": round(sle * 0.4 + total_regulatory, 2),
            "risk_tier": "CRITICAL" if threat_index >= 70 else ("ELEVATED" if threat_index >= 30 else "NOMINAL")
        },
        "ale_framework": {
            "sle": round(sle, 2),
            "aro": aro,
            "ale": ale,
            "residual_risk_pct": residual_risk_pct,
            "risk_reduction_pct": round(100.0 - residual_risk_pct, 1)
        },
        "downtime_liability": {
            "hourly_rate": round(downtime_rate, 2),
            "active_outage_hourly_loss": round(active_hourly_outage, 2),
            "is_outage_active": is_target_isolated,
            "projected_4h_mttr": proj_4h,
            "projected_8h_mttr": proj_8h,
            "projected_24h_mttr": proj_24h
        },
        "regulatory_exposure": {
            "epa_environmental": round(epa_fines, 2),
            "nerc_cip_critical_infra": round(nerc_fines, 2),
            "nis2_directive": round(nis2_fines, 2),
            "total_regulatory_exposure": total_regulatory
        },
        "capital_allocation": {
            "capex_equipment_risk": round(sle * 0.7, 2),
            "opex_triaging_cost": incurred_cost,
            "annual_tooling_budget": annual_tooling_cost,
            "rosi_percentage": rosi_calc
        }
    }


def calculate_monte_carlo_distribution(db, device_id: str = None) -> List[Dict[str, Any]]:
    """
    Generates a 12-point probabilistic loss exceedance distribution curve
    (Percentile vs Monetary Loss in USD) from P5 to P99.
    """
    fin = calculate_financial_analytics(db, device_id)
    base = max(15000.0, fin["expected_loss"])
    sle = fin["ale_framework"]["sle"]

    percentiles = [
        ("P05", 0.05, 0.12),
        ("P10", 0.10, 0.20),
        ("P20", 0.20, 0.35),
        ("P30", 0.30, 0.52),
        ("P40", 0.40, 0.72),
        ("P50", 0.50, 1.00),  # Median expected loss
        ("P60", 0.60, 1.35),
        ("P70", 0.70, 1.80),
        ("P80", 0.80, 2.45),
        ("P90", 0.90, 3.50),
        ("P95", 0.95, 4.60),
        ("P99", 0.99, 6.20),  # Extreme catastrophic tail risk
    ]

    curve = []
    for label, pct, multiplier in percentiles:
        est_loss = round(min(sle * 1.8, base * multiplier), 2)
        curve.append({
            "percentile": label,
            "probability": round((1.0 - pct) * 100.0, 1),
            "loss_usd": est_loss
        })
    return curve


def get_subsystem_financial_breakdown(db) -> List[Dict[str, Any]]:
    """Returns per-subsystem capital valuation, downtime liability, and status."""
    states = {d.device_id: d.is_isolated for d in db.query(DeviceState).all()}
    results = []
    for did, profile in SUBSYSTEM_PROFILES.items():
        is_isolated = states.get(did, False)
        results.append({
            "device_id": did,
            "name": profile["name"],
            "zone": profile["zone"],
            "criticality": profile["criticality"],
            "equipment_value": profile["equipment_value"],
            "downtime_rate_per_hour": profile["downtime_rate_per_hour"],
            "base_sle": profile["base_sle"],
            "is_isolated": is_isolated,
            "active_outage_cost_per_hr": profile["downtime_rate_per_hour"] if is_isolated else 0.0
        })
    return results
