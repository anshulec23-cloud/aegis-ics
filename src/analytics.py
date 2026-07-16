from database import TelemetryLog, AuditLog

def calculate_financial_analytics(db):
    """
    Financial & Risk Analytics Engine
    """
    # Fetch last 50 telemetry logs
    telemetry = db.query(TelemetryLog).order_by(TelemetryLog.timestamp.desc()).limit(50).all()
    # Fetch security violations
    violations = db.query(AuditLog).filter(AuditLog.action.like("%VIOLATION%")).all()
    violation_count = len(violations)
    
    # 1. Incurred Incident Response & Triage Cost
    # Each breach attempt incurs $5,000 in investigation/triage costs
    incurred_cost = violation_count * 5000.0
    
    # 2. Prevented Loss (Aegis Savings)
    # Rupture damage: $250,000 + Downtime loss: 3 days * 24 hours * $2,083 = $150,000 -> $400,000 total per breach prevented
    prevented_cost = violation_count * 400000.0
    
    # 3. Dynamic Threat Index (Breach Probability 0-100%)
    threat_index = 0.0
    drift_risk = 0.0
    corr_risk = 0.0
    boundary_risk = 0.0
    
    n = len(telemetry)
    if n >= 15:
        # Reverse telemetry list to make it chronological for calculation
        chrono_telemetry = list(reversed(telemetry))
        temps = [t.temperature for t in chrono_telemetry]
        pressures = [t.pressure for t in chrono_telemetry]
        times = [t.timestamp for t in chrono_telemetry]
        
        # A. Thermal Drift Risk
        latest_temp = temps[-1]
        older_temp = temps[-15]
        time_diff = (times[-1] - times[-15]) / 60.0 # Delta in minutes
        drift = abs((latest_temp - older_temp) / (time_diff or 1.0))
        drift_risk = min(30.0, drift * 5.0) # Max 30% contribution
        
        # B. Sensor Correlation (Pearson r)
        t_mean = sum(temps) / n
        p_mean = sum(pressures) / n
        num = sum((temps[i] - t_mean) * (pressures[i] - p_mean) for i in range(n))
        den_t = sum((temps[i] - t_mean) ** 2 for i in range(n))
        den_p = sum((pressures[i] - p_mean) ** 2 for i in range(n))
        r = num / ((den_t * den_p) ** 0.5 or 1.0)
        
        # Decorrelation signals spoofing
        if n > 20:
            abs_r = abs(r)
            if abs_r < 0.2:
                corr_risk = 40.0 # Max 40%
            elif abs_r < 0.5:
                corr_risk = 20.0
                
        # C. Proximity Risk (approaching limits)
        if temps[-1] >= 45.0: boundary_risk += 15.0
        if pressures[-1] >= 6.0: boundary_risk += 15.0
        
        threat_index = min(100.0, drift_risk + corr_risk + boundary_risk)
        
    expected_loss = (threat_index / 100.0) * 400000.0
    
    return {
        "violation_count": violation_count,
        "incurred_cost": incurred_cost,
        "prevented_cost": prevented_cost,
        "threat_index": round(threat_index, 1),
        "drift_risk": round(drift_risk, 1),
        "corr_risk": round(corr_risk, 1),
        "boundary_risk": round(boundary_risk, 1),
        "expected_loss": round(expected_loss, 2)
    }
