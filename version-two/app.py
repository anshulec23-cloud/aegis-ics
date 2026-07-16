import os
import time
import json
import threading
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from werkzeug.security import check_password_hash
import paho.mqtt.client as mqtt

from database import init_db, SessionLocal, User, AuditLog, TelemetryLog, Rule, DeviceState
from safety_enforcer import validate_command
from sqlalchemy.orm import joinedload
from flask import send_file
from io import BytesIO

# ReportLab components for generating security PDF reports
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.lineplots import LinePlot

# Initialize database
init_db()

import secrets
from datetime import timedelta
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())

# Session Security Hardening
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get("FLASK_SESSION_SECURE", "False").lower() in ("true", "1")

# Rate Limiter State
login_attempts = defaultdict(list)
attempts_lock = threading.Lock()

def check_login_rate_limit(ip):
    if app.config.get("TESTING"):
        return True
    with attempts_lock:
        now = time.time()
        # Clean up attempts older than 60 seconds
        login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 60]
        if len(login_attempts[ip]) >= 5:
            return False
        login_attempts[ip].append(now)
        return True

# CSRF Protection State
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

app.jinja_env.globals.update(csrf_token=generate_csrf_token)

@app.before_request
def csrf_protect():
    # Bypass CSRF checks in testing mode and for the device telemetry API
    if app.config.get("TESTING") or request.path == "/api/telemetry":
        return
    # Only protect mutating HTTP methods
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        # Retrieve token from form field or header
        token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        
        if not token and request.is_json:
            try:
                token = request.json.get("csrf_token")
            except Exception:
                pass
                
        session_token = session.get("csrf_token")
        
        if not session_token or not token or not secrets.compare_digest(session_token, token):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "CSRF token missing or invalid."}), 400
            return render_template("login.html", error="CSRF validation failed. Please authenticate again."), 400

MQTT_HOST = os.environ.get("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
DEVICE_KEY = os.environ.get("DEVICE_KEY_ESP32_001", "device_key_001")

# MQTT client for publishing commands and listening to telemetry
mqtt_client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id="aegis-server")

def on_connect(client, userdata, flags, rc, properties=None):
    client.subscribe("ics/telemetry/+")
    print("[Server] Connected to MQTT Broker - Subscribed to telemetry")

def verify_signature(payload: dict) -> bool:
    import hmac
    import hashlib
    
    def _canonicalize(p):
        result = {}
        for k, v in p.items():
            if k in ("temperature", "pressure", "humidity", "rssi"):
                result[k] = f"{float(v):.2f}"
            elif k == "timestamp":
                result[k] = f"{float(v):.3f}"
            else:
                result[k] = v
        return result

    sig = payload.get("signature")
    body = {k: v for k, v in payload.items() if k != "signature"}
    canonical = json.dumps(_canonicalize(body), sort_keys=True, separators=(",", ":"))
    expected = hmac.new(DEVICE_KEY.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, str(sig)) if sig else False

import pickle
class LocalRFModel:
    def __init__(self, model_path="model/rf_model.pkl"):
        self.model = None
        try:
            if os.path.exists(model_path):
                with open(model_path, "rb") as f:
                    self.model = pickle.load(f)
        except Exception as e:
            print(f"[Server] Failed to load Random Forest model: {e}")
                
    def predict_anomaly(self, telemetry: dict) -> bool:
        # Extract features: [temperature, pressure, vibration, hall_effect, current]
        features = [[
            float(telemetry.get("temperature", 0.0)),
            float(telemetry.get("pressure", 0.0)),
            float(telemetry.get("vibration", 0.0) or telemetry.get("pressure", 0.0) if str(telemetry.get("device_id")) == "ESP32_002" else 0.0),
            float(telemetry.get("hall_effect", 0.0) or telemetry.get("humidity", 0.0) if str(telemetry.get("device_id")) == "ESP32_002" else 0.0),
            float(telemetry.get("current", 0.0) or telemetry.get("humidity", 0.0) if str(telemetry.get("device_id")) == "ESP32_001" else 0.0)
        ]]
        if self.model is None:
            # Fallback heuristic
            temp = features[0][0]
            pressure = features[0][1]
            vib = features[0][2]
            hall = features[0][3]
            curr = features[0][4]
            anomaly = 0.0
            if temp < 0.0 or temp > 50.0: anomaly += 0.3
            if pressure < 0.0 or pressure > 8.0: anomaly += 0.3
            if vib > 6.0: anomaly += 0.4
            if hall > 1800.0: anomaly += 0.4
            if curr > 8.0: anomaly += 0.4
            return min(1.0, anomaly) > 0.5
            
        try:
            proba = self.model.predict_proba(features)[0]
            return float(proba[1]) > 0.5
        except Exception:
            return False

rf_model = LocalRFModel(os.path.join(os.path.dirname(__file__), "model", "rf_model.pkl"))

def process_telemetry(payload: dict) -> bool:
    db = SessionLocal()
    device_id = payload.get("device_id", "unknown")
    
    # 0. Check if device is isolated. If isolated, reject incoming data to freeze dashboard.
    state = db.query(DeviceState).filter_by(device_id=device_id).first()
    if state and state.is_isolated:
        db.close()
        print(f"[Server] Telemetry REJECTED from isolated device: {device_id}")
        return False
        
    sig_valid = verify_signature(payload)
    ml_anomaly = rf_model.predict_anomaly(payload)
    is_anomaly = (not sig_valid) or ml_anomaly
    
    try:
        log = TelemetryLog(
            timestamp=payload.get("timestamp", time.time()),
            device_id=device_id,
            temperature=payload.get("temperature", 0.0),
            pressure=payload.get("pressure", 0.0),
            humidity=payload.get("humidity", 0.0),
            vibration=payload.get("vibration", 0.0),
            hall_effect=payload.get("hall_effect", 0.0),
            current=payload.get("current", 0.0),
            rssi=payload.get("rssi", 0.0),
            is_anomaly=is_anomaly
        )
        db.add(log)
        db.commit()

        # Automatic Security Isolation Policy: Isolate device if signature is invalid or ML detects anomaly
        if is_anomaly and device_id != "unknown":
            state = db.query(DeviceState).filter_by(device_id=device_id).first()
            if state and not state.is_isolated:
                state.is_isolated = True
                
                # Log automatic isolation to audit log
                reason = "invalid HMAC signature" if not sig_valid else "AI Random Forest anomaly detection"
                audit = AuditLog(
                    user_id=None, # System action
                    action="AUTO_ISOLATION",
                    location="SYSTEM",
                    details=f"System automatically isolated device {device_id} due to {reason}."
                )
                db.add(audit)
                db.commit()
                print(f"[SYSTEM] AUTOMATIC ISOLATION TRIGGERED FOR DEVICE {device_id} ({reason})")
        return True
    except Exception as e:
        print(f"[Server] Database write failed: {e}")
        return False
    finally:
        db.close()

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
    except Exception as e:
        print(f"[Server] Failed to decode telemetry: {e}")
        return
    process_telemetry(payload)

# Start MQTT Background Loop
def start_mqtt():
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    try:
        mqtt_client.connect(MQTT_HOST, MQTT_PORT, 60)
        mqtt_client.loop_start()
    except Exception as e:
        print(f"[Server] WARNING: Could not connect to MQTT broker: {e}. Telemetry ingestion disabled.")

threading.Thread(target=start_mqtt, daemon=True).start()

# --- Auth Helpers ---
def login_required(f):
    def decorator(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    decorator.__name__ = f.__name__
    return decorator

# --- Financial & Risk Analytics Engine ---
def calculate_financial_analytics(db):
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

# --- Routes ---
@app.route("/")
@login_required
def index():
    return render_template("dashboard.html", username=session.get("username"), location=session.get("location"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # 1. Rate Limit Check
        ip = request.remote_addr
        if not check_login_rate_limit(ip):
            return render_template("login.html", error="Too many authentication attempts. Please try again in 60 seconds."), 429
            
        username = request.form.get("username")
        password = request.form.get("password")
        coord_x = request.form.get("coord_x", "0.0")
        coord_y = request.form.get("coord_y", "0.0")
        coord_z = request.form.get("coord_z", "0.0")
        
        # 2. Parse and Validate Coordinates (blocks XSS / injection)
        try:
            cx = float(coord_x)
            cy = float(coord_y)
            cz = float(coord_z)
            location_str = f"X={cx:.2f}, Y={cy:.2f}, Z={cz:.2f}"
        except ValueError:
            return render_template("login.html", error="Station coordinates must be numeric values."), 400
        
        db = SessionLocal()
        user = db.query(User).filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session.permanent = True
            session["user_id"] = user.id
            session["username"] = user.username
            session["location"] = location_str
            
            # Log successful login
            audit = AuditLog(
                user_id=user.id,
                action="LOGIN",
                location=location_str,
                details=f"User {username} successfully authenticated."
            )
            db.add(audit)
            db.commit()
            db.close()
            return redirect(url_for("index"))
            
        db.close()
        return render_template("login.html", error="Invalid credentials."), 401
        
    return render_template("login.html")

@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    location = session.get("location", "Unknown")
    username = session.get("username", "Unknown")
    
    if user_id:
        db = SessionLocal()
        audit = AuditLog(
            user_id=user_id,
            action="LOGOUT",
            location=location,
            details=f"User {username} logged out."
        )
        db.add(audit)
        db.commit()
        db.close()
        
    session.clear()
    return redirect(url_for("login"))

@app.route("/api/setpoint", methods=["POST"])
@login_required
def setpoint():
    payload = request.json or {}
    cmd_type = payload.get("type")
    value = float(payload.get("value", 0))
    db = SessionLocal()
    # 0. Check if device is isolated
    state = db.query(DeviceState).filter_by(device_id="ESP32_001").first()
    if state and state.is_isolated:
        db.close()
        return jsonify({"success": False, "error": "Blocked: Control loop commands are rejected because device ESP32_001 is currently isolated."}), 403

    # 1. Run Safety Policy Enforcer boundary (AI + Rules)
    allowed, reason = validate_command({"type": cmd_type, "value": value}, db)
    
    user_id = session["user_id"]
    location = session["location"]
    
    if not allowed:
        # Audit Log Security Violation Attempt
        audit = AuditLog(
            user_id=user_id,
            action="SECURITY_VIOLATION_BLOCKED",
            location=location,
            details=f"Blocked attempt to set {cmd_type} to {value}. Reason: {reason}"
        )
        db.add(audit)
        db.commit()
        db.close()
        return jsonify({"success": False, "error": reason}), 403
        
    # 2. Publish to MQTT Broker
    topic = f"ics/control/ESP32_001"
    command_payload = json.dumps({"type": cmd_type, "value": value})
    try:
        mqtt_client.publish(topic, command_payload, qos=1)
        print(f"[Server] Dispatched control command: {cmd_type}={value}")
    except Exception as e:
        db.close()
        return jsonify({"success": False, "error": f"Broker publish failed: {e}"}), 500

    # 3. Log Success
    audit = AuditLog(
        user_id=user_id,
        action="CHANGE_SETPOINT",
        location=location,
        details=f"Changed {cmd_type} to {value}."
    )
    db.add(audit)
    db.commit()
    db.close()
    
    return jsonify({"success": True, "details": f"Successfully updated setpoint to {value}."})

def generate_incident_report_pdf(db_session, username, location):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    story = []
    
    # Custom styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#000000'),
        spaceAfter=5
    )
    meta_style = ParagraphStyle(
        'MetaStyle',
        parent=styles['Normal'],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#86868b'),
        spaceAfter=15
    )
    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Heading2'],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#1d1d1f'),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyStyle',
        parent=styles['Normal'],
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#1d1d1f'),
        spaceAfter=8
    )
    table_text = ParagraphStyle(
        'TableText',
        parent=styles['Normal'],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#1d1d1f')
    )
    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#1d1d1f'),
        fontName='Helvetica-Bold'
    )
    
    # 1. Header
    story.append(Paragraph("Aegis SCADA Security & Loss Analysis Report", title_style))
    story.append(Paragraph(f"Generated: {datetime.now(timezone.utc).isoformat()} | Station Coordinates: {location} | Operator: {username}", meta_style))
    story.append(Spacer(1, 10))
    
    # 2. Executive Summary & Financial Audit
    story.append(Paragraph("1. Incident Financial Audit & Loss Projections", h2_style))
    
    # Run financials
    financials = calculate_financial_analytics(db_session)
    
    # Table of Financial Projections
    fin_data = [
        [Paragraph("Audit Category", table_header), Paragraph("Financial Impact", table_header), Paragraph("Security / Cost Breakdown", table_header)],
        [Paragraph("Incurred Incident Cost", table_text), Paragraph(f"${financials['incurred_cost']:,.2f}", table_text), Paragraph("Triage and investigation cost ($5,000 per violation attempt)", table_text)],
        [Paragraph("Projected Downtime Cost", table_text), Paragraph(f"${financials['expected_loss']:,.2f}", table_text), Paragraph("Liability projection based on dynamic Threat Index", table_text)],
        [Paragraph("Total Prevented Losses (Savings)", table_text), Paragraph(f"${financials['prevented_cost']:,.2f}", table_text), Paragraph("Savings from blocked centrifugal casing ruptures ($400,000 each)", table_text)]
    ]
    t_fin = Table(fin_data, colWidths=[150, 100, 280])
    t_fin.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f5f5f7')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#d2d2d7')),
    ]))
    story.append(t_fin)
    story.append(Spacer(1, 15))
    
    # 3. Telemetry Visualizer Chart
    story.append(Paragraph("2. Telemetry Plot (Historical Temperature vs. Pressure)", h2_style))
    
    telemetry = db_session.query(TelemetryLog).order_by(TelemetryLog.timestamp.desc()).limit(30).all()
    if telemetry:
        chrono_telemetry = list(reversed(telemetry))
        drawing = Drawing(530, 160)
        
        # Draw background card bounding box
        drawing.add(Rect(0, 0, 530, 160, fillColor=colors.HexColor('#fafafa'), strokeColor=colors.HexColor('#e5e5ea'), strokeWidth=1))
        
        # Build coordinates lists
        temp_pts = []
        pres_pts = []
        for idx, t in enumerate(chrono_telemetry):
            # Scale x: width = 430, margin left = 50. x goes from 50 to 480.
            # Scale y: height = 110, margin bottom = 30. y goes from 30 to 140.
            x = 50 + (idx / max(1, len(chrono_telemetry)-1)) * 430
            # Scale temperature (0 to 80C)
            y_temp = 30 + (min(80.0, max(0.0, t.temperature)) / 80.0) * 110
            # Scale pressure (0 to 10bar)
            y_pres = 30 + (min(10.0, max(0.0, t.pressure)) / 10.0) * 110
            
            temp_pts.append((x, y_temp))
            pres_pts.append((x, y_pres))
            
        # Draw lines manually using shapes
        from reportlab.graphics.shapes import Line
        
        # Grid lines
        for y_val in [30, 57.5, 85, 112.5, 140]:
            drawing.add(Line(50, y_val, 480, y_val, strokeColor=colors.HexColor('#e5e5ea'), strokeWidth=0.5))
            
        # Draw Temperature Line (solid black)
        for i in range(len(temp_pts) - 1):
            p1 = temp_pts[i]
            p2 = temp_pts[i+1]
            drawing.add(Line(p1[0], p1[1], p2[0], p2[1], strokeColor=colors.HexColor('#000000'), strokeWidth=1.5))
            
        # Draw Pressure Line (dashed grey)
        for i in range(len(pres_pts) - 1):
            p1 = pres_pts[i]
            p2 = pres_pts[i+1]
            drawing.add(Line(p1[0], p1[1], p2[0], p2[1], strokeColor=colors.HexColor('#86868b'), strokeWidth=1, strokeDashArray=[3, 3]))
            
        # Labels and axes
        drawing.add(String(10, 135, "Temp (C)", fontName="Helvetica-Bold", fontSize=8, fillColor=colors.HexColor('#000000')))
        drawing.add(String(490, 135, "Pres (bar)", fontName="Helvetica-Bold", fontSize=8, fillColor=colors.HexColor('#86868b')))
        drawing.add(String(10, 82, "40C / 5bar", fontName="Helvetica", fontSize=7, fillColor=colors.HexColor('#86868b')))
        drawing.add(String(10, 30, "0C / 0bar", fontName="Helvetica", fontSize=7, fillColor=colors.HexColor('#86868b')))
        
        story.append(drawing)
    else:
        story.append(Paragraph("No telemetry readings available for charting.", body_style))
    story.append(Spacer(1, 15))
    
    # 4. Detailed Chronological Audit Narrative
    story.append(Paragraph("3. Chronological Incident Narrative", h2_style))
    story.append(Paragraph("Below is the complete sequence of logged user access, parameter updates, enforcer interventions, and isolation actions.", body_style))
    
    # Query last 100 audit events
    audit_logs = db_session.query(AuditLog).options(joinedload(AuditLog.user)).order_by(AuditLog.timestamp.desc()).limit(100).all()
    
    audit_headers = [
        Paragraph("Timestamp", table_header),
        Paragraph("User", table_header),
        Paragraph("Action", table_header),
        Paragraph("Location Coords", table_header),
        Paragraph("Event Details", table_header)
    ]
    audit_rows = [audit_headers]
    
    for a in reversed(audit_logs):
        u_name = a.user.username if a.user else "SYSTEM"
        action_text = a.action
        
        # Style highlighted events
        color_hex = "#1d1d1f"
        if "VIOLATION" in action_text or "ISOLATION" in action_text:
            color_hex = "#c93b3b"
        elif "LOGIN" in action_text or "REJOIN" in action_text:
            color_hex = "#1f824c"
            
        act_style = ParagraphStyle('ActStyle', parent=table_text, textColor=colors.HexColor(color_hex), fontName="Helvetica-Bold")
        
        audit_rows.append([
            Paragraph(a.timestamp.strftime('%Y-%m-%d %H:%M:%S'), table_text),
            Paragraph(u_name, table_text),
            Paragraph(action_text, act_style),
            Paragraph(a.location, table_text),
            Paragraph(a.details or "", table_text)
        ])
        
    t_audit = Table(audit_rows, colWidths=[90, 60, 110, 90, 180])
    t_audit.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f5f5f7')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e5ea')),
    ]))
    
    story.append(t_audit)
    story.append(Spacer(1, 15))
    
    # 5. Recovery & Mitigations Section
    story.append(Paragraph("4. Recommended Mitigation Steps", h2_style))
    story.append(Paragraph("• <b>HMAC Credential Rotation</b>: Rotate secret device validation keys (DEVICE_KEY) on all ESP32 PLCs to prevent replay and injection vectors.<br/>"
                           "• <b>Session Audit</b>: Inspect operator station coordinates to isolate coordinates outside permitted operational zones.<br/>"
                           "• <b>Device Loop Check</b>: If a device status is MANUAL_ISOLATION, run hardware testing loop checks before rejoining the device to the operational loop.<br/>"
                           "• <b>Stuxnet Mitigation</b>: Keep Aegis enforcer correlation rules active. The enforcer prevents centrifugal over-pressurization even under administrator credentials.", body_style))
    
    # Build Document
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()

@app.route("/api/device/status", methods=["GET"])
@login_required
def device_status():
    db = SessionLocal()
    state = db.query(DeviceState).filter_by(device_id="ESP32_001").first()
    is_isolated = state.is_isolated if state else False
    db.close()
    return jsonify({"is_isolated": is_isolated})

@app.route("/api/device/isolate", methods=["POST"])
@login_required
def isolate_device_v2():
    db = SessionLocal()
    state = db.query(DeviceState).filter_by(device_id="ESP32_001").first()
    if state:
        state.is_isolated = True
        
        # Log manual isolation
        audit = AuditLog(
            user_id=session["user_id"],
            action="MANUAL_ISOLATION",
            location=session["location"],
            details="Operator manually isolated the device from the control loop."
        )
        db.add(audit)
        db.commit()
    db.close()
    return jsonify({"success": True, "details": "Device ESP32_001 successfully isolated."})

@app.route("/api/device/rejoin", methods=["POST"])
@login_required
def rejoin_device_v2():
    db = SessionLocal()
    state = db.query(DeviceState).filter_by(device_id="ESP32_001").first()
    if state:
        state.is_isolated = False
        
        # Log manual rejoin
        audit = AuditLog(
            user_id=session["user_id"],
            action="MANUAL_REJOIN",
            location=session["location"],
            details="Operator manually rejoined the device to the control loop."
        )
        db.add(audit)
        db.commit()
    db.close()
    return jsonify({"success": True, "details": "Device ESP32_001 successfully rejoined to control loop."})

@app.route("/api/report/download", methods=["GET"])
@login_required
def download_report():
    db = SessionLocal()
    try:
        pdf_data = generate_incident_report_pdf(db, session["username"], session["location"])
        return send_file(
            BytesIO(pdf_data),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"aegis_scada_report_{int(time.time())}.pdf"
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        db.close()

@app.route("/api/simulate-attack", methods=["POST"])
@login_required
def simulate_attack():
    payload = request.json or {}
    attack_type = payload.get("type")
    
    db = SessionLocal()
    user_id = session["user_id"]
    location = session["location"]
    
    if attack_type == "stuxnet":
        # 1. Seed telemetry showing high pressure
        log = TelemetryLog(
            timestamp=time.time(),
            device_id="ESP32_001",
            temperature=30.0,
            pressure=7.5,
            humidity=50.0,
            is_anomaly=False
        )
        db.add(log)
        db.commit()
        
        # 2. Add security violation record (blocked Stuxnet command attempt)
        audit = AuditLog(
            user_id=user_id,
            action="SECURITY_VIOLATION_BLOCKED",
            location=location,
            details="Blocked attempt to set set_temp to 55.0. Reason: Stuxnet Prevention Policy - Temperature setpoint (55.0) rejected while system pressure is high (7.5 bar)."
        )
        db.add(audit)
        db.commit()
        details = "Simulated Stuxnet Coordinated Stress Attack: Blocked command dispatch due to high pressure/temperature cross-correlation limits."
        
    elif attack_type == "injection":
        # 1. Seed telemetry with is_anomaly=True (invalid signature)
        log = TelemetryLog(
            timestamp=time.time(),
            device_id="ESP32_001",
            temperature=58.0,
            pressure=4.0,
            humidity=50.0,
            is_anomaly=True
        )
        db.add(log)
        
        # 2. Trigger automatic isolation
        state = db.query(DeviceState).filter_by(device_id="ESP32_001").first()
        if state:
            state.is_isolated = True
            
        audit = AuditLog(
            user_id=None,
            action="AUTO_ISOLATION",
            location="SYSTEM",
            details="System automatically isolated device ESP32_001 due to invalid HMAC signature (Telemetry Spoofing / Injection Attack detected)."
        )
        db.add(audit)
        db.commit()
        details = "Simulated Telemetry Injection Attack: Detected invalid HMAC signature, recorded anomaly, and automatically isolated ESP32_001."
        
    elif attack_type == "privilege":
        # Simulate a privilege escalation / session attack
        audit = AuditLog(
            user_id=user_id,
            action="SECURITY_VIOLATION_BLOCKED",
            location=location,
            details="Blocked unauthorized modification of safety thresholds: Attempted to set temp_max to 100.0 without Master Engineering credentials."
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
@login_required
def get_data():
    db = SessionLocal()
    # Fetch last 50 telemetry readings
    telemetry = db.query(TelemetryLog).order_by(TelemetryLog.timestamp.desc()).limit(50).all()
    # Fetch last 30 audit logs (using joinedload to avoid N+1 query)
    audit_logs = db.query(AuditLog).options(joinedload(AuditLog.user)).order_by(AuditLog.timestamp.desc()).limit(30).all()
    
    telemetry_data = [{
        "timestamp": t.timestamp,
        "device_id": t.device_id,
        "temperature": t.temperature,
        "pressure": t.pressure,
        "humidity": t.humidity,
        "vibration": t.vibration or 0.0,
        "hall_effect": t.hall_effect or 0.0,
        "current": t.current or 0.0,
        "rssi": t.rssi,
        "is_anomaly": t.is_anomaly
    } for t in reversed(telemetry)]
    
    audit_data = [{
        "timestamp": a.timestamp.isoformat(),
        "username": a.user.username if a.user else "Unknown",
        "action": a.action,
        "location": a.location,
        "details": a.details
    } for a in audit_logs]
    
    financials = calculate_financial_analytics(db)
    db.close()
    return jsonify({
        "telemetry": telemetry_data,
        "audit_logs": audit_data,
        "financials": financials
    })

@app.route("/api/telemetry", methods=["POST"])
def api_telemetry():
    payload = request.json or {}
    device_id = payload.get("device_id")
    if not device_id:
        return jsonify({"success": False, "error": "Missing device_id"}), 400
    
    success = process_telemetry(payload)
    if success:
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Processing failed"}), 500

@app.route("/health", methods=["GET"])
def health():
    try:
        db = SessionLocal()
        db.query(User).first()
        db.close()
        return jsonify({"status": "healthy", "components": {"database": "connected"}}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
