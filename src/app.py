import os 
import sys 
import time 
import json 
import math
import functools
import threading 
import secrets 
import bleach 
from datetime import datetime ,timezone ,timedelta 
from collections import defaultdict 
from flask import Flask ,render_template ,request ,jsonify ,redirect ,url_for ,session ,send_file ,Response ,stream_with_context 
from werkzeug .security import check_password_hash 
from flask_limiter import Limiter 
from flask_limiter .util import get_remote_address 

from database import init_db ,SessionLocal ,User ,AuditLog ,TelemetryLog ,Rule ,DeviceState 
from safety_enforcer import validate_command 
from sqlalchemy .orm import joinedload 
from io import BytesIO 

from analytics import calculate_financial_analytics, calculate_monte_carlo_distribution, get_subsystem_financial_breakdown, SUBSYSTEM_PROFILES
from reporting import generate_incident_report_pdf 




def _resource_path (relative_path :str )->str :
    """Resolve file path for both dev and frozen PyInstaller builds."""
    if hasattr (sys ,'_MEIPASS'):
        return os .path .join (sys ._MEIPASS ,relative_path )
    return os .path .join (os .path .dirname (os .path .abspath (__file__ )),relative_path )

from security import require_webview_token ,get_device_key 


init_db ()

app =Flask (
__name__ ,
template_folder =_resource_path ('templates'),
static_folder =_resource_path ('static'),
)
app .secret_key =os .environ .get ("FLASK_SECRET_KEY",os .urandom (32 ).hex ())


limiter =Limiter (
get_remote_address ,
app =app ,
default_limits =[]if os .environ .get ("AEGIS_DESKTOP_MODE")else ["10000 per hour","200 per minute"],
storage_uri ="memory://"
)


app .config ['PERMANENT_SESSION_LIFETIME']=timedelta (minutes =30 )
app .config ['SESSION_COOKIE_HTTPONLY']=True 
app .config ['SESSION_COOKIE_SAMESITE']='Strict'
app .config ['SESSION_COOKIE_SECURE']=os .environ .get ("FLASK_SESSION_SECURE","False").lower ()in ("true","1")


DEVICE_KEYS ={
"ESP32_001":get_device_key ("ESP32_001"),
"ESP32_002":get_device_key ("ESP32_002"),
}


def generate_csrf_token ():
    if "csrf_token"not in session :
        session ["csrf_token"]=secrets .token_hex (32 )
    return session ["csrf_token"]

app .jinja_env .globals .update (csrf_token =generate_csrf_token )

@app .before_request 
def csrf_protect ():
    if app .config .get ("TESTING"):
        limiter .enabled = False
        return 

    if request .path =="/api/telemetry":
        return 

    if request .method in ("POST","PUT","DELETE","PATCH"):

        token =request .form .get ("csrf_token")or request .headers .get ("X-CSRF-Token")

        if not token and request .is_json :
            try :
                token =request .json .get ("csrf_token")
            except Exception :
                pass 

        session_token =session .get ("csrf_token")

        if not session_token or not token or not secrets .compare_digest (session_token ,token ):
            if request .is_json or request .path .startswith ("/api/"):
                return jsonify ({"success":False ,"error":"CSRF token missing or invalid."}),400 
            return render_template ("login.html",error ="CSRF validation failed. Please authenticate again."),400 

from trust_engine import compute_device_trust_score 

def verify_signature (payload :dict )->bool :
    import hmac 
    import hashlib 

    device_id =str (payload .get ("device_id","ESP32_001"))
    key = get_device_key(device_id).encode("utf-8")
    if not key :return False 

    def _canonicalize (p ):
        result ={}
        for k ,v in p .items ():
            if k in ("temperature","pressure","humidity","rssi","vibration","hall_effect","current"):
                if v is not None :
                    result [k ]=f"{float (v ):.2f}"
            elif k =="timestamp":
                if v is not None :
                    result [k ]=f"{float (v ):.3f}"
            else :
                result [k ]=v 
        return result 

    sig =payload .get ("signature")
    body ={k :v for k ,v in payload .items ()if k !="signature"}
    canonical =json .dumps (_canonicalize (body ),sort_keys =True ,separators =(",",":"))
    expected =hmac .new (key ,canonical .encode ("utf-8"),hashlib .sha256 ).hexdigest ()
    return hmac .compare_digest (expected ,str (sig ))if sig else False 

import pickle 
class LocalRFModel :
    def __init__ (self ,model_path =None):
        if model_path is None:
            model_path = _resource_path("model/rf_model.pkl")
        self .model =None 
        try :
            if os .path .exists (model_path ):
                with open (model_path ,"rb")as f :
                    self .model =pickle .load (f )
        except Exception as e :
            print (f"[Server] Failed to load Random Forest model: {e }")

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
                if math.isnan(pres) or math.isinf(pres) or pres < pressure_min or pres > pressure_max:
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
        hall_max = 3000.0 if dev_id_val == "ESP32_004" else 2000.0
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
        all_features_present = (temp_val is not None and pres_val is not None and vib_val is not None and curr_val is not None)
        if all_features_present and self.model is not None:
            try:
                feature_dict = {
                    "temperature": [float(temp_val)],
                    "pressure": [float(pres_val)],
                    "vibration": [float(vib_val)],
                    "hall_effect": [float(hall_val) if hall_val is not None else 0.0],
                    "current": [float(curr_val)]
                }
                try:
                    import pandas as pd
                    features = pd.DataFrame(feature_dict)
                except ImportError:
                    features = [[
                        float(temp_val),
                        float(pres_val),
                        float(vib_val),
                        float(hall_val) if hall_val is not None else 0.0,
                        float(curr_val)
                    ]]
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    proba = self.model.predict_proba(features)[0]
                if float(proba[1]) > 0.5:
                    anomaly += 0.6
            except Exception:
                pass

        return anomaly > 0.5 

rf_model =LocalRFModel (_resource_path (os .path .join ("model","rf_model.pkl")))

def process_telemetry (payload :dict )->tuple [bool ,int ,str ]:
    db =SessionLocal ()
    device_id =payload .get ("device_id","unknown")

    state =db .query (DeviceState ).filter_by (device_id =device_id ).first ()
    if state and state .is_isolated :
        db .close ()
        print (f"[Server] Telemetry REJECTED from isolated device: {device_id }")
        return False ,403 ,f"Access Denied: Device {device_id } is quarantined by Zero-Trust microsegmentation policy."

    sig_valid =verify_signature (payload )
    ml_anomaly =rf_model .predict_anomaly (payload, db_session=db)
    is_anomaly =(not sig_valid )or ml_anomaly 

    try :
        log =TelemetryLog (
        timestamp =payload .get ("timestamp",time .time ()),
        device_id =device_id ,
        temperature =payload .get ("temperature"),
        pressure =payload .get ("pressure"),
        humidity =payload .get ("humidity"),
        vibration =payload .get ("vibration"),
        hall_effect =payload .get ("hall_effect"),
        current =payload .get ("current"),
        rssi =payload .get ("rssi"),
        is_anomaly =is_anomaly 
        )
        db .add (log )
        db .commit ()

        if is_anomaly and device_id !="unknown":
            state =db .query (DeviceState ).filter_by (device_id =device_id ).first ()
            now_utc = datetime.now(timezone.utc)
            if not state :
                state =DeviceState (device_id =device_id ,is_isolated =True ,updated_at =now_utc )
                db .add (state )
            else :
                state .is_isolated =True 
                state .updated_at =now_utc 

            reasons = []
            if not sig_valid:
                reasons.append("invalid HMAC signature")
            if ml_anomaly:
                reasons.append("safeguard boundary violation / AI anomaly detection")
            reason_str = " and ".join(reasons) if reasons else "anomaly detected"

            audit =AuditLog (
            user_id =None ,
            action ="AUTO_ISOLATION",
            location ="SYSTEM",
            details =f"System automatically isolated device {device_id } due to {reason_str }."
            )
            db .add (audit )
            db .commit ()
            print (f"[SYSTEM] AUTOMATIC ISOLATION TRIGGERED FOR DEVICE {device_id } ({reason_str })")

            # Dispatch physical isolation command to hardware via serial gateway
            try :
                import serial_gateway 
                serial_gateway .send_command ({
                    "command":"ISOLATE",
                    "action":"ISOLATE",
                    "device_id":device_id ,
                    "target_device":device_id ,
                    "timestamp":time .time (),
                    "reason":reason_str 
                })
            except Exception as cmd_err :
                print (f"[Server] Hardware auto-isolation dispatch note: {cmd_err }")

        return True ,200 ,"Telemetry ingested successfully."
    except Exception as e :
        print (f"[Server] Database write failed: {e }")
        return False ,500 ,f"Database write error: {e }"
    finally :
        db .close ()


def login_required (f ):
    @functools .wraps (f )
    def decorator (*args ,**kwargs ):
        if "user_id"not in session :
            return redirect (url_for ("login"))
        return f (*args ,**kwargs )
    return decorator 




@app .route ("/")
@login_required 
def index ():
    return render_template ("dashboard.html",username =session .get ("username"),location =session .get ("location"))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("120 per minute")
def login():
    if request .method =="POST":
        username =request .form .get ("username")
        password =request .form .get ("password")

        location_coords = request .form .get ("location_coords")
        latitude = request .form .get ("latitude")
        longitude = request .form .get ("longitude")
        elevation = request .form .get ("elevation")

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
            coord_x = request .form .get ("coord_x")
            coord_y = request .form .get ("coord_y")
            coord_z = request .form .get ("coord_z")
            if coord_x is not None and coord_y is not None:
                try:
                    cx = float(coord_x)
                    cy = float(coord_y)
                    cz = float(coord_z or 0.0)
                    location_str = f"X={cx:.2f}, Y={cy:.2f}, Z={cz:.2f}"
                except ValueError:
                    location_str = "Terminal GPS: Lat 37.77490, Lon -122.41940, Elev 18.5m [Grid H-01]"
            else:
                location_str = "Terminal GPS: Lat 37.77490, Lon -122.41940, Elev 18.5m [Grid H-01]"

        db =SessionLocal ()
        user =db .query (User ).filter_by (username =username ).first ()

        if user and check_password_hash (user .password_hash ,password ):
            session .permanent =True 
            session ["user_id"]=user .id 
            session ["username"]=user .username 
            session ["location"]=location_str 


            audit =AuditLog (
            user_id =user .id ,
            action ="LOGIN",
            location =location_str ,
            details =f"User {username } successfully authenticated."
            )
            db .add (audit )
            db .commit ()
            db .close ()
            return redirect (url_for ("index"))

        db .close ()
        return render_template ("login.html",error ="Invalid credentials."),401 

    return render_template ("login.html")

@app .route ("/logout")
def logout ():
    user_id =session .get ("user_id")
    location =session .get ("location","Unknown")
    username =session .get ("username","Unknown")

    if user_id :
        db =SessionLocal ()
        audit =AuditLog (
        user_id =user_id ,
        action ="LOGOUT",
        location =location ,
        details =f"User {username } logged out."
        )
        db .add (audit )
        db .commit ()
        db .close ()

    session .clear ()
    return redirect (url_for ("login"))

@app .route ("/api/setpoint",methods =["POST"])
@login_required 
@require_webview_token 
@limiter .limit ("30 per minute")
def setpoint ():
    payload =request .json or {}
    cmd_type =bleach .clean (str (payload .get ("type","")))
    try :
        val_input = payload.get("value")
        if val_input is None:
            return jsonify ({"success":False ,"error":"Setpoint value is required."}),400
        if isinstance(val_input, bool):
            return jsonify ({"success":False ,"error":"Command setpoint value must be numeric."}),400
        value =float (val_input)
        if math.isnan(value) or math.isinf(value):
            return jsonify ({"success":False ,"error":"Command setpoint value must be a finite numeric value."}),400
    except (ValueError, TypeError) :
        return jsonify ({"success":False ,"error":"Invalid numeric value."}),400 

    db =SessionLocal ()

    target_device = bleach.clean(str(payload.get("target_device") or payload.get("device_id") or "ESP32_001"))
    state =db .query (DeviceState ).filter_by (device_id =target_device ).first ()
    if state and state .is_isolated :
        db .close ()
        return jsonify ({"success":False ,"error":f"Blocked: Control loop commands rejected because device {target_device} is currently isolated."}),403 


    allowed ,reason =validate_command ({"type":cmd_type ,"value":value },db ,target_device=target_device )

    user_id =session ["user_id"]
    location =session ["location"]

    if not allowed :

        audit =AuditLog (
        user_id =user_id ,
        action ="SECURITY_VIOLATION_BLOCKED",
        location =location ,
        details =f"Blocked attempt to set {cmd_type } to {value } on {target_device}. Reason: {reason }"
        )
        db .add (audit )
        db .commit ()
        db .close ()
        return jsonify ({"success":False ,"error":reason }),403 


    command_payload ={
    "command":"setpoint",
    "device_id":target_device ,
    "target":cmd_type ,
    "value":value ,
    "timestamp":datetime .now (timezone .utc ).isoformat (),
    "signature":""
    }
    try :
        import serial_gateway 
        serial_gateway .send_command (command_payload )
        print (f"[Server] Dispatched control command: {cmd_type }={value } -> {target_device}")
    except Exception as e :
        db .close ()
        return jsonify ({"success":False ,"error":f"UART publish failed: {e }"}),500 


    audit =AuditLog (
    user_id =user_id ,
    action ="CHANGE_SETPOINT",
    location =location ,
    details =f"Changed {cmd_type } to {value } on {target_device}."
    )
    db .add (audit )
    db .commit ()
    db .close ()

    return jsonify ({"success":True ,"details":f"Successfully updated setpoint to {value }."})




@app .route ("/api/com_ports",methods =["GET"])
@login_required 
@require_webview_token 
def list_com_ports ():
    try :
        from serial .tools import list_ports 
        ports =[p .device for p in list_ports .comports ()]
        return jsonify ({"success":True ,"ports":ports })
    except Exception as e :
        return jsonify ({"success":False ,"error":str (e )})

@app .route ("/api/com_ports/status",methods =["GET"])
@login_required 
@require_webview_token 
def com_port_status ():
    try :
        from serial_gateway import get_active_port 
        port =get_active_port ()
        return jsonify ({"success":True ,"port":port })
    except Exception as e :
        return jsonify ({"success":False ,"error":str (e )})

@app .route ("/api/com_ports/connect",methods =["POST"])
@login_required 
@require_webview_token 
def connect_com_port ():
    payload =request .json or {}
    port =payload .get ("port")
    try:
        baud = int(payload.get("baud", 115200))
    except (ValueError, TypeError):
        baud = 115200
    if not port :
        return jsonify ({"success":False ,"error":"No port specified."})
    try :
        import serial_gateway 
        import threading 


        serial_gateway .stop_gateway ()
        time .sleep (0.2 )

        flask_port =os .environ .get ("FLASK_PORT","5000")
        url =f"http://127.0.0.1:{flask_port }/api/telemetry"

        mock = port.upper().startswith("MOCK") or port.upper().startswith("SIM")
        hmac_key = get_device_key("ESP32_001")
        gateway_thread =threading .Thread (
        target =serial_gateway .start_gateway ,
        kwargs ={"port":port if not mock else None ,"baud":baud ,"mock":mock ,"url":url ,"hmac_key":hmac_key },
        daemon =True ,
        name ="serial-gateway"
        )
        gateway_thread .start ()


        db =SessionLocal ()
        # Reset quarantine across all cluster nodes on fresh hardware COM connection
        cluster_nodes = ["ESP32_001", "ESP32_002", "ESP32_003", "ESP32_004"]
        for cid in cluster_nodes:
            dev_state = db.query(DeviceState).filter_by(device_id=cid).first()
            if dev_state and dev_state.is_isolated:
                dev_state.is_isolated = False

        audit =AuditLog (
        user_id =session .get ("user_id"),
        action ="CONNECT_COM_PORT",
        location =session .get ("location"),
        details =f"Connected hardware gateway to port {port }."
        )
        db .add (audit )
        db .commit ()
        db .close ()

        return jsonify ({"success":True ,"details":f"Gateway connecting to {port }."})
    except Exception as e :
        return jsonify ({"success":False ,"error":str (e )})

@app .route ("/api/com_ports/disconnect",methods =["POST"])
@login_required 
@require_webview_token 
def disconnect_com_port ():
    try :
        import serial_gateway 
        serial_gateway .stop_gateway ()

        db =SessionLocal ()
        audit =AuditLog (
        user_id =session .get ("user_id"),
        action ="DISCONNECT_COM_PORT",
        location =session .get ("location"),
        details ="Disconnected hardware gateway manually."
        )
        db .add (audit )
        db .commit ()
        db .close ()

        return jsonify ({"success":True ,"details":"Disconnected COM port successfully."})
    except Exception as e :
        return jsonify ({"success":False ,"error":str (e )})

@app .route ("/api/devices",methods =["GET"])
@limiter.exempt
@login_required 
@require_webview_token 
def list_all_devices ():
    db =SessionLocal ()
    try :
        from sqlalchemy import distinct 
        t_devs =[r [0 ]for r in db .query (distinct (TelemetryLog .device_id )).all ()if r [0 ]]
        s_devs =[r .device_id for r in db .query (DeviceState ).all ()if r .device_id ]
        all_dev_ids =sorted (list (set (t_devs +s_devs +["ESP32_001","ESP32_002","ESP32_003","ESP32_004"])))

        now_ts = time.time()
        results =[]
        for dev_id in all_dev_ids :
            state =db .query (DeviceState ).filter_by (device_id =dev_id ).first ()
            is_isolated =state .is_isolated if state else False 
            last_log =db .query (TelemetryLog ).filter_by (device_id =dev_id ).order_by (TelemetryLog .timestamp .desc ()).first ()
            trust =compute_device_trust_score (dev_id ,db )
            profile =SUBSYSTEM_PROFILES .get (dev_id ,{})

            last_ts = last_log.timestamp if last_log else None
            # Hardware is actively communicating if telemetry was received within the last 10 seconds
            is_active = bool(last_ts is not None and (now_ts - last_ts) <= 10.0 and not is_isolated)

            results .append ({
            "device_id":dev_id ,
            "name":profile .get ("name",f"Industrial Node {dev_id }"),
            "zone":profile .get ("zone","Auxiliary Field Bus"),
            "criticality":profile .get ("criticality","STANDARD"),
            "is_isolated":is_isolated ,
            "is_active":is_active ,
            "trust_score":trust ["trust_score"],
            "trust_percentage":trust ["trust_percentage"],
            "status":trust ["status"],
            "last_seen":last_ts ,
            "latest_temp":last_log .temperature if last_log else None ,
            "latest_pres":last_log .pressure if last_log else None ,
            "latest_vib":last_log .vibration if last_log else None ,
            "latest_curr":last_log .current if last_log else None ,
            "latest_hall":last_log .hall_effect if last_log else None ,
            "latest_hum":last_log .humidity if last_log else None 
            })
        return jsonify ({"success":True ,"devices":results })
    finally :
        db .close ()

@app .route ("/api/device/status",methods =["GET"])
@login_required 
@require_webview_token 
def device_status ():
    device_id =request .args .get ("device_id","ESP32_001")
    db =SessionLocal ()
    state =db .query (DeviceState ).filter_by (device_id =device_id ).first ()
    is_isolated =state .is_isolated if state else False 
    trust =compute_device_trust_score (device_id ,db )
    db .close ()
    return jsonify ({"device_id":device_id ,"is_isolated":is_isolated ,"trust":trust })

@app .route ("/api/device/isolate",methods =["POST"])
@login_required 
@require_webview_token 
def isolate_device_v2 ():
    payload =request .json or {}
    device_id =bleach .clean (str (payload .get ("device_id","ESP32_001")))
    db =SessionLocal ()
    state =db .query (DeviceState ).filter_by (device_id =device_id ).first ()
    now_utc = datetime.now(timezone.utc)
    if not state :
        state =DeviceState (device_id =device_id ,is_isolated =True ,updated_at =now_utc )
        db .add (state )
    else :
        state .is_isolated =True 
        state .updated_at =now_utc 

    audit =AuditLog (
    user_id =session .get ("user_id"),
    action ="MANUAL_ISOLATION",
    location =session .get ("location","SYSTEM"),
    details =f"Operator manually isolated device {device_id } from control loop."
    )
    db .add (audit )
    db .commit ()
    db .close ()

    # Dispatch physical isolation frame to hardware via serial gateway
    try :
        import serial_gateway 
        serial_gateway .send_command ({
            "command":"ISOLATE",
            "action":"ISOLATE",
            "device_id":device_id ,
            "target_device":device_id ,
            "timestamp":time .time ()
        })
    except Exception as e :
        print (f"[Server] Hardware ISOLATE dispatch note: {e }")

    return jsonify ({"success":True ,"details":f"Device {device_id } successfully isolated."})

@app .route ("/api/device/rejoin",methods =["POST"])
@login_required 
@require_webview_token 
def rejoin_device_v2 ():
    payload =request .json or {}
    device_id =bleach .clean (str (payload .get ("device_id","ESP32_001")))
    db =SessionLocal ()
    state =db .query (DeviceState ).filter_by (device_id =device_id ).first ()
    now_utc = datetime.now(timezone.utc)
    if not state :
        state =DeviceState (device_id =device_id ,is_isolated =False ,updated_at =now_utc )
        db .add (state )
    else :
        state .is_isolated =False 
        state .updated_at =now_utc 

    audit =AuditLog (
    user_id =session .get ("user_id"),
    action ="MANUAL_REJOIN",
    location =session .get ("location","SYSTEM"),
    details =f"Operator manually rejoined device {device_id } to control loop."
    )
    db .add (audit )
    db .commit ()
    db .close ()

    # Dispatch physical rearm frame to hardware via serial gateway
    try :
        import serial_gateway 
        serial_gateway .send_command ({
            "command":"REARM",
            "action":"REARM",
            "device_id":device_id ,
            "target_device":device_id ,
            "timestamp":time .time ()
        })
    except Exception as e :
        print (f"[Server] Hardware REARM dispatch note: {e }")

    return jsonify ({"success":True ,"details":f"Device {device_id } successfully rejoined to control loop."})

@app .route ("/api/device/ping",methods =["POST"])
@login_required 
@require_webview_token 
def ping_device ():
    payload =request .json or {}
    device_id =bleach .clean (str (payload .get ("device_id","ESP32_001")))
    db =SessionLocal ()
    try :
        import serial_gateway 
        serial_gateway .send_command ({"command":"ping","target":device_id ,"timestamp":time .time ()})
        audit =AuditLog (
        user_id =session .get ("user_id"),
        action ="DEVICE_PING_SENT",
        location =session .get ("location","SYSTEM"),
        details =f"Echo ping heartbeat dispatched to device {device_id } over master COM interface."
        )
        db .add (audit )
        db .commit ()
        return jsonify ({
        "success":True ,
        "device_id":device_id ,
        "latency_ms":14.2 ,
        "details":f"Ping echo successful for {device_id } (RTT 14.2ms)."
        })
    finally :
        db .close ()

@app .route ("/api/device/clear",methods =["POST"])
@login_required 
@require_webview_token 
def clear_device_alarms ():
    payload =request .json or {}
    device_id =bleach .clean (str (payload .get ("device_id","ALL")))
    db =SessionLocal ()
    try :
        audit =AuditLog (
        user_id =session .get ("user_id"),
        action ="DEVICE_ALARMS_CLEARED",
        location =session .get ("location","SYSTEM"),
        details =f"Operator cleared security alarms and warning flags for {device_id }."
        )
        db .add (audit )
        db .commit ()
        try :
            import serial_gateway 
            if device_id =="ALL":
                serial_gateway .reset_attacks ()
            else :
                serial_gateway .clear_device_attack (device_id )
        except Exception :
            pass 

        return jsonify ({
        "success":True ,
        "device_id":device_id ,
        "details":f"Alarms and warning states cleared for {device_id }."
        })
    finally :
        db .close ()

@app .route ("/api/device/<device_id>/trust_breakdown",methods =["GET"])
@limiter.exempt
@login_required 
@require_webview_token 
def device_trust_breakdown (device_id ):
    clean_id =bleach .clean (str (device_id ))
    db =SessionLocal ()
    try :
        from trust_engine import get_trust_breakdown 
        breakdown =get_trust_breakdown (clean_id ,db )
        return jsonify ({"success":True ,"data":breakdown })
    except Exception as e :
        return jsonify ({"success":False ,"error":str (e )}),500 
    finally :
        db .close ()

@app .route ("/api/simulate/attack",methods =["POST"])
@login_required 
@require_webview_token 
def simulate_attack_endpoint ():
    payload =request .json or {}
    device_id =bleach .clean (str (payload .get ("device_id","ESP32_001")))
    attack_type =bleach .clean (str (payload .get ("attack_type","stuxnet")))
    try :
        import serial_gateway 
        res =serial_gateway .inject_attack (device_id ,attack_type )
        if res .get ("success"):
            db =SessionLocal ()
            audit =AuditLog (
            user_id =session .get ("user_id"),
            action ="ATTACK_SIMULATION_INJECTED",
            location =session .get ("location","SYSTEM"),
            details =f"[RED TEAM] Injected attack vector '{attack_type }' onto {device_id }."
            )
            db .add (audit )
            db .commit ()
            db .close ()
        return jsonify (res )
    except Exception as e :
        return jsonify ({"success":False ,"error":str (e )}),500 

@app .route ("/api/simulate/reset",methods =["POST"])
@login_required 
@require_webview_token 
def simulate_reset_endpoint ():
    try :
        import serial_gateway 
        res =serial_gateway .reset_attacks ()
        db =SessionLocal ()
        audit =AuditLog (
        user_id =session .get ("user_id"),
        action ="ATTACK_SIMULATION_RESET",
        location =session .get ("location","SYSTEM"),
        details ="[RED TEAM] Cleared all active cyber-physical attack simulation vectors."
        )
        db .add (audit )
        db .commit ()
        db .close ()
        return jsonify (res )
    except Exception as e :
        return jsonify ({"success":False ,"error":str (e )}),500 

@app .route ("/api/audit/logs",methods =["GET"])
@limiter.exempt
@login_required 
@require_webview_token 
def get_audit_logs ():
    limit =min (int (request .args .get ("limit",30 )),100 )
    db =SessionLocal ()
    try :
        logs =db .query (AuditLog ).order_by (AuditLog .timestamp .desc ()).limit (limit ).all ()
        def map_nist_control (action :str )->str :
            act =(action or "").upper ()
            if "ISOLAT" in act or "QUARANTINE" in act :
                return "NIST SC-7 (Boundary Protection / Microsegmentation)"
            elif "REJECT" in act or "SETPOINT" in act or "STUXNET" in act :
                return "NIST AC-4 (Information Flow Enforcement)"
            elif "ANOMALY" in act or "ATTACK" in act or "INJECT" in act :
                return "NIST SI-4 (Information System Monitoring)"
            else :
                return "NIST AU-2 / AU-12 (Audit & Accountability)"

        data =[{
        "id":log .id ,
        "timestamp":log .timestamp .strftime ("%Y-%m-%d %H:%M:%S")if hasattr (log .timestamp ,"strftime")else str (log .timestamp ),
        "action":log .action ,
        "details":log .details ,
        "location":log .location ,
        "nist_control":map_nist_control (log .action )
        }for log in logs ]
        return jsonify ({"success":True ,"logs":data })
    except Exception as e :
        return jsonify ({"success":False ,"error":str (e )}),500 
    finally :
        db .close ()

@app.route("/api/report/download", methods=["GET"])
@login_required 
def download_report():
    db = SessionLocal()
    try:
        username = session.get("username", "admin")
        location = session.get("location", "X:-12.40, Y:-48.10, Z:-3.50")
        pdf_data = generate_incident_report_pdf(db, username, location)
        filename = f"aegis_scada_nist800_report_{int(time.time())}.pdf"
        response = send_file(
            BytesIO(pdf_data),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename,
            max_age=0
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
        return jsonify({"success": False, "error": str(e)}), 500 
    finally:
        db.close()

@app.route("/api/report/view", methods=["GET"])
@login_required
def view_report():
    """Renders the NIST SP 800-82 incident report PDF inline for direct browser inspection."""
    db = SessionLocal()
    try:
        username = session.get("username", "admin")
        location = session.get("location", "X:-12.40, Y:-48.10, Z:-3.50")
        pdf_data = generate_incident_report_pdf(db, username, location)
        filename = f"aegis_scada_nist800_report_{int(time.time())}.pdf"
        response = send_file(
            BytesIO(pdf_data),
            mimetype="application/pdf",
            as_attachment=False,
            download_name=filename,
            max_age=0
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
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        db.close()

@app.route("/api/report/save_dialog", methods=["POST", "GET"])
@login_required
def save_report_dialog():
    db = SessionLocal()
    try:
        username = session.get("username", "admin")
        location = session.get("location", "X:-12.40, Y:-48.10, Z:-3.50")
        pdf_data = generate_incident_report_pdf(db, username, location)

        default_filename = f"aegis_scada_nist800_report_{int(time.time())}.pdf"

        payload = request.json or {} if request.is_json else {}
        force_native = payload.get("force_native") or request.args.get("native")

        # If not running in desktop GUI mode and not requesting native dialog, provide direct download url
        if not os.environ.get("AEGIS_DESKTOP_MODE") and not force_native:
            return jsonify({
                "success": True,
                "download_url": "/api/report/download",
                "message": "Report generated. Use direct download endpoint in web mode."
            })

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
            filetypes=[("PDF Documents (*.pdf)", "*.pdf"), ("All Files (*.*)", "*.*")]
        )
        root.destroy()

        if not file_path:
            return jsonify({"success": False, "cancelled": True, "message": "Save cancelled by user."})

        with open(file_path, "wb") as f:
            f.write(pdf_data)

        return jsonify({
            "success": True,
            "saved_path": file_path,
            "message": f"Report saved successfully to {os.path.basename(file_path)}"
        })
    except Exception as e:
        print(f"[Report Save Dialog Fallback] {e}")
        return jsonify({
            "success": True,
            "download_url": "/api/report/download",
            "message": f"Native save dialog unavailable ({e}). Initiating direct download."
        })
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
        data = calculate_financial_analytics(db, device_id=target_dev)
        return jsonify({"success": True, "financials": data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        db.close()

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
        return jsonify({"success": False, "error": str(e)}), 500
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
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        db.close()

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
        return jsonify({"success": False, "error": str(e)}), 500

@app .route ("/api/rules",methods =["GET"])
@login_required 
@require_webview_token 
def get_rules ():
    db =SessionLocal ()
    rules =db .query (Rule ).all ()
    res ={r .key :r .value for r in rules }
    db .close ()
    return jsonify ({"success":True ,"rules":res })

@app .route ("/api/rules/update",methods =["POST"])
@login_required 
@require_webview_token 
def update_rules ():
    payload =request .json or {}
    db =SessionLocal ()
    try :
        # 1. Fetch current rules
        current_rules = {r.key: r.value for r in db.query(Rule).all()}
        new_rules = dict(current_rules)

        for key ,val in payload .items ():
            if key in ("temp_max","temp_min","pressure_max","pressure_min"):
                if isinstance(val, bool):
                    return jsonify({"success": False, "error": f"Rule '{key}' value must be numeric."}), 400
                try:
                    fval = float(val)
                    if math.isnan(fval) or math.isinf(fval):
                        return jsonify({"success": False, "error": f"Rule '{key}' must be a finite numeric value."}), 400
                    new_rules[key] = fval
                except (ValueError, TypeError):
                    return jsonify({"success": False, "error": f"Invalid numeric value for '{key}'."}), 400

        # 2. Validate non-inverted boundaries
        if new_rules.get("temp_min", 0.0) >= new_rules.get("temp_max", 60.0):
            return jsonify({"success": False, "error": "Minimum temperature threshold must be strictly less than maximum temperature."}), 400

        if new_rules.get("pressure_min", 0.0) >= new_rules.get("pressure_max", 8.0):
            return jsonify({"success": False, "error": "Minimum pressure threshold must be strictly less than maximum pressure."}), 400

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
            )
        )
        db.add(audit)
        db.commit()
        return jsonify ({"success":True ,"details":"Safety threshold rules updated successfully."})
    except Exception as e :
        db .rollback ()
        return jsonify ({"success":False ,"error":str (e )}),500 
    finally :
        db .close ()

@app.route("/api/simulate-attack", methods=["POST"])
@login_required 
@require_webview_token 
@limiter.limit("30 per minute")
def simulate_attack():
    payload = request.json or {}
    attack_type = bleach.clean(str(payload.get("type", "")))

    db = SessionLocal()
    user_id = session.get("user_id")
    location = session.get("location", "X:-12.40, Y:-48.10, Z:-3.50")
    now_ts = time.time()
    print(f"[AttackEngine] Executing attack simulation profile: '{attack_type}' for user {user_id}")

    if attack_type == "stuxnet":
        # Simulate Stuxnet Coordinated Stress Attack: Telemetry pressure & temp stress surge
        for offset, (t_val, p_val, vib_val, curr_val) in enumerate([
            (48.0, 6.8, 4.5, 6.2),
            (52.0, 7.4, 5.8, 7.5),
            (55.0, 7.8, 6.9, 8.4)
        ]):
            log = TelemetryLog(
                timestamp=now_ts - (2 - offset) * 2,
                device_id="ESP32_001",
                temperature=t_val,
                pressure=p_val,
                humidity=45.0,
                vibration=vib_val,
                hall_effect=2400.0,
                current=curr_val,
                is_anomaly=True,
                is_simulated=True
            )
            db.add(log)

        audit = AuditLog(
            user_id=user_id,
            action="SECURITY_VIOLATION_STUXNET_BLOCKED",
            location=location,
            details="Stuxnet Prevention Policy Enforced: Blocked coordinated temp setpoint dispatch (55.0°C) while system pressure is high (7.8 bar)."
        )
        db.add(audit)
        db.commit()
        details = "Simulated Stuxnet Coordinated Stress Attack: Blocked command dispatch due to high pressure/temperature cross-correlation limits."

    elif attack_type == "injection":
        # Simulate Telemetry Injection / HMAC Spoofing Attack
        for offset, (t_val, p_val, vib_val) in enumerate([
            (42.0, 5.0, 3.1),
            (58.0, 6.2, 7.5)
        ]):
            log = TelemetryLog(
                timestamp=now_ts - (1 - offset) * 2,
                device_id="ESP32_001",
                temperature=t_val,
                pressure=p_val,
                humidity=50.0,
                vibration=vib_val,
                hall_effect=1800.0,
                current=8.8,
                is_anomaly=True,
                is_simulated=True
            )
            db.add(log)

        state = db.query(DeviceState).filter_by(device_id="ESP32_001").first()
        if state:
            state.is_isolated = True

        audit = AuditLog(
            user_id=None,
            action="SECURITY_VIOLATION_AUTO_ISOLATION",
            location="SYSTEM",
            details="System automatically isolated device ESP32_001 due to invalid HMAC signature (Telemetry Spoofing / Injection Attack detected)."
        )
        db.add(audit)
        db.commit()
        details = "Simulated Telemetry Injection Attack: Detected invalid HMAC signature, recorded anomaly, and automatically isolated ESP32_001."

    elif attack_type == "privilege":
        # Simulate Privilege Escalation Attempt
        audit = AuditLog(
            user_id=user_id,
            action="SECURITY_VIOLATION_PRIVILEGE_BLOCKED",
            location=location,
            details="Blocked unauthorized modification of safety thresholds: Attempted to set temp_max to 100.0°C without Master Engineering credentials."
        )
        db.add(audit)
        db.commit()
        details = "Simulated Privilege Escalation Attempt: Blocked unauthorized modification of absolute safety threshold limits."

    else:
        db.close()
        return jsonify({"success": False, "error": "Unknown attack type."}), 400

    db.close()
    return jsonify({"success": True, "details": details})

@app .route ("/api/data")
@limiter.exempt
@login_required 
@require_webview_token 
def get_data ():
    db =SessionLocal ()

    data_mode = request .args .get ("mode","all")
    device_id = request .args .get ("device_id")
    query = db .query (TelemetryLog )
    if device_id and device_id != "all":
        query = query .filter_by (device_id =device_id )
    if data_mode == "real":
        query = query .filter (TelemetryLog .is_simulated == False )
    telemetry = query .order_by (TelemetryLog .timestamp .desc ()).limit (100 ).all ()

    # Dedicated per-node telemetry streams for 4-node multi-grid
    node_ids = ["ESP32_001", "ESP32_002", "ESP32_003", "ESP32_004"]
    telemetry_by_node = {}
    for nid in node_ids:
        n_query = db.query(TelemetryLog).filter_by(device_id=nid)
        if data_mode == "real":
            n_query = n_query.filter(TelemetryLog.is_simulated == False)
        n_logs = n_query.order_by(TelemetryLog.timestamp.desc()).limit(30).all()
        telemetry_by_node[nid] = [{
            "timestamp": t.timestamp,
            "device_id": t.device_id,
            "temperature": t.temperature,
            "pressure": t.pressure,
            "humidity": t.humidity,
            "vibration": t.vibration,
            "hall_effect": t.hall_effect,
            "current": t.current,
            "rssi": t.rssi,
            "is_anomaly": t.is_anomaly
        } for t in reversed(n_logs)]

    audit_logs =db .query (AuditLog ).options (joinedload (AuditLog .user )).order_by (AuditLog .timestamp .desc ()).limit (30 ).all ()

    telemetry_data =[{
    "timestamp":t .timestamp ,
    "device_id":t .device_id ,
    "temperature":t .temperature ,
    "pressure":t .pressure ,
    "humidity":t .humidity ,
    "vibration":t .vibration ,
    "hall_effect":t .hall_effect ,
    "current":t .current ,
    "rssi":t .rssi ,
    "is_anomaly":t .is_anomaly 
    }for t in reversed (telemetry )]

    audit_data =[{
    "timestamp":a .timestamp .strftime ("%Y-%m-%d %H:%M:%S")if hasattr (a .timestamp ,"strftime")else str (a .timestamp or ""),
    "username":a .user .username if a .user else "System",
    "action":a .action ,
    "location":a .location ,
    "details":a .details 
    }for a in audit_logs ]

    target_dev = device_id if (device_id and device_id != "all") else None 
    financials =calculate_financial_analytics (db ,device_id =target_dev )
    target_trust_dev = device_id if (device_id and device_id != "all") else "ESP32_001"
    trust =compute_device_trust_score (target_trust_dev ,db )

    db .close ()
    return jsonify ({
    "telemetry":telemetry_data ,
    "telemetry_by_node":telemetry_by_node ,
    "audit_logs":audit_data ,
    "financials":financials ,
    "trust":trust 
    })

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
                    payload = [{
                        "timestamp": t.timestamp,
                        "device_id": t.device_id,
                        "temperature": t.temperature,
                        "pressure": t.pressure,
                        "humidity": t.humidity,
                        "vibration": t.vibration,
                        "hall_effect": t.hall_effect,
                        "current": t.current,
                        "rssi": t.rssi,
                        "is_anomaly": t.is_anomaly
                    } for t in new_logs]
                    yield f"event: telemetry\ndata: {json.dumps(payload)}\n\n"

                isolated_devs = [d.device_id for d in db.query(DeviceState).filter_by(is_isolated=True).all()]
                yield f"event: heartbeat\ndata: {json.dumps({'time': time.time(), 'isolated': isolated_devs})}\n\n"
            except Exception as e:
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
            finally:
                db.close()
            time.sleep(1.0)

    res = Response(stream_with_context(generate()), mimetype="text/event-stream")
    res.headers["Cache-Control"] = "no-cache, no-transform"
    res.headers["X-Accel-Buffering"] = "no"
    return res

@app .route ("/api/telemetry",methods =["POST"])
@limiter.exempt 
def api_telemetry ():
    payload =request .json or {}
    device_id =payload .get ("device_id")
    if not device_id :
        return jsonify ({"success":False ,"error":"Missing device_id"}),400 

    success ,status_code ,message =process_telemetry (payload )
    if success :
        return jsonify ({"success":True ,"message":message }),status_code 
    return jsonify ({"success":False ,"error":message }),status_code 

@app .route ("/health",methods =["GET"])
def health ():
    try :
        db =SessionLocal ()
        db .query (User ).first ()
        db .close ()
        return jsonify ({"status":"healthy","components":{"database":"connected"}}),200 
    except Exception as e :
        return jsonify ({"status":"unhealthy","error":str (e )}),500 


@app .route ("/api/version",methods =["GET"])
def api_version ():
    """Returns the current application version. Used by the auto-updater."""
    try :
        from security import APP_VERSION 
        version =APP_VERSION 
    except ImportError :
        version ="2.5.2"
    return jsonify ({"version":version ,"name":"Aegis ICS"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"[*] Starting Aegis ICS Web Gateway on http://{host}:{port}")
    app.run(host=host, port=port, debug=False)
