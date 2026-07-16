import time 
import json 
import threading 
from datetime import datetime ,timezone 
from flask import Flask ,render_template ,request ,jsonify ,redirect ,url_for ,session 
from werkzeug .security import check_password_hash 
import paho .mqtt .client as mqtt 

from database import init_db ,SessionLocal ,User ,AuditLog ,TelemetryLog ,Rule 
from safety_enforcer import validate_command 


init_db ()

app =Flask (__name__ )
app .secret_key ="aegis_v2_super_secret_key"

MQTT_HOST ="127.0.0.1"
MQTT_PORT =1883 
DEVICE_KEY ="device_key_001"


mqtt_client =mqtt .Client (callback_api_version =mqtt .CallbackAPIVersion .VERSION2 ,client_id ="aegis-server")

def on_connect (client ,userdata ,flags ,rc ,properties =None ):
    client .subscribe ("ics/telemetry/+")
    print ("[Server] Connected to MQTT Broker - Subscribed to telemetry")

def on_message (client ,userdata ,msg ):
    try :
        payload =json .loads (msg .payload .decode ())
    except Exception as e :
        print (f"[Server] Failed to decode telemetry: {e }")
        return 



    import hmac 
    import hashlib 

    def canonicalize (p ):
        canonical ={}
        for k ,v in p .items ():
            if k in ("temperature","pressure","humidity","rssi"):
                canonical [k ]=f"{float (v ):.2f}"
            elif k =="timestamp":
                canonical [k ]=f"{float (v ):.3f}"
            else :
                canonical [k ]=v 
        return canonical 

    sig =payload .get ("signature")
    body ={k :v for k ,v in payload .items ()if k !="signature"}
    canonical =json .dumps (canonical (body ),sort_keys =True ,separators =(",",":"))
    expected =hmac .new (DEVICE_KEY .encode ("utf-8"),canonical .encode ("utf-8"),hashlib .sha256 ).hexdigest ()

    sig_valid =hmac .compare_digest (expected ,str (sig ))if sig else False 


    db =SessionLocal ()
    try :
        log =TelemetryLog (
        timestamp =payload .get ("timestamp",time .time ()),
        device_id =payload .get ("device_id","unknown"),
        temperature =payload .get ("temperature",0.0 ),
        pressure =payload .get ("pressure",0.0 ),
        humidity =payload .get ("humidity",0.0 ),
        rssi =payload .get ("rssi",0.0 ),
        is_anomaly =not sig_valid 
        )
        db .add (log )
        db .commit ()
    except Exception as e :
        print (f"[Server] Database write failed: {e }")
    finally :
        db .close ()


def start_mqtt ():
    mqtt_client .on_connect =on_connect 
    mqtt_client .on_message =on_message 
    try :
        mqtt_client .connect (MQTT_HOST ,MQTT_PORT ,60 )
        mqtt_client .loop_start ()
    except Exception as e :
        print (f"[Server] WARNING: Could not connect to MQTT broker: {e }. Telemetry ingestion disabled.")

threading .Thread (target =start_mqtt ,daemon =True ).start ()


def login_required (f ):
    def decorator (*args ,**kwargs ):
        if "user_id"not in session :
            return redirect (url_for ("login"))
        return f (*args ,**kwargs )
    decorator .__name__ =f .__name__ 
    return decorator 


@app .route ("/")
@login_required 
def index ():
    return render_template ("dashboard.html",username =session .get ("username"),location =session .get ("location"))

@app .route ("/login",methods =["GET","POST"])
def login ():
    if request .method =="POST":
        username =request .form .get ("username")
        password =request .form .get ("password")
        coord_x =request .form .get ("coord_x","0.0")
        coord_y =request .form .get ("coord_y","0.0")
        coord_z =request .form .get ("coord_z","0.0")

        db =SessionLocal ()
        user =db .query (User ).filter_by (username =username ).first ()

        if user and check_password_hash (user .password_hash ,password ):
            session ["user_id"]=user .id 
            session ["username"]=user .username 
            location_str =f"X={coord_x }, Y={coord_y }, Z={coord_z }"
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
        return render_template ("login.html",error ="Invalid credentials.")

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
def setpoint ():
    payload =request .json or {}
    cmd_type =payload .get ("type")
    value =float (payload .get ("value",0 ))

    db =SessionLocal ()


    allowed ,reason =validate_command ({"type":cmd_type ,"value":value },db )

    user_id =session ["user_id"]
    location =session ["location"]

    if not allowed :

        audit =AuditLog (
        user_id =user_id ,
        action ="SECURITY_VIOLATION_BLOCKED",
        location =location ,
        details =f"Blocked attempt to set {cmd_type } to {value }. Reason: {reason }"
        )
        db .add (audit )
        db .commit ()
        db .close ()
        return jsonify ({"success":False ,"error":reason }),403 


    topic =f"ics/control/ESP32_001"
    command_payload =json .dumps ({"type":cmd_type ,"value":value })
    try :
        mqtt_client .publish (topic ,command_payload ,qos =1 )
        print (f"[Server] Dispatched control command: {cmd_type }={value }")
    except Exception as e :
        db .close ()
        return jsonify ({"success":False ,"error":f"Broker publish failed: {e }"}),500 


    audit =AuditLog (
    user_id =user_id ,
    action ="CHANGE_SETPOINT",
    location =location ,
    details =f"Changed {cmd_type } to {value }."
    )
    db .add (audit )
    db .commit ()
    db .close ()

    return jsonify ({"success":True ,"details":f"Successfully updated setpoint to {value }."})

@app .route ("/api/data")
@login_required 
def get_data ():
    db =SessionLocal ()

    telemetry =db .query (TelemetryLog ).order_by (TelemetryLog .timestamp .desc ()).limit (50 ).all ()

    audit_logs =db .query (AuditLog ).order_by (AuditLog .timestamp .desc ()).limit (30 ).all ()

    telemetry_data =[{
    "timestamp":t .timestamp ,
    "device_id":t .device_id ,
    "temperature":t .temperature ,
    "pressure":t .pressure ,
    "humidity":t .humidity ,
    "rssi":t .rssi ,
    "is_anomaly":t .is_anomaly 
    }for t in reversed (telemetry )]

    audit_data =[{
    "timestamp":a .timestamp .isoformat (),
    "username":db .query (User ).filter_by (id =a .user_id ).first ().username if a .user_id else "Unknown",
    "action":a .action ,
    "location":a .location ,
    "details":a .details 
    }for a in audit_logs ]

    db .close ()
    return jsonify ({"telemetry":telemetry_data ,"audit_logs":audit_data })

if __name__ =="__main__":
    app .run (host ="127.0.0.1",port =5000 ,debug =True )
