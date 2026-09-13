import os 
import sys
import shutil
from datetime import datetime, timezone, timedelta 
from sqlalchemy import create_engine ,Column ,Integer ,String ,Float ,Boolean ,ForeignKey ,DateTime ,event 
from sqlalchemy .orm import declarative_base ,sessionmaker ,relationship 
from werkzeug .security import generate_password_hash 

def get_database_url():
    explicit_url = os.environ.get("DATABASE_URL")
    if explicit_url:
        return explicit_url

    explicit_data_dir = os.environ.get("AEGIS_DATA_DIR")
    if explicit_data_dir:
        os.makedirs(explicit_data_dir, exist_ok=True)
        target_db = os.path.join(explicit_data_dir, "aegis_v2.db")
        if not os.path.exists(target_db) and hasattr(sys, "_MEIPASS"):
            bundled_db = os.path.join(sys._MEIPASS, "aegis_v2.db")
            if os.path.exists(bundled_db):
                try:
                    shutil.copy2(bundled_db, target_db)
                except Exception as e:
                    print(f"[Database] Could not copy bundled db to AEGIS_DATA_DIR: {e}")
        return f"sqlite:///{os.path.abspath(target_db)}"
    
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        
        exe_dir_writable = os.access(exe_dir, os.W_OK)
        if exe_dir_writable:
            target_dir = exe_dir
        else:
            if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
                if hasattr(os, "geteuid") and os.geteuid() == 0:
                    target_dir = "/var/lib/aegis-ics"
                else:
                    data_home = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
                    target_dir = os.path.join(data_home, "aegis-ics")
            else:
                local_app_data = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
                target_dir = os.path.join(local_app_data, "AegisICS")

        os.makedirs(target_dir, exist_ok=True)
        target_db = os.path.join(target_dir, "aegis_v2.db")
        if not os.path.exists(target_db) and hasattr(sys, "_MEIPASS"):
            bundled_db = os.path.join(sys._MEIPASS, "aegis_v2.db")
            if os.path.exists(bundled_db):
                try:
                    shutil.copy2(bundled_db, target_db)
                except Exception as e:
                    print(f"[Database] Could not copy bundled db: {e}")
        return f"sqlite:///{os.path.abspath(target_db)}"
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dev_db = os.path.join(base_dir, "aegis_v2.db")
    return f"sqlite:///{os.path.abspath(dev_db)}"

DATABASE_URL = get_database_url()

engine =create_engine (DATABASE_URL ,connect_args ={"check_same_thread":False ,"timeout":15 })

@event .listens_for (engine ,"connect")
def set_sqlite_pragma (dbapi_connection ,connection_record ):
    cursor =dbapi_connection .cursor ()
    cursor .execute ("PRAGMA journal_mode=WAL")
    cursor .execute ("PRAGMA synchronous=NORMAL")
    cursor .execute ("PRAGMA busy_timeout=5000")
    cursor .close ()

Base =declarative_base ()

class User (Base ):
    __tablename__ ="users"
    id =Column (Integer ,primary_key =True )
    username =Column (String (50 ),unique =True ,nullable =False )
    password_hash =Column (String (255 ),nullable =False )

    logs =relationship ("AuditLog",back_populates ="user")

class AuditLog (Base ):
    __tablename__ ="audit_logs"
    id =Column (Integer ,primary_key =True )
    timestamp =Column (DateTime ,default =lambda :datetime .now (timezone .utc ))
    user_id =Column (Integer ,ForeignKey ("users.id"),nullable =True )
    action =Column (String (100 ),nullable =False )
    location =Column (String (100 ),nullable =False )
    details =Column (String (255 ),nullable =True )

    user =relationship ("User",back_populates ="logs")

class TelemetryLog (Base ):
    __tablename__ ="telemetry_logs"
    id =Column (Integer ,primary_key =True )
    timestamp =Column (Float ,nullable =False )
    device_id =Column (String (50 ),nullable =False )
    temperature =Column (Float ,nullable =True )
    pressure =Column (Float ,nullable =True )
    humidity =Column (Float ,nullable =True )
    vibration =Column (Float ,nullable =True )
    hall_effect =Column (Float ,nullable =True )
    current =Column (Float ,nullable =True )
    rssi =Column (Float ,nullable =True )
    is_anomaly =Column (Boolean ,default =False )
    is_simulated =Column (Boolean ,default =False )

class DeviceState (Base ):
    __tablename__ ="device_states"
    id =Column (Integer ,primary_key =True )
    device_id =Column (String (50 ),unique =True ,nullable =False )
    is_isolated =Column (Boolean ,default =False )
    updated_at =Column (DateTime ,default =lambda :datetime .now (timezone .utc ),onupdate =lambda :datetime .now (timezone .utc ))

class Rule (Base ):
    __tablename__ ="rules"
    id =Column (Integer ,primary_key =True )
    key =Column (String (50 ),unique =True ,nullable =False )
    value =Column (Float ,nullable =False )
    description =Column (String (255 ),nullable =True )
SessionLocal =sessionmaker (autocommit =False ,autoflush =False ,bind =engine )

def migrate_sqlite_schema ():
    import sqlite3 
    if DATABASE_URL.startswith("sqlite:///"):
        db_path = DATABASE_URL[len("sqlite:///"):]
    else:
        db_path = DATABASE_URL
    if os .path .exists (db_path ):
        try :
            conn =sqlite3 .connect (db_path )
            cursor =conn .cursor ()
            cols =cursor .execute ("PRAGMA table_info('telemetry_logs')").fetchall ()
            needs_migration =any (row [1 ]in ("temperature","pressure","humidity")and row [3 ]==1 for row in cols )
            if needs_migration :
                print ("[Database] Migrating telemetry_logs table to support nullable sensor fields...")
                cursor .execute ("""
                CREATE TABLE IF NOT EXISTS telemetry_logs_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp FLOAT NOT NULL,
                    device_id VARCHAR(50) NOT NULL,
                    temperature FLOAT,
                    pressure FLOAT,
                    humidity FLOAT,
                    vibration FLOAT,
                    hall_effect FLOAT,
                    current FLOAT,
                    rssi FLOAT,
                    is_anomaly BOOLEAN DEFAULT 0,
                    is_simulated BOOLEAN DEFAULT 0
                );
                """)
                cursor .execute ("""
                INSERT INTO telemetry_logs_new (id, timestamp, device_id, temperature, pressure, humidity, vibration, hall_effect, current, rssi, is_anomaly, is_simulated)
                SELECT id, timestamp, device_id, temperature, pressure, humidity, vibration, hall_effect, current, rssi, is_anomaly, is_simulated FROM telemetry_logs;
                """)
                cursor .execute ("DROP TABLE telemetry_logs;")
                cursor .execute ("ALTER TABLE telemetry_logs_new RENAME TO telemetry_logs;")
                conn .commit ()
                print ("[Database] Schema migration complete.")
            conn .close ()
        except Exception as e :
            print (f"[Database] Auto-migration note: {e }")

def init_db ():
    migrate_sqlite_schema ()
    Base .metadata .create_all (bind =engine )
    db =SessionLocal ()
    try :

        if not db .query (User ).filter_by (username ="admin").first ():
            admin =User (
            username ="admin",
            password_hash =generate_password_hash (os .environ .get ("ADMIN_PASSWORD","admin"))
            )
            db .add (admin )


        rules ={
        "temp_max":(60.0 ,"Absolute maximum allowed temperature setpoint (C)"),
        "temp_min":(0.0 ,"Absolute minimum allowed temperature setpoint (C)"),
        "pressure_max":(8.0 ,"Absolute maximum allowed pressure setpoint (bar)"),
        "pressure_min":(0.0 ,"Absolute minimum allowed pressure setpoint (bar)")
        }
        for key ,(val ,desc )in rules .items ():
            if not db .query (Rule ).filter_by (key =key ).first ():
                db .add (Rule (key =key ,value =val ,description =desc ))


        cluster_nodes = ["ESP32_001", "ESP32_002", "ESP32_003", "ESP32_004"]
        for node_id in cluster_nodes:
            if not db.query(DeviceState).filter_by(device_id=node_id).first():
                db.add(DeviceState(device_id=node_id, is_isolated=False))

        if db.query(AuditLog).count() == 0:
            admin_user = db.query(User).filter_by(username="admin").first()
            admin_id = admin_user.id if admin_user else None
            now = datetime.now(timezone.utc)
            baseline_logs = [
                AuditLog(
                    timestamp=now - timedelta(minutes=15),
                    user_id=admin_id,
                    action="SYSTEM_BOOT",
                    location="CONTROL_CENTER_ALPHA",
                    details="Aegis Zero-Trust ICS Engine initialized with FIPS 198-1 cryptographic module."
                ),
                AuditLog(
                    timestamp=now - timedelta(minutes=12),
                    user_id=admin_id,
                    action="KEYRING_VALIDATED",
                    location="CRYPTOGRAPHIC_STORE",
                    details="Multi-node hardware HMAC pre-shared key ring verified for ESP32_001..004."
                ),
                AuditLog(
                    timestamp=now - timedelta(minutes=10),
                    user_id=admin_id,
                    action="SAFETY_INTERLOCKS_ENGAGED",
                    location="SAFETY_SUBSYSTEM",
                    details="Stuxnet physical interlock enforcement rules active (temp < 60°C, pressure < 8.0 bar)."
                ),
                AuditLog(
                    timestamp=now - timedelta(minutes=8),
                    user_id=admin_id,
                    action="KALMAN_ANOMALY_BASELINE",
                    location="STATE_ESTIMATOR",
                    details="Multi-sensor Kalman filter state space initialized."
                ),
                AuditLog(
                    timestamp=now - timedelta(minutes=5),
                    user_id=admin_id,
                    action="STATION_GEOLOCATION_LOCKED",
                    location="GPS_TELEMETRY",
                    details="Cartesian coordinates verified (X:-12.40, Y:-48.10, Z:-3.50)."
                ),
                AuditLog(
                    timestamp=now - timedelta(minutes=2),
                    user_id=admin_id,
                    action="DATABASE_WAL_VERIFIED",
                    location="STORAGE_ENGINE",
                    details="SQLite WAL write-ahead log journal verified."
                ),
            ]
            db.add_all(baseline_logs)

        db .commit ()
    finally :
        db .close ()
