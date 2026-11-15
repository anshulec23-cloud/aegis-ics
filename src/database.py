import os
import sys
from datetime import datetime, timezone
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    Boolean,
    ForeignKey,
    Text,
    DateTime,
    event,
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from werkzeug.security import generate_password_hash


def _default_data_dir() -> str:
    """Writable per-installation directory for the database, host identity, session key,
    setup token and retrained models.

    Precedence: ``AEGIS_DATA_DIR`` > frozen app (per-user/system data dir, or next to the
    executable when a file named ``aegis_portable`` sits beside it) > repository root (dev).
    The PyInstaller bundle directory (``sys._MEIPASS``) is temporary and never used for data.
    """
    explicit = os.environ.get("AEGIS_DATA_DIR")
    if explicit:
        return os.path.abspath(explicit)
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        if os.path.exists(os.path.join(exe_dir, "aegis_portable")):
            return exe_dir
        if sys.platform.startswith(("linux", "darwin")):
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                return "/var/lib/aegis-ics"
            data_home = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
            return os.path.join(data_home, "aegis-ics")
        local_app_data = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(local_app_data, "AegisICS")
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_database_url():
    explicit_url = os.environ.get("DATABASE_URL")
    if explicit_url:
        return explicit_url
    data_dir = _default_data_dir()
    os.makedirs(data_dir, exist_ok=True)
    return f"sqlite:///{os.path.join(data_dir, 'aegis_v2.db')}"


DATABASE_URL = get_database_url()


def _data_dir_for(url: str) -> str:
    if url.startswith("sqlite:///"):
        return os.path.dirname(os.path.abspath(url[len("sqlite:///") :]))
    return _default_data_dir()


# Directory holding all mutable state of this installation (see _default_data_dir).
DATA_DIR = _data_dir_for(DATABASE_URL)
os.makedirs(DATA_DIR, exist_ok=True)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False, "timeout": 15})


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

    logs = relationship("AuditLog", back_populates="user")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    location = Column(String(100), nullable=False)
    details = Column(String(255), nullable=True)
    # True for entries written by red-team drills / simulations. Reports and risk
    # analytics exclude them; the dashboard shows them with a SIMULATED badge.
    is_simulated = Column(Boolean, default=False, nullable=False)

    user = relationship("User", back_populates="logs")


class TelemetryLog(Base):
    __tablename__ = "telemetry_logs"
    id = Column(Integer, primary_key=True)
    timestamp = Column(Float, nullable=False)
    device_id = Column(String(50), nullable=False)
    temperature = Column(Float, nullable=True)
    pressure = Column(Float, nullable=True)
    humidity = Column(Float, nullable=True)
    vibration = Column(Float, nullable=True)
    hall_effect = Column(Float, nullable=True)
    current = Column(Float, nullable=True)
    rssi = Column(Float, nullable=True)
    is_anomaly = Column(Boolean, default=False)
    is_simulated = Column(Boolean, default=False)
    # Comma-separated sensor faults reported by the device (protocol v1), e.g. "temperature".
    faults = Column(String(120), nullable=True)


class DeviceState(Base):
    __tablename__ = "device_states"
    id = Column(Integer, primary_key=True)
    device_id = Column(String(50), unique=True, nullable=False)
    is_isolated = Column(Boolean, default=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class Device(Base):
    """Registry of field devices discovered on the bus (ADR 0006).

    status: ``pending`` (announced, awaiting operator approval) -> ``approved`` (key derived,
    telemetry accepted) -> ``revoked``. Devices provisioned the legacy way (env / key file,
    protocol v0) do not need a row here.
    """

    __tablename__ = "devices"
    id = Column(Integer, primary_key=True)
    device_id = Column(String(50), unique=True, nullable=False)
    name = Column(String(80), nullable=True)
    status = Column(String(16), nullable=False, default="pending")
    public_key = Column(String(64), nullable=True)
    fingerprint = Column(String(20), nullable=True)
    hmac_key = Column(String(64), nullable=True)
    firmware = Column(String(32), nullable=True)
    sensors = Column(Text, nullable=True)  # JSON list
    protocol = Column(Integer, nullable=False, default=1)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, nullable=True)
    approved_at = Column(DateTime, nullable=True)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    enrollment_confirmed = Column(Boolean, nullable=False, default=False)
    relay_tripped = Column(Boolean, nullable=True)
    # Replay protection state (device -> host): current boot id, last sequence, recent boots.
    last_boot = Column(Integer, nullable=True)
    last_seq = Column(Integer, nullable=True)
    seen_boots = Column(Text, nullable=True)  # JSON list of recent boot ids
    # Host -> device command sequence (monotonic per device; the device rejects <= last seen).
    host_seq = Column(Integer, nullable=False, default=0)


class CommandLog(Base):
    """Lifecycle of every command sent to a protocol-v1 device."""

    __tablename__ = "command_log"
    id = Column(Integer, primary_key=True)
    device_id = Column(String(50), nullable=False)
    seq = Column(Integer, nullable=False)
    command = Column(String(16), nullable=False)
    args = Column(Text, nullable=True)
    status = Column(
        String(12), nullable=False, default="QUEUED"
    )  # QUEUED/SENT/ACKED/REJECTED/EXPIRED/FAILED
    result = Column(String(120), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    sent_at = Column(DateTime, nullable=True)
    acked_at = Column(DateTime, nullable=True)


class Rule(Base):
    __tablename__ = "rules"
    id = Column(Integer, primary_key=True)
    key = Column(String(50), unique=True, nullable=False)
    value = Column(Float, nullable=False)
    description = Column(String(255), nullable=True)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def to_utc_epoch(dt) -> float:
    """Epoch seconds for a DateTime read back from SQLite.

    SQLite drops tzinfo, so naive values are UTC by construction (they are written with
    ``datetime.now(timezone.utc)``). Calling ``.timestamp()`` on them directly would
    interpret them as local time (debug report F9).
    """
    if dt is None:
        return 0.0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def migrate_sqlite_schema():
    import sqlite3

    if DATABASE_URL.startswith("sqlite:///"):
        db_path = DATABASE_URL[len("sqlite:///") :]
    else:
        db_path = DATABASE_URL
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cols = cursor.execute("PRAGMA table_info('telemetry_logs')").fetchall()
            needs_migration = any(
                row[1] in ("temperature", "pressure", "humidity") and row[3] == 1 for row in cols
            )
            tel_cols = [
                row[1] for row in cursor.execute("PRAGMA table_info('telemetry_logs')").fetchall()
            ]
            if tel_cols and "faults" not in tel_cols:
                cursor.execute("ALTER TABLE telemetry_logs ADD COLUMN faults VARCHAR(120)")
                conn.commit()
            audit_cols = [
                row[1] for row in cursor.execute("PRAGMA table_info('audit_logs')").fetchall()
            ]
            if audit_cols and "is_simulated" not in audit_cols:
                print("[Database] Adding audit_logs.is_simulated column...")
                cursor.execute(
                    "ALTER TABLE audit_logs ADD COLUMN is_simulated BOOLEAN NOT NULL DEFAULT 0"
                )
                conn.commit()
            if needs_migration:
                print(
                    "[Database] Migrating telemetry_logs table to support nullable sensor fields..."
                )
                cursor.execute("""
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
                cursor.execute("""
                INSERT INTO telemetry_logs_new (id, timestamp, device_id, temperature, pressure, humidity, vibration, hall_effect, current, rssi, is_anomaly, is_simulated)
                SELECT id, timestamp, device_id, temperature, pressure, humidity, vibration, hall_effect, current, rssi, is_anomaly, is_simulated FROM telemetry_logs;
                """)
                cursor.execute("DROP TABLE telemetry_logs;")
                cursor.execute("ALTER TABLE telemetry_logs_new RENAME TO telemetry_logs;")
                conn.commit()
                print("[Database] Schema migration complete.")
            conn.close()
        except Exception as e:
            print(f"[Database] Auto-migration note: {e}")


def _bootstrap_accounts(db) -> list:
    """Create or repair operator accounts. Returns audit messages describing what changed.

    See ``bootstrap.py``: no default password ever exists. Without a valid
    ``ADMIN_PASSWORD`` the admin account stays locked until the first-run setup page is used.
    """
    from werkzeug.security import check_password_hash

    from bootstrap import LEGACY_DEFAULT_PASSWORD, configured_admin_password, locked_password_hash

    events = []
    configured = configured_admin_password()
    admin = db.query(User).filter_by(username="admin").first()

    if admin is None:
        if configured:
            db.add(User(username="admin", password_hash=generate_password_hash(configured)))
            events.append("Created 'admin' account from ADMIN_PASSWORD.")
        else:
            db.add(User(username="admin", password_hash=locked_password_hash()))
            events.append("Created locked 'admin' account; waiting for first-run setup.")
    elif check_password_hash(admin.password_hash, LEGACY_DEFAULT_PASSWORD):
        if configured:
            admin.password_hash = generate_password_hash(configured)
            events.append("Replaced legacy default 'admin' password with ADMIN_PASSWORD.")
        else:
            admin.password_hash = locked_password_hash()
            events.append(
                "Locked 'admin' account that used the legacy default password; setup required."
            )

    legacy = db.query(User).filter_by(username="noodles").first()
    if legacy and check_password_hash(legacy.password_hash, LEGACY_DEFAULT_PASSWORD):
        db.query(AuditLog).filter_by(user_id=legacy.id).update({AuditLog.user_id: None})
        db.delete(legacy)
        events.append("Removed legacy 'noodles' account that still used the default password.")
    return events


def setup_required() -> bool:
    """True while no operator account has a usable password (first run / locked upgrade)."""
    from bootstrap import is_locked_hash

    db = SessionLocal()
    try:
        users = db.query(User).all()
        return not any(u.password_hash and not is_locked_hash(u.password_hash) for u in users)
    finally:
        db.close()


def init_db():
    migrate_sqlite_schema()
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        account_events = _bootstrap_accounts(db)

        rules = {
            "temp_max": (60.0, "Absolute maximum allowed temperature setpoint (C)"),
            "temp_min": (0.0, "Absolute minimum allowed temperature setpoint (C)"),
            "pressure_max": (8.0, "Absolute maximum allowed pressure setpoint (bar)"),
            "pressure_min": (0.0, "Absolute minimum allowed pressure setpoint (bar)"),
        }
        for key, (val, desc) in rules.items():
            if not db.query(Rule).filter_by(key=key).first():
                db.add(Rule(key=key, value=val, description=desc))

        # No hard-coded node list: devices are discovered on the bus and enrolled through
        # the registry (ADR 0006); their DeviceState rows are created on approval.

        # Only record things that actually happened (the old fabricated "baseline"
        # audit entries were removed in v2.6 -- debug report R2).
        from version import __version__

        db.add(
            AuditLog(
                user_id=None,
                action="SYSTEM_STARTUP",
                location="SYSTEM",
                details=f"Aegis ICS v{__version__} started; database schema verified.",
            )
        )
        for message in account_events:
            db.add(
                AuditLog(
                    user_id=None, action="ACCOUNT_BOOTSTRAP", location="SYSTEM", details=message
                )
            )

        db.commit()
    finally:
        db.close()
