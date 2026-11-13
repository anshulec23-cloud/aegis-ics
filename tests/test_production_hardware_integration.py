import sys
import os
import time
import json
import pytest

src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
sys.path.insert(0, src_dir)

# Isolate database for tests to prevent modifying production aegis_v2.db
test_db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_hardware_integration.db"))
os.environ["DATABASE_URL"] = f"sqlite:///{test_db_path}"

from database import init_db, SessionLocal, User, AuditLog, TelemetryLog, DeviceState
from serial_gateway import (
    parse_serial_line,
    find_esp32_ports,
    get_master_bridge_info,
    get_gateway_health,
    get_active_nodes,
    _active_nodes,
    _master_bridge_info,
    _gateway_state
)
import serial_gateway
from app import app
from werkzeug.security import generate_password_hash

init_db()

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "hardware_engineer"
        yield client

def test_serial_gateway_master_bridge_announcement():
    """Verify Master Concentrator boot announcement parsing and state update."""
    raw_announcement = json.dumps({
        "system": "Aegis Master Concentrator",
        "bridge_id": "MASTER_BRIDGE_ALPHA",
        "firmware": "2.3.0-hw",
        "baud": 115200,
        "nodes_attached": 4
    })
    parsed = parse_serial_line(raw_announcement)
    assert parsed is not None
    assert parsed.get("type") == "MASTER_ANNOUNCEMENT"
    assert parsed.get("bridge_id") == "MASTER_BRIDGE_ALPHA"
    
    bridge = get_master_bridge_info()
    assert bridge.get("bridge_id") == "MASTER_BRIDGE_ALPHA"
    assert bridge.get("firmware") == "2.3.0-hw"

def test_serial_gateway_5_sensor_parsing_and_mapping():
    """Verify parsing of 5 distinct transducers (temp, pres, vib, curr, rpm/hall)."""
    raw_payload = json.dumps({
        "device_id": "ESP32_005",
        "timestamp": 1700000000.0,
        "temperature": 42.5,
        "pressure": 5.12,
        "vibration": 0.85,
        "current": 12.4,
        "rpm": 2850
    })
    parsed = parse_serial_line(raw_payload)
    assert parsed is not None
    assert parsed["device_id"] == "ESP32_005"
    assert parsed["temperature"] == 42.5
    assert parsed["pressure"] == 5.12
    assert parsed["vibration"] == 0.85
    assert parsed["current"] == 12.4
    assert parsed["hall_effect"] == 2850

def test_find_esp32_ports():
    """Verify that find_esp32_ports correctly annotates candidate hardware serial ports."""
    ports = find_esp32_ports()
    assert isinstance(ports, list)
    for p in ports:
        assert "device" in p
        assert "description" in p
        assert "is_esp32_candidate" in p

def test_cluster_topology_endpoint(client):
    """Verify GET /api/cluster/topology returns dynamic cluster hierarchy."""
    # Seed active node
    _active_nodes["ESP32_TURBINE_1"] = {
        "device_id": "ESP32_TURBINE_1",
        "last_seen": time.time(),
        "sensors": ["temperature", "pressure", "vibration", "current", "hall_effect"],
        "active_sensors_count": 5
    }
    
    res = client.get("/api/cluster/topology")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "total_nodes_count" in data
    assert "total_active_sensors" in data
    assert "master_bridge" in data
    assert "nodes" in data
    assert any(n["device_id"] == "ESP32_TURBINE_1" for n in data["nodes"])

def test_devices_dynamic_enumeration(client):
    """Verify GET /api/devices includes dynamic hardware nodes and active_sensors_count."""
    res = client.get("/api/devices")
    assert res.status_code == 200
    data = res.get_json()
    assert "devices" in data
    dev_ids = [d["device_id"] for d in data["devices"]]
    assert "ESP32_TURBINE_1" in dev_ids
    turbine = next(d for d in data["devices"] if d["device_id"] == "ESP32_TURBINE_1")
    assert turbine["active_sensors_count"] == 5

def test_isolated_device_quarantine_telemetry_persistence(client):
    """Verify that when a device is isolated, telemetry returns 403 (for test compliance)
    AND persists the quarantine record in the database for forensic post-trip analysis."""
    db = SessionLocal()
    try:
        # Isolate ESP32_003
        state = db.query(DeviceState).filter_by(device_id="ESP32_003").first()
        if not state:
            state = DeviceState(device_id="ESP32_003", is_isolated=True)
            db.add(state)
        else:
            state.is_isolated = True
        db.commit()

        # Send post-trip de-energized telemetry
        payload = {
            "device_id": "ESP32_003",
            "timestamp": time.time(),
            "temperature": 22.0,
            "pressure": 0.0,
            "vibration": 0.0,
            "current": 0.0,
            "hall_effect": 0.0
        }
        res = client.post("/api/telemetry", json=payload)
        assert res.status_code == 403
        
        # Verify telemetry was logged as anomaly/quarantine in DB
        record = db.query(TelemetryLog).filter_by(device_id="ESP32_003").order_by(TelemetryLog.id.desc()).first()
        assert record is not None
        assert record.is_anomaly is True
        assert record.pressure == 0.0
    finally:
        try:
            st = db.query(DeviceState).filter_by(device_id="ESP32_003").first()
            if st:
                st.is_isolated = False
                db.commit()
        except Exception:
            pass
        db.close()

def test_financial_analytics_data_contract(client):
    """Verify /api/financial/analytics returns proper structure with financials key."""
    res = client.get("/api/financial/analytics")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "financials" in data
    fin = data["financials"]
    assert "expected_loss" in fin
    assert "incurred_cost" in fin
    assert "prevented_cost" in fin
    assert "threat_index" in fin

def test_monte_carlo_loss_distribution_endpoint(client):
    """Verify /api/financial/loss_distribution returns loss exceedance distribution (P05 to P99)."""
    res = client.get("/api/financial/loss_distribution")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "distribution" in data
    dist = data["distribution"]
    assert len(dist) >= 6
    percentiles = [d["percentile"] for d in dist]
    assert "P05" in percentiles
    assert "P50" in percentiles
    assert "P99" in percentiles
    for d in dist:
        assert d["loss_usd"] >= 0

def test_subsystem_financial_breakdown_endpoint(client):
    """Verify /api/financial/subsystems includes dynamic nodes and calculates outage costs."""
    res = client.get("/api/financial/subsystems")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "subsystems" in data
    subs = data["subsystems"]
    assert len(subs) >= 4
    for sub in subs:
        assert "device_id" in sub
        assert "name" in sub
        assert "equipment_value" in sub
        assert "downtime_rate_per_hour" in sub
        assert "active_outage_cost_per_hr" in sub

def test_manual_isolation_and_rejoin(client):
    """Verify manual isolation and rejoin endpoints properly toggle device status."""
    # 1. Isolate
    res1 = client.post("/api/device/isolate", json={"device_id": "ESP32_001"})
    assert res1.status_code == 200
    
    # Check DB
    db = SessionLocal()
    try:
        st = db.query(DeviceState).filter_by(device_id="ESP32_001").first()
        assert st is not None
        assert st.is_isolated is True
    finally:
        db.close()
        
    # 2. Rejoin
    res2 = client.post("/api/device/rejoin", json={"device_id": "ESP32_001"})
    assert res2.status_code == 200
    
    # Check DB
    db = SessionLocal()
    try:
        st = db.query(DeviceState).filter_by(device_id="ESP32_001").first()
        assert st is not None
        assert st.is_isolated is False
    finally:
        db.close()
