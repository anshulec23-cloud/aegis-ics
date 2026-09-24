import pytest
import time
import json
import os
import sys

# Ensure src/ is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import serial_gateway
from app import app, SessionLocal, User, DeviceState, TelemetryLog

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin"
            sess["location"] = "Central SCADA Enclave"
        yield c

def test_master_bridge_bus_topology_parsing():
    """Verify Master Concentrator BUS_TOPOLOGY frames dynamically register active slaves and transducers."""
    topo_payload = {
        "system": "Aegis Master Concentrator",
        "type": "BUS_TOPOLOGY",
        "status": "ONLINE",
        "version": "2.5.2",
        "slave_count": 4,
        "slaves": ["ESP32_001", "ESP32_002", "ESP32_003", "ESP32_004"],
        "sensors": {
            "ESP32_001": ["temperature", "pressure", "vibration", "current"],
            "ESP32_002": ["temperature", "pressure", "vibration", "hall_effect", "current"],
            "ESP32_003": ["temperature", "pressure", "current"],
            "ESP32_004": ["temperature", "pressure", "vibration", "hall_effect", "current"]
        }
    }
    raw_line = json.dumps(topo_payload)
    parsed = serial_gateway.parse_serial_line(raw_line)

    assert parsed is not None
    assert parsed.get("_is_bridge_msg") is True
    assert parsed.get("type") == "BUS_TOPOLOGY"

    active_nodes = serial_gateway.get_active_nodes()
    assert "ESP32_001" in active_nodes
    assert "ESP32_002" in active_nodes
    assert "ESP32_003" in active_nodes
    assert "ESP32_004" in active_nodes

    assert "hall_effect" in active_nodes["ESP32_002"]["sensors"]
    assert "hall_effect" not in active_nodes["ESP32_003"]["sensors"]

    health = serial_gateway.get_gateway_health()
    assert health["active_nodes_count"] >= 4
    assert health["total_active_sensors"] >= 17
    assert health["master_bridge"]["status"] == "ONLINE"

def test_slave_node_announce_parsing():
    """Verify individual slave NODE_ANNOUNCE frames dynamically register the node and its sensor array."""
    announce_payload = {
        "type": "NODE_ANNOUNCE",
        "device_id": "ESP32_005_CUSTOM",
        "hardware": "ESP32-S3",
        "version": "2.5.2",
        "sensors": ["temperature", "pressure", "vibration"],
        "sensor_count": 3
    }
    raw_line = json.dumps(announce_payload)
    parsed = serial_gateway.parse_serial_line(raw_line)

    assert parsed is not None
    assert parsed.get("_is_bridge_msg") is True
    assert parsed.get("type") == "NODE_ANNOUNCE"

    active_nodes = serial_gateway.get_active_nodes()
    assert "ESP32_005_CUSTOM" in active_nodes
    assert active_nodes["ESP32_005_CUSTOM"]["active_sensors_count"] == 3
    assert "temperature" in active_nodes["ESP32_005_CUSTOM"]["sensors"]

def test_cluster_topology_endpoint(client):
    """Verify /api/cluster/topology returns connected slaves and active sensor counts."""
    res = client.get("/api/cluster/topology")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "nodes" in data
    assert data["total_nodes_count"] >= 4
    assert data["total_active_sensors"] >= 10

def test_cluster_discover_endpoint(client):
    """Verify /api/cluster/discover enqueues discovery command to hardware."""
    res = client.post("/api/cluster/discover")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "Discovery probe dispatched" in data["message"]

def test_emergency_shutdown_endpoint(client):
    """Verify /api/device/shutdown trips device isolation and logs emergency audit event."""
    res = client.post("/api/device/shutdown", json={"device_id": "ESP32_001"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "shutdown instruction dispatched" in data["details"].lower()

    # Verify device state in database
    db = SessionLocal()
    dev = db.query(DeviceState).filter_by(device_id="ESP32_001").first()
    assert dev is not None
    assert dev.is_isolated is True
    db.close()
