import time
import json
import random
import hashlib
import hmac
import os
import paho.mqtt.client as mqtt

DEVICE_ID = "ESP32_001"
HMAC_KEY = os.environ.get("DEVICE_KEY_ESP32_001", "device_key_001")
MQTT_HOST = os.environ.get("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))

# Hardware-Level Immutable Safety Thresholds (Stuxnet Defense)
HARDWARE_TEMP_LIMIT = 65.0
HARDWARE_PRESSURE_LIMIT = 8.5

current_temp = 25.0
current_pressure = 4.0

def canonicalize_payload(payload: dict) -> dict:
    canonical = {}
    for k, v in payload.items():
        if k in ("temperature", "pressure", "humidity", "rssi"):
            canonical[k] = f"{float(v):.2f}"
        elif k == "timestamp":
            canonical[k] = f"{float(v):.3f}"
        else:
            canonical[k] = v
    return canonical

def sign_message(payload: dict, key: str) -> str:
    canonical_payload = canonicalize_payload(payload)
    canonical = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()

mqtt_connected = False

def on_connect(client, userdata, flags, rc, properties=None):
    global mqtt_connected
    if rc == 0:
        mqtt_connected = True
        client.subscribe(f"ics/control/{DEVICE_ID}")
        print(f"[{DEVICE_ID}] Connected to MQTT Broker - Subscribed to ics/control/{DEVICE_ID}")
    else:
        mqtt_connected = False
        print(f"[{DEVICE_ID}] MQTT Connection failed with code {rc}")

def on_disconnect(client, userdata, flags, rc, properties=None):
    global mqtt_connected
    mqtt_connected = False
    print(f"[{DEVICE_ID}] Disconnected from MQTT Broker")

def on_message(client, userdata, msg):
    global current_temp, current_pressure
    try:
        command = json.loads(msg.payload.decode())
    except Exception as e:
        print(f"[{DEVICE_ID}] ERROR: Malformed command: {e}")
        return
        
    cmd_type = command.get("type")
    value = command.get("value")
    
    if cmd_type == "set_temp":
        # Immutable Hardware Safety Boundary
        if value > HARDWARE_TEMP_LIMIT:
            print(f"[{DEVICE_ID}] SECURITY REJECTION: Temp setpoint {value}C exceeds hard hardware limit ({HARDWARE_TEMP_LIMIT}C)!")
            return
        current_temp = float(value)
        print(f"[{DEVICE_ID}] Applied Temp setpoint: {current_temp}C")
        
    elif cmd_type == "set_pressure":
        # Immutable Hardware Safety Boundary
        if value > HARDWARE_PRESSURE_LIMIT:
            print(f"[{DEVICE_ID}] SECURITY REJECTION: Pressure setpoint {value} bar exceeds hard hardware limit ({HARDWARE_PRESSURE_LIMIT} bar)!")
            return
        current_pressure = float(value)
        print(f"[{DEVICE_ID}] Applied Pressure setpoint: {current_pressure} bar")

def main():
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id=DEVICE_ID)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    
    try:
        client.connect(MQTT_HOST, MQTT_PORT, 60)
    except Exception as e:
        print(f"[{DEVICE_ID}] Connection failed: {e}. Running in standalone mode.")
        
    client.loop_start()
    
    seq = 0
    print(f"[{DEVICE_ID}] Simulator running. Press Ctrl+C to stop.")
    try:
        while True:
            # Generate simulated values around current setpoints
            temp_reading = current_temp + random.uniform(-0.5, 0.5)
            pressure_reading = current_pressure + random.uniform(-0.1, 0.1)
            humidity_reading = 45.0 + random.uniform(-2.0, 2.0)
            rssi_reading = -50.0 - random.uniform(0.0, 15.0)
            
            payload = {
                "device_id": DEVICE_ID,
                "timestamp": time.time(),
                "sequence": seq,
                "temperature": round(temp_reading, 2),
                "pressure": round(pressure_reading, 2),
                "humidity": round(humidity_reading, 2),
                "rssi": round(rssi_reading, 2)
            }
            
            payload["signature"] = sign_message(payload, HMAC_KEY)
            
            published = False
            if mqtt_connected:
                try:
                    client.publish(f"ics/telemetry/{DEVICE_ID}", json.dumps(payload))
                    print(f"[{DEVICE_ID}] Telemetry published via MQTT: Temp={payload['temperature']}C, Pres={payload['pressure']} bar")
                    published = True
                except Exception as e:
                    print(f"[{DEVICE_ID}] MQTT publish failed: {e}. Falling back to HTTP.")
            
            if not published:
                # HTTP Fallback
                try:
                    import urllib.request
                    req = urllib.request.Request(
                        "http://127.0.0.1:5000/api/telemetry",
                        data=json.dumps(payload).encode("utf-8"),
                        headers={"Content-Type": "application/json"}
                    )
                    with urllib.request.urlopen(req, timeout=2) as response:
                        if response.status == 200:
                            print(f"[{DEVICE_ID}] Telemetry published via HTTP fallback: Temp={payload['temperature']}C, Pres={payload['pressure']} bar")
                        else:
                            print(f"[{DEVICE_ID}] HTTP fallback response error: {response.status}")
                except Exception as e:
                    print(f"[{DEVICE_ID}] HTTP fallback publish failed: {e}. Ensure Flask server is running.")
                
            seq += 1
            time.sleep(2)
            
    except KeyboardInterrupt:
        print(f"[{DEVICE_ID}] Simulator stopped.")
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
