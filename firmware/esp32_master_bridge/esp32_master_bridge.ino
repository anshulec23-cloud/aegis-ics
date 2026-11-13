/**
 * ==============================================================================================
 * Aegis ICS — Edge Concentrator Master Bridge Reference Firmware
 * Target: ESP32 / ESP32-S3 / ESP32-WROOM-32
 * Description: Master concentrator gateway bridging multi-node RS-485 field buses
 *              to the Aegis ICS Edge SCADA host over USB-CDC Serial at 115200 baud.
 * Features:
 *  - Dynamic multi-slave node tracking, active polling, and transducer discovery
 *  - Master bus topology reporting (slave counts, active sensor lists per node)
 *  - Dual-UART ring buffer routing (HardwareSerial Serial2 <-> Serial)
 *  - High-precision half-duplex direction switching with hardware FIFO flushing
 *  - Host command dispatching (DISCOVER, SHUTDOWN, ISOLATE, REARM, SETPOINT)
 * Standard Compliance: NIST SP 800-82 Rev 3 (OT Security)
 * ==============================================================================================
 */

#include <Arduino.h>
#include <ArduinoJson.h>

// --- UART PINS FOR RS-485 FIELD BUS ---
#define RS485_RX_PIN        16    // RO (Receiver Output) -> UART2 RX
#define RS485_TX_PIN        17    // DI (Driver Input)    -> UART2 TX
#define RS485_DIR_PIN       4     // DE & RE tied together (Driver / Receiver Enable)
#define STATUS_LED_PIN      2     // On-board LED for activity heartbeat

#define HOST_BAUD_RATE      115200
#define RS485_BAUD_RATE     115200

#define MAX_SLAVES          16
#define SLAVE_TIMEOUT_MS    8000
#define TOPOLOGY_INTERVAL   3000

HardwareSerial rs485(2); // Use UART2 for RS-485 bus

struct SlaveRecord {
    char device_id[24];
    unsigned long last_seen_ms;
    unsigned long packet_count;
    bool is_active;
    bool has_temp;
    bool has_pres;
    bool has_vib;
    bool has_hall;
    bool has_curr;
};

SlaveRecord slave_table[MAX_SLAVES];
int registered_slave_count = 0;

unsigned long frame_sequence = 0;
unsigned long command_sequence = 0;
unsigned long last_topology_broadcast = 0;
unsigned long last_led_toggle = 0;

void setup() {
    // Primary USB-Serial interface to Aegis ICS Gateway host
    Serial.begin(HOST_BAUD_RATE);

    // RS-485 direction and status LED pins
    pinMode(RS485_DIR_PIN, OUTPUT);
    digitalWrite(RS485_DIR_PIN, LOW); // Receive mode by default

    pinMode(STATUS_LED_PIN, OUTPUT);
    digitalWrite(STATUS_LED_PIN, LOW);

    // Initialize UART2 for RS-485 bus communication
    rs485.begin(RS485_BAUD_RATE, SERIAL_8N1, RS485_RX_PIN, RS485_TX_PIN);

    // Initialize slave registry
    for (int i = 0; i < MAX_SLAVES; i++) {
        slave_table[i].device_id[0] = '\0';
        slave_table[i].is_active = false;
        slave_table[i].last_seen_ms = 0;
        slave_table[i].packet_count = 0;
        slave_table[i].has_temp = false;
        slave_table[i].has_pres = false;
        slave_table[i].has_vib = false;
        slave_table[i].has_hall = false;
        slave_table[i].has_curr = false;
    }

    delay(500);
    Serial.println(F("{\"system\":\"Aegis Master Concentrator\",\"status\":\"ONLINE\",\"version\":\"2.5.2\",\"baud\":115200,\"bridge_id\":\"MASTER_BRIDGE_01\"}"));
}

// Non-blocking UART line buffer state
char rs485_buf[768];
size_t rs485_idx = 0;
char host_buf[512];
size_t host_idx = 0;

bool readNonBlockingLine(Stream &stream, char *buffer, size_t max_len, size_t &idx) {
    while (stream.available()) {
        char c = (char)stream.read();
        if (c == '\n') {
            buffer[idx] = '\0';
            idx = 0;
            return true;
        } else if (c != '\r') {
            if (idx < max_len - 1) {
                buffer[idx++] = c;
            } else {
                idx = 0; // Buffer overflow protection
            }
        }
    }
    return false;
}

void register_slave_telemetry(const char* dev_id, bool temp, bool pres, bool vib, bool hall, bool curr) {
    if (!dev_id || strlen(dev_id) == 0) return;
    unsigned long now = millis();

    // Check if slave is already registered
    for (int i = 0; i < registered_slave_count; i++) {
        if (strcmp(slave_table[i].device_id, dev_id) == 0) {
            slave_table[i].last_seen_ms = now;
            slave_table[i].packet_count++;
            slave_table[i].is_active = true;
            if (temp) slave_table[i].has_temp = true;
            if (pres) slave_table[i].has_pres = true;
            if (vib) slave_table[i].has_vib = true;
            if (hall) slave_table[i].has_hall = true;
            if (curr) slave_table[i].has_curr = true;
            return;
        }
    }

    // Register new slave if space available
    if (registered_slave_count < MAX_SLAVES) {
        strncpy(slave_table[registered_slave_count].device_id, dev_id, sizeof(slave_table[0].device_id) - 1);
        slave_table[registered_slave_count].device_id[sizeof(slave_table[0].device_id) - 1] = '\0';
        slave_table[registered_slave_count].last_seen_ms = now;
        slave_table[registered_slave_count].packet_count = 1;
        slave_table[registered_slave_count].is_active = true;
        slave_table[registered_slave_count].has_temp = temp;
        slave_table[registered_slave_count].has_pres = pres;
        slave_table[registered_slave_count].has_vib = vib;
        slave_table[registered_slave_count].has_hall = hall;
        slave_table[registered_slave_count].has_curr = curr;
        registered_slave_count++;
    }
}

void broadcast_rs485(const char* msg) {
    if (!msg || strlen(msg) == 0) return;
    digitalWrite(RS485_DIR_PIN, HIGH);
    delayMicroseconds(60);
    rs485.println(msg);
    rs485.flush();
    delayMicroseconds(100);
    digitalWrite(RS485_DIR_PIN, LOW);
}

void emit_bus_topology() {
    unsigned long now = millis();
    int active_count = 0;

    // Prune stale slaves
    for (int i = 0; i < registered_slave_count; i++) {
        if (now - slave_table[i].last_seen_ms <= SLAVE_TIMEOUT_MS) {
            slave_table[i].is_active = true;
            active_count++;
        } else {
            slave_table[i].is_active = false;
        }
    }

    StaticJsonDocument<1024> doc;
    doc["system"] = "Aegis Master Concentrator";
    doc["type"] = "BUS_TOPOLOGY";
    doc["status"] = "ONLINE";
    doc["version"] = "2.5.2";
    doc["slave_count"] = active_count;

    JsonArray slaves_arr = doc.createNestedArray("slaves");
    JsonObject sensors_obj = doc.createNestedObject("sensors");

    for (int i = 0; i < registered_slave_count; i++) {
        if (slave_table[i].is_active) {
            slaves_arr.add(slave_table[i].device_id);
            JsonArray dev_sensors = sensors_obj.createNestedArray(slave_table[i].device_id);
            if (slave_table[i].has_temp) dev_sensors.add("temperature");
            if (slave_table[i].has_pres) dev_sensors.add("pressure");
            if (slave_table[i].has_vib) dev_sensors.add("vibration");
            if (slave_table[i].has_hall) dev_sensors.add("hall_effect");
            if (slave_table[i].has_curr) dev_sensors.add("current");
        }
    }

    char out_buf[1024];
    serializeJson(doc, out_buf, sizeof(out_buf));
    Serial.println(out_buf);
    Serial.flush();
    last_topology_broadcast = now;
}

void loop() {
    unsigned long now = millis();

    // --- 1. SLAVE INGESTION: Read telemetry frames from RS-485 Bus (Non-blocking) ---
    if (readNonBlockingLine(rs485, rs485_buf, sizeof(rs485_buf), rs485_idx)) {
        size_t len = strlen(rs485_buf);
        if (len > 0 && rs485_buf[0] == '{' && rs485_buf[len - 1] == '}') {
            // Forward verified frame to Aegis Edge Host over USB Serial
            Serial.println(rs485_buf);
            Serial.flush();
            frame_sequence++;

            // Heartbeat blink on packet ingestion
            digitalWrite(STATUS_LED_PIN, HIGH);
            delayMicroseconds(200);
            digitalWrite(STATUS_LED_PIN, LOW);

            // Parse frame to extract slave identity and attached transducers
            StaticJsonDocument<512> frame_doc;
            DeserializationError err = deserializeJson(frame_doc, rs485_buf);
            if (!err) {
                const char* dev_id = frame_doc["device_id"] | frame_doc["id"];
                const char* frame_type = frame_doc["type"];

                if (frame_type && strcmp(frame_type, "NODE_ANNOUNCE") == 0) {
                    // Explicit node announcement frame
                    bool has_t = false, has_p = false, has_v = false, has_h = false, has_c = false;
                    JsonArray s_list = frame_doc["sensors"];
                    for (JsonVariant s : s_list) {
                        const char* s_str = s.as<const char*>();
                        if (!s_str) continue;
                        if (strcmp(s_str, "temperature") == 0 || strcmp(s_str, "temp") == 0) has_t = true;
                        if (strcmp(s_str, "pressure") == 0 || strcmp(s_str, "pres") == 0) has_p = true;
                        if (strcmp(s_str, "vibration") == 0 || strcmp(s_str, "vib") == 0) has_v = true;
                        if (strcmp(s_str, "hall_effect") == 0 || strcmp(s_str, "hall") == 0 || strcmp(s_str, "rpm") == 0) has_h = true;
                        if (strcmp(s_str, "current") == 0 || strcmp(s_str, "curr") == 0) has_c = true;
                    }
                    register_slave_telemetry(dev_id, has_t, has_p, has_v, has_h, has_c);
                } else if (dev_id) {
                    // Standard wire telemetry frame
                    bool has_t = frame_doc.containsKey("temperature") || frame_doc.containsKey("temp");
                    bool has_p = frame_doc.containsKey("pressure") || frame_doc.containsKey("pres");
                    bool has_v = frame_doc.containsKey("vibration") || frame_doc.containsKey("vib");
                    bool has_h = frame_doc.containsKey("hall_effect") || frame_doc.containsKey("hall") || frame_doc.containsKey("rpm");
                    bool has_c = frame_doc.containsKey("current") || frame_doc.containsKey("curr");
                    register_slave_telemetry(dev_id, has_t, has_p, has_v, has_h, has_c);
                }
            }
        }
    }

    // --- 2. COMMAND DISPATCH: Read setpoint/actuator commands from Aegis Host (Non-blocking) ---
    if (readNonBlockingLine(Serial, host_buf, sizeof(host_buf), host_idx)) {
        size_t len = strlen(host_buf);
        if (len > 0 && host_buf[0] == '{') {
            StaticJsonDocument<384> cmd_doc;
            DeserializationError err = deserializeJson(cmd_doc, host_buf);
            if (!err) {
                const char* cmd = cmd_doc["command"] | cmd_doc["action"];
                const char* target = cmd_doc["target_device"] | cmd_doc["device_id"];

                if (cmd && (strcmp(cmd, "DISCOVER") == 0 || strcmp(cmd, "GET_TOPOLOGY") == 0)) {
                    // Broadcast discover request on RS-485 bus to wake all slaves
                    broadcast_rs485("{\"command\":\"DISCOVER\"}");
                    // Emit immediate topology back to host
                    emit_bus_topology();
                } else if (cmd && strcmp(cmd, "SHUTDOWN") == 0 && target && strcmp(target, "ALL") == 0) {
                    // Universal bus emergency shutdown
                    broadcast_rs485(host_buf);
                    Serial.println(F("{\"system\":\"Aegis Master Concentrator\",\"type\":\"COMMAND_ACK\",\"status\":\"BUS_SHUTDOWN\",\"action\":\"ALL_SLAVES_DISARMED\"}"));
                    Serial.flush();
                } else {
                    // Forward targeted command (ISOLATE, REARM, SETPOINT, etc.) to RS-485 bus
                    broadcast_rs485(host_buf);
                    command_sequence++;
                }
            } else {
                // Raw forwarding fallback
                broadcast_rs485(host_buf);
            }

            // Status indication
            digitalWrite(STATUS_LED_PIN, HIGH);
            delayMicroseconds(500);
            digitalWrite(STATUS_LED_PIN, LOW);
        }
    }

    // --- 3. PERIODIC TOPOLOGY HEARTBEAT TO HOST ---
    if (now - last_topology_broadcast >= TOPOLOGY_INTERVAL) {
        emit_bus_topology();
    }
}
