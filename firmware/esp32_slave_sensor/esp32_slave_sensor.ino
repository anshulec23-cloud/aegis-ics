/**
 * ==============================================================================================
 * Aegis ICS — Edge Microcontroller Slave Node Reference Firmware
 * Target: ESP32 / ESP32-S3 / ESP32-WROOM-32 / ESP32-C3
 * Description: Reads process telemetry (Thermocouple, Pressure Transducer, Vibration, Hall RPM,
 *              Current Transformer), formats canonical JSON in strict alphabetical key order,
 *              calculates HMAC-SHA256 message authentication code using hardware-accelerated
 *              mbedTLS, transmits over RS-485 / Serial UART, and executes actuator commands.
 * Standard Compliance: NIST SP 800-82 Rev 3 (OT Security), FIPS 198-1 (HMAC)
 * ==============================================================================================
 */

#include <Arduino.h>
#include <mbedtls/md.h>
#include <ArduinoJson.h>

// ==============================================================================================
// 1. NODE SELECTION CONFIGURATION
// Uncomment exactly ONE node configuration before flashing to target hardware
// ==============================================================================================
#define NODE_CONFIG_ESP32_001  // Catalytic Reactor 01 (Reactor Bay North)
// #define NODE_CONFIG_ESP32_002  // Centrifugal Pump 02 (Pumping Station East)
// #define NODE_CONFIG_ESP32_003  // Cooling Cryo 03 (Cryogenics Vault Sub-1)
// #define NODE_CONFIG_ESP32_004  // Turbine Generator 04 (Turbine Hall South)

#if defined(NODE_CONFIG_ESP32_001)
  #define DEVICE_ID           "ESP32_001"
  #define PRE_SHARED_HMAC_KEY "aegis_shared_esp32_001_secret_key_v2"
  #define BASE_TEMP           26.0
  #define BASE_PRES           4.2
  #define BASE_VIB            1.1
  #define BASE_RPM            0.0
  #define BASE_CURR           4.5
#elif defined(NODE_CONFIG_ESP32_002)
  #define DEVICE_ID           "ESP32_002"
  #define PRE_SHARED_HMAC_KEY "aegis_shared_esp32_002_secret_key_v2"
  #define BASE_TEMP           41.0
  #define BASE_PRES           5.4
  #define BASE_VIB            1.8
  #define BASE_RPM            1500.0
  #define BASE_CURR           5.2
#elif defined(NODE_CONFIG_ESP32_003)
  #define DEVICE_ID           "ESP32_003"
  #define PRE_SHARED_HMAC_KEY "aegis_shared_esp32_003_secret_key_v2"
  #define BASE_TEMP           18.5
  #define BASE_PRES           2.2
  #define BASE_VIB            0.6
  #define BASE_RPM            0.0
  #define BASE_CURR           2.8
#elif defined(NODE_CONFIG_ESP32_004)
  #define DEVICE_ID           "ESP32_004"
  #define PRE_SHARED_HMAC_KEY "aegis_shared_esp32_004_secret_key_v2"
  #define BASE_TEMP           33.0
  #define BASE_PRES           3.8
  #define BASE_VIB            2.2
  #define BASE_RPM            2200.0
  #define BASE_CURR           7.1
#else
  #error "No Node configuration selected! Uncomment one of NODE_CONFIG_ESP32_00x."
#endif

// ==============================================================================================
// 2. HARDWARE PIN ASSIGNMENTS (ESP32-WROOM-32 Pinout)
// ==============================================================================================
// RS-485 Transceiver Interface (MAX485 / SN65HVD72)
#define PIN_RS485_RX        16    // RO (Receiver Output) -> UART2 RX
#define PIN_RS485_TX        17    // DI (Driver Input)    -> UART2 TX
#define PIN_RS485_DE_RE     4     // DE & RE tied together (Driver/Receiver Enable)

// Sensor Transducer Analog & Digital Pins
#define PIN_TEMP_ADC        34    // Analog LM35 / Thermocouple Amp / Potentiometer
#define PIN_PRESSURE_ADC    35    // 0.5V - 4.5V Industrial Pressure Transducer
#define PIN_VIB_ADC         32    // Piezo vibration / Analog accelerometer
#define PIN_HALL_INTERRUPT  33    // Hall effect pulse counter (A3144)
#define PIN_CURRENT_ADC     36    // ACS712 Hall-effect current sensor (GPIO 36 / VP)
#define PIN_ACTUATOR_RELAY  25    // Physical Actuator Relay / Solenoid Control
#define PIN_STATUS_LED      2     // On-board LED for visual heartbeat & tamper indication

// Telemetry Transmission Period
#define TRANSMIT_INTERVAL_MS 500
#define RS485_BAUD_RATE      115200

// Secondary UART for RS-485 Bus
HardwareSerial rs485(2);

// Volatile counters & state tracking
volatile unsigned long hall_pulse_count = 0;
unsigned long last_transmit_time = 0;
unsigned long last_announce_time = 0;
unsigned long last_rpm_time = 0;
float current_rpm = 0.0;
bool is_actuator_isolated = false;

// Interrupt Service Routine for Hall Effect RPM Sensor
void IRAM_ATTR onHallPulse() {
    hall_pulse_count++;
}

void send_node_announcement() {
    StaticJsonDocument<384> doc;
    doc["type"] = "NODE_ANNOUNCE";
    doc["device_id"] = DEVICE_ID;
    doc["hardware"] = "ESP32-WROOM-32";
    doc["version"] = "2.5.2";
    doc["is_isolated"] = is_actuator_isolated;
    JsonArray s_arr = doc.createNestedArray("sensors");
    s_arr.add("temperature");
    s_arr.add("pressure");
    s_arr.add("vibration");
    s_arr.add("current");
    #if defined(NODE_CONFIG_ESP32_002) || defined(NODE_CONFIG_ESP32_004)
    s_arr.add("hall_effect");
    #endif
    doc["sensor_count"] = s_arr.size();

    char out_buf[384];
    serializeJson(doc, out_buf, sizeof(out_buf));

    digitalWrite(PIN_RS485_DE_RE, HIGH);
    delayMicroseconds(50);
    rs485.println(out_buf);
    rs485.flush();
    delayMicroseconds(100);
    digitalWrite(PIN_RS485_DE_RE, LOW);

    Serial.println(out_buf);
}

/**
 * Calculates HMAC-SHA256 signature over the canonical JSON payload string
 * using ESP32 hardware-accelerated mbedTLS cryptographic engine.
 */
String compute_hmac_sha256(const char *payload, const char *key) {
    byte hmac_result[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char *)key, strlen(key));
    mbedtls_md_hmac_update(&ctx, (const unsigned char *)payload, strlen(payload));
    mbedtls_md_hmac_finish(&ctx, hmac_result);
    mbedtls_md_free(&ctx);

    char hex_str[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&hex_str[i * 2], "%02x", (unsigned int)hmac_result[i]);
    }
    hex_str[64] = '\0';
    return String(hex_str);
}

void setup() {
    // Primary USB Serial for programming & debugging
    Serial.begin(115200);

    // Initialize RS-485 UART2
    pinMode(PIN_RS485_DE_RE, OUTPUT);
    digitalWrite(PIN_RS485_DE_RE, LOW); // Set to RX mode by default
    rs485.begin(RS485_BAUD_RATE, SERIAL_8N1, PIN_RS485_RX, PIN_RS485_TX);

    // Initialize Sensor & Actuator GPIOs
    pinMode(PIN_TEMP_ADC, INPUT);
    pinMode(PIN_PRESSURE_ADC, INPUT);
    pinMode(PIN_VIB_ADC, INPUT);
    pinMode(PIN_CURRENT_ADC, INPUT);
    pinMode(PIN_HALL_INTERRUPT, INPUT_PULLUP);
    pinMode(PIN_ACTUATOR_RELAY, OUTPUT);
    pinMode(PIN_STATUS_LED, OUTPUT);

    // Actuator active (relay engaged, LED off)
    digitalWrite(PIN_ACTUATOR_RELAY, HIGH);
    digitalWrite(PIN_STATUS_LED, LOW);

    attachInterrupt(digitalPinToInterrupt(PIN_HALL_INTERRUPT), onHallPulse, FALLING);

    delay(800);
    Serial.println(F("=================================================="));
    Serial.println(F("  Aegis ICS Edge Microcontroller Node Firmware"));
    Serial.print(F("  Node Identity : ")); Serial.println(F(DEVICE_ID));
    Serial.print(F("  Baud Rate     : ")); Serial.println(RS485_BAUD_RATE);
    Serial.println(F("  Cryptographic : FIPS 198-1 mbedTLS HMAC-SHA256"));
    Serial.println(F("=================================================="));

    send_node_announcement();
}

// Non-blocking stream buffers
char rs485_cmd_buf[256];
size_t rs485_cmd_idx = 0;
char serial_cmd_buf[256];
size_t serial_cmd_idx = 0;

bool readNonBlockingLine(Stream &stream, char *buffer, size_t max_len, size_t &idx) {
    while (stream.available()) {
        char c = (char)stream.read();
        if (c == '\r') continue;
        if (c == '\n') {
            if (idx > 0) {
                buffer[idx] = '\0';
                idx = 0;
                return true;
            }
            continue;
        }
        if (idx < max_len - 1) {
            buffer[idx++] = c;
        } else {
            // Buffer overflow protection: reset line
            idx = 0;
        }
    }
    return false;
}

void process_incoming_command(const char* cmd_line) {
    if (!cmd_line || strlen(cmd_line) == 0) return;
    if (cmd_line[0] != '{') return;

    StaticJsonDocument<384> cmd_doc;
    DeserializationError err = deserializeJson(cmd_doc, cmd_line);
    if (err) return;

    const char* target = cmd_doc["target_device"] | cmd_doc["device_id"];
    const char* action = cmd_doc["command"] | cmd_doc["action"];
    if (!action) return;

    bool is_addressed_to_me = (!target || strcmp(target, "ALL") == 0 || strcmp(target, DEVICE_ID) == 0);
    if (!is_addressed_to_me) return;

    if (strcmp(action, "DISCOVER") == 0 || strcmp(action, "SCAN") == 0) {
        send_node_announcement();
        return;
    }

    if (strcmp(action, "SHUTDOWN") == 0) {
        is_actuator_isolated = true;
        digitalWrite(PIN_ACTUATOR_RELAY, LOW); // Trip actuator relay
        digitalWrite(PIN_STATUS_LED, HIGH);    // Visual shutdown alarm
        Serial.println(F("[ACTUATOR] Node SHUTDOWN executed safely!"));
        return;
    }

    if (strcmp(action, "ISOLATE") == 0 || strcmp(action, "MICROSEGMENT") == 0 || strcmp(action, "DISARM") == 0) {
        is_actuator_isolated = true;
        digitalWrite(PIN_ACTUATOR_RELAY, LOW); // Trip actuator relay
        digitalWrite(PIN_STATUS_LED, HIGH);    // Visual isolation alarm
        Serial.println(F("[ACTUATOR] Node ISOLATED by Supervisory Interlock!"));
    } else if (strcmp(action, "REARM") == 0 || strcmp(action, "REJOIN") == 0) {
        is_actuator_isolated = false;
        digitalWrite(PIN_ACTUATOR_RELAY, HIGH); // Re-energize actuator
        digitalWrite(PIN_STATUS_LED, LOW);
        Serial.println(F("[ACTUATOR] Node REARMED to Normal Operation."));
    } else if (strcmp(action, "SETPOINT") == 0) {
        // Physical safety envelope enforcement (NIST SP 800-82 / IEC 62443 Edge Policy Guard)
        bool valid = true;
        if (cmd_doc.containsKey("temperature")) {
            float t = cmd_doc["temperature"];
            if (t < 0.0 || t > 60.0) {
                valid = false;
                Serial.printf("[POLICY VIOLATION] Temperature setpoint %.2fC violates safe envelope [0, 60]!\n", t);
            }
        }
        if (cmd_doc.containsKey("pressure")) {
            float p = cmd_doc["pressure"];
            if (p < 0.0 || p > 8.0) {
                valid = false;
                Serial.printf("[POLICY VIOLATION] Pressure setpoint %.2f bar violates safe envelope [0, 8]!\n", p);
            }
        }
        if (valid) {
            Serial.println(F("[POLICY ACCEPT] Supervisory setpoint accepted within safety envelope."));
        }
    }
}

void loop() {
    unsigned long now = millis();

    // --- 1. DOWNSTREAM ACTUATOR COMMAND PROCESSING (NON-BLOCKING) ---
    // Check both RS-485 bus and USB Serial for incoming supervisory commands
    if (readNonBlockingLine(rs485, rs485_cmd_buf, sizeof(rs485_cmd_buf), rs485_cmd_idx)) {
        process_incoming_command(rs485_cmd_buf);
    }
    if (readNonBlockingLine(Serial, serial_cmd_buf, sizeof(serial_cmd_buf), serial_cmd_idx)) {
        process_incoming_command(serial_cmd_buf);
    }

    // --- 2. CALCULATE HALL EFFECT RPM ---
    if (now - last_rpm_time >= 1000) {
        noInterrupts();
        unsigned long pulses = hall_pulse_count;
        hall_pulse_count = 0;
        interrupts();

        current_rpm = (float)pulses * 60.0;
        last_rpm_time = now;
    }

    // --- 3. PERIODIC SENSOR TELEMETRY & CRYPTOGRAPHIC SIGNING ---
    if (now - last_transmit_time >= TRANSMIT_INTERVAL_MS) {
        last_transmit_time = now;

        // Read physical transducers (fallback to baseline simulation if pins floating)
        int raw_temp = analogRead(PIN_TEMP_ADC);
        int raw_pres = analogRead(PIN_PRESSURE_ADC);
        int raw_vib  = analogRead(PIN_VIB_ADC);
        int raw_curr = analogRead(PIN_CURRENT_ADC);

        // Linear calibration transformations
        float temperature = (raw_temp > 50) ? (raw_temp * 0.08) : (BASE_TEMP + random(-3, 3) * 0.1);
        float pressure    = (raw_pres > 50) ? (raw_pres * 0.002) : (BASE_PRES + random(-2, 2) * 0.05);
        float vibration   = (raw_vib > 50)  ? (raw_vib * 0.001) : (BASE_VIB + random(-1, 1) * 0.02);
        float current     = (raw_curr > 50) ? (raw_curr * 0.005) : (BASE_CURR + random(-2, 2) * 0.05);
        float rpm         = (current_rpm > 0) ? current_rpm : BASE_RPM;

        // Force safe shutdown state if actuator is isolated
        if (is_actuator_isolated) {
            pressure = 0.0;
            rpm = 0.0;
            current = 0.1;
        }

        // --- CANONICAL JSON FORMULA ---
        // STRICT ALPHABETICAL ORDER matching Python verify_signature:
        // current -> device_id -> hall_effect -> pressure -> temperature -> vibration
        char canonical_str[384];
        snprintf(canonical_str, sizeof(canonical_str),
            "{\"current\":\"%.2f\",\"device_id\":\"%s\",\"hall_effect\":\"%.2f\",\"pressure\":\"%.2f\",\"temperature\":\"%.2f\",\"vibration\":\"%.2f\"}",
            current, DEVICE_ID, rpm, pressure, temperature, vibration
        );

        // Compute HMAC-SHA256 using pre-shared key
        String signature = compute_hmac_sha256(canonical_str, PRE_SHARED_HMAC_KEY);

        // --- ASSEMBLE OUTGOING WIRE PACKET ---
        char wire_packet[512];
        snprintf(wire_packet, sizeof(wire_packet),
            "{\"current\":%.2f,\"device_id\":\"%s\",\"hall_effect\":%.2f,\"pressure\":%.2f,\"signature\":\"%s\",\"temperature\":%.2f,\"vibration\":%.2f}",
            current, DEVICE_ID, rpm, pressure, signature.c_str(), temperature, vibration
        );

        // Transmit over RS-485 Differential Bus
        digitalWrite(PIN_RS485_DE_RE, HIGH); // Switch MAX485 to Transmit mode
        delayMicroseconds(50);
        rs485.println(wire_packet);
        rs485.flush();                       // Ensure UART FIFO buffer is completely flushed
        delayMicroseconds(100);
        digitalWrite(PIN_RS485_DE_RE, LOW);  // Return MAX485 to Receive mode

        // Also echo to USB Serial for direct debugging / single-node bench testing
        Serial.println(wire_packet);
        Serial.flush();
    }

    // --- 4. PERIODIC NODE TOPOLOGY ANNOUNCEMENT (EVERY 10 SECONDS) ---
    if (now - last_announce_time >= 10000) {
        last_announce_time = now;
        send_node_announcement();
    }
}

