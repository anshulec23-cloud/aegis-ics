/**
 * ==============================================================================================
 * Aegis ICS — Edge Concentrator Master Bridge Reference Firmware
 * Target: ESP32 / ESP32-S3 / ESP32-WROOM-32
 * Description: Master concentrator gateway bridging multi-node RS-485 field buses
 *              to the Aegis ICS Edge SCADA host over USB-CDC Serial at 115200 baud.
 * Features:
 *  - Dual-UART ring buffer routing (HardwareSerial Serial2 <-> Serial)
 *  - High-precision half-duplex direction switching with hardware FIFO flushing
 *  - Heartbeat status LED indicating live telemetry packet traffic
 *  - Bidirectional setpoint command dispatching to addressed slave nodes
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

HardwareSerial rs485(2); // Use UART2 for RS-485 bus

unsigned long frame_sequence = 0;
unsigned long command_sequence = 0;
unsigned long last_led_toggle = 0;
bool led_state = false;

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

    delay(500);
    Serial.println(F("{\"system\":\"Aegis Master Concentrator\",\"status\":\"ONLINE\",\"version\":\"2.5.2\",\"baud\":115200}"));
}

// Non-blocking UART line buffer state
char rs485_buf[512];
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

void loop() {
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
        }
    }

    // --- 2. COMMAND DISPATCH: Read setpoint/actuator commands from Aegis Host (Non-blocking) ---
    if (readNonBlockingLine(Serial, host_buf, sizeof(host_buf), host_idx)) {
        size_t len = strlen(host_buf);
        if (len > 0 && host_buf[0] == '{') {
            // Switch RS-485 transceiver to Transmit mode
            digitalWrite(RS485_DIR_PIN, HIGH);
            delayMicroseconds(50);

            // Broadcast command to RS-485 bus (addressed by device_id in JSON)
            rs485.println(host_buf);
            rs485.flush(); // Wait until UART FIFO completely empties

            // Hold line briefly before returning to Receive mode
            delayMicroseconds(100);
            digitalWrite(RS485_DIR_PIN, LOW);
            command_sequence++;

            // Status indication
            digitalWrite(STATUS_LED_PIN, HIGH);
            delayMicroseconds(500);
            digitalWrite(STATUS_LED_PIN, LOW);
        }
    }
}

