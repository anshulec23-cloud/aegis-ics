/**
 * =============================================================================================
 * Aegis ICS — Master Bridge Firmware (protocol v1, polled RS-485 bus)
 * Target : ESP32 / ESP32-WROOM-32 (Arduino-ESP32 core 2.x or 3.x), ArduinoJson 7.x
 *
 * Role: a transparent, *scheduling* relay between the Aegis host (USB serial) and any number
 * of slave nodes on a half-duplex RS-485 bus. The bridge holds no keys and makes no security
 * decisions: authentication happens end-to-end between each slave and the host.
 *
 * Bus discipline (fixes uncoordinated slave transmission, debug report F5):
 *   - Slaves only talk when addressed. The bridge polls every known slave in turn with
 *     {"type":"POLL","id":X} and forwards the single reply to the host.
 *   - Every DISCOVERY_INTERVAL_MS (and on the host's DISCOVER) it opens a discovery window:
 *     {"type":"DISCOVER","v":1}; slaves answer HELLO after a random delay. New IDs join the
 *     poll list automatically, so slaves can be added or replaced at any time (no limit
 *     other than MAX_SLAVES).
 *   - Host frames (CMD / WELCOME / legacy commands) are sent between polls; the bridge then
 *     listens for the addressed slave's ACK and forwards it.
 *   - A BUS_TOPOLOGY summary goes to the host every TOPOLOGY_INTERVAL_MS.
 * =============================================================================================
 */

#include <Arduino.h>
#include <ArduinoJson.h>

#define RS485_RX_PIN          16
#define RS485_TX_PIN          17
#define RS485_DIR_PIN         4     // DE+RE (HIGH = transmit)
#define STATUS_LED_PIN        2

#define BAUD                  115200
#define AEGIS_LINE_MAX              768
#define MAX_SLAVES            32
#define POLL_REPLY_TIMEOUT_MS 120   // a TEL frame (~350 B) takes ~31 ms at 115200 baud
#define CMD_REPLY_TIMEOUT_MS  250
#define DISCOVERY_WINDOW_MS   450   // slaves reply within a random 0-300 ms slot
#define DISCOVERY_INTERVAL_MS 10000
#define TOPOLOGY_INTERVAL_MS  3000
#define POLL_GAP_MS           40
#define SLAVE_EXPIRY_MS       20000 // dropped from the poll list after this much silence
#define HOST_QUEUE_LEN        8
#define BRIDGE_VERSION        "2.6.0"

HardwareSerial rs485(2);

struct Slave {
    char id[24];
    uint32_t last_seen_ms;
    uint32_t frames;
    uint16_t misses;
    bool used;
};

Slave slaves[MAX_SLAVES];
int poll_cursor = 0;

char host_queue[HOST_QUEUE_LEN][AEGIS_LINE_MAX];
int q_head = 0, q_count = 0;

char bus_buf[AEGIS_LINE_MAX]; size_t bus_len = 0;
char host_buf[AEGIS_LINE_MAX]; size_t host_len = 0;

uint32_t last_discovery_ms = 0, last_topology_ms = 0, last_poll_ms = 0;
bool discovery_requested = true;

// ------------------------------------------------------------------------ helpers ---
static void bus_send(const char *line) {
    digitalWrite(RS485_DIR_PIN, HIGH);
    delayMicroseconds(60);
    rs485.println(line);
    rs485.flush();
    delayMicroseconds(60);
    digitalWrite(RS485_DIR_PIN, LOW);
}

static bool read_line(Stream &s, char *buf, size_t &len) {
    while (s.available()) {
        char c = (char)s.read();
        if (c == '\r') continue;
        if (c == '\n') { buf[len] = '\0'; bool has = len > 0; len = 0; return has; }
        if (len < AEGIS_LINE_MAX - 1) buf[len++] = c; else len = 0;
    }
    return false;
}

static int find_slave(const char *id) {
    for (int i = 0; i < MAX_SLAVES; i++)
        if (slaves[i].used && !strcmp(slaves[i].id, id)) return i;
    return -1;
}

static void note_slave(const char *id) {
    if (!id || !*id || strlen(id) >= sizeof(slaves[0].id)) return;
    int i = find_slave(id);
    if (i < 0) {
        for (i = 0; i < MAX_SLAVES && slaves[i].used; i++) {}
        if (i == MAX_SLAVES) return;  // table full
        slaves[i] = Slave{};
        strncpy(slaves[i].id, id, sizeof(slaves[i].id) - 1);
        slaves[i].used = true;
    }
    slaves[i].last_seen_ms = millis();
    slaves[i].frames++;
    slaves[i].misses = 0;
}

// Forward one bus line to the host and learn the sender's id.
static void forward_bus_line(char *line) {
    Serial.println(line);
    if (line[0] != '{') return;
    JsonDocument filter;
    filter["id"] = true;
    filter["device_id"] = true;
    JsonDocument doc;
    if (deserializeJson(doc, line, DeserializationOption::Filter(filter))) return;
    const char *id = doc["id"] | (doc["device_id"] | "");
    note_slave(id);
    digitalWrite(STATUS_LED_PIN, !digitalRead(STATUS_LED_PIN));
}

// Listen on the bus for up to timeout_ms; forward everything. Returns lines received.
static int listen_bus(uint32_t timeout_ms, int max_lines) {
    uint32_t start = millis();
    int got = 0;
    while (millis() - start < timeout_ms && got < max_lines) {
        if (read_line(rs485, bus_buf, bus_len)) {
            forward_bus_line(bus_buf);
            got++;
        }
        if (read_line(Serial, host_buf, host_len)) {   // keep the host side responsive
            if (q_count < HOST_QUEUE_LEN) {
                strncpy(host_queue[(q_head + q_count) % HOST_QUEUE_LEN], host_buf, AEGIS_LINE_MAX - 1);
                q_count++;
            }
        }
        delay(1);
    }
    return got;
}

static void emit_topology() {
    JsonDocument doc;
    doc["system"] = "Aegis Master Concentrator";
    doc["type"] = "BUS_TOPOLOGY";
    doc["status"] = "ONLINE";
    doc["version"] = BRIDGE_VERSION;
    JsonArray list = doc["slaves"].to<JsonArray>();
    int n = 0;
    for (int i = 0; i < MAX_SLAVES; i++) {
        if (!slaves[i].used) continue;
        list.add(slaves[i].id);
        n++;
    }
    doc["slave_count"] = n;
    char out[2048];
    serializeJson(doc, out, sizeof(out));
    Serial.println(out);
}

static void expire_slaves() {
    uint32_t now = millis();
    for (int i = 0; i < MAX_SLAVES; i++)
        if (slaves[i].used && now - slaves[i].last_seen_ms > SLAVE_EXPIRY_MS) slaves[i].used = false;
}

// ------------------------------------------------------------------- host frames ---
static void handle_host_line(const char *line) {
    if (line[0] != '{') return;
    JsonDocument filter;
    filter["type"] = true;
    filter["command"] = true;
    JsonDocument doc;
    if (deserializeJson(doc, line, DeserializationOption::Filter(filter))) return;
    const char *type = doc["type"] | "";
    const char *legacy = doc["command"] | "";
    if (!strcmp(type, "DISCOVER") || !strcmp(legacy, "DISCOVER") || !strcmp(legacy, "GET_TOPOLOGY")) {
        discovery_requested = true;
        return;
    }
    // CMD, WELCOME and legacy v0 commands: put on the bus, then collect the reply (ACK).
    bus_send(line);
    listen_bus(CMD_REPLY_TIMEOUT_MS, 1);
}

static void drain_host_queue() {
    while (q_count > 0) {
        char line[AEGIS_LINE_MAX];
        strncpy(line, host_queue[q_head], AEGIS_LINE_MAX - 1);
        line[AEGIS_LINE_MAX - 1] = '\0';
        q_head = (q_head + 1) % HOST_QUEUE_LEN;
        q_count--;
        handle_host_line(line);
    }
}

// ----------------------------------------------------------------------- schedule ---
static void run_discovery() {
    bus_send("{\"type\":\"DISCOVER\",\"v\":1}");
    listen_bus(DISCOVERY_WINDOW_MS, MAX_SLAVES);
    last_discovery_ms = millis();
    discovery_requested = false;
}

static void poll_next_slave() {
    for (int tries = 0; tries < MAX_SLAVES; tries++) {
        poll_cursor = (poll_cursor + 1) % MAX_SLAVES;
        if (!slaves[poll_cursor].used) continue;
        char poll[64];
        snprintf(poll, sizeof poll, "{\"id\":\"%s\",\"type\":\"POLL\"}", slaves[poll_cursor].id);
        bus_send(poll);
        if (listen_bus(POLL_REPLY_TIMEOUT_MS, 1) == 0) slaves[poll_cursor].misses++;
        return;
    }
}

void setup() {
    Serial.begin(BAUD);
    rs485.begin(BAUD, SERIAL_8N1, RS485_RX_PIN, RS485_TX_PIN);
    pinMode(RS485_DIR_PIN, OUTPUT);
    digitalWrite(RS485_DIR_PIN, LOW);
    pinMode(STATUS_LED_PIN, OUTPUT);
    for (int i = 0; i < MAX_SLAVES; i++) slaves[i].used = false;
    delay(300);
    Serial.println(F("{\"system\":\"Aegis Master Concentrator\",\"status\":\"ONLINE\",\"version\":\"" BRIDGE_VERSION
                     "\",\"bridge_id\":\"MASTER_BRIDGE_01\",\"protocol\":1}"));
}

void loop() {
    uint32_t now = millis();

    if (read_line(Serial, host_buf, host_len) && q_count < HOST_QUEUE_LEN) {
        strncpy(host_queue[(q_head + q_count) % HOST_QUEUE_LEN], host_buf, AEGIS_LINE_MAX - 1);
        q_count++;
    }
    drain_host_queue();   // host commands take priority over routine polling

    if (discovery_requested || now - last_discovery_ms > DISCOVERY_INTERVAL_MS) {
        run_discovery();
    } else if (now - last_poll_ms >= POLL_GAP_MS) {
        poll_next_slave();
        last_poll_ms = millis();
    }

    // Unsolicited lines (should not happen on a polled bus) are still forwarded.
    if (read_line(rs485, bus_buf, bus_len)) forward_bus_line(bus_buf);

    if (now - last_topology_ms > TOPOLOGY_INTERVAL_MS) {
        expire_slaves();
        emit_topology();
        last_topology_ms = now;
    }
}
