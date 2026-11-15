/**
 * =============================================================================================
 * Aegis ICS — Slave Sensor Node Firmware (protocol v1, zero-touch enrollment)
 * Target : ESP32 / ESP32-WROOM-32 (Arduino-ESP32 core 2.x or 3.x)
 * Libs   : ArduinoJson 7.x, mbedTLS (bundled with the ESP32 core), Preferences (NVS)
 *
 * ONE image for every slave. Nothing is configured per node and no key is compiled in:
 *   - Device ID derived from the chip's eFuse MAC        ->  "ESP32_A1B2C3"
 *   - X25519 identity generated on first boot, kept in NVS
 *   - Session key derived from the host's WELCOME (X25519 + HKDF-SHA256), kept in NVS
 *   - Only transmits when addressed by the master (POLL / DISCOVER / CMD) -> no bus collisions
 *   - Every command is verified (HMAC + host sequence number) and answered with a signed ACK
 *   - Trip state survives reboots (a quarantined node boots tripped); task watchdog enabled
 *   - Floating / shorted sensors are reported as faults, never replaced with fake values
 *
 * Protocol: docs/01-architecture/protocols.md   Design: docs/adr/0006-zero-touch-enrollment.md
 * Test vectors shared with the host: tests/security/protocol_v1_vectors.json
 *
 * Factory reset (forget identity + key, e.g. when re-deploying a board): hold the BOOT button
 * (GPIO0) while powering up until the status LED blinks rapidly (~3 s).
 * =============================================================================================
 */

#include <Arduino.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <esp_arduino_version.h>
#include <esp_random.h>
#include <esp_task_wdt.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>

// ---------------------------------------------------------------------------- pins ---
#define PIN_RS485_RX        16   // MAX485 RO
#define PIN_RS485_TX        17   // MAX485 DI
#define PIN_RS485_DE_RE     4    // MAX485 DE+RE (HIGH = transmit)
#define PIN_TEMP_ADC        34   // LM35 / thermocouple amplifier
#define PIN_PRESSURE_ADC    35   // 0.5-4.5 V pressure transducer (via divider)
#define PIN_VIB_ADC         32   // piezo / analog accelerometer
#define PIN_HALL_INTERRUPT  33   // A3144 hall pulse input
#define PIN_CURRENT_ADC     36   // ACS712 current sensor
#define PIN_ACTUATOR_RELAY  25   // trip relay (HIGH = energised / running)
#define PIN_HEATER_PWM      26   // temperature setpoint actuator output (PWM)
#define PIN_PUMP_PWM        27   // pressure setpoint actuator output (PWM)
#define PIN_STATUS_LED      2
#define PIN_BOOT_BUTTON     0

#define FIRMWARE_VERSION    "2.6.0"
#define BUS_BAUD            115200
#define AEGIS_LINE_MAX            640
#define USB_FREE_RUN_MS     1000   // telemetry period when wired directly to the host over USB
#define POLL_SILENCE_MS     5000   // no POLL for this long => not on a polled RS-485 bus
#define CONTROL_PERIOD_MS   500
#define WDT_TIMEOUT_S       8

// Sensor plausibility window (raw 12-bit ADC). Outside = floating or shorted input.
#define ADC_FAULT_LOW       50
#define ADC_FAULT_HIGH      4090

// Device-side safety envelope (independent of the host's checks).
#define SP_TEMP_MIN 0.0f
#define SP_TEMP_MAX 60.0f
#define SP_PRES_MIN 0.0f
#define SP_PRES_MAX 8.0f

HardwareSerial rs485(2);
Preferences nvs;

// ---------------------------------------------------------------------------- state ---
struct Reading { bool ok; float value; };  // declared first: Arduino generates prototypes early

char device_id[16];
uint8_t dev_priv[32];
uint8_t dev_pub[32];
char dev_pub_hex[65];
char session_key[65];          // 64 hex chars, "" until enrolled
bool enrolled = false;
uint32_t host_seq = 0;         // last accepted host command sequence (persisted)
uint32_t boot_id = 0;          // random per power-up
uint32_t tx_seq = 0;           // our frame sequence within this boot
bool tripped = false;
float sp_temp = NAN, sp_pres = NAN;

volatile uint32_t hall_pulses = 0;
float rpm = 0.0f;
uint32_t last_rpm_ms = 0, last_poll_ms = 0, last_usb_tel_ms = 0, last_control_ms = 0;

char rs485_buf[AEGIS_LINE_MAX]; size_t rs485_len = 0;
char usb_buf[AEGIS_LINE_MAX];   size_t usb_len = 0;

void IRAM_ATTR on_hall_pulse() { hall_pulses = hall_pulses + 1; }

// --------------------------------------------------------------------------- utils ---
static int rng(void *, unsigned char *out, size_t len) {
    esp_fill_random(out, len);
    return 0;
}

static void to_hex(const uint8_t *in, size_t len, char *out) {
    static const char *digits = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0F];
    }
    out[2 * len] = '\0';
}

static bool from_hex(const char *in, uint8_t *out, size_t len) {
    if (!in || strlen(in) != 2 * len) return false;
    for (size_t i = 0; i < len; i++) {
        char pair[3] = {in[2 * i], in[2 * i + 1], 0};
        char *end = nullptr;
        out[i] = (uint8_t)strtoul(pair, &end, 16);
        if (*end) return false;
    }
    return true;
}

static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, key, key_len);
    mbedtls_md_hmac_update(&ctx, msg, msg_len);
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

// HMAC over a canonical string with the 64-hex-char session key (same as protocol.sign()).
static void sign_hex(const char *key_hex, const char *canonical, char out_hex[65]) {
    uint8_t mac[32];
    hmac_sha256((const uint8_t *)key_hex, strlen(key_hex), (const uint8_t *)canonical, strlen(canonical), mac);
    to_hex(mac, 32, out_hex);
}

static bool const_time_eq(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    uint8_t diff = (uint8_t)(la ^ lb);
    for (size_t i = 0; i < la && i < lb; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static void fingerprint(const uint8_t pub[32], char out[15]) {
    uint8_t digest[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), pub, 32, digest);
    char hex[13];
    to_hex(digest, 6, hex);
    for (int i = 0; i < 12; i++) hex[i] = toupper(hex[i]);
    snprintf(out, 15, "%.4s-%.4s-%.4s", hex, hex + 4, hex + 8);
}

// ------------------------------------------------------------------------- crypto ---
// X25519 key pair (RFC 7748 little-endian encoding, matching Python's cryptography library).
static bool generate_identity() {
    mbedtls_ecp_group grp; mbedtls_mpi d; mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp); mbedtls_mpi_init(&d); mbedtls_ecp_point_init(&Q);
    size_t olen = 0;
    bool ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) == 0
           && mbedtls_ecdh_gen_public(&grp, &d, &Q, rng, nullptr) == 0
           && mbedtls_mpi_write_binary_le(&d, dev_priv, 32) == 0
           && mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, dev_pub, 32) == 0
           && olen == 32;
    mbedtls_ecp_point_free(&Q); mbedtls_mpi_free(&d); mbedtls_ecp_group_free(&grp);
    return ok;
}

// key = HMAC(PRK, info || 0x01), PRK = HMAC("aegis-ics-v1", X25519(dev_priv, host_pub)),
// info = device_id | "|" | dev_pub | host_pub   (enrollment.derive_session_key on the host)
static bool derive_session_key(const uint8_t host_pub[32], char out_hex[65]) {
    mbedtls_ecp_group grp; mbedtls_mpi d, z; mbedtls_ecp_point Qp;
    mbedtls_ecp_group_init(&grp); mbedtls_mpi_init(&d); mbedtls_mpi_init(&z); mbedtls_ecp_point_init(&Qp);
    uint8_t shared[32];
    bool ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) == 0
           && mbedtls_mpi_read_binary_le(&d, dev_priv, 32) == 0
           && mbedtls_ecp_point_read_binary(&grp, &Qp, host_pub, 32) == 0
           && mbedtls_ecdh_compute_shared(&grp, &z, &Qp, &d, rng, nullptr) == 0
           && mbedtls_mpi_write_binary_le(&z, shared, 32) == 0;
    mbedtls_ecp_point_free(&Qp); mbedtls_mpi_free(&z); mbedtls_mpi_free(&d); mbedtls_ecp_group_free(&grp);
    if (!ok) return false;

    uint8_t zero_check = 0;
    for (int i = 0; i < 32; i++) zero_check |= shared[i];
    if (zero_check == 0) return false;  // low-order point

    static const char salt[] = "aegis-ics-v1";
    uint8_t prk[32];
    hmac_sha256((const uint8_t *)salt, strlen(salt), shared, 32, prk);

    uint8_t info[16 + 1 + 32 + 32 + 1];
    size_t n = strlen(device_id);
    memcpy(info, device_id, n);
    info[n++] = '|';
    memcpy(info + n, dev_pub, 32); n += 32;
    memcpy(info + n, host_pub, 32); n += 32;
    info[n++] = 0x01;
    uint8_t okm[32];
    hmac_sha256(prk, 32, info, n, okm);
    to_hex(okm, 32, out_hex);
    memset(shared, 0, sizeof(shared));
    memset(prk, 0, sizeof(prk));
    return true;
}

#ifdef AEGIS_SELFTEST
// Known-answer test from tests/security/protocol_v1_vectors.json. Build with
// -DAEGIS_SELFTEST (or uncomment the define) and check the USB console for PASS/FAIL.
static void run_selftest() {
    uint8_t save_priv[32], save_pub[32];
    char save_id[16];
    memcpy(save_priv, dev_priv, 32); memcpy(save_pub, dev_pub, 32); strcpy(save_id, device_id);

    uint8_t host_pub[32];
    from_hex("a8abababababababababababababababababababababababababababababab6b", dev_priv, 32);
    from_hex("e3712d851a0e5d79b831c5e34ab22b41a198171de209b8b8faca23a11c624859", dev_pub, 32);
    from_hex("b5bea823d9c9ff576091c54b7c596c0ae296884f0e150290e88455d7fba6126f", host_pub, 32);
    strcpy(device_id, "ESP32_0A1B2C");
    char key[65] = "";
    bool ok = derive_session_key(host_pub, key)
           && !strcmp(key, "9621f0033c62d2a91ae900031dbcbca9636d241f518a0adc55d59725824e7c13");
    char sig[65];
    sign_hex(key, "{\"boot\":1,\"faults\":[],\"id\":\"ESP32_0A1B2C\",\"seq\":1,\"temperature\":\"26.10\","
                  "\"tripped\":false,\"type\":\"TEL\",\"v\":1}", sig);
    ok = ok && !strcmp(sig, "0819048460a637af25d2286c7649ac94e7f9277e042072161616290a8d53ad23");
    Serial.printf("[SELFTEST] protocol v1 key agreement + signature: %s\n", ok ? "PASS" : "FAIL");

    memcpy(dev_priv, save_priv, 32); memcpy(dev_pub, save_pub, 32); strcpy(device_id, save_id);
}
#endif

// ---------------------------------------------------------------------- transport ---
static bool usb_only_tx = false;  // true while free-running to a host on USB

static void bus_send(const char *line) {
    if (usb_only_tx) {
        Serial.println(line);
        return;
    }
    digitalWrite(PIN_RS485_DE_RE, HIGH);
    delayMicroseconds(60);
    rs485.println(line);
    rs485.flush();
    delayMicroseconds(60);
    digitalWrite(PIN_RS485_DE_RE, LOW);
    Serial.println(line);  // mirror on USB (direct-to-host bench use and diagnostics)
}

// Serialise a JsonDocument whose keys were inserted in sorted order (canonical form),
// sign it, append "sig" and transmit.
static void send_signed(JsonDocument &doc) {
    char canonical[AEGIS_LINE_MAX];
    serializeJson(doc, canonical, sizeof(canonical));
    char sig[65];
    sign_hex(session_key, canonical, sig);
    doc["sig"] = sig;
    char wire[AEGIS_LINE_MAX + 80];
    serializeJson(doc, wire, sizeof(wire));
    bus_send(wire);
}

static void fmt2(char *out, size_t n, float v) { snprintf(out, n, "%.2f", v); }

// ------------------------------------------------------------------------- frames ---
static void send_hello() {
    JsonDocument doc;           // keys in sorted order
    doc["boot"] = boot_id;
    doc["enrolled"] = enrolled;
    doc["fw"] = FIRMWARE_VERSION;
    doc["id"] = device_id;
    doc["pub"] = dev_pub_hex;
    JsonArray s = doc["sensors"].to<JsonArray>();
    s.add("temperature"); s.add("pressure"); s.add("vibration"); s.add("hall_effect"); s.add("current");
    doc["type"] = "HELLO";
    doc["v"] = 1;
    char wire[AEGIS_LINE_MAX];
    serializeJson(doc, wire, sizeof(wire));
    bus_send(wire);
}

static void send_ack(uint32_t ack_seq, const char *result, const char *reason) {
    JsonDocument doc;           // sorted: ack, boot, id, reason, result, seq, type, v
    doc["ack"] = ack_seq;
    doc["boot"] = boot_id;
    doc["id"] = device_id;
    if (reason && *reason) doc["reason"] = reason;
    doc["result"] = result;
    doc["seq"] = ++tx_seq;
    doc["type"] = "ACK";
    doc["v"] = 1;
    send_signed(doc);
}

static Reading read_adc(int pin, float scale) {
    int raw = analogRead(pin);
    if (raw <= ADC_FAULT_LOW || raw >= ADC_FAULT_HIGH) return {false, NAN};
    return {true, raw * scale};
}

static Reading r_temp, r_pres, r_vib, r_curr;

static void sample_sensors() {
    r_temp = read_adc(PIN_TEMP_ADC, 0.0806f);      // LM35: 10 mV/C on 3.3 V / 12-bit
    r_pres = read_adc(PIN_PRESSURE_ADC, 0.002f);   // 0..8.19 bar span after divider
    r_vib  = read_adc(PIN_VIB_ADC, 0.001f);
    r_curr = read_adc(PIN_CURRENT_ADC, 0.005f);
}

static void send_telemetry() {
    if (!enrolled) { send_hello(); return; }
    sample_sensors();
    char t[16], p[16], v[16], c[16], h[16], st[16], sp[16];
    JsonDocument doc;           // keys inserted in sorted order (canonical)
    doc["boot"] = boot_id;
    if (r_curr.ok) { fmt2(c, sizeof c, r_curr.value); doc["current"] = c; }
    JsonArray faults = doc["faults"].to<JsonArray>();
    if (!r_curr.ok) faults.add("current");
    if (!r_pres.ok) faults.add("pressure");
    if (!r_temp.ok) faults.add("temperature");
    if (!r_vib.ok) faults.add("vibration");
    fmt2(h, sizeof h, rpm); doc["hall_effect"] = h;
    doc["id"] = device_id;
    if (r_pres.ok) { fmt2(p, sizeof p, r_pres.value); doc["pressure"] = p; }
    doc["seq"] = ++tx_seq;
    if (!isnan(sp_pres)) { fmt2(sp, sizeof sp, sp_pres); doc["sp_p"] = sp; }
    if (!isnan(sp_temp)) { fmt2(st, sizeof st, sp_temp); doc["sp_t"] = st; }
    if (r_temp.ok) { fmt2(t, sizeof t, r_temp.value); doc["temperature"] = t; }
    doc["tripped"] = tripped;
    doc["type"] = "TEL";
    doc["v"] = 1;
    if (r_vib.ok) { fmt2(v, sizeof v, r_vib.value); doc["vibration"] = v; }
    send_signed(doc);
}

// ---------------------------------------------------------------------- actuation ---
static void apply_relay() {
    digitalWrite(PIN_ACTUATOR_RELAY, tripped ? LOW : HIGH);
    digitalWrite(PIN_STATUS_LED, tripped ? HIGH : LOW);
}

static void pwm_write(int pin, uint32_t duty) {
#if ESP_ARDUINO_VERSION_MAJOR >= 3
    ledcWrite(pin, duty);
#else
    ledcWrite(pin == PIN_HEATER_PWM ? 0 : 1, duty);
#endif
}

static void pwm_setup() {
#if ESP_ARDUINO_VERSION_MAJOR >= 3
    ledcAttach(PIN_HEATER_PWM, 1000, 8);
    ledcAttach(PIN_PUMP_PWM, 1000, 8);
#else
    ledcSetup(0, 1000, 8); ledcAttachPin(PIN_HEATER_PWM, 0);
    ledcSetup(1, 1000, 8); ledcAttachPin(PIN_PUMP_PWM, 1);
#endif
}

// Simple proportional control towards the operator setpoints. Outputs are forced to zero
// while tripped, when no setpoint is set, or when the feedback sensor is faulted.
static void control_step() {
    uint32_t heat = 0, pump = 0;
    if (!tripped && !isnan(sp_temp) && r_temp.ok)
        heat = (uint32_t)constrain((sp_temp - r_temp.value) * 40.0f, 0.0f, 255.0f);
    if (!tripped && !isnan(sp_pres) && r_pres.ok)
        pump = (uint32_t)constrain((sp_pres - r_pres.value) * 120.0f, 0.0f, 255.0f);
    pwm_write(PIN_HEATER_PWM, heat);
    pwm_write(PIN_PUMP_PWM, pump);
}

static void persist_state() {
    nvs.putUInt("hseq", host_seq);
    nvs.putBool("tripped", tripped);
    nvs.putFloat("sp_t", sp_temp);
    nvs.putFloat("sp_p", sp_pres);
}

// ------------------------------------------------------------------ host commands ---
// Recomputes the canonical form of a host frame (keys arrive sorted from the host) without
// "sig" and checks it against the session key.
static bool verify_frame_signature(JsonDocument &doc, const char *key_hex) {
    const char *sig_in = doc["sig"] | "";
    char sig[65];
    strncpy(sig, sig_in, sizeof sig);
    sig[64] = '\0';
    if (strlen(sig) != 64 || !key_hex || strlen(key_hex) != 64) return false;
    doc.remove("sig");
    char canonical[AEGIS_LINE_MAX];
    serializeJson(doc, canonical, sizeof(canonical));
    char expected[65];
    sign_hex(key_hex, canonical, expected);
    return const_time_eq(expected, sig);
}

static void handle_welcome(JsonDocument &doc) {
    uint8_t host_pub[32];
    if (!from_hex(doc["hpub"] | "", host_pub, 32)) return;
    char candidate[65];
    if (!derive_session_key(host_pub, candidate)) return;
    if (!verify_frame_signature(doc, candidate)) {
        Serial.println(F("[ENROLL] WELCOME signature mismatch - ignored"));
        return;
    }
    strcpy(session_key, candidate);
    enrolled = true;
    host_seq = 0;
    nvs.putString("key", session_key);
    persist_state();
    Serial.println(F("[ENROLL] Session key derived and stored. Device enrolled."));
    send_ack(0, "OK", "enrolled");
}

static void handle_command(JsonDocument &doc) {
    if (!enrolled) return;
    uint32_t seq = doc["seq"] | 0;
    if (!verify_frame_signature(doc, session_key)) { send_ack(seq, "BAD_SIG", "signature check failed"); return; }
    if (seq <= host_seq) { send_ack(seq, "REPLAY", "sequence already used"); return; }
    host_seq = seq;

    const char *cmd = doc["cmd"] | "";
    if (!strcmp(cmd, "ISOLATE") || !strcmp(cmd, "SHUTDOWN")) {
        tripped = true; apply_relay(); control_step(); persist_state();
        send_ack(seq, "OK", "relay tripped");
    } else if (!strcmp(cmd, "REARM")) {
        tripped = false; apply_relay(); persist_state();
        send_ack(seq, "OK", "relay energised");
    } else if (!strcmp(cmd, "PING")) {
        persist_state();
        send_ack(seq, "OK", "pong");
    } else if (!strcmp(cmd, "SETPOINT")) {
        const char *param = doc["args"]["param"] | "";
        const char *val_s = doc["args"]["value"] | "";
        char *end = nullptr;
        float value = strtof(val_s, &end);
        bool numeric = val_s[0] && end && *end == '\0';
        bool is_temp = !strcmp(param, "temperature"), is_pres = !strcmp(param, "pressure");
        if (!numeric || (!is_temp && !is_pres)) {
            persist_state(); send_ack(seq, "REJECTED", "invalid setpoint"); return;
        }
        float lo = is_temp ? SP_TEMP_MIN : SP_PRES_MIN, hi = is_temp ? SP_TEMP_MAX : SP_PRES_MAX;
        if (value < lo || value > hi) {
            persist_state(); send_ack(seq, "REJECTED", "outside device envelope"); return;
        }
        if (tripped) { persist_state(); send_ack(seq, "REJECTED", "relay tripped"); return; }
        if (is_temp) sp_temp = value; else sp_pres = value;
        persist_state();
        char reason[48];
        snprintf(reason, sizeof reason, "%s setpoint %.2f applied", param, value);
        send_ack(seq, "OK", reason);
    } else {
        persist_state();
        send_ack(seq, "UNKNOWN_CMD", cmd);
    }
}

static void handle_line(char *line, bool from_usb) {
    if (line[0] != '{') return;
    JsonDocument doc;
    if (deserializeJson(doc, line)) return;
    const char *type = doc["type"] | "";
    const char *target = doc["id"] | "";

    if (!strcmp(type, "DISCOVER") || !strcmp(doc["command"] | "", "DISCOVER")) {
        delay(esp_random() % 300);           // random slot: spread replies on the shared bus
        send_hello();
        return;
    }
    if (strcmp(target, device_id) != 0) return; // not for us
    if (!strcmp(type, "POLL")) { if (!from_usb) last_poll_ms = millis(); send_telemetry(); return; }
    if (!strcmp(type, "WELCOME")) { handle_welcome(doc); return; }
    if (!strcmp(type, "CMD")) { handle_command(doc); return; }
}

static bool read_line(Stream &s, char *buf, size_t &len) {
    while (s.available()) {
        char c = (char)s.read();
        if (c == '\r') continue;
        if (c == '\n') { buf[len] = '\0'; bool has = len > 0; len = 0; return has; }
        if (len < AEGIS_LINE_MAX - 1) buf[len++] = c; else len = 0; // overflow: drop the line
    }
    return false;
}

// ---------------------------------------------------------------------------- setup ---
static void factory_reset_if_requested() {
    pinMode(PIN_BOOT_BUTTON, INPUT_PULLUP);
    uint32_t start = millis();
    while (digitalRead(PIN_BOOT_BUTTON) == LOW) {
        if (millis() - start > 3000) {
            nvs.clear();
            for (int i = 0; i < 20; i++) { digitalWrite(PIN_STATUS_LED, i & 1); delay(50); }
            Serial.println(F("[RESET] Identity and session key erased."));
            return;
        }
        delay(10);
    }
}

static void setup_watchdog() {
#if ESP_ARDUINO_VERSION_MAJOR >= 3
    esp_task_wdt_config_t cfg = {};
    cfg.timeout_ms = WDT_TIMEOUT_S * 1000;
    cfg.trigger_panic = true;
    esp_task_wdt_reconfigure(&cfg);
#else
    esp_task_wdt_init(WDT_TIMEOUT_S, true);
#endif
    esp_task_wdt_add(nullptr);
}

void setup() {
    Serial.begin(BUS_BAUD);
    rs485.begin(BUS_BAUD, SERIAL_8N1, PIN_RS485_RX, PIN_RS485_TX);
    pinMode(PIN_RS485_DE_RE, OUTPUT);
    digitalWrite(PIN_RS485_DE_RE, LOW);
    pinMode(PIN_ACTUATOR_RELAY, OUTPUT);
    pinMode(PIN_STATUS_LED, OUTPUT);
    pinMode(PIN_HALL_INTERRUPT, INPUT_PULLUP);
    attachInterrupt(digitalPinToInterrupt(PIN_HALL_INTERRUPT), on_hall_pulse, FALLING);
    analogReadResolution(12);
    pwm_setup();

    nvs.begin("aegis", false);
    factory_reset_if_requested();

    // Restore trip state FIRST: a quarantined node must come back tripped (fail-safe).
    tripped = nvs.getBool("tripped", false);
    apply_relay();

    uint64_t mac = ESP.getEfuseMac();
    const uint8_t *m = (const uint8_t *)&mac;
    snprintf(device_id, sizeof device_id, "ESP32_%02X%02X%02X", m[3], m[4], m[5]);

    if (nvs.getBytes("priv", dev_priv, 32) != 32 || nvs.getBytes("pub", dev_pub, 32) != 32) {
        if (!generate_identity()) {
            Serial.println(F("[FATAL] Could not generate X25519 identity"));
            while (true) delay(1000);   // watchdog not armed yet: stay safe (relay state already set)
        }
        nvs.putBytes("priv", dev_priv, 32);
        nvs.putBytes("pub", dev_pub, 32);
    }
    to_hex(dev_pub, 32, dev_pub_hex);

    String key = nvs.getString("key", "");
    enrolled = key.length() == 64;
    strncpy(session_key, enrolled ? key.c_str() : "", sizeof session_key);
    host_seq = nvs.getUInt("hseq", 0);
    sp_temp = nvs.getFloat("sp_t", NAN);
    sp_pres = nvs.getFloat("sp_p", NAN);
    boot_id = esp_random() & 0x7FFFFFFF;

    char fp[15];
    fingerprint(dev_pub, fp);
    Serial.printf("[AEGIS] %s firmware %s  fingerprint %s  %s  relay %s\n", device_id, FIRMWARE_VERSION, fp,
                  enrolled ? "ENROLLED" : "AWAITING APPROVAL", tripped ? "TRIPPED" : "ENERGISED");

#ifdef AEGIS_SELFTEST
    run_selftest();
#endif
    setup_watchdog();
    send_hello();
}

// ----------------------------------------------------------------------------- loop ---
void loop() {
    esp_task_wdt_reset();
    uint32_t now = millis();

    if (read_line(rs485, rs485_buf, rs485_len)) handle_line(rs485_buf, false);
    if (read_line(Serial, usb_buf, usb_len)) handle_line(usb_buf, true);

    if (now - last_rpm_ms >= 1000) {
        noInterrupts();
        uint32_t pulses = hall_pulses;
        hall_pulses = 0;
        interrupts();
        rpm = pulses * 60.0f;
        last_rpm_ms = now;
    }

    if (now - last_control_ms >= CONTROL_PERIOD_MS) {
        sample_sensors();
        control_step();
        last_control_ms = now;
    }

    // Wired straight to the host over USB (no master polling us): stream on USB only, so a
    // slave on a polled RS-485 bus never transmits unprompted and the bus stays collision-free.
    uint32_t period = enrolled ? USB_FREE_RUN_MS : 3000;
    if (now - last_poll_ms > POLL_SILENCE_MS && now - last_usb_tel_ms >= period) {
        last_usb_tel_ms = now;
        usb_only_tx = true;
        send_telemetry();   // sends HELLO instead while not enrolled
        usb_only_tx = false;
    }
}
