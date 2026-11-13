# Wire protocols

Three links exist:

```
slave ESP32 ──RS-485 (115200, half-duplex, MAX485, DE/RE=GPIO4)── master ESP32 ──USB-CDC (115200)── host serial_gateway ──HTTP loopback── Flask
```

All framing is **newline-delimited UTF-8 JSON**. There is no length prefix, no CRC beyond the HMAC, no sequence number and no ACK.

---

## 1. Telemetry frame (slave → host)

Emitted by `esp32_slave_sensor.ino` every `TRANSMIT_INTERVAL_MS` (500 ms):

```json
{"current":4.52,"device_id":"ESP32_001","hall_effect":0.00,"pressure":4.21,"signature":"9f…e1","temperature":26.10,"vibration":1.08}
```

| Field | Unit | Source pin | Firmware conversion |
|---|---|---|---|
| temperature | °C | GPIO34 (LM35) | `raw*0.08` (⚠️ random baseline if raw ≤ 50) |
| pressure | bar | GPIO35 | `raw*0.002` |
| vibration | g | GPIO32 | `raw*0.001` |
| hall_effect | RPM | GPIO33 interrupt | pulses/s × 60 |
| current | A | GPIO36 (ACS712) | `raw*0.005` |

When the node is isolated, it reports `pressure=0`, `hall_effect=0`, `current=0.1`.

### Canonical signing string

The signature is computed over the frame **without** `signature`, with:
- keys sorted alphabetically, compact separators `,` and `:`;
- sensor values (`temperature, pressure, humidity, rssi, vibration, hall_effect, current`) rendered as **JSON strings** with two decimals;
- `timestamp` (if present) rendered as a string with three decimals;
- all other fields unchanged.

Example canonical string for the frame above:

```
{"current":"4.52","device_id":"ESP32_001","hall_effect":"0.00","pressure":"4.21","temperature":"26.10","vibration":"1.08"}
```

`signature = hex(HMAC-SHA256(device_key, canonical))`

Implementations: firmware `snprintf` template; host `serial_gateway.canonicalize_payload/sign_message`; server `app.verify_signature._canonicalize`. ⚠️ These are three hand-written copies. `verify_signature` crashes on a non-numeric timestamp, while `canonicalize_payload` stringifies it.

### Alternative input formats accepted by `parse_serial_line`

| Format | Example | Mapping |
|---|---|---|
| JSON with short keys | `{"id":"X","temp":25,"pres":3}` | `temp/pres/vib/hall|rpm/curr/hum` → long names |
| CSV, 5 fields | `25.1,3.2,1.0,1500,4.5` | T,P,V,RPM,I |
| CSV, 1 or 2 fields | `25.1` / `25.1,3.2` | T / T,P |
| key:value | `T:25.1,P:3.2` or `temp=25.1` | t,p,v,h,c aliases |

Non-JSON formats carry no `device_id` (default `ESP32_001` in `plc` mode) and no signature. Since v2.6 the gateway **drops** unsigned frames; it isn't a signing authority. For bench work with sensors that can't sign, `serial_gateway.py --allow-unsigned` signs them with the device key. Never use that in production.

---

## 2. Bridge and discovery frames (master → host)

| Frame | When | Shape |
|---|---|---|
| Boot announcement | bridge start | `{"system":"Aegis Master Concentrator","status":"ONLINE","version":"2.5.2","baud":115200,"bridge_id":"MASTER_BRIDGE_01"}` |
| `BUS_TOPOLOGY` | every 3 s and on `DISCOVER` | `{"system":…,"type":"BUS_TOPOLOGY","status":"ONLINE","slave_count":N,"slaves":[ids],"sensors":{id:[names]}}` |
| `COMMAND_ACK` | after `SHUTDOWN` to `ALL` | `{"type":"COMMAND_ACK","status":"BUS_SHUTDOWN",…}` |
| `NODE_ANNOUNCE` (from slave) | on `DISCOVER`/`SCAN` | `{"type":"NODE_ANNOUNCE","device_id":…,"hardware":"ESP32-WROOM-32","version":…,"is_isolated":bool,"sensors":[…],"sensor_count":n}` |

Slaves are pruned from the bridge's table after 8 s of silence (`SLAVE_TIMEOUT_MS`).

---

## 3. Command frame (host → bridge → slaves)

Produced by `app.py` and enqueued with `serial_gateway.send_command()`, which signs with the target device's key (broadcasts to `ALL` stay unsigned until protocol v1 adds a bus key). Commands are only queued while a gateway is connected, and any command older than `AEGIS_COMMAND_TTL_S` (5 s) is dropped instead of being written late.

```json
{"command":"ISOLATE","action":"ISOLATE","device_id":"ESP32_002","target_device":"ESP32_002","timestamp":1763050000.12,"reason":"…","signature":"…"}
```

| Host sends | Firmware action | Status |
|---|---|---|
| `DISCOVER` (target `ALL`) | bridge broadcasts `{"command":"DISCOVER"}`, emits topology; slaves send `NODE_ANNOUNCE` | works |
| `ISOLATE` | relay GPIO25 LOW, LED on | works (unauthenticated ⚠️) |
| `REARM` | relay HIGH | works (unauthenticated ⚠️) |
| `SHUTDOWN` (device or `ALL`) | relay LOW | works (unauthenticated ⚠️) |
| `setpoint` (`target`,`value`) | none: firmware expects `SETPOINT` + `temperature`/`pressure` keys, and only validates | ⚠️ broken |
| `ping` | none | ⚠️ server fakes the reply |

Addressing: a slave acts if `target_device`/`device_id` is missing, `ALL`, or equal to its own `DEVICE_ID`.

---

## 4. Gateway → Flask (loopback HTTP)

`POST http://127.0.0.1:${FLASK_PORT}/api/telemetry`, JSON body = normalised payload (long field names, `device_id`, optional `timestamp`, `signature`). Responses: `200` accepted, `403` device isolated, `400` bad or expired timestamp, `500` DB error. See [REST API](../03-api/rest-api.md).

---

## 5. Server-Sent Events (Flask → browser)

`GET /api/stream`, `text/event-stream`, one cycle per second. Events: `telemetry` (array of rows), `heartbeat` (`{time, isolated}`), `topology`, `error`.

---

## 6. Gaps to close (tracked in the restructure plan)

- Add `seq` (monotonic per device) and `ts`/boot-nonce to every frame, and reject replays on both sides.
- Firmware must verify command HMAC before acting.
- Command ACK frames (`{"type":"ACK","seq":…,"result":…}`) and host-side timeouts.
- Bus arbitration: master-polled request/response instead of free-running slave transmit.
- One machine-readable protocol spec (JSON Schema) plus shared test vectors used by both pytest and a firmware unit test.
