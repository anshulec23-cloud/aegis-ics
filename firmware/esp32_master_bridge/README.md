# Aegis ICS — Master Bridge Firmware

Scheduling relay between the Aegis host (USB serial, 115200) and any number of slaves on a half-duplex RS-485 bus. The bridge holds **no keys** and makes no security decisions: every frame is authenticated end-to-end between slave and host.

- **Polling:** polls each known slave in turn (`{"type":"POLL","id":...}`) and forwards its reply, so slaves never talk over each other.
- **Discovery:** opens a discovery window every 10 s or when the host sends `DISCOVER`. New slaves join the poll list automatically; silent ones drop off after 20 s.
- **Commands:** host `CMD`/`WELCOME` frames are put on the bus between polls; the addressed slave's `ACK` is forwarded back.
- **Topology:** sends a `BUS_TOPOLOGY` frame (slave list and count) to the host every 3 s.

| Pin | Function |
|---|---|
| 16 / 17 / 4 | RS-485 RX / TX / DE+RE |
| 2 | Activity LED |

Build: Arduino IDE or `arduino-cli compile --fqbn esp32:esp32:esp32 firmware/esp32_master_bridge`. Full guide: [`../README.md`](../README.md).
