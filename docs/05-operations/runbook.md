# Operator runbook

Procedures for running Aegis ICS day to day. Installation: [linux-deployment.md](linux-deployment.md). Builds: [build-pipeline.md](build-pipeline.md).

## Start / stop / status
| Platform | Start | Stop | Logs |
|---|---|---|---|
| Linux (systemd) | `sudo systemctl start aegis-ics` | `sudo systemctl stop aegis-ics` | `journalctl -u aegis-ics -f` |
| Linux (SysV, MX Linux) | `sudo service aegis-ics start` | `sudo service aegis-ics stop` | `/var/log/aegis-ics.log` |
| Windows desktop | run `AegisICS.exe` | tray icon → Quit | console when run with `--server` |

Health: `curl http://127.0.0.1:5000/health`.

## Connecting hardware
1. Plug in the master bridge. On Linux, the service user needs the `dialout` group.
2. Dashboard → Station 06 → *Scan* → pick the port flagged as an ESP32 candidate → *Connect*.
3. Expect a `BUS_TOPOLOGY` frame within 3 s and nodes marked LIVE within 10 s.
4. ⚠️ Connecting clears every node's quarantine (known issue S8). Check Station 02 straight after connecting.

## A node goes ISOLATED
1. Open Station 07 and filter category **QUARANTINE**. Read the `AUTO_ISOLATION` reason (bad signature, trust collapse, anomaly).
2. **Bad signature:** check that the firmware key matches `DEVICE_KEY_<id>`, and check for anyone else on the bus. Until S1 is fixed, a single forged HTTP request can also cause this, so check the client IPs in the web-server logs.
3. **Trust collapse / anomaly:** compare live readings with the physical gauges. Look for a failed sensor (F7: a disconnected sensor reports plausible fake values).
4. Fix the root cause, then Station 03 → *Rejoin*. That sends `REARM` and records `MANUAL_REJOIN`.
5. Remember: a node that reboots **re-energises its relay** until the host sends `ISOLATE` again.

## Emergency shutdown
Station 03 → *Emergency shutdown* → target a node or `ALL`. This sends `SHUTDOWN`; relays open. The bridge acknowledges `ALL` with a `COMMAND_ACK` frame. Individual nodes don't acknowledge, so confirm physically.

## Setpoint denied
The response explains why: rule limits, stale telemetry (no fresh data in 120 s for high-risk values), NSPN refusal, or the 45 °C / 6 bar coupling invariant. ⚠️ Approved setpoints aren't applied by the current firmware (F2).

## Backups
SQLite in WAL mode. Back up online with:
```bash
sqlite3 /var/lib/aegis-ics/aegis_v2.db ".backup '/backup/aegis_$(date +%F).db'"
```
Also back up `src/model/` (or the frozen bundle's model directory) and your key material.

## Rotating secrets
- Session key: change `FLASK_SECRET_KEY` (or delete `.aegis_session_key`) and restart; all sessions are logged out.
- Device keys: reflash the node with the new key and update `DEVICE_KEY_<id>` at the same time. The node is quarantined in between.
- Operator password: there is no UI yet. Update the hash in `users` with `werkzeug.security.generate_password_hash`.

## Troubleshooting
| Symptom | Likely cause |
|---|---|
| Nodes 002–004 isolated right after connecting the simulator | F1 (shared HMAC key in the gateway) |
| Setpoint "success" but nothing changes | F2, or no gateway connected (F3) |
| Duplicate telemetry after reconnecting | F4 (two gateway threads); restart the service |
| Garbled frames with more than one slave | F5 (RS-485 collisions) |
| Audit times off by hours | F9 (timezone handling) |
| 500 on audit log filter | F10 (non-numeric `limit`) |
