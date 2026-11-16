# Operator runbook

Procedures for running Aegis ICS day to day. Installation: [linux-deployment.md](linux-deployment.md). Builds: [build-pipeline.md](build-pipeline.md).

## Start / stop / status
| Platform | Start | Stop | Logs |
|---|---|---|---|
| Linux (systemd) | `sudo systemctl start aegis-ics` | `sudo systemctl stop aegis-ics` | `journalctl -u aegis-ics -f` |
| Linux (SysV, MX Linux) | `sudo service aegis-ics start` | `sudo service aegis-ics stop` | `/var/log/aegis-ics.log` |
| Windows desktop | run `AegisICS.exe` | tray icon → Quit | console when run with `--server` |

Health: `curl http://127.0.0.1:5000/health`.

## First start
The packaged app opens the **First-run setup** screen to create the admin password. Headless/service installs print the setup URL in the log (`journalctl -u aegis-ics`) and write it to `<data dir>/setup_token.txt`. Open it from the server itself (or an SSH tunnel), since the service only listens on localhost.

## Connecting hardware and enrolling devices
1. Plug in the master bridge. On Linux, the service user needs the `dialout` group (the `.deb` sets that up).
2. Station 06 → *Scan* → pick the port flagged as an ESP32 candidate → *Connect gateway*.
3. Within ~10 s every slave on the bus appears under **Field device enrollment** as **PENDING**. Each slave prints its fingerprint on its USB console at boot; compare them for devices you're not sure about.
4. Name the device and click **APPROVE**. The status becomes APPROVED; "KEY DELIVERY PENDING" disappears once the device confirms its key, and telemetry starts.
5. **Unknown pending device you didn't install:** click **REJECT** and investigate who connected it to the bus.
6. Quarantine survives reconnects and restarts: on connect the gateway re-sends `ISOLATE` to every isolated node, and any quarantined device that re-enrolls is tripped again.

## Adding, replacing or retiring a slave
- **Add:** flash the standard slave image, wire it to the bus, approve it. No configuration and no key handling.
- **Replace a failed board:** the new board has a new ID and fingerprint. Approve it, then **REVOKE** the old entry.
- **Same ID, new key** (board reflashed with a factory reset): the device drops back to PENDING with a `DEVICE_KEY_CHANGED` audit entry. Re-approve only if you did the reset yourself.
- **Re-deploy elsewhere:** hold BOOT at power-up for ~3 s to erase its identity, then revoke it here.

## A node goes ISOLATED
1. Open Station 07 and filter category **QUARANTINE**. Read the `AUTO_ISOLATION` reason.
2. **"N invalid HMAC signatures"** or `SIGNATURE_REJECTED`: someone is injecting frames on the bus, or the device's key no longer matches (it was factory-reset). Check the bus physically; if needed, revoke the device and approve it again.
3. **`REPLAY_REJECTED`:** captured frames are being re-sent on the bus. Treat it as an intrusion.
4. **Trust collapse / anomaly:** compare live readings with the physical gauges. A `faults` entry means a sensor is disconnected or shorted.
5. Fix the root cause, then Station 03 → *Rejoin* (sends `REARM`; the response confirms the device's ACK).
6. A tripped node stays tripped through power cycles until it's rearmed.

## Emergency shutdown
Station 03 → *Emergency shutdown* → target a node or `ALL`. Each enrolled device receives a signed `SHUTDOWN` and acknowledges it; check Station 07 for the ACKs or confirm physically.

## Setpoint denied or not applied
The response explains why. **Host-side:** rule limits, stale telemetry (no data in 120 s for high-risk values), NSPN refusal, or the 45 °C / 6 bar coupling invariant. **Device-side (409):** outside the device envelope (0–60 °C, 0–8 bar) or relay tripped. **504:** sent but no ACK; check the bus and the device.

## Backups
SQLite in WAL mode. Back up online with:
```bash
sqlite3 /var/lib/aegis-ics/aegis_v2.db ".backup '/backup/aegis_$(date +%F).db'"
```
Back up the whole **data directory**: besides the database it holds `host_identity.key`. Losing that key means every device must be re-approved.

## Rotating secrets
- Session key: change `FLASK_SECRET_KEY` (or delete `.aegis_session_key`) and restart; all sessions are logged out.
- Device keys (v1): revoke the device, factory-reset it (BOOT at power-up), and approve it again. A new key pair and session key are created.
- Operator password: there is no UI yet. Update the hash in `users` with `werkzeug.security.generate_password_hash`.

## Troubleshooting
| Symptom | Likely cause |
|---|---|
| No devices appear after connecting | wrong COM port (pick the master, not a slave); RS-485 A/B swapped; slaves unpowered. The master's USB console should show `BUS_TOPOLOGY` with slave ids |
| Device stuck at "KEY DELIVERY PENDING" | WELCOME didn't reach it: check the bus. It's re-sent automatically when the device next announces itself |
| Device keeps returning to PENDING | its key changed (factory reset / reflash / impersonation): verify the fingerprint before approving |
| Setpoint returns 503 | no gateway connected |
| Setpoint returns 504 | device didn't acknowledge within 3 s |
| Telemetry from a legacy (v0) node gets 403 "not provisioned" | legacy firmware needs `DEVICE_KEY_<id>`; better, flash the v1 firmware |
| Can't log in after upgrading from 2.5.x | the legacy default admin password was locked: complete the first-run setup (`setup_token.txt` in the data dir) |
