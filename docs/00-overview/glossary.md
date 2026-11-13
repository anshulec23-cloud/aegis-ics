# Glossary

| Term | Meaning in this project |
|---|---|
| **ACK** | Acknowledgement frame from a device confirming a command (planned; not implemented yet) |
| **ALE / SLE / ARO** | Annualised Loss Expectancy = Single Loss Expectancy × Annualised Rate of Occurrence (FAIR / classic risk terms) |
| **Anomaly** | A telemetry row flagged by a rule breach, the Random Forest, or a bad signature (`telemetry_logs.is_anomaly`) |
| **Audit log** | `audit_logs` table of operator and system actions |
| **Bridge / master concentrator** | ESP32 that relays between the RS-485 bus and the host's USB port |
| **Canonical JSON** | Deterministic serialisation (sorted keys, fixed float formatting) used for HMAC signing |
| **Coupling invariant** | Hard rule on combined variables: no temperature setpoint ≥ 45 °C while pressure ≥ 6 bar, and vice versa |
| **DEGRADED / SUSPICIOUS / CRITICAL / TRUSTED** | Trust bands (≥0.5 / ≥0.4 / <0.4 / ≥0.8) |
| **FAIR** | Factor Analysis of Information Risk, a quantitative cyber-risk framework |
| **FDI** | False Data Injection: forged sensor values |
| **Gateway** | `serial_gateway.py` thread that reads the serial port and forwards frames |
| **HMAC-SHA256** | Keyed hash used to sign frames with a pre-shared per-device key |
| **Isolation / quarantine / micro-segmentation** | `device_states.is_isolated = True` plus an `ISOLATE` command that opens the node's relay |
| **NSPN** | Neural Safety Policy Network: MLP estimating P(safe) for a (state, setpoint) pair |
| **Purdue model** | ICS reference architecture levels 0 (process) to 5 (enterprise) |
| **Rejoin / rearm** | Clearing quarantine and re-energising the relay (`REARM`) |
| **RF** | Random Forest anomaly classifier |
| **RS-485** | Differential multi-drop serial bus used between field nodes |
| **Setpoint** | Operator command `set_temp` / `set_pressure` |
| **SSE** | Server-Sent Events: one-way HTTP push stream to the dashboard |
| **Station** | A dashboard page (01–07) |
| **Stuxnet-style attack** | Coordinated manipulation of several variables that each look normal in isolation |
| **Trust score** | `0.35(1−S_anomaly)+0.30 S_signature+0.20 S_history+0.15 S_stability` |
| **WAL** | SQLite write-ahead-log journal mode |
