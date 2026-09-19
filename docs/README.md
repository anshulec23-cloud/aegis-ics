# Aegis ICS — Technical Documentation & Engineering Specifications

Welcome to the technical documentation repository for **Aegis ICS v2.5.2**. This directory provides architectural specifications, threat modeling, mathematical scoring formalisms, empirical benchmark results, deployment guides, and scientific research publications.

---

## Documentation Index & Sitemap

| Document | Format | Description |
|---|---|---|
| [`architecture.html`](architecture.html) | Interactive HTML | Visual 5-layer interactive architecture map detailing Presentation, Intelligence, Zero-Trust Enforcement, Communication, and Field Device layers. |
| [`threat_model.md`](threat_model.md) | Markdown | Industrial threat taxonomy identifying threat actors (APT Tier 5, Insiders, Ransomware), attack scenarios (Stuxnet, HMAC replay, Thermal creep), and NIST defensive controls. |
| [`trust_scoring.md`](trust_scoring.md) | Markdown | Mathematical formalism for the continuous 4-parameter trust scoring engine ($T_{\text{final}}$), historical deviation, signal stability variance, and low-confidence fallback logic. |
| [`linux_deployment.md`](linux_deployment.md) | Markdown | Comprehensive operations and installation guide for **MX Linux (XFCE)** and Debian, covering `.deb` installation, SysVinit scripts, systemd units, and USB serial permissions. |
| [`evaluation.md`](evaluation.md) | Markdown | Empirical evaluation results, cryptographic throughput benchmarks (>12,000 pkts/sec), Neural Safety Policy inference (0.025 ms), microsegmentation reaction latency (12.7 ms), 6 publication-quality empirical figures, and the full 60/60 test pass matrix. |
| [`build_pipeline.md`](build_pipeline.md) | Markdown | Detailed compilation and packaging pipeline documentation for building standalone executables and packages on Windows (`dist/AegisICS.exe`) and Linux (`dist/linux/` ELF, `.deb`, `.tar.gz`). |
| [`paper_draft.md`](paper_draft.md) | Academic Draft | Publication-grade academic manuscript targeted for *IEEE TNNLS*, *IEEE Transactions on Cybernetics*, and *ACM TCPS*, incorporating 6 empirical evaluation figures and FAIR financial modeling. |

---

## Industrial Zero-Trust Enforcement Pipeline

```text
[ Field Sensor Nodes ] (ESP32 / RTU / PLC)
         │
         ▼  (HMAC-SHA256 Signed Wire Packet over RS-485)
[ RS-485 / UART Serial Gateway Layer ] (serial_gateway.py)
         │
         ▼
[ Aegis Multi-Layer Enforcement Pipeline ]
   ├─ 1. Canonical Schema & Freshness Verification (< 120s)
   ├─ 2. Cryptographic HMAC-SHA256 Signature Audit (Per-device key)
   ├─ 3. 6D Local Neural Safety Policy Network (NSPN in neural_policy.py)
   │      - Deep MLP: 6 -> 64 -> 32 -> 16 -> 1 (0.020–0.025 ms CPU inference)
   │      - Proactive command setpoint validation against Stuxnet damage profiles
   ├─ 4. 5-Feature Random Forest ML Anomaly Classification (rf_model.pkl)
   └─ 5. Continuous 4-Parameter Trust Engine (trust_engine.py)
         │
         ├─ Nominal (Tfinal >= 0.50) ──► SCADA Live Stream & 2D Digital Twin
         │
         └─ Compromised (Tfinal < 0.40) ──► Autonomous Hardware Relay Open (12.74 ms)
                                              + NIST SP 800-61 Tactical Incident Advisor SOP
                                              + Multi-Tone Auditory Annunciator Chime
```

---

## Purdue Model Level Mapping

* **Purdue Level 0 (Physical Process)**: Industrial transducers, thermowells, pressure vessels, rotating turbine shafts, and optocoupler isolation relays.
* **Purdue Level 1 (Basic Control)**: ESP32 field microcontrollers executing C/C++ firmware with hardware mbedTLS HMAC signing.
* **Purdue Level 2 (Area Supervisory Control)**: Aegis ICS Edge Gateway executing Python runtime, Flask REST API, SQLite WAL audit engine, FAIR financial modeling, and SCADA dashboard.
