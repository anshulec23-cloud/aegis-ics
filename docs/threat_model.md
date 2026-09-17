# Aegis ICS: Industrial Zero-Trust Threat Model & Risk Taxonomy (v2.5.2)

## 1. System Overview & Scope
Aegis ICS protects critical Operational Technology (OT) and Industrial Control Systems (ICS) at Purdue Levels 0, 1, and 2. The boundary encloses:
- **Edge Microcontrollers & Sensor Nodes**: ESP32 field units measuring temperature, pressure, vibration, rotor Hall effect (RPM), and CT line current.
- **Physical Communication Bus**: RS-485 serial multidrop bus with UART gateway interfacing the supervisory server.
- **Supervisory Gateway & Physical Enforcer**: High-performance zero-trust enforcer enforcing cryptographic signatures, multi-variable physical limits, and autonomous hardware micro-segmentation.
- **Operator SCADA Presentation Tier**: Standalone desktop PyWebView and web SCADA interface with NIST SP 800-61 incident guidance.

---

## 2. Threat Actors & Capabilities

| Threat Actor | Motivation | Capabilities | Profile Level |
|---|---|---|---|
| **Nation-State Advanced Persistent Threat (APT)** | Strategic sabotage, turbine rotor resonance, catalytic reactor runaway | Firmware reverse-engineering, zero-day injection, coordinated multi-variable stress attacks | Tier 5 (Stuxnet, Industroyer2) |
| **Rogue Internal Operator / Disgruntled Insider** | Sabotage, extortion, physical safety bypass | Physical console access, valid login credentials, intentional rule modification | Tier 3 (Insider Threat) |
| **Industrial Ransomware Operator** | Financial extortion, operational downtime | Lateral network movement, telemetry spoofing, denial of service | Tier 4 (Colonial Pipeline, Ekans) |
| **Untrusted Supply-Chain Hardware** | Subversion of cryptographic integrity | Modified third-party firmware, hardcoded key extraction | Tier 3 (Supply Chain) |

---

## 3. Threat Vectors & Attack Scenarios

### 3.1 Scenario A: Stuxnet-Style Coordinated Resonance Attack
- **Mechanism**: The adversary accelerates Turbine Generator 04 rotor RPM beyond mechanical resonance (e.g. >3,000 RPM) while artificially suppressing vibration telemetry or holding pressure constant.
- **Impact**: Mechanical catastrophic disintegration of the rotor assembly, loss of life, facility destruction, and up to $850,000 in immediate financial asset loss.
- **Aegis ICS Defense**:
  - Multi-variable cross-parameter physical safety enforcer evaluates joint mathematical limits.
  - Retrained 5-feature Random Forest ML anomaly classifier detects joint divergence in real time.
  - Autonomous hardware isolation relay disconnects motor control within 50 milliseconds.

### 3.2 Scenario B: Rogue HMAC Spoofing & Replay Attack
- **Mechanism**: Adversary intercepts or generates forged telemetry packets with altered setpoints without possessing the device pre-shared key.
- **Impact**: False setpoint drift, reactor overheating, and misleading operator indicators.
- **Aegis ICS Defense**:
  - Strict Canonical JSON serialization with HMAC-SHA256 verification.
  - Per-device cryptographic key isolation (`security.py`).
  - Cryptographic rejection drops packets immediately and triggers audit violation logging.

### 3.3 Scenario C: Exothermic Catalytic Runaway (Thermal Creep)
- **Mechanism**: Stealthy, low-amplitude thermal drift gradually elevating reactor temperature toward 60°C to induce vessel breach.
- **Impact**: Toxic runaway reaction, chemical spill, thermal explosion.
- **Aegis ICS Defense**:
  - Rolling mean historical deviation detection ($S_{\text{history}}$) in the Continuous Trust Engine.
  - Early warning amber annunciator alerts operator at T-60s before high-pressure trip.

### 3.4 Scenario D: Physical Tampering & Unauthorized Console Access
- **Mechanism**: An adversary attempts setpoint modifications from an unauthorized terminal or zone.
- **Impact**: Safety boundary override without attribution.
- **Aegis ICS Defense**:
  - 3D physical location tagging (`X, Y, Z`) cryptographically recorded for every login and configuration change.
  - Inverted boundary rejection (e.g., $T_{\text{max}} < T_{\text{min}}$ rejected with audit trail).

---

## 4. Security Controls & Defensive Taxonomy (NIST SP 800-82 / SP 800-61)

```
[ Field Sensor Nodes ] (ESP32 / RTU / PLC)
         │
         ▼  (HMAC-SHA256 Signed Wire Packet)
[ RS-485 / UART Serial Gateway Layer ]
         │
         ▼
[ Aegis Multi-Layer Enforcement Pipeline ]
  ├─ 1. Canonical Schema & Freshness Verification
  ├─ 2. Cryptographic HMAC-SHA256 Signature Audit
  ├─ 3. Multi-Variable Physical Stress Safety Boundary
  ├─ 4. 5-Feature Random Forest ML Anomaly Classification
  └─ 5. Continuous 4-Parameter Trust Engine (Tfinal)
         │
         ├─ Nominal (Tfinal >= 0.50) ──► SCADA Live Stream & Digital Twin
         │
         └─ Compromised (Tfinal < 0.40) ──► Autonomous Hardware Relay Open
                                              + NIST SP 800-61 Incident Advisor SOP
                                              + Multi-Tone Annunciator Chime
```

---

## 5. Residual Risk & Mitigation Strategy
- **Physical Wire Tapping**: Mitigated via RS-485 differential signaling and end-to-end payload signature hashing.
- **Host Compromise**: Standalone executable (`AegisICS.exe`) packages Python runtime without external dependencies, with SQLite integrity checks and CSRF-tokenized API gateways.
