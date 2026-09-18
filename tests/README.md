# Aegis ICS — Automated Quality Assurance & Test Suite

This directory contains the comprehensive automated test suite for validating all cryptographic, mathematical, physical safety, and API mechanisms in **Aegis ICS v2.5.2**.

---

## Test Suite Overview (`test_full_suite.py`)

The suite contains **46 automated test modules** providing 100% pass rate across:

1. **Database & User Authentication**: Table creation, credential hashing, spatial coordinate audit logs, and schema auto-migration.
2. **Cryptographic HMAC Security**: Canonical JSON formatting, 2-decimal float precision, deterministic HMAC-SHA256 signature calculation, and per-node key isolation.
3. **Stuxnet-Proof Safety Rules**: Single-parameter boundary enforcement, anti-inversion validation, and coordinated multi-variable stress prevention (blocking high temperature when system pressure is elevated).
4. **Machine Learning Model Inference**: Synthetic 5-feature inference against `rf_model.pkl` verifying nominal classification vs. Stuxnet resonance, bearing failure, and thermal runaway.
5. **Continuous Mathematical Trust Engine**: Verification of $S_{\text{anomaly}}$, $S_{\text{signature}}$, $S_{\text{history}}$, and $S_{\text{stability}}$ scoring and low-confidence fallback penalties.
6. **Autonomous Microsegmentation & Interlocks**: Quarantining compromised nodes, returning HTTP 403 on subsequent packets, and dispatching physical UART `ISOLATE` commands.
7. **Cyber-Financial Governance (FAIR)**: Testing TEF, LEF, SLE, ALE, ARO, MTTR downtime liabilities, statutory regulatory exposure, and 12-point Monte Carlo loss distributions.
8. **NIST SP 800-82 Incident PDF Generation**: Verification of binary PDF output generated via ReportLab, ensuring valid PDF header, structure, and tables.
9. **Serial Gateway Parsing**: Robust multi-format parsing across canonical JSON, CSV, and key-value formats.
10. **Concurrency & Load Stress**: Multi-threaded simulated client requests under high volume.
11. **Security Payload Fuzzing**: Testing system resilience against SQL injection, XSS vectors, NaN values, infinite floats, and malformed strings.
12. **Air-Gapped Static Asset Verification**: Verifying offline presence and integrity of bundled `chart.umd.js` and `tailwind.min.css`.

---

## Test Database Isolation

All automated tests use an isolated database (`tests/test_aegis.db` via `DATABASE_URL=sqlite:///tests/test_aegis.db`). This guarantees that test runs **never** pollute, modify, or corrupt the production rules or audit records in `aegis_v2.db`.

---

## Running the Tests

### On Windows:
```powershell
python -m pytest tests/ -v
```

### On Linux (Debian / MX Linux / WSL):
```bash
python3 -m pytest tests/ -v
```
