# Project overview

## In one paragraph
Aegis ICS is a research prototype of a **zero-trust security gateway for industrial control systems**. ESP32 field nodes sign their sensor readings. A Python host verifies the signatures, scores each node's trustworthiness with rules, a Random Forest and a weighted trust formula, and quarantines suspicious nodes by tripping a relay on the node. It also checks every operator setpoint against safety limits and a small neural network before sending it. Operators use a terminal-styled web dashboard, which also produces audit trails, FAIR-style financial risk estimates and NIST-styled PDF reports.

## Problem it addresses
Classic ICS intrusion detection is passive: it alerts after a bad command has already reached the actuator. Aegis explores an **inline** approach:
- authenticate field data (stop spoofing and injection),
- judge commands against the *combined* physical state (stop Stuxnet-style "each value looks fine on its own" attacks),
- contain compromised nodes automatically (micro-segmentation at the relay).

## Scope
| In scope | Out of scope (today) |
|---|---|
| Four-node demo cell (reactor, pump, chiller, turbine) | Real PLC protocols (Modbus, OPC UA, DNP3) |
| Custom JSON over RS-485 / USB | Network IDS, packet capture |
| Single host, single SQLite DB | Clustering, HA, multi-site |
| Single operator role | RBAC, SSO |
| Synthetic-data ML | Validated real-plant detection |

## Maturity (honest status, Nov 2026)
| Area | Status |
|---|---|
| Dashboard, API, simulator | Works end-to-end in software |
| Device onboarding | Automatic discovery of any number of slaves, one-click approval, X25519 key agreement (v2.6) |
| Telemetry signing / replay protection | Per-device keys, boot/seq replay protection (v2.6) |
| Quarantine | Works; survives restarts; devices re-tripped on reconnect/re-enrollment |
| Setpoints / commands to hardware | Signed, verified on the device, acknowledged (v2.6 firmware; compile-check pending) |
| ML models | Trained on synthetic data only |
| Tests | 126 tests with all security controls on, including an end-to-end simulator run |
| Packaging | Windows exe, Linux ELF, `.deb`, tarball scripts |

Details: [Debug report](../07-reports/DEBUG_REPORT.md). Path forward: [Restructure plan](../08-roadmap/RESTRUCTURE_PLAN.md).

## Key ideas worth keeping
1. **Defence in depth on commands:** learned policy plus deterministic invariants plus firmware envelope.
2. **Continuous trust** rather than binary allow/deny.
3. **Fail closed on stale data** for high-risk commands.
4. **Cyber-to-financial translation** (FAIR) to talk to plant management.
5. **Offline-first** UI (vendored assets).

## Where to go next
- New developer: [getting-started](../04-development/getting-started.md), then [ARCHITECTURE](../01-architecture/ARCHITECTURE.md).
- Reviewer or examiner: [DEBUG_REPORT](../07-reports/DEBUG_REPORT.md), [security model](../02-security/security-model.md), [evaluation](../06-research/evaluation.md).
- Operator: [runbook](../05-operations/runbook.md).
