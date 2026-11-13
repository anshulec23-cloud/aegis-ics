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
| Telemetry signing | Implemented; key management and replay protection missing |
| Quarantine | Works; can be triggered by unauthenticated requests |
| Setpoint dispatch to hardware | **Not working** (protocol mismatch) |
| Command authentication on devices | **Not implemented** |
| ML models | Trained on synthetic data only |
| Tests | 69 tests; security controls disabled during tests |
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
