# Aegis ICS documentation

Everything you need to understand, run, change, review and extend Aegis ICS. The documents describe the code **as it actually behaves** (v2.5.2 / 2.5.3); known gaps are marked ⚠️ and linked to the debug report.

## Start here

| If you are… | Read in this order |
|---|---|
| **New to the project** | [Project overview](00-overview/project-overview.md) → [ARCHITECTURE](01-architecture/ARCHITECTURE.md) → [Getting started](04-development/getting-started.md) |
| **A reviewer / senior engineer** | [DEBUG_REPORT](07-reports/DEBUG_REPORT.md) → [ARCHITECTURE](01-architecture/ARCHITECTURE.md) → [RESTRUCTURE_PLAN](08-roadmap/RESTRUCTURE_PLAN.md) |
| **Working on the code** | [Getting started](04-development/getting-started.md) → [Components](01-architecture/components/) → [Contributing](04-development/contributing.md) → [Testing](04-development/testing.md) |
| **Working on firmware** | [Firmware](01-architecture/components/firmware.md) → [Protocols](01-architecture/protocols.md) |
| **Operating a deployment** | [Runbook](05-operations/runbook.md) → [Configuration](04-development/configuration.md) → [Linux deployment](05-operations/linux-deployment.md) |
| **Writing the paper / evaluating** | [Evaluation](06-research/evaluation.md) → [Trust scoring](06-research/trust-scoring.md) → [ML engines](01-architecture/components/ml-engines.md) → [Paper draft](06-research/paper-draft.md) |

## Map

```text
docs/
├── README.md                         ← you are here
├── 00-overview/
│   ├── project-overview.md           what it is, scope, honest maturity status
│   └── glossary.md                   terms and abbreviations
├── 01-architecture/
│   ├── ARCHITECTURE.md               ★ system architecture (C4 context/containers, flows, data, deployment)
│   ├── data-model.md                 database tables, columns, seeding, migrations
│   ├── protocols.md                  wire formats: telemetry, signing, commands, bridge frames, SSE
│   ├── architecture.html             legacy interactive 5-layer diagram (open in a browser)
│   └── components/                   one page per module
│       ├── backend-flask.md          src/app.py
│       ├── serial-gateway.md         src/serial_gateway.py
│       ├── ml-engines.md             Random Forest + NSPN + training
│       ├── trust-engine.md           src/trust_engine.py
│       ├── safety-enforcer.md        src/safety_enforcer.py
│       ├── analytics-reporting.md    src/analytics.py, src/reporting.py
│       ├── dashboard.md              templates + static
│       ├── desktop-shell.md          src/main.py, tray.py, updater.py
│       └── firmware.md               ESP32 master bridge + slave sensor
├── 02-security/
│   ├── security-model.md             assets, trust boundaries, controls in code, gaps
│   └── threat-model.md               adversaries and attack scenarios
├── 03-api/
│   └── rest-api.md                   every HTTP route with auth, body, responses
├── 04-development/
│   ├── getting-started.md            install, configure, run, simulate
│   ├── configuration.md              all env vars and CLI flags
│   ├── testing.md                    test layout, limitations, target strategy
│   └── contributing.md               workflow, code standards, definition of done
├── 05-operations/
│   ├── runbook.md                    start/stop, quarantine handling, backups, troubleshooting
│   ├── build-pipeline.md             PyInstaller / .deb / tarball builds
│   └── linux-deployment.md           Debian & MX Linux install and services
├── 06-research/
│   ├── evaluation.md                 benchmarks and figures
│   ├── trust-scoring.md              trust score formalism
│   └── paper-draft.md                manuscript draft
├── 07-reports/
│   └── DEBUG_REPORT.md               ★ full debug session: 35 findings, reproduced results, fixes
├── 08-roadmap/
│   └── RESTRUCTURE_PLAN.md           ★ phased plan to v3.0: target layout, migration map, timeline
├── adr/                              architecture decision records (0001–0005 + template)
└── figures/                          benchmark PNGs (written by tests/generate_graphs.py; path kept stable)
```

★ = the three core documents.

## Conventions
- Paths in docs are relative to the repository root unless they're links.
- ⚠️ marks a behaviour that differs from what the README or older docs claim, or that's a known defect.
- Finding IDs (S1, F2, R3 …) refer to [DEBUG_REPORT](07-reports/DEBUG_REPORT.md). Task IDs (P1.3 …) refer to [RESTRUCTURE_PLAN](08-roadmap/RESTRUCTURE_PLAN.md).
- When code changes, update the matching page in the same PR ([contributing](04-development/contributing.md)).
