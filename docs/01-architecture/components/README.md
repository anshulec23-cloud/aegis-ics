# Component reference

One page per runtime component. Each page lists responsibility, public surface, internals, dependencies, configuration, known issues (linking to the [debug report](../../07-reports/DEBUG_REPORT.md)), and what changes in the [restructure plan](../../08-roadmap/RESTRUCTURE_PLAN.md).

| Component | Source | Page |
|---|---|---|
| HTTP backend | `src/app.py` | [backend-flask.md](backend-flask.md) |
| Serial gateway and simulator | `src/serial_gateway.py` | [serial-gateway.md](serial-gateway.md) |
| Detection and safety ML | `src/app.py` (`LocalRFModel`), `src/neural_policy.py`, `src/train_model.py` | [ml-engines.md](ml-engines.md) |
| Trust engine | `src/trust_engine.py` | [trust-engine.md](trust-engine.md) |
| Safety enforcer | `src/safety_enforcer.py` | [safety-enforcer.md](safety-enforcer.md) |
| Persistence | `src/database.py` | [../data-model.md](../data-model.md) |
| Security utilities | `src/security.py` | [../../02-security/security-model.md](../../02-security/security-model.md) |
| Risk analytics and PDF reports | `src/analytics.py`, `src/reporting.py` | [analytics-reporting.md](analytics-reporting.md) |
| Web dashboard | `src/templates/`, `src/static/` | [dashboard.md](dashboard.md) |
| Desktop shell | `src/main.py`, `src/tray.py`, `src/updater.py` | [desktop-shell.md](desktop-shell.md) |
| Firmware | `firmware/` | [firmware.md](firmware.md) |
