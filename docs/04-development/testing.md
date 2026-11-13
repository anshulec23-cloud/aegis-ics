# Testing

## Layout
| File | Tests | Scope |
|---|---|---|
| `tests/test_full_suite.py` | 50 | Unit + Flask test-client integration: DB, HMAC, safety enforcer, NSPN, analytics, PDF, gateway parsing, routes, concurrency stress, fuzzing, regressions V1–V5 |
| `tests/test_production_hardware_integration.py` | 10 | Gateway/firmware protocol parity, command dispatch (no real hardware needed) |
| `tests/test_multi_slave_discovery.py` | 5 | Bridge topology and node-announce parsing |
| `tests/test_security_hardening.py` | 4 | Template and static hardening checks |
| `tests/benchmark_suite.py` | n/a (script) | Latency and attack-simulation benchmarks → `tests/benchmark_results/*.json` |
| `tests/generate_graphs.py` | n/a (script) | Renders `docs/figures/*.png` from benchmark JSON |

Run all: `python -m pytest tests -q` · one test: `python -m pytest tests/test_full_suite.py::test_flask_api_routes -q`.

## Test database
Each module sets `DATABASE_URL=sqlite:///tests/test_aegis.db` **before** importing `database`. The file isn't deleted between runs, so state leaks from run to run, and import order decides which module's URL wins. Delete `tests/test_aegis.db` for a clean run.

## Important limitation
Most API tests set `app.config["TESTING"] = True`. In this codebase that flag **turns off security**:
- CSRF check (`csrf_protect` returns early and disables the limiter)
- webview-token check
- telemetry timestamp-skew check

So the suite can't detect regressions in those controls, and several confirmed vulnerabilities pass it. One test asserts that the default `noodles/noodles` login succeeds.

## Target test strategy (restructure plan Phase 1–2)
```
tests/
├── conftest.py              app factory fixture, temp DB per test, signed-frame + CSRF helpers
├── unit/                    pure functions: codec, canonicaliser, trust math, enforcer, analytics
├── integration/             Flask client with security ON
├── security/                one regression test per DEBUG_REPORT finding (S1…S14, F1…F15)
├── contract/                protocol test vectors shared with firmware
├── e2e/                     Playwright smoke test of the dashboard against the simulator
└── hardware/                marked @pytest.mark.hardware, skipped in CI
```
Coverage gate: 80 % lines on `aegis_ics/` (excluding desktop shell). Also run `ruff`, `mypy --strict` on core packages, `bandit` and `pip-audit` in CI.
