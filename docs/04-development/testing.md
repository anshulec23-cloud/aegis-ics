# Testing

## Layout
| File | Tests | Scope |
|---|---|---|
| `tests/test_full_suite.py` | 50 | Unit + Flask test-client integration: DB, HMAC, safety enforcer, NSPN, analytics, PDF, gateway parsing, routes, concurrency stress, fuzzing, regressions V1–V5 |
| `tests/test_production_hardware_integration.py` | 10 | Gateway/firmware protocol parity, command dispatch (no real hardware needed) |
| `tests/test_multi_slave_discovery.py` | 5 | Bridge topology and node-announce parsing |
| `tests/test_security_hardening.py` | 4 | Template and static hardening checks |
| `tests/security/test_debug_findings.py` | 39 | One regression test per [debug-report](../07-reports/DEBUG_REPORT.md) finding, run with all security controls on; findings fixed in later phases are `xfail(strict=True)` |
| `tests/conftest.py` | – | Deletes the test DB at session start; sets test-only admin password, device keys and gateway token |
| `tests/benchmark_suite.py` | n/a (script) | Latency and attack-simulation benchmarks → `tests/benchmark_results/*.json` |
| `tests/generate_graphs.py` | n/a (script) | Renders `docs/figures/*.png` from benchmark JSON |

Run all: `python -m pytest tests -q` · one test: `python -m pytest tests/test_full_suite.py::test_flask_api_routes -q`.

## Test database and secrets
`tests/conftest.py` runs before any test module. It deletes `tests/test_aegis.db` (plus WAL files) so every session starts empty. It also sets test-only values for `ADMIN_PASSWORD`, `DEVICE_KEY_ESP32_00x` and `AEGIS_GATEWAY_TOKEN`; tests import these as `TEST_ADMIN_PASSWORD`, `TEST_DEVICE_KEYS` and `GATEWAY_HEADERS`.

## Security controls stay on in tests
Since v2.6, `app.config["TESTING"] = True` only disables **rate limiting** (so the stress tests don't hit 429). CSRF, the webview token, the gateway token, the timestamp window and signature checks all run exactly as in production. Tests therefore have to:
- put a `csrf_token` in the session and send it as `X-CSRF-Token` (fixtures do this via `client.environ_base`);
- sign telemetry with the device key and send `GATEWAY_HEADERS`;
- patch `serial_gateway.is_connected` when they expect commands to be queued, and read them with `serial_gateway.pop_ready_commands()`.

The suite must leave the working tree unchanged (CI runs `git diff --exit-code` after the tests).

Current result: **105 passed, 3 xfailed** (S3, F2, F6, which are open in later phases).

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
