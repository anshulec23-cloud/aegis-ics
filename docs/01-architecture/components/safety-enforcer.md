# Safety enforcer — `src/safety_enforcer.py`

## API
`validate_command(command: {"type","value"}, db, target_device=None) -> (allowed: bool, reason: str)`

## Decision pipeline
| # | Check | Fail result |
|---|---|---|
| 1 | `type ∈ {set_temp, set_pressure}` | deny "Unknown command type" |
| 2 | value numeric, not bool, finite | deny |
| 3 | within `rules` min/max for that type | deny "Rule violation" |
| 4 | latest telemetry **for the target device** is fresh: −5 s ≤ age ≤ 120 s | go to stale branch |
| 5a | fresh: NSPN `P(safe) ≥ 0.5`; any exception means deny (fail closed) | deny with explanation |
| 5b | fresh: invariants `set_temp ≥ 45 ∧ P_live ≥ 6`, `set_pressure ≥ 6 ∧ T_live ≥ 45` | deny "Stuxnet prevention" |
| 6 | stale or none: deny high-risk (`set_temp ≥ 45` or `set_pressure ≥ 6`); allow the rest with a warning | deny "Stale telemetry" |

The caller (`/api/setpoint`) logs `STALE_TELEMETRY_BLOCKED` or `SECURITY_VIOLATION_BLOCKED` on denial, and `CHANGE_SETPOINT` on success.

## Design properties
- **Defence in depth:** the deterministic invariants run even when the NSPN approves.
- **Fail-closed** on NSPN errors and on stale data for high-risk values.
- **Fail-open** for low-risk commands with stale data (by design; document it in the safety case).

## Gaps
- Freshness can be satisfied by simulated rows or by rows recorded during quarantine.
- Only two command types exist; rate-of-change limits (e.g. max ΔT per minute) aren't checked.
- Hard limits (45 °C / 6 bar) are constants in two files (`safety_enforcer.py`, `neural_policy.py`) and a third copy lives in the firmware (0–60 °C, 0–8 bar).
- No per-device limits: a cryogenic chiller and a reactor share the same envelope.
