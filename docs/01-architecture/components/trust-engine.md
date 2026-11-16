# Trust engine — `src/trust_engine.py`

The mathematical specification is [`../../06-research/trust-scoring.md`](../../06-research/trust-scoring.md). This page documents the implementation.

## API
- `compute_device_trust_score(device_id, db, latest_is_anomaly=None, latest_sig_valid=None, anomaly_prob=0.0, model_confidence=0.85) -> dict`
- `get_device_trust_score(device_id, db) -> float` (percentage)
- `get_trust_breakdown(device_id, db) -> dict` (score, weighted components, zone metadata, packet stats)

## Algorithm
| Step | Rule |
|---|---|
| Isolated device | score 0.0, status `ISOLATED` |
| No history, known ID (ESP32_001–004) | 0.50 `INITIALIZING` |
| No history, unknown ID | 0.25 `UNREGISTERED` |
| S_anomaly | fraction of the last 15 rows with `is_anomaly`, raised to ≥ 0.7 if the latest frame is anomalous |
| S_signature | 1.0 or 0.0 from the latest verification; 1.0 when unknown |
| S_history | `1 − min(1, (|T₀−μT|/25 + |P₀−μP|/5)/2)` (needs ≥ 2 T and P values, else 0.5) |
| S_stability | `1 − min(1, varT/100 + varP/10)` (needs ≥ 3, else 0.5) |
| Combine | `0.35(1−S_a) + 0.30 S_s + 0.20 S_h + 0.15 S_st` |
| Warm-up | for n < 10 rows: `0.5(1−n/10) + T·n/10` |
| Low-confidence fallback | only when `model_confidence < 0.5`; callers never pass it, so this path is unused |
| Bands | ≥0.80 TRUSTED · ≥0.50 DEGRADED · ≥0.40 SUSPICIOUS · else CRITICAL |

## Notes
- The score is recomputed on every call (no caching); `/api/devices` calls it for every node on each poll.
- `anomaly_prob` is accepted but unused.
- S_history and S_stability only look at temperature and pressure; vibration, RPM and current don't affect trust directly.
- Zone metadata here duplicates `analytics.SUBSYSTEM_PROFILES` (with slightly different names, e.g. "Cooling Cryo 03" vs "Cryogenic Chiller 03" in the README).
