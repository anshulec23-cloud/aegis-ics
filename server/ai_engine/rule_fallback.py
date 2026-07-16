from __future__ import annotations

from typing import Any


def fallback_score(message: dict[str, Any], signature_valid: float) -> float:
    temp = float(message.get("temperature", 0.0))
    pressure = float(message.get("pressure", 0.0))

    score = 1.0
    if temp < 0.0 or temp > 50.0:
        score -= 0.35
    if pressure < 0.0 or pressure > 8.0:
        score -= 0.25
    if signature_valid < 1.0:
        score -= 0.4
    return max(0.0, min(1.0, score))

