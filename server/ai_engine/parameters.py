from __future__ import annotations

from collections.abc import Sequence
from statistics import pvariance
from typing import Any


def anomaly_frequency(anomaly_probability: float) -> float:
    return max(0.0, min(1.0, float(anomaly_probability)))


def signature_validity(message: dict[str, Any]) -> float:
    return 1.0 if message.get("signature_valid", True) else 0.0


def time_log_score(history: Sequence[dict[str, Any]], message: dict[str, Any]) -> float:
    if not history:
        return 1.0

    temp_values = [float(item.get("temperature", 0.0)) for item in history[-10:]]
    pressure_values = [float(item.get("pressure", 0.0)) for item in history[-10:]]
    current_temp = float(message.get("temperature", 0.0))
    current_pressure = float(message.get("pressure", 0.0))

    temp_mean = sum(temp_values) / len(temp_values)
    pressure_mean = sum(pressure_values) / len(pressure_values)

    temp_delta = abs(current_temp - temp_mean)
    pressure_delta = abs(current_pressure - pressure_mean)
    deviation = (temp_delta / 25.0) + (pressure_delta / 5.0)
    return max(0.0, 1.0 - min(1.0, deviation / 2.0))


def sensor_stability(history: Sequence[dict[str, Any]]) -> float:
    if len(history) < 2:
        return 1.0

    temps = [float(item.get("temperature", 0.0)) for item in history[-10:]]
    pressures = [float(item.get("pressure", 0.0)) for item in history[-10:]]
    temp_var = pvariance(temps) if len(temps) > 1 else 0.0
    pressure_var = pvariance(pressures) if len(pressures) > 1 else 0.0
    combined = (temp_var / 100.0) + (pressure_var / 10.0)
    return max(0.0, 1.0 - min(1.0, combined))

