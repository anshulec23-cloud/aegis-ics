"""Telemetry anomaly generation."""

from __future__ import annotations

from dataclasses import dataclass
import random


@dataclass
class AnomalyInjector:
    mode: str = "normal"
    drift_step: float = 0.0
    flatline_value: tuple[float, float] | None = None

    def apply(self, temperature: float, pressure: float) -> tuple[float, float]:
        if self.mode == "spike":
            return temperature + random.uniform(20.0, 35.0), pressure + random.uniform(1.0, 3.0)
        if self.mode == "drift":
            self.drift_step += 0.2
            return temperature + self.drift_step, pressure + (self.drift_step / 10.0)
        if self.mode == "flatline":
            if self.flatline_value is None:
                self.flatline_value = (temperature, pressure)
            return self.flatline_value
        if self.mode == "noise_burst":
            return temperature + random.uniform(-8.0, 8.0), pressure + random.uniform(-1.0, 1.0)
        return temperature, pressure

