from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import joblib  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional dependency
    joblib = None


@dataclass
class RFModel:
    model_path: Path
    model: Any | None = None

    @classmethod
    def load(cls, model_path: str | Path) -> "RFModel":
        path = Path(model_path)
        model = None
        if joblib is not None and path.exists():
            model = joblib.load(path)
        return cls(model_path=path, model=model)

    def predict_anomaly_probability(self, telemetry: dict[str, Any]) -> tuple[float, float]:
        """Return (probability, confidence)."""

        features = [[
            float(telemetry.get("temperature", 0.0)),
            float(telemetry.get("pressure", 0.0)),
        ]]

        if self.model is None:
            temp = features[0][0]
            pressure = features[0][1]
            anomaly = 0.0
            if temp < 0.0 or temp > 50.0:
                anomaly += 0.5
            if pressure < 0.0 or pressure > 8.0:
                anomaly += 0.5
            return min(1.0, anomaly), 0.35

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(features)[0]
            if len(probabilities) == 1:
                return float(probabilities[0]), 0.95
            anomaly_probability = float(probabilities[1])
            return anomaly_probability, 0.95

        prediction = self.model.predict(features)[0]
        anomaly_probability = 1.0 if int(prediction) else 0.0
        return anomaly_probability, 0.7
