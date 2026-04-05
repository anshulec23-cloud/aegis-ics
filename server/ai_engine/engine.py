from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Sequence

try:
    from .microseg import MicroSegmentationStore
    from .parameters import anomaly_frequency, sensor_stability, signature_validity, time_log_score
    from .rf_model import RFModel
    from .rule_fallback import fallback_score
except ImportError:  # pragma: no cover - direct script execution fallback
    from microseg import MicroSegmentationStore
    from parameters import anomaly_frequency, sensor_stability, signature_validity, time_log_score
    from rf_model import RFModel
    from rule_fallback import fallback_score


@dataclass
class TrustDecision:
    device_id: str
    trust_score: float
    action: str
    breakdown: dict[str, float]


class TrustEngine:
    def __init__(self, model_path: str | Path = "model/rf_model.pkl", store_path: str | Path = "isolated_devices.json") -> None:
        self.rf_model = RFModel.load(model_path)
        self.microseg = MicroSegmentationStore(Path(store_path))
        self.microseg.load()

    @staticmethod
    def verify_signature(telemetry: dict[str, Any], device_key: str | None) -> bool:
        if not device_key:
            return False
        signature = telemetry.get("signature")
        if not signature:
            return False

        body = {k: v for k, v in telemetry.items() if k != "signature"}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        expected = hmac.new(device_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, str(signature))

    def score(
        self,
        telemetry: dict[str, Any],
        history: Sequence[dict[str, Any]] | None = None,
        device_key: str | None = None,
    ) -> TrustDecision:
        history = history or []
        device_id = str(telemetry.get("device_id", "unknown"))

        signature_ok = self.verify_signature(telemetry, device_key)
        telemetry = dict(telemetry)
        telemetry["signature_valid"] = signature_ok

        anomaly_probability, model_confidence = self.rf_model.predict_anomaly_probability(telemetry)
        anomaly_frequency_score = anomaly_frequency(anomaly_probability)
        signature_score = signature_validity(telemetry)
        history_score = time_log_score(history, telemetry)
        stability_score = sensor_stability(history)

        trust_score = (
            0.35 * (1.0 - anomaly_frequency_score)
            + 0.30 * signature_score
            + 0.20 * history_score
            + 0.15 * stability_score
        )

        if model_confidence < 0.5:
            trust_score = (trust_score + fallback_score(telemetry, signature_score)) / 2.0

        trust_score = max(0.0, min(1.0, trust_score))
        action = "normal"
        if trust_score < 0.4:
            self.microseg.isolate(device_id)
            action = "isolate"
        elif trust_score > 0.75 and device_id in self.microseg.isolated_devices:
            action = "manual_reauth_required"

        return TrustDecision(
            device_id=device_id,
            trust_score=round(trust_score, 4),
            action=action,
            breakdown={
                "anomaly_frequency": round(anomaly_frequency_score, 4),
                "signature_validity": round(signature_score, 4),
                "time_log_score": round(history_score, 4),
                "sensor_stability": round(stability_score, 4),
                "model_confidence": round(model_confidence, 4),
            },
        )

    def rejoin(self, device_id: str) -> None:
        self.microseg.rejoin(device_id)

    def list_isolated(self) -> list[str]:
        return self.microseg.list_isolated()
