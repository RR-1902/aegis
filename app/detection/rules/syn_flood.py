"""Stateless SYN-flood detection rule."""

from dataclasses import dataclass
from typing import Optional

from app.config.settings import settings
from app.detection.rules.base import DetectionRule
from app.models.detection import DetectionResult, DetectionSeverity
from app.models.flow import FeatureObservation


@dataclass(frozen=True)
class SynFloodRule(DetectionRule):
    """Detect SYN-flood-like observations from one finalized feature window."""

    syn_rate_threshold: float = settings.syn_rate_threshold
    syn_incomplete_ratio: float = settings.syn_incomplete_ratio
    rule_id: str = "syn_flood"
    rule_name: str = "SYN Flood"

    def evaluate(self, observation: FeatureObservation) -> Optional[DetectionResult]:
        syn_rate = float(observation.features.get("syn_rate", 0.0) or 0.0)
        incomplete_ratio = float(observation.features.get("incomplete_connection_ratio", 0.0) or 0.0)

        syn_rate_triggered = syn_rate >= self.syn_rate_threshold
        incomplete_ratio_triggered = incomplete_ratio >= self.syn_incomplete_ratio
        triggered = syn_rate_triggered and incomplete_ratio_triggered
        if not triggered:
            return None

        severity = DetectionSeverity.MEDIUM
        if syn_rate > self.syn_rate_threshold and incomplete_ratio > self.syn_incomplete_ratio:
            severity = DetectionSeverity.HIGH

        syn_count = observation.features.get("syn_count", 0)
        syn_to_total_ratio = observation.features.get("syn_to_total_ratio", 0.0)
        connection_attempts = observation.features.get("connection_attempts", 0)
        packet_count = observation.features.get("packet_count", 0)

        evidence = {
            "observation": {
                "flow_key": str(observation.flow_key),
                "window_start": observation.window_start.isoformat(),
                "window_end": observation.window_end.isoformat(),
            },
            "features": {
                "syn_rate": syn_rate,
                "incomplete_connection_ratio": incomplete_ratio,
                "syn_count": syn_count,
                "syn_to_total_ratio": syn_to_total_ratio,
                "connection_attempts": connection_attempts,
                "packet_count": packet_count,
            },
            "thresholds": {
                "syn_rate_threshold": self.syn_rate_threshold,
                "syn_incomplete_ratio": self.syn_incomplete_ratio,
            },
            "comparisons": {
                "syn_rate >= syn_rate_threshold": syn_rate_triggered,
                "incomplete_connection_ratio >= syn_incomplete_ratio": incomplete_ratio_triggered,
            },
        }

        explanation = (
            f"SYN flood indicators were observed in window "
            f"[{observation.window_start.isoformat()}, {observation.window_end.isoformat()}): "
            f"syn_rate={syn_rate} met or exceeded {self.syn_rate_threshold} and "
            f"incomplete_connection_ratio={incomplete_ratio} met or exceeded "
            f"{self.syn_incomplete_ratio}."
        )

        return DetectionResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=severity,
            flow_key=observation.flow_key,
            window_start=observation.window_start,
            window_end=observation.window_end,
            evidence=evidence,
            explanation=explanation,
        )
