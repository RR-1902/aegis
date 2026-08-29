"""Stateless port-scan detection rule."""

from dataclasses import dataclass
from typing import Optional

from app.config.settings import settings
from app.detection.rules.base import DetectionRule
from app.models.detection import DetectionResult, DetectionSeverity
from app.models.flow import FeatureObservation


@dataclass(frozen=True)
class PortScanRule(DetectionRule):
    """Detect high unique-destination-port activity within one observation.

    Detection visibility depends on the configured FlowKey strategy. In
    `five_tuple` mode, port changes may be split across multiple observations;
    in `three_tuple` mode they can aggregate into one observation; in
    `bidirectional` mode the identity is direction-independent and should be
    interpreted accordingly.
    """

    port_scan_threshold: int = settings.port_scan_threshold
    port_scan_time_window: int = settings.port_scan_time_window
    rule_id: str = "port_scan"
    rule_name: str = "Port Scan"

    def evaluate(self, observation: FeatureObservation) -> Optional[DetectionResult]:
        unique_ports = int(observation.features.get("unique_destination_ports", 0) or 0)
        triggered = unique_ports >= self.port_scan_threshold
        if not triggered:
            return None

        severity = DetectionSeverity.MEDIUM
        if unique_ports > self.port_scan_threshold:
            severity = DetectionSeverity.HIGH

        syn_count = observation.features.get("syn_count", 0)
        syn_rate = observation.features.get("syn_rate", 0.0)
        connection_attempts = observation.features.get("connection_attempts", 0)
        successful_ratio = observation.features.get("successful_connection_ratio", 0.0)
        incomplete_ratio = observation.features.get("incomplete_connection_ratio", 0.0)
        duration = observation.features.get("duration_seconds", 0.0)

        evidence = {
            "observation": {
                "flow_key": str(observation.flow_key),
                "window_start": observation.window_start.isoformat(),
                "window_end": observation.window_end.isoformat(),
            },
            "features": {
                "unique_destination_ports": unique_ports,
                "syn_count": syn_count,
                "syn_rate": syn_rate,
                "connection_attempts": connection_attempts,
                "successful_connection_ratio": successful_ratio,
                "incomplete_connection_ratio": incomplete_ratio,
                "duration_seconds": duration,
            },
            "thresholds": {
                "port_scan_threshold": self.port_scan_threshold,
                "port_scan_time_window": self.port_scan_time_window,
            },
            "comparisons": {
                "unique_destination_ports >= port_scan_threshold": triggered,
            },
        }

        explanation = (
            f"{unique_ports} unique destination ports were observed in window "
            f"[{observation.window_start.isoformat()}, {observation.window_end.isoformat()}), "
            f"meeting or exceeding the configured port-scan threshold of "
            f"{self.port_scan_threshold}."
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
