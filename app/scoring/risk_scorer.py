"""Stateless heuristic risk scoring for AEGIS."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

from app.config.settings import settings
from app.models.detection import DetectionResult, DetectionSeverity
from app.models.flow import FlowKey
from app.models.risk import RiskLevel, RiskScore


ObservationIdentity = Tuple[FlowKey, datetime, datetime]
ContributionKey = Tuple[str, DetectionSeverity]


@dataclass(frozen=True)
class RiskScorer:
    """Pure stateless scorer for one observation's detection results.

    The 0-100 score is a deterministic heuristic engineering value, not a
    probability and not a calibrated estimate of compromise likelihood.
    """

    port_scan_medium: int = settings.score_port_scan_medium
    port_scan_high: int = settings.score_port_scan_high
    syn_flood_medium: int = settings.score_syn_flood_medium
    syn_flood_high: int = settings.score_syn_flood_high
    low_threshold: int = settings.threat_score_low
    medium_threshold: int = settings.threat_score_medium
    high_threshold: int = settings.threat_score_high

    def score(self, detections: Iterable[DetectionResult]) -> RiskScore:
        detection_list = list(detections)
        if not detection_list:
            return RiskScore(
                score=0,
                level=RiskLevel.LOW,
                flow_key=None,
                window_start=None,
                window_end=None,
                detections=[],
                explanation="No detections were provided, so the heuristic risk score is 0 (LOW).",
            )

        identity = self._validate_and_get_identity(detection_list)
        contributions = []
        total = 0
        for detection in detection_list:
            contribution = self._get_contribution(detection)
            total += contribution
            contributions.append((detection, contribution))

        final_score = min(total, 100)
        level = self._map_level(final_score)
        explanation = self._build_explanation(final_score, level, contributions)

        return RiskScore(
            score=final_score,
            level=level,
            flow_key=identity[0],
            window_start=identity[1],
            window_end=identity[2],
            detections=detection_list,
            explanation=explanation,
        )

    def _validate_and_get_identity(self, detections: List[DetectionResult]) -> ObservationIdentity:
        first = detections[0]
        identity = (first.flow_key, first.window_start, first.window_end)
        for detection in detections[1:]:
            current = (detection.flow_key, detection.window_start, detection.window_end)
            if current != identity:
                raise ValueError("RiskScorer requires detections from exactly one observation identity")
        return identity

    def _get_contribution(self, detection: DetectionResult) -> int:
        contribution_map: Dict[ContributionKey, int] = {
            ("port_scan", DetectionSeverity.MEDIUM): self.port_scan_medium,
            ("port_scan", DetectionSeverity.HIGH): self.port_scan_high,
            ("syn_flood", DetectionSeverity.MEDIUM): self.syn_flood_medium,
            ("syn_flood", DetectionSeverity.HIGH): self.syn_flood_high,
        }
        return contribution_map.get((detection.rule_id, detection.severity), 0)

    def _map_level(self, score: int) -> RiskLevel:
        if score <= self.low_threshold:
            return RiskLevel.LOW
        if score <= self.medium_threshold:
            return RiskLevel.MEDIUM
        if score <= self.high_threshold:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL

    def _build_explanation(
        self,
        final_score: int,
        level: RiskLevel,
        contributions: List[Tuple[DetectionResult, int]],
    ) -> str:
        parts = []
        for detection, contribution in contributions:
            parts.append(
                f"{detection.rule_name} ({detection.severity.name}) contributed {contribution}"
            )

        detection_summary = "; ".join(parts) if parts else "no contributing detections"
        return (
            f"Heuristic risk score {final_score}/100 mapped to {level.name} based on "
            f"{len(contributions)} detection(s): {detection_summary}."
        )
