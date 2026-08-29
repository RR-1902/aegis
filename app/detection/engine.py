"""Stateless deterministic detection engine for AEGIS."""

from __future__ import annotations

from typing import Iterable, List, Optional, Set, Tuple

from app.detection.rules.base import DetectionRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.syn_flood import SynFloodRule
from app.models.detection import DetectionResult
from app.models.flow import FeatureObservation, FlowKey


DetectionIdentity = Tuple[str, FlowKey, object, object]


class DetectionEngine:
    """Evaluate finalized feature observations against deterministic rules."""

    def __init__(self, rules: Optional[Iterable[DetectionRule]] = None):
        self.rules: List[DetectionRule] = list(rules) if rules is not None else [
            PortScanRule(),
            SynFloodRule(),
        ]
        self._seen_detections: Set[DetectionIdentity] = set()

    def evaluate(self, observation: FeatureObservation) -> List[DetectionResult]:
        """Evaluate all configured rules in deterministic order."""
        if not observation.features:
            return []

        results: List[DetectionResult] = []
        for rule in self.rules:
            result = rule.evaluate(observation)
            if result is None:
                continue

            identity = (result.rule_id, result.flow_key, result.window_start, result.window_end)
            if identity in self._seen_detections:
                continue

            self._seen_detections.add(identity)
            results.append(result)

        return results

    def reset(self) -> None:
        """Clear in-memory detection deduplication state."""
        self._seen_detections.clear()
