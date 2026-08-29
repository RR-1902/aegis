"""Base interface for stateless detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from app.models.flow import FeatureObservation
from app.models.detection import DetectionResult


class DetectionRule(ABC):
    """Abstract base class for one stateless deterministic detection rule."""

    rule_id: str
    rule_name: str

    @abstractmethod
    def evaluate(self, observation: FeatureObservation) -> Optional[DetectionResult]:
        """Return a DetectionResult if this rule triggers, else None."""
        raise NotImplementedError
