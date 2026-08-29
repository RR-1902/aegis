"""Detection result models for AEGIS."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict

from app.models.flow import FlowKey


class DetectionSeverity(Enum):
    """Deterministic rule-level severity classification."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class DetectionResult:
    """Immutable explainable detection outcome for one rule on one observation."""

    rule_id: str
    rule_name: str
    severity: DetectionSeverity
    flow_key: FlowKey
    window_start: datetime
    window_end: datetime
    evidence: Dict[str, Any]
    explanation: str
