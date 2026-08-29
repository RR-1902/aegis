"""Risk scoring models for AEGIS."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional

from app.models.detection import DetectionResult
from app.models.flow import FlowKey


class RiskLevel(Enum):
    """Deterministic heuristic risk level for combined detections."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class RiskScore:
    """Immutable heuristic risk score for one observation identity."""

    score: int
    level: RiskLevel
    flow_key: Optional[FlowKey]
    window_start: Optional[datetime]
    window_end: Optional[datetime]
    detections: List[DetectionResult]
    explanation: str
