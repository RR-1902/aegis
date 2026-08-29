"""Policy decision models for AEGIS."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional

from app.models.flow import FlowKey
from app.models.risk import RiskLevel


class PolicyAction(Enum):
    """Constrained policy action vocabulary."""

    LOG_ONLY = "log_only"
    ALERT_ONLY = "alert_only"
    BLOCK_SOURCE = "block_source"


class ExecutionMode(Enum):
    """Disposition for a future response engine."""

    NONE = "none"
    SIMULATE = "simulate"
    EXECUTE = "execute"


@dataclass(frozen=True)
class ResponseTarget:
    """Conservative response target description."""

    ip: str
    port: Optional[int]
    role: str


@dataclass(frozen=True)
class ResponseDecision:
    """Immutable policy decision with no execution behavior."""

    recommended_action: PolicyAction
    allowed: bool
    execution_mode: ExecutionMode
    flow_key: Optional[FlowKey]
    window_start: Optional[datetime]
    window_end: Optional[datetime]
    risk_score: int
    risk_level: RiskLevel
    detection_ids: List[str]
    target: Optional[ResponseTarget]
    explanation: str
