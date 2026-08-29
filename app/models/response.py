"""Response result models for AEGIS."""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from app.models.policy import PolicyAction, ResponseTarget


class ResponseStatus(Enum):
    """Outcome states for handling a response decision."""

    NO_ACTION = "no_action"
    SIMULATED = "simulated"
    EXECUTED = "executed"
    REJECTED = "rejected"
    FAILED = "failed"


@dataclass(frozen=True)
class ResponseResult:
    """Immutable simulation/execution outcome for a response decision."""

    action: PolicyAction
    status: ResponseStatus
    simulated: bool
    target: Optional[ResponseTarget]
    message: str
    error: Optional[str]
    timestamp: datetime
