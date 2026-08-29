"""Security event models and serialization for AEGIS."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional

from app.models.detection import DetectionResult, DetectionSeverity
from app.models.flow import FlowKey
from app.models.policy import ExecutionMode, PolicyAction, ResponseDecision, ResponseTarget
from app.models.response import ResponseResult, ResponseStatus
from app.models.risk import RiskLevel, RiskScore


class SecurityEventStatus(Enum):
    """Persisted terminal lifecycle state for a complete security event."""

    NO_ACTION = "no_action"
    SIMULATED = "simulated"
    REJECTED = "rejected"


@dataclass(frozen=True)
class SecurityEvent:
    """Immutable durable audit record for one finalized observation identity."""

    event_id: str
    flow_key: FlowKey
    window_start: datetime
    window_end: datetime
    recorded_at: datetime
    detections: List[DetectionResult]
    risk: RiskScore
    policy: ResponseDecision
    response: ResponseResult
    lifecycle_status: SecurityEventStatus

    def __post_init__(self) -> None:
        _require_utc_datetime(self.window_start, "window_start")
        _require_utc_datetime(self.window_end, "window_end")
        _require_utc_datetime(self.recorded_at, "recorded_at")

        expected_event_id = self.generate_event_id(self.flow_key, self.window_start, self.window_end)
        if self.event_id != expected_event_id:
            raise ValueError("event_id does not match the semantic observation identity")

        _validate_json_compatible(self.to_serializable_dict(), context="security event")
        self._validate_identity_consistency()
        self._validate_response_consistency()
        self._validate_lifecycle_consistency()

    @classmethod
    def create(
        cls,
        *,
        flow_key: FlowKey,
        window_start: datetime,
        window_end: datetime,
        detections: List[DetectionResult],
        risk: RiskScore,
        policy: ResponseDecision,
        response: ResponseResult,
        recorded_at: Optional[datetime] = None,
    ) -> "SecurityEvent":
        recorded = recorded_at or datetime.now(timezone.utc)
        lifecycle_status = cls.status_from_response(response.status)
        return cls(
            event_id=cls.generate_event_id(flow_key, window_start, window_end),
            flow_key=flow_key,
            window_start=window_start,
            window_end=window_end,
            recorded_at=recorded,
            detections=list(detections),
            risk=risk,
            policy=policy,
            response=response,
            lifecycle_status=lifecycle_status,
        )

    @staticmethod
    def generate_event_id(flow_key: FlowKey, window_start: datetime, window_end: datetime) -> str:
        _require_utc_datetime(window_start, "window_start")
        _require_utc_datetime(window_end, "window_end")
        payload = {
            "flow_key": serialize_flow_key(flow_key),
            "window_start": serialize_datetime(window_start),
            "window_end": serialize_datetime(window_end),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return f"security-event:{digest}"

    @staticmethod
    def status_from_response(response_status: ResponseStatus) -> SecurityEventStatus:
        if response_status == ResponseStatus.NO_ACTION:
            return SecurityEventStatus.NO_ACTION
        if response_status == ResponseStatus.SIMULATED:
            return SecurityEventStatus.SIMULATED
        if response_status == ResponseStatus.REJECTED:
            return SecurityEventStatus.REJECTED
        if response_status in (ResponseStatus.EXECUTED, ResponseStatus.FAILED):
            raise ValueError(
                "ResponseStatus.EXECUTED and ResponseStatus.FAILED are unsupported for persisted SecurityEvent because no real executor is implemented."
            )
        raise ValueError(f"Unsupported response status for SecurityEvent: {response_status}")

    def _validate_identity_consistency(self) -> None:
        identity = (self.flow_key, self.window_start, self.window_end)

        for detection in self.detections:
            current = (detection.flow_key, detection.window_start, detection.window_end)
            if current != identity:
                raise ValueError("All detections must match the SecurityEvent observation identity")

        risk_identity = (self.risk.flow_key, self.risk.window_start, self.risk.window_end)
        if risk_identity != identity:
            raise ValueError("RiskScore must match the SecurityEvent observation identity")

        policy_identity = (self.policy.flow_key, self.policy.window_start, self.policy.window_end)
        if policy_identity != identity:
            raise ValueError("ResponseDecision must match the SecurityEvent observation identity")

        risk_detection_ids = [(d.rule_id, d.flow_key, d.window_start, d.window_end) for d in self.risk.detections]
        event_detection_ids = [(d.rule_id, d.flow_key, d.window_start, d.window_end) for d in self.detections]
        if risk_detection_ids != event_detection_ids:
            raise ValueError("RiskScore detections must match the SecurityEvent detections")

        policy_detection_ids = [d.rule_id for d in self.detections]
        if self.policy.detection_ids != policy_detection_ids:
            raise ValueError("ResponseDecision detection_ids must match the SecurityEvent detections")

    def _validate_response_consistency(self) -> None:
        if self.response.action != self.policy.recommended_action:
            raise ValueError("ResponseResult action must match the ResponseDecision recommended action")
        if self.response.target != self.policy.target:
            raise ValueError("ResponseResult target must match the ResponseDecision target")

    def _validate_lifecycle_consistency(self) -> None:
        expected = self.status_from_response(self.response.status)
        if self.lifecycle_status != expected:
            raise ValueError("lifecycle_status must match the mapped ResponseResult status")

    def to_serializable_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "flow_key": serialize_flow_key(self.flow_key),
            "window_start": serialize_datetime(self.window_start),
            "window_end": serialize_datetime(self.window_end),
            "recorded_at": serialize_datetime(self.recorded_at),
            "detections": [serialize_detection_result(d) for d in self.detections],
            "risk": serialize_risk_score(self.risk),
            "policy": serialize_response_decision(self.policy),
            "response": serialize_response_result(self.response),
            "lifecycle_status": self.lifecycle_status.value,
        }

    @classmethod
    def from_serializable_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        return cls(
            event_id=data["event_id"],
            flow_key=deserialize_flow_key(data["flow_key"]),
            window_start=deserialize_datetime(data["window_start"]),
            window_end=deserialize_datetime(data["window_end"]),
            recorded_at=deserialize_datetime(data["recorded_at"]),
            detections=[deserialize_detection_result(item) for item in data["detections"]],
            risk=deserialize_risk_score(data["risk"]),
            policy=deserialize_response_decision(data["policy"]),
            response=deserialize_response_result(data["response"]),
            lifecycle_status=SecurityEventStatus(data["lifecycle_status"]),
        )


def _require_utc_datetime(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime):
        raise ValueError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC")
    if value.astimezone(timezone.utc).utcoffset() != timezone.utc.utcoffset(value):
        raise ValueError(f"{field_name} must be normalized to UTC")


def serialize_datetime(value: datetime) -> str:
    _require_utc_datetime(value, "datetime")
    return value.astimezone(timezone.utc).isoformat()


def deserialize_datetime(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    _require_utc_datetime(dt, "datetime")
    return dt.astimezone(timezone.utc)


def serialize_flow_key(flow_key: FlowKey) -> Dict[str, Any]:
    return {
        "src_ip": flow_key.src_ip,
        "dst_ip": flow_key.dst_ip,
        "protocol": flow_key.protocol,
        "src_port": flow_key.src_port,
        "dst_port": flow_key.dst_port,
    }


def deserialize_flow_key(data: Dict[str, Any]) -> FlowKey:
    return FlowKey(
        src_ip=data["src_ip"],
        dst_ip=data["dst_ip"],
        protocol=data["protocol"],
        src_port=data.get("src_port"),
        dst_port=data.get("dst_port"),
    )


def serialize_detection_result(result: DetectionResult) -> Dict[str, Any]:
    _validate_json_compatible(result.evidence, context="detection evidence")
    return {
        "rule_id": result.rule_id,
        "rule_name": result.rule_name,
        "severity": result.severity.value,
        "flow_key": serialize_flow_key(result.flow_key),
        "window_start": serialize_datetime(result.window_start),
        "window_end": serialize_datetime(result.window_end),
        "evidence": result.evidence,
        "explanation": result.explanation,
    }


def deserialize_detection_result(data: Dict[str, Any]) -> DetectionResult:
    return DetectionResult(
        rule_id=data["rule_id"],
        rule_name=data["rule_name"],
        severity=DetectionSeverity(data["severity"]),
        flow_key=deserialize_flow_key(data["flow_key"]),
        window_start=deserialize_datetime(data["window_start"]),
        window_end=deserialize_datetime(data["window_end"]),
        evidence=data["evidence"],
        explanation=data["explanation"],
    )


def serialize_risk_score(risk: RiskScore) -> Dict[str, Any]:
    return {
        "score": risk.score,
        "level": risk.level.value,
        "flow_key": serialize_flow_key(risk.flow_key) if risk.flow_key is not None else None,
        "window_start": serialize_datetime(risk.window_start) if risk.window_start is not None else None,
        "window_end": serialize_datetime(risk.window_end) if risk.window_end is not None else None,
        "detections": [serialize_detection_result(d) for d in risk.detections],
        "explanation": risk.explanation,
    }


def deserialize_risk_score(data: Dict[str, Any]) -> RiskScore:
    return RiskScore(
        score=data["score"],
        level=RiskLevel(data["level"]),
        flow_key=deserialize_flow_key(data["flow_key"]) if data["flow_key"] is not None else None,
        window_start=deserialize_datetime(data["window_start"]) if data["window_start"] is not None else None,
        window_end=deserialize_datetime(data["window_end"]) if data["window_end"] is not None else None,
        detections=[deserialize_detection_result(item) for item in data["detections"]],
        explanation=data["explanation"],
    )


def serialize_response_target(target: Optional[ResponseTarget]) -> Optional[Dict[str, Any]]:
    if target is None:
        return None
    return {
        "ip": target.ip,
        "port": target.port,
        "role": target.role,
    }


def deserialize_response_target(data: Optional[Dict[str, Any]]) -> Optional[ResponseTarget]:
    if data is None:
        return None
    return ResponseTarget(ip=data["ip"], port=data.get("port"), role=data["role"])


def serialize_response_decision(decision: ResponseDecision) -> Dict[str, Any]:
    return {
        "recommended_action": decision.recommended_action.value,
        "allowed": decision.allowed,
        "execution_mode": decision.execution_mode.value,
        "flow_key": serialize_flow_key(decision.flow_key) if decision.flow_key is not None else None,
        "window_start": serialize_datetime(decision.window_start) if decision.window_start is not None else None,
        "window_end": serialize_datetime(decision.window_end) if decision.window_end is not None else None,
        "risk_score": decision.risk_score,
        "risk_level": decision.risk_level.value,
        "detection_ids": list(decision.detection_ids),
        "target": serialize_response_target(decision.target),
        "explanation": decision.explanation,
    }


def deserialize_response_decision(data: Dict[str, Any]) -> ResponseDecision:
    return ResponseDecision(
        recommended_action=PolicyAction(data["recommended_action"]),
        allowed=data["allowed"],
        execution_mode=ExecutionMode(data["execution_mode"]),
        flow_key=deserialize_flow_key(data["flow_key"]) if data["flow_key"] is not None else None,
        window_start=deserialize_datetime(data["window_start"]) if data["window_start"] is not None else None,
        window_end=deserialize_datetime(data["window_end"]) if data["window_end"] is not None else None,
        risk_score=data["risk_score"],
        risk_level=RiskLevel(data["risk_level"]),
        detection_ids=list(data["detection_ids"]),
        target=deserialize_response_target(data.get("target")),
        explanation=data["explanation"],
    )


def serialize_response_result(result: ResponseResult) -> Dict[str, Any]:
    return {
        "action": result.action.value,
        "status": result.status.value,
        "simulated": result.simulated,
        "target": serialize_response_target(result.target),
        "message": result.message,
        "error": result.error,
        "timestamp": serialize_datetime(result.timestamp),
    }


def deserialize_response_result(data: Dict[str, Any]) -> ResponseResult:
    return ResponseResult(
        action=PolicyAction(data["action"]),
        status=ResponseStatus(data["status"]),
        simulated=data["simulated"],
        target=deserialize_response_target(data.get("target")),
        message=data["message"],
        error=data.get("error"),
        timestamp=deserialize_datetime(data["timestamp"]),
    )


def _validate_json_compatible(value: Any, *, context: str) -> None:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_compatible(item, context=context)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{context} contains a non-string dictionary key")
            _validate_json_compatible(item, context=context)
        return
    raise ValueError(f"{context} contains unsupported non-JSON data: {type(value).__name__}")
