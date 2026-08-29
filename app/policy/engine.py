"""Stateless conservative policy engine for AEGIS."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.config.settings import settings
from app.models.policy import ExecutionMode, PolicyAction, ResponseDecision, ResponseTarget
from app.models.risk import RiskLevel, RiskScore


@dataclass(frozen=True)
class PolicyEngine:
    """Convert risk assessments into constrained response decisions.

    This component is deterministic, stateless, and side-effect free. It does
    not execute actions; it only expresses what a future response layer may do.
    """

    safe_mode: bool = settings.safe_mode

    def decide(self, risk_score: RiskScore) -> ResponseDecision:
        detection_ids = [d.rule_id for d in risk_score.detections]
        action = PolicyAction.LOG_ONLY
        target: Optional[ResponseTarget] = None
        attribution_reason = "No actionable attribution required."

        if risk_score.level == RiskLevel.LOW:
            action = PolicyAction.LOG_ONLY
        elif risk_score.level == RiskLevel.MEDIUM:
            action = PolicyAction.ALERT_ONLY
        else:
            action, target, attribution_reason = self._decide_high_or_critical(risk_score)

        execution_mode = ExecutionMode.NONE
        if action == PolicyAction.BLOCK_SOURCE:
            execution_mode = ExecutionMode.SIMULATE if self.safe_mode else ExecutionMode.EXECUTE

        explanation = self._build_explanation(
            risk_score=risk_score,
            detection_ids=detection_ids,
            action=action,
            target=target,
            attribution_reason=attribution_reason,
            execution_mode=execution_mode,
        )

        return ResponseDecision(
            recommended_action=action,
            allowed=True,
            execution_mode=execution_mode,
            flow_key=risk_score.flow_key,
            window_start=risk_score.window_start,
            window_end=risk_score.window_end,
            risk_score=risk_score.score,
            risk_level=risk_score.level,
            detection_ids=detection_ids,
            target=target,
            explanation=explanation,
        )

    def _decide_high_or_critical(self, risk_score: RiskScore) -> tuple[PolicyAction, Optional[ResponseTarget], str]:
        detection_ids = {d.rule_id for d in risk_score.detections}
        has_syn_flood = "syn_flood" in detection_ids
        has_port_scan = "port_scan" in detection_ids

        if has_syn_flood:
            target = self._extract_defensible_observed_source_target(risk_score)
            if target is not None:
                return (
                    PolicyAction.BLOCK_SOURCE,
                    target,
                    "Blocking is recommended because SYN flood evidence is present and explicit observed source attribution is available in detection evidence.",
                )

        if has_port_scan and risk_score.level == RiskLevel.CRITICAL:
            target = self._extract_defensible_observed_source_target(risk_score)
            if target is not None:
                return (
                    PolicyAction.BLOCK_SOURCE,
                    target,
                    "Blocking is recommended because critical port-scan risk is present and explicit observed source attribution is available in detection evidence.",
                )

        return (
            PolicyAction.ALERT_ONLY,
            None,
            "Automatic blocking was not authorized because explicit defensible source attribution was not available from the detection evidence.",
        )

    def _extract_defensible_observed_source_target(self, risk_score: RiskScore) -> Optional[ResponseTarget]:
        for detection in risk_score.detections:
            evidence = detection.evidence or {}
            target = evidence.get("response_target")
            if not isinstance(target, dict):
                continue
            if target.get("role") != "observed_source":
                continue
            ip = target.get("ip")
            if not ip:
                continue
            port = target.get("port")
            return ResponseTarget(ip=ip, port=port, role="observed_source")
        return None

    def _build_explanation(
        self,
        *,
        risk_score: RiskScore,
        detection_ids: list[str],
        action: PolicyAction,
        target: Optional[ResponseTarget],
        attribution_reason: str,
        execution_mode: ExecutionMode,
    ) -> str:
        target_text = "no target" if target is None else f"target {target.ip} ({target.role})"
        safe_mode_text = "enabled" if self.safe_mode else "disabled"
        return (
            f"Risk score {risk_score.score} ({risk_score.level.name}) with detections {detection_ids} "
            f"resulted in policy action {action.name} and {target_text}. "
            f"{attribution_reason} SAFE_MODE is {safe_mode_text}, so execution mode is {execution_mode.name}."
        )
