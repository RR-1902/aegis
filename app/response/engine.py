"""Simulation-only response engine for AEGIS."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
from typing import Optional

from app.config.settings import settings
from app.models.policy import ExecutionMode, PolicyAction, ResponseDecision, ResponseTarget
from app.models.response import ResponseResult, ResponseStatus


@dataclass(frozen=True)
class ResponseEngine:
    """Validate and simulate constrained response decisions.

    This engine is intentionally OS-neutral and simulation-only. It does not
    execute firewall commands, spawn subprocesses, or modify system state.
    """

    safe_mode: bool = settings.safe_mode

    def handle(self, decision: ResponseDecision) -> ResponseResult:
        structure_error = self._validate_decision_structure(decision)
        if structure_error:
            return self._reject(None, None, structure_error)

        action = decision.recommended_action

        action_error = self._validate_action(action)
        if action_error:
            return self._reject(action, decision.target, action_error)

        mode_error = self._validate_execution_mode(decision.execution_mode)
        if mode_error:
            return self._reject(action, decision.target, mode_error)

        consistency_error = self._validate_action_specific_consistency(decision)
        if consistency_error:
            return self._reject(action, decision.target, consistency_error)

        target_error = self._validate_target(decision)
        if target_error:
            return self._reject(action, decision.target, target_error)

        safe_mode_error = self._validate_safe_mode_consistency(decision)
        if safe_mode_error:
            return self._reject(action, decision.target, safe_mode_error)

        if action in (PolicyAction.LOG_ONLY, PolicyAction.ALERT_ONLY):
            return ResponseResult(
                action=action,
                status=ResponseStatus.NO_ACTION,
                simulated=False,
                target=decision.target,
                message=f"No external action taken for {action.name}.",
                error=None,
                timestamp=datetime.now(timezone.utc),
            )

        if action == PolicyAction.BLOCK_SOURCE:
            if self.safe_mode:
                return ResponseResult(
                    action=action,
                    status=ResponseStatus.SIMULATED,
                    simulated=True,
                    target=decision.target,
                    message=f"Simulated BLOCK_SOURCE for {decision.target.ip}; no system state changed.",
                    error=None,
                    timestamp=datetime.now(timezone.utc),
                )

            return self._reject(
                action,
                decision.target,
                "Real execution unavailable; no ActionExecutor is installed.",
            )

        return self._reject(action, decision.target, "Unsupported action.")

    def _validate_decision_structure(self, decision: ResponseDecision) -> Optional[str]:
        if not isinstance(decision, ResponseDecision):
            return "Invalid decision type; ResponseEngine accepts only ResponseDecision."
        return None

    def _validate_action(self, action: PolicyAction) -> Optional[str]:
        if not isinstance(action, PolicyAction):
            return "Unsupported action type."
        if action not in (PolicyAction.LOG_ONLY, PolicyAction.ALERT_ONLY, PolicyAction.BLOCK_SOURCE):
            return f"Unsupported action: {action}."
        return None

    def _validate_execution_mode(self, execution_mode: ExecutionMode) -> Optional[str]:
        if not isinstance(execution_mode, ExecutionMode):
            return "Unsupported execution mode type."
        if execution_mode not in (ExecutionMode.NONE, ExecutionMode.SIMULATE, ExecutionMode.EXECUTE):
            return f"Unsupported execution mode: {execution_mode}."
        return None

    def _validate_action_specific_consistency(self, decision: ResponseDecision) -> Optional[str]:
        if decision.recommended_action == PolicyAction.LOG_ONLY and decision.execution_mode != ExecutionMode.NONE:
            return "LOG_ONLY decisions must use execution mode NONE."
        if decision.recommended_action == PolicyAction.ALERT_ONLY and decision.execution_mode != ExecutionMode.NONE:
            return "ALERT_ONLY decisions must use execution mode NONE."
        if decision.recommended_action == PolicyAction.BLOCK_SOURCE and decision.target is None:
            return "BLOCK_SOURCE requires a target."
        return None

    def _validate_target(self, decision: ResponseDecision) -> Optional[str]:
        if decision.recommended_action != PolicyAction.BLOCK_SOURCE:
            return None
        target = decision.target
        if target is None:
            return "BLOCK_SOURCE requires a target."
        if not isinstance(target, ResponseTarget):
            return "Invalid target type."
        if target.role != "observed_source":
            return "Invalid or ambiguous target role for BLOCK_SOURCE."
        try:
            ipaddress.ip_address(target.ip)
        except ValueError:
            return f"Invalid target IP: {target.ip}"
        return None

    def _validate_safe_mode_consistency(self, decision: ResponseDecision) -> Optional[str]:
        if decision.recommended_action in (PolicyAction.LOG_ONLY, PolicyAction.ALERT_ONLY):
            return None
        if decision.recommended_action == PolicyAction.BLOCK_SOURCE:
            if self.safe_mode and decision.execution_mode != ExecutionMode.SIMULATE:
                return "BLOCK_SOURCE must use SIMULATE when SAFE_MODE is enabled."
            if not self.safe_mode and decision.execution_mode != ExecutionMode.EXECUTE:
                return "BLOCK_SOURCE must use EXECUTE when SAFE_MODE is disabled."
        return None

    def _reject(self, action: Optional[PolicyAction], target: Optional[ResponseTarget], reason: str) -> ResponseResult:
        if isinstance(action, PolicyAction):
            rejected_action = action
            action_label = action.name
        else:
            rejected_action = PolicyAction.ALERT_ONLY
            action_label = "UNKNOWN_ACTION"

        return ResponseResult(
            action=rejected_action,
            status=ResponseStatus.REJECTED,
            simulated=False,
            target=target,
            message=f"Rejected {action_label}: {reason}",
            error=reason,
            timestamp=datetime.now(timezone.utc),
        )
