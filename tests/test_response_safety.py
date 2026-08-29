"""Tests for the simulation-only response engine."""

from datetime import datetime, timedelta, timezone

from app.models.flow import FlowKey
from app.models.policy import ExecutionMode, PolicyAction, ResponseDecision, ResponseTarget
from app.models.response import ResponseStatus
from app.models.risk import RiskLevel
from app.response.engine import ResponseEngine


def make_decision(action=PolicyAction.ALERT_ONLY, execution_mode=ExecutionMode.NONE, target=None):
    return ResponseDecision(
        recommended_action=action,
        allowed=True,
        execution_mode=execution_mode,
        flow_key=FlowKey(src_ip="192.168.1.10", dst_ip="192.168.1.20", protocol="TCP"),
        window_start=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        window_end=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
        risk_score=80,
        risk_level=RiskLevel.CRITICAL,
        detection_ids=["syn_flood"],
        target=target,
        explanation="policy explanation",
    )


class TestResponseEngineBasic:
    def test_log_only_no_action(self):
        result = ResponseEngine().handle(make_decision(action=PolicyAction.LOG_ONLY, execution_mode=ExecutionMode.NONE))
        assert result.action == PolicyAction.LOG_ONLY
        assert result.status == ResponseStatus.NO_ACTION
        assert result.simulated is False

    def test_alert_only_no_action(self):
        result = ResponseEngine().handle(make_decision(action=PolicyAction.ALERT_ONLY, execution_mode=ExecutionMode.NONE))
        assert result.action == PolicyAction.ALERT_ONLY
        assert result.status == ResponseStatus.NO_ACTION
        assert result.simulated is False

    def test_block_source_safe_mode_true_simulates(self):
        decision = make_decision(
            action=PolicyAction.BLOCK_SOURCE,
            execution_mode=ExecutionMode.SIMULATE,
            target=ResponseTarget(ip="10.0.0.5", port=12345, role="observed_source"),
        )
        result = ResponseEngine(safe_mode=True).handle(decision)
        assert result.status == ResponseStatus.SIMULATED
        assert result.simulated is True
        assert "no system state changed" in result.message
        assert "blocked successfully" not in result.message.lower()

    def test_block_source_safe_mode_false_rejected_without_executor(self):
        decision = make_decision(
            action=PolicyAction.BLOCK_SOURCE,
            execution_mode=ExecutionMode.EXECUTE,
            target=ResponseTarget(ip="10.0.0.5", port=12345, role="observed_source"),
        )
        result = ResponseEngine(safe_mode=False).handle(decision)
        assert result.status == ResponseStatus.REJECTED
        assert result.simulated is False
        assert result.error == "Real execution unavailable; no ActionExecutor is installed."


class TestResponseEngineValidation:
    def test_missing_target_rejected(self):
        decision = make_decision(action=PolicyAction.BLOCK_SOURCE, execution_mode=ExecutionMode.SIMULATE, target=None)
        result = ResponseEngine(safe_mode=True).handle(decision)
        assert result.status == ResponseStatus.REJECTED
        assert "requires a target" in result.error

    def test_invalid_ip_rejected(self):
        decision = make_decision(
            action=PolicyAction.BLOCK_SOURCE,
            execution_mode=ExecutionMode.SIMULATE,
            target=ResponseTarget(ip="not-an-ip", port=1, role="observed_source"),
        )
        result = ResponseEngine(safe_mode=True).handle(decision)
        assert result.status == ResponseStatus.REJECTED
        assert "Invalid target IP" in result.error

    def test_invalid_target_role_rejected(self):
        decision = make_decision(
            action=PolicyAction.BLOCK_SOURCE,
            execution_mode=ExecutionMode.SIMULATE,
            target=ResponseTarget(ip="10.0.0.5", port=1, role="attacker"),
        )
        result = ResponseEngine(safe_mode=True).handle(decision)
        assert result.status == ResponseStatus.REJECTED
        assert "Invalid or ambiguous target role" in result.error

    def test_unsupported_action_type_rejected(self):
        decision = make_decision()
        object.__setattr__(decision, "recommended_action", "BLOCK_DESTINATION")
        result = ResponseEngine().handle(decision)
        assert result.status == ResponseStatus.REJECTED
        assert "Unsupported action type" in result.error

    def test_malformed_decision_type_rejected(self):
        result = ResponseEngine().handle("not a decision")
        assert result.status == ResponseStatus.REJECTED
        assert "ResponseEngine accepts only ResponseDecision" in result.error

    def test_inconsistent_execution_mode_rejected(self):
        decision = make_decision(action=PolicyAction.LOG_ONLY, execution_mode=ExecutionMode.SIMULATE)
        result = ResponseEngine().handle(decision)
        assert result.status == ResponseStatus.REJECTED
        assert "LOG_ONLY decisions must use execution mode NONE" in result.error


class TestResponseEngineMetadataAndDeterminism:
    def test_action_target_and_timestamp_preserved(self):
        target = ResponseTarget(ip="10.0.0.5", port=12345, role="observed_source")
        decision = make_decision(
            action=PolicyAction.BLOCK_SOURCE,
            execution_mode=ExecutionMode.SIMULATE,
            target=target,
        )
        result = ResponseEngine(safe_mode=True).handle(decision)
        assert result.action == PolicyAction.BLOCK_SOURCE
        assert result.target == target
        assert result.timestamp is not None

    def test_errors_present_for_rejection(self):
        decision = make_decision(action=PolicyAction.BLOCK_SOURCE, execution_mode=ExecutionMode.SIMULATE, target=None)
        result = ResponseEngine(safe_mode=True).handle(decision)
        assert result.status == ResponseStatus.REJECTED
        assert result.error is not None

    def test_same_decision_same_status_message_and_action(self):
        target = ResponseTarget(ip="10.0.0.5", port=12345, role="observed_source")
        decision = make_decision(
            action=PolicyAction.BLOCK_SOURCE,
            execution_mode=ExecutionMode.SIMULATE,
            target=target,
        )
        engine = ResponseEngine(safe_mode=True)
        first = engine.handle(decision)
        second = engine.handle(decision)
        assert first.action == second.action
        assert first.status == second.status
        assert first.simulated == second.simulated
        assert first.target == second.target
        assert first.message == second.message
        assert first.error == second.error
