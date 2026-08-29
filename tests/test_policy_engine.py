"""Tests for the stateless conservative policy engine."""

from datetime import datetime, timedelta, timezone

from app.models.detection import DetectionResult, DetectionSeverity
from app.models.flow import FlowKey
from app.models.policy import ExecutionMode, PolicyAction
from app.models.risk import RiskLevel, RiskScore
from app.policy.engine import PolicyEngine


def make_detection(rule_id: str, *, flow_key=None, evidence=None):
    flow_key = flow_key or FlowKey(src_ip="192.168.1.10", dst_ip="192.168.1.20", protocol="TCP", src_port=50000, dst_port=80)
    window_start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    window_end = window_start + timedelta(seconds=10)
    return DetectionResult(
        rule_id=rule_id,
        rule_name=rule_id.replace("_", " ").title(),
        severity=DetectionSeverity.HIGH,
        flow_key=flow_key,
        window_start=window_start,
        window_end=window_end,
        evidence=evidence or {},
        explanation=f"{rule_id} explanation",
    )


def make_risk(level: RiskLevel, score: int, detections=None, flow_key=None):
    flow_key = flow_key or FlowKey(src_ip="192.168.1.10", dst_ip="192.168.1.20", protocol="TCP", src_port=50000, dst_port=80)
    window_start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    window_end = window_start + timedelta(seconds=10)
    return RiskScore(
        score=score,
        level=level,
        flow_key=flow_key,
        window_start=window_start,
        window_end=window_end,
        detections=detections or [],
        explanation=f"Risk {score} {level.name}",
    )


class TestPolicyEngineRiskMappings:
    def test_low_risk_maps_to_log_only(self):
        decision = PolicyEngine().decide(make_risk(RiskLevel.LOW, 10))
        assert decision.recommended_action == PolicyAction.LOG_ONLY
        assert decision.execution_mode == ExecutionMode.NONE
        assert decision.allowed is True

    def test_medium_risk_maps_to_alert_only(self):
        decision = PolicyEngine().decide(make_risk(RiskLevel.MEDIUM, 40))
        assert decision.recommended_action == PolicyAction.ALERT_ONLY
        assert decision.execution_mode == ExecutionMode.NONE

    def test_high_port_scan_without_attribution_stays_alert_only(self):
        detections = [make_detection("port_scan")]
        decision = PolicyEngine().decide(make_risk(RiskLevel.HIGH, 70, detections=detections))
        assert decision.recommended_action == PolicyAction.ALERT_ONLY
        assert decision.target is None

    def test_critical_port_scan_with_attribution_can_recommend_block(self):
        detections = [make_detection("port_scan", evidence={"response_target": {"ip": "10.0.0.5", "port": 12345, "role": "observed_source"}})]
        decision = PolicyEngine(safe_mode=True).decide(make_risk(RiskLevel.CRITICAL, 85, detections=detections))
        assert decision.recommended_action == PolicyAction.BLOCK_SOURCE
        assert decision.target is not None
        assert decision.target.ip == "10.0.0.5"
        assert decision.target.role == "observed_source"
        assert decision.execution_mode == ExecutionMode.SIMULATE

    def test_high_syn_flood_with_attribution_can_recommend_block(self):
        detections = [make_detection("syn_flood", evidence={"response_target": {"ip": "10.0.0.8", "port": 40000, "role": "observed_source"}})]
        decision = PolicyEngine(safe_mode=False).decide(make_risk(RiskLevel.HIGH, 70, detections=detections))
        assert decision.recommended_action == PolicyAction.BLOCK_SOURCE
        assert decision.execution_mode == ExecutionMode.EXECUTE
        assert decision.target is not None
        assert decision.target.ip == "10.0.0.8"

    def test_multiple_detections_use_stronger_actionable_signal(self):
        detections = [
            make_detection("port_scan"),
            make_detection("syn_flood", evidence={"response_target": {"ip": "10.0.0.9", "port": 4444, "role": "observed_source"}}),
        ]
        decision = PolicyEngine(safe_mode=True).decide(make_risk(RiskLevel.CRITICAL, 95, detections=detections))
        assert decision.recommended_action == PolicyAction.BLOCK_SOURCE
        assert decision.target is not None
        assert decision.target.ip == "10.0.0.9"


class TestPolicyEngineAttributionSafety:
    def test_directional_flow_does_not_automatically_imply_attacker(self):
        flow_key = FlowKey(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP", src_port=1234, dst_port=80)
        detections = [make_detection("syn_flood", flow_key=flow_key)]
        decision = PolicyEngine().decide(make_risk(RiskLevel.CRITICAL, 90, detections=detections, flow_key=flow_key))
        assert decision.recommended_action == PolicyAction.ALERT_ONLY
        assert decision.target is None
        assert "explicit defensible source attribution was not available" in decision.explanation

    def test_bidirectional_like_flow_does_not_automatically_produce_block_target(self):
        flow_key = FlowKey(src_ip="192.168.1.10", dst_ip="192.168.1.20", protocol="TCP", src_port=80, dst_port=50000)
        detections = [make_detection("port_scan", flow_key=flow_key)]
        decision = PolicyEngine().decide(make_risk(RiskLevel.CRITICAL, 90, detections=detections, flow_key=flow_key))
        assert decision.recommended_action == PolicyAction.ALERT_ONLY
        assert decision.target is None

    def test_missing_target_stays_alert_only(self):
        detections = [make_detection("syn_flood", evidence={"response_target": {"role": "observed_source"}})]
        decision = PolicyEngine().decide(make_risk(RiskLevel.HIGH, 70, detections=detections))
        assert decision.recommended_action == PolicyAction.ALERT_ONLY
        assert decision.target is None

    def test_ambiguous_target_role_stays_alert_only(self):
        detections = [make_detection("syn_flood", evidence={"response_target": {"ip": "10.0.0.1", "role": "attacker"}})]
        decision = PolicyEngine().decide(make_risk(RiskLevel.CRITICAL, 90, detections=detections))
        assert decision.recommended_action == PolicyAction.ALERT_ONLY
        assert decision.target is None


class TestPolicyEngineSafeModeAndMetadata:
    def test_safe_mode_true_actionable_becomes_simulate(self):
        detections = [make_detection("syn_flood", evidence={"response_target": {"ip": "10.0.0.7", "role": "observed_source"}})]
        decision = PolicyEngine(safe_mode=True).decide(make_risk(RiskLevel.CRITICAL, 90, detections=detections))
        assert decision.recommended_action == PolicyAction.BLOCK_SOURCE
        assert decision.allowed is True
        assert decision.execution_mode == ExecutionMode.SIMULATE

    def test_safe_mode_false_actionable_becomes_execute(self):
        detections = [make_detection("syn_flood", evidence={"response_target": {"ip": "10.0.0.7", "role": "observed_source"}})]
        decision = PolicyEngine(safe_mode=False).decide(make_risk(RiskLevel.CRITICAL, 90, detections=detections))
        assert decision.execution_mode == ExecutionMode.EXECUTE

    def test_log_and_alert_actions_use_none_execution_mode(self):
        low = PolicyEngine().decide(make_risk(RiskLevel.LOW, 10))
        medium = PolicyEngine().decide(make_risk(RiskLevel.MEDIUM, 40))
        assert low.execution_mode == ExecutionMode.NONE
        assert medium.execution_mode == ExecutionMode.NONE

    def test_metadata_is_preserved(self):
        flow_key = FlowKey(src_ip="10.1.1.1", dst_ip="10.1.1.2", protocol="TCP")
        detections = [make_detection("port_scan", flow_key=flow_key)]
        risk = make_risk(RiskLevel.MEDIUM, 35, detections=detections, flow_key=flow_key)
        decision = PolicyEngine().decide(risk)
        assert decision.flow_key == risk.flow_key
        assert decision.window_start == risk.window_start
        assert decision.window_end == risk.window_end
        assert decision.risk_score == risk.score
        assert decision.risk_level == risk.level
        assert decision.detection_ids == ["port_scan"]


class TestPolicyEngineExplainabilityAndDeterminism:
    def test_explanation_contains_score_level_action_attribution_safe_mode_and_execution(self):
        detections = [make_detection("syn_flood", evidence={"response_target": {"ip": "10.0.0.7", "role": "observed_source"}})]
        decision = PolicyEngine(safe_mode=True).decide(make_risk(RiskLevel.CRITICAL, 90, detections=detections))
        assert "90" in decision.explanation
        assert "CRITICAL" in decision.explanation
        assert "syn_flood" in decision.explanation
        assert "BLOCK_SOURCE" in decision.explanation
        assert "SAFE_MODE is enabled" in decision.explanation
        assert "SIMULATE" in decision.explanation

    def test_same_input_produces_same_output(self):
        detections = [make_detection("port_scan")]
        risk = make_risk(RiskLevel.HIGH, 70, detections=detections)
        engine = PolicyEngine(safe_mode=True)
        first = engine.decide(risk)
        second = engine.decide(risk)
        assert first == second
