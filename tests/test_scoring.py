"""Tests for stateless heuristic risk scoring."""

from datetime import datetime, timedelta, timezone

import pytest

from app.config.settings import settings
from app.models.detection import DetectionResult, DetectionSeverity
from app.models.flow import FlowKey
from app.models.risk import RiskLevel
from app.scoring.risk_scorer import RiskScorer


def make_detection(rule_id: str, rule_name: str, severity: DetectionSeverity, *, flow_key=None, window_start=None, window_end=None):
    flow_key = flow_key or FlowKey(src_ip="192.168.1.10", dst_ip="192.168.1.20", protocol="TCP")
    window_start = window_start or datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    window_end = window_end or (window_start + timedelta(seconds=10))
    return DetectionResult(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        flow_key=flow_key,
        window_start=window_start,
        window_end=window_end,
        evidence={"marker": f"{rule_id}:{severity.value}"},
        explanation=f"{rule_name} explained",
    )


class TestRiskScorerCore:
    def test_empty_detection_list(self):
        scorer = RiskScorer()
        result = scorer.score([])
        assert result.score == 0
        assert result.level == RiskLevel.LOW
        assert result.flow_key is None
        assert result.window_start is None
        assert result.window_end is None
        assert result.detections == []

    def test_one_detection(self):
        scorer = RiskScorer(port_scan_medium=25)
        detection = make_detection("port_scan", "Port Scan", DetectionSeverity.MEDIUM)
        result = scorer.score([detection])
        assert result.score == 25
        assert result.level == RiskLevel.LOW
        assert result.detections == [detection]

    def test_multiple_detections(self):
        scorer = RiskScorer(port_scan_medium=25, syn_flood_high=55)
        detections = [
            make_detection("port_scan", "Port Scan", DetectionSeverity.MEDIUM),
            make_detection("syn_flood", "SYN Flood", DetectionSeverity.HIGH),
        ]
        result = scorer.score(detections)
        assert result.score == 80
        assert result.level == RiskLevel.CRITICAL

    def test_mixed_severity_detections(self):
        scorer = RiskScorer(port_scan_high=40, syn_flood_medium=35)
        detections = [
            make_detection("port_scan", "Port Scan", DetectionSeverity.HIGH),
            make_detection("syn_flood", "SYN Flood", DetectionSeverity.MEDIUM),
        ]
        result = scorer.score(detections)
        assert result.score == 75
        assert result.level == RiskLevel.HIGH

    def test_score_cap_at_100(self):
        scorer = RiskScorer(port_scan_high=60, syn_flood_high=70)
        detections = [
            make_detection("port_scan", "Port Scan", DetectionSeverity.HIGH),
            make_detection("syn_flood", "SYN Flood", DetectionSeverity.HIGH),
        ]
        result = scorer.score(detections)
        assert result.score == 100
        assert result.level == RiskLevel.CRITICAL


class TestRiskScorerThresholdBoundaries:
    def test_exactly_threat_score_low(self):
        scorer = RiskScorer(port_scan_medium=settings.threat_score_low)
        result = scorer.score([make_detection("port_scan", "Port Scan", DetectionSeverity.MEDIUM)])
        assert result.score == settings.threat_score_low
        assert result.level == RiskLevel.LOW

    def test_one_point_above_threat_score_low(self):
        scorer = RiskScorer(port_scan_medium=settings.threat_score_low + 1)
        result = scorer.score([make_detection("port_scan", "Port Scan", DetectionSeverity.MEDIUM)])
        assert result.score == settings.threat_score_low + 1
        assert result.level == RiskLevel.MEDIUM

    def test_exactly_threat_score_medium(self):
        scorer = RiskScorer(port_scan_medium=settings.threat_score_medium)
        result = scorer.score([make_detection("port_scan", "Port Scan", DetectionSeverity.MEDIUM)])
        assert result.level == RiskLevel.MEDIUM

    def test_one_point_above_threat_score_medium(self):
        scorer = RiskScorer(port_scan_medium=settings.threat_score_medium + 1)
        result = scorer.score([make_detection("port_scan", "Port Scan", DetectionSeverity.MEDIUM)])
        assert result.level == RiskLevel.HIGH

    def test_exactly_threat_score_high(self):
        scorer = RiskScorer(port_scan_high=settings.threat_score_high)
        result = scorer.score([make_detection("port_scan", "Port Scan", DetectionSeverity.HIGH)])
        assert result.level == RiskLevel.HIGH

    def test_one_point_above_threat_score_high(self):
        scorer = RiskScorer(port_scan_high=settings.threat_score_high + 1)
        result = scorer.score([make_detection("port_scan", "Port Scan", DetectionSeverity.HIGH)])
        assert result.level == RiskLevel.CRITICAL


class TestRiskScorerConfigAndIdentity:
    def test_changing_scoring_weights_changes_score(self):
        detection = make_detection("syn_flood", "SYN Flood", DetectionSeverity.HIGH)
        low_weight = RiskScorer(syn_flood_high=45).score([detection])
        high_weight = RiskScorer(syn_flood_high=65).score([detection])
        assert low_weight.score == 45
        assert high_weight.score == 65

    def test_detection_thresholds_and_scoring_weights_are_separate(self):
        detection = make_detection("port_scan", "Port Scan", DetectionSeverity.MEDIUM)
        scorer = RiskScorer(port_scan_medium=33)
        result = scorer.score([detection])
        assert settings.port_scan_threshold == 20
        assert result.score == 33

    def test_flow_key_and_window_metadata_preserved(self):
        flow_key = FlowKey(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="TCP")
        window_start = datetime(2024, 2, 1, 0, 0, 0, tzinfo=timezone.utc)
        window_end = window_start + timedelta(seconds=5)
        detection = make_detection(
            "port_scan",
            "Port Scan",
            DetectionSeverity.MEDIUM,
            flow_key=flow_key,
            window_start=window_start,
            window_end=window_end,
        )
        result = RiskScorer().score([detection])
        assert result.flow_key == flow_key
        assert result.window_start == window_start
        assert result.window_end == window_end

    def test_mixed_identities_raise_value_error(self):
        d1 = make_detection("port_scan", "Port Scan", DetectionSeverity.MEDIUM)
        d2 = make_detection(
            "syn_flood",
            "SYN Flood",
            DetectionSeverity.HIGH,
            window_start=datetime(2024, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 0, 1, 10, tzinfo=timezone.utc),
        )
        with pytest.raises(ValueError, match="exactly one observation identity"):
            RiskScorer().score([d1, d2])


class TestRiskScorerExplainabilityAndDeterminism:
    def test_explanation_contains_score_level_rules_and_contributions(self):
        scorer = RiskScorer(port_scan_medium=25, syn_flood_high=55)
        detections = [
            make_detection("port_scan", "Port Scan", DetectionSeverity.MEDIUM),
            make_detection("syn_flood", "SYN Flood", DetectionSeverity.HIGH),
        ]
        result = scorer.score(detections)
        assert "80/100" in result.explanation
        assert "CRITICAL" in result.explanation
        assert "Port Scan (MEDIUM) contributed 25" in result.explanation
        assert "SYN Flood (HIGH) contributed 55" in result.explanation

    def test_original_detection_evidence_preserved(self):
        detection = make_detection("port_scan", "Port Scan", DetectionSeverity.MEDIUM)
        result = RiskScorer().score([detection])
        assert result.detections[0].evidence == detection.evidence
        assert result.detections[0].explanation == detection.explanation

    def test_repeated_scoring_is_deterministic(self):
        detections = [
            make_detection("port_scan", "Port Scan", DetectionSeverity.HIGH),
            make_detection("syn_flood", "SYN Flood", DetectionSeverity.MEDIUM),
        ]
        scorer = RiskScorer()
        first = scorer.score(detections)
        second = scorer.score(detections)
        assert first == second


class TestRiskScorerSlidingAndSafety:
    def test_overlapping_observations_are_scored_independently(self):
        flow_key = FlowKey(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="TCP")
        t1 = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2024, 1, 1, 0, 0, 5, tzinfo=timezone.utc)
        d1 = make_detection("port_scan", "Port Scan", DetectionSeverity.MEDIUM, flow_key=flow_key, window_start=t1, window_end=t1 + timedelta(seconds=10))
        d2 = make_detection("port_scan", "Port Scan", DetectionSeverity.MEDIUM, flow_key=flow_key, window_start=t2, window_end=t2 + timedelta(seconds=10))
        scorer = RiskScorer(port_scan_medium=25)
        r1 = scorer.score([d1])
        r2 = scorer.score([d2])
        assert r1.window_start != r2.window_start
        assert r1.score == r2.score == 25

    def test_safe_mode_has_no_effect(self):
        detection = make_detection("syn_flood", "SYN Flood", DetectionSeverity.HIGH)
        original_safe_mode = settings.safe_mode
        try:
            settings.safe_mode = True
            safe = RiskScorer().score([detection])
            settings.safe_mode = False
            unsafe = RiskScorer().score([detection])
        finally:
            settings.safe_mode = original_safe_mode
        assert safe == unsafe
