"""Tests for the stateless deterministic detection engine."""

from datetime import datetime, timedelta, timezone

from app.config.settings import settings
from app.detection.engine import DetectionEngine
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.syn_flood import SynFloodRule
from app.models.detection import DetectionSeverity
from app.models.flow import FeatureObservation, FlowKey


def make_observation(**feature_overrides) -> FeatureObservation:
    window_start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    window_end = window_start + timedelta(seconds=10)
    features = {
        "packet_count": 0,
        "byte_count": 0,
        "syn_count": 0,
        "ack_count": 0,
        "fin_count": 0,
        "rst_count": 0,
        "psh_count": 0,
        "connection_attempts": 0,
        "successful_connections": 0,
        "failed_connections": 0,
        "incomplete_connections": 0,
        "unique_destination_ports": 0,
        "unique_destination_ips": 0,
        "packets_per_second": 0.0,
        "bytes_per_second": 0.0,
        "syn_rate": 0.0,
        "connection_rate": 0.0,
        "syn_to_total_ratio": 0.0,
        "incomplete_connection_ratio": 0.0,
        "successful_connection_ratio": 0.0,
        "rst_to_total_ratio": 0.0,
        "duration_seconds": 0.0,
        "average_packet_size": 0.0,
        "min_packet_size": 0,
        "max_packet_size": 0,
        "bytes_sent": 0,
        "bytes_received": 0,
        "bytes_ratio": 0.0,
    }
    features.update(feature_overrides)
    return FeatureObservation(
        flow_key=FlowKey(src_ip="192.168.1.10", dst_ip="192.168.1.20", protocol="TCP"),
        window_start=window_start,
        window_end=window_end,
        features=features,
        finalized=True,
        sliding=False,
    )


class TestPortScanRule:
    def test_below_threshold_no_detection(self):
        rule = PortScanRule(port_scan_threshold=20, port_scan_time_window=10)
        observation = make_observation(unique_destination_ports=19, syn_count=10, syn_rate=5.0)
        assert rule.evaluate(observation) is None

    def test_exactly_threshold_triggers(self):
        rule = PortScanRule(port_scan_threshold=20, port_scan_time_window=10)
        observation = make_observation(unique_destination_ports=20, syn_count=10)
        result = rule.evaluate(observation)
        assert result is not None
        assert result.rule_id == "port_scan"
        assert result.severity == DetectionSeverity.MEDIUM

    def test_above_threshold_triggers_high(self):
        rule = PortScanRule(port_scan_threshold=20, port_scan_time_window=10)
        observation = make_observation(unique_destination_ports=27, syn_count=15, syn_rate=12.5)
        result = rule.evaluate(observation)
        assert result is not None
        assert result.severity == DetectionSeverity.HIGH

    def test_evidence_and_explanation_are_consistent(self):
        rule = PortScanRule(port_scan_threshold=20, port_scan_time_window=10)
        observation = make_observation(
            unique_destination_ports=27,
            syn_count=15,
            syn_rate=12.5,
            connection_attempts=14,
            successful_connection_ratio=0.1,
            incomplete_connection_ratio=0.9,
            duration_seconds=4.0,
        )
        result = rule.evaluate(observation)
        assert result is not None
        assert result.flow_key == observation.flow_key
        assert result.window_start == observation.window_start
        assert result.window_end == observation.window_end
        assert result.evidence["features"]["unique_destination_ports"] == 27
        assert result.evidence["thresholds"]["port_scan_threshold"] == 20
        assert result.evidence["comparisons"]["unique_destination_ports >= port_scan_threshold"] is True
        assert "27 unique destination ports" in result.explanation
        assert "20" in result.explanation

    def test_five_tuple_limitation_example_does_not_trigger(self):
        rule = PortScanRule(port_scan_threshold=20, port_scan_time_window=10)
        observation = make_observation(unique_destination_ports=1)
        assert rule.evaluate(observation) is None

    def test_three_tuple_like_aggregation_can_trigger(self):
        rule = PortScanRule(port_scan_threshold=20, port_scan_time_window=10)
        observation = make_observation(unique_destination_ports=25)
        assert rule.evaluate(observation) is not None

    def test_bidirectional_observation_can_trigger(self):
        rule = PortScanRule(port_scan_threshold=20, port_scan_time_window=10)
        observation = make_observation(unique_destination_ports=21)
        bidirectional_obs = FeatureObservation(
            flow_key=FlowKey(src_ip="192.168.1.10", dst_ip="192.168.1.20", protocol="TCP", src_port=50000, dst_port=80),
            window_start=observation.window_start,
            window_end=observation.window_end,
            features=observation.features,
            finalized=True,
            sliding=False,
        )
        assert rule.evaluate(bidirectional_obs) is not None


class TestSynFloodRule:
    def test_below_syn_rate_threshold_no_detection(self):
        rule = SynFloodRule(syn_rate_threshold=10.0, syn_incomplete_ratio=0.7)
        observation = make_observation(syn_rate=9.9, incomplete_connection_ratio=0.9, syn_count=50)
        assert rule.evaluate(observation) is None

    def test_exact_thresholds_trigger(self):
        rule = SynFloodRule(syn_rate_threshold=10.0, syn_incomplete_ratio=0.7)
        observation = make_observation(
            syn_rate=10.0,
            incomplete_connection_ratio=0.7,
            syn_count=20,
            syn_to_total_ratio=1.0,
            connection_attempts=20,
            packet_count=20,
        )
        result = rule.evaluate(observation)
        assert result is not None
        assert result.severity == DetectionSeverity.MEDIUM

    def test_above_thresholds_trigger_high(self):
        rule = SynFloodRule(syn_rate_threshold=10.0, syn_incomplete_ratio=0.7)
        observation = make_observation(
            syn_rate=12.0,
            incomplete_connection_ratio=0.9,
            syn_count=40,
            syn_to_total_ratio=1.0,
            connection_attempts=40,
            packet_count=40,
        )
        result = rule.evaluate(observation)
        assert result is not None
        assert result.severity == DetectionSeverity.HIGH

    def test_incomplete_ratio_boundary_below_no_detection(self):
        rule = SynFloodRule(syn_rate_threshold=10.0, syn_incomplete_ratio=0.7)
        observation = make_observation(syn_rate=10.0, incomplete_connection_ratio=0.69)
        assert rule.evaluate(observation) is None

    def test_evidence_and_explanation_are_consistent(self):
        rule = SynFloodRule(syn_rate_threshold=10.0, syn_incomplete_ratio=0.7)
        observation = make_observation(
            syn_rate=10.0,
            incomplete_connection_ratio=0.75,
            syn_count=12,
            syn_to_total_ratio=0.9,
            connection_attempts=11,
            packet_count=15,
        )
        result = rule.evaluate(observation)
        assert result is not None
        assert result.evidence["features"]["syn_rate"] == 10.0
        assert result.evidence["features"]["incomplete_connection_ratio"] == 0.75
        assert result.evidence["thresholds"]["syn_rate_threshold"] == 10.0
        assert result.evidence["thresholds"]["syn_incomplete_ratio"] == 0.7
        assert result.evidence["comparisons"]["syn_rate >= syn_rate_threshold"] is True
        assert result.evidence["comparisons"]["incomplete_connection_ratio >= syn_incomplete_ratio"] is True
        assert "syn_rate=10.0" in result.explanation
        assert "0.7" in result.explanation

    def test_udp_like_observation_does_not_trigger(self):
        rule = SynFloodRule(syn_rate_threshold=10.0, syn_incomplete_ratio=0.7)
        observation = make_observation(packet_count=50, bytes_per_second=1000.0)
        assert rule.evaluate(observation) is None


class TestDetectionEngine:
    def test_zero_detections(self):
        engine = DetectionEngine(rules=[PortScanRule(port_scan_threshold=20, port_scan_time_window=10)])
        observation = make_observation(unique_destination_ports=1)
        assert engine.evaluate(observation) == []

    def test_one_detection(self):
        engine = DetectionEngine(rules=[PortScanRule(port_scan_threshold=20, port_scan_time_window=10)])
        observation = make_observation(unique_destination_ports=25)
        results = engine.evaluate(observation)
        assert len(results) == 1
        assert results[0].rule_id == "port_scan"

    def test_multiple_rules_triggered(self):
        engine = DetectionEngine(rules=[
            PortScanRule(port_scan_threshold=20, port_scan_time_window=10),
            SynFloodRule(syn_rate_threshold=10.0, syn_incomplete_ratio=0.7),
        ])
        observation = make_observation(
            unique_destination_ports=25,
            syn_rate=12.0,
            incomplete_connection_ratio=0.9,
            syn_count=30,
            packet_count=30,
        )
        results = engine.evaluate(observation)
        assert [result.rule_id for result in results] == ["port_scan", "syn_flood"]

    def test_deterministic_ordering(self):
        engine = DetectionEngine(rules=[
            PortScanRule(port_scan_threshold=20, port_scan_time_window=10),
            SynFloodRule(syn_rate_threshold=10.0, syn_incomplete_ratio=0.7),
        ])
        observation = make_observation(unique_destination_ports=20, syn_rate=10.0, incomplete_connection_ratio=0.7)
        results = engine.evaluate(observation)
        assert [result.rule_id for result in results] == ["port_scan", "syn_flood"]

    def test_duplicate_evaluation_is_deduplicated(self):
        engine = DetectionEngine(rules=[PortScanRule(port_scan_threshold=20, port_scan_time_window=10)])
        observation = make_observation(unique_destination_ports=25)
        first = engine.evaluate(observation)
        second = engine.evaluate(observation)
        assert len(first) == 1
        assert second == []

    def test_separate_rule_identities_are_preserved(self):
        engine = DetectionEngine(rules=[
            PortScanRule(port_scan_threshold=20, port_scan_time_window=10),
            SynFloodRule(syn_rate_threshold=10.0, syn_incomplete_ratio=0.7),
        ])
        observation = make_observation(unique_destination_ports=25, syn_rate=10.0, incomplete_connection_ratio=0.7)
        results = engine.evaluate(observation)
        assert len(results) == 2
        assert results[0].rule_id != results[1].rule_id

    def test_observation_metadata_preserved(self):
        engine = DetectionEngine(rules=[PortScanRule(port_scan_threshold=20, port_scan_time_window=10)])
        observation = make_observation(unique_destination_ports=20)
        result = engine.evaluate(observation)[0]
        assert result.flow_key == observation.flow_key
        assert result.window_start == observation.window_start
        assert result.window_end == observation.window_end

    def test_safe_mode_does_not_change_detection_behavior(self):
        engine = DetectionEngine(rules=[SynFloodRule(syn_rate_threshold=10.0, syn_incomplete_ratio=0.7)])
        observation = make_observation(syn_rate=10.0, incomplete_connection_ratio=0.7)
        original_safe_mode = settings.safe_mode
        try:
            settings.safe_mode = True
            results_safe = engine.evaluate(observation)
            engine.reset()
            settings.safe_mode = False
            results_unsafe = engine.evaluate(observation)
        finally:
            settings.safe_mode = original_safe_mode
        assert len(results_safe) == 1
        assert len(results_unsafe) == 1
        assert results_safe[0].rule_id == results_unsafe[0].rule_id

    def test_empty_feature_map_yields_no_detection(self):
        engine = DetectionEngine()
        observation = FeatureObservation(
            flow_key=FlowKey(src_ip="192.168.1.10", dst_ip="192.168.1.20", protocol="TCP"),
            window_start=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
            features={},
            finalized=True,
            sliding=False,
        )
        assert engine.evaluate(observation) == []
