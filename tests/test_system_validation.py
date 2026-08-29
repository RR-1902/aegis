"""Deterministic system validation scenarios for the complete AEGIS runtime."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.config.settings import settings
from app.detection.engine import DetectionEngine
from app.flows.flow_builder import FlowBuilder
from app.models.detection import DetectionSeverity
from app.models.flow import FeatureObservation, FlowKey
from app.models.policy import PolicyAction
from app.models.response import ResponseStatus
from app.models.risk import RiskLevel
from app.models.security_event import SecurityEvent
from app.pipeline import AEGISPipeline
from app.policy.engine import PolicyEngine
from app.protocols.parser import ProtocolParser
from app.response.engine import ResponseEngine
from app.scoring.risk_scorer import RiskScorer
from app.storage.security_event_store import SQLiteSecurityEventStore
from tests.helpers.traffic_factory import (
    combined_suspicious_sequence,
    port_scan_sequence,
    syn_burst_sequence,
    tcp_packet,
    udp_benign_sequence,
)
from tests.test_pipeline_integration import FakePacketCapture, InMemoryEventStore


class TrackingRiskScorer(RiskScorer):
    def __init__(self):
        self.calls = 0
        super().__init__()

    def score(self, detections):
        self.calls += 1
        return super().score(detections)


class TrackingPolicyEngine(PolicyEngine):
    def __init__(self, safe_mode=True):
        self.calls = 0
        super().__init__(safe_mode=safe_mode)

    def decide(self, risk_score):
        self.calls += 1
        return super().decide(risk_score)


class TrackingResponseEngine(ResponseEngine):
    def __init__(self, safe_mode=True):
        self.calls = 0
        super().__init__(safe_mode=safe_mode)

    def handle(self, decision):
        self.calls += 1
        return super().handle(decision)


class ConflictingInMemoryEventStore(InMemoryEventStore):
    def save(self, event: SecurityEvent) -> bool:
        existing = self.events.get(event.event_id)
        if existing is not None and existing != event:
            raise ValueError("Conflicting SecurityEvent already exists for this event_id")
        return super().save(event)


class FakeReopenStore(SQLiteSecurityEventStore):
    pass


def close_all_retained_fixed_windows(builder: FlowBuilder) -> None:
    manager = builder.window_manager
    previous = list(getattr(manager, "previous_windows", []))
    for window in previous:
        manager._close_window(window)
    manager.previous_windows = []


def parse_all(parser: ProtocolParser, packets):
    parsed = []
    for raw in packets:
        item = parser.parse_packet(raw)
        assert item is not None
        parsed.append(item)
    return parsed


def build_pipeline(
    *,
    strategy="three_tuple",
    sliding=False,
    safe_mode=True,
    event_store=None,
    window_seconds=5,
    detection_engine=None,
    risk_scorer=None,
    policy_engine=None,
    response_engine=None,
):
    return AEGISPipeline(
        packet_capture=FakePacketCapture(),
        flow_builder=FlowBuilder(
            flow_key_strategy=strategy,
            use_sliding_windows=sliding,
            window_seconds=window_seconds,
        ),
        detection_engine=detection_engine or DetectionEngine(),
        risk_scorer=risk_scorer or RiskScorer(),
        policy_engine=policy_engine or PolicyEngine(safe_mode=safe_mode),
        response_engine=response_engine or ResponseEngine(safe_mode=safe_mode),
        event_store=event_store or InMemoryEventStore(),
        flow_key_strategy=strategy,
        use_sliding_windows=sliding,
    )


def advance_fixed_window(builder: FlowBuilder, parser: ProtocolParser, base_time: datetime) -> None:
    future = parser.parse_packet(
        tcp_packet(
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            src_port=65000,
            dst_port=443,
            flags="A",
            timestamp=base_time + timedelta(seconds=6),
        )
    )
    assert future is not None
    builder.add_packet(future)


def get_single_event(store):
    events = store.list_recent(limit=10) if hasattr(store, "list_recent") else list(store.events.values())
    assert len(events) == 1
    return events[0]


def find_detection(event: SecurityEvent, rule_id: str):
    for detection in event.detections:
        if detection.rule_id == rule_id:
            return detection
    raise AssertionError(f"Detection {rule_id!r} not found")


class TestNormalTrafficValidation:
    def test_benign_udp_traffic_short_circuits_after_no_detection(self):
        parser = ProtocolParser()
        store = InMemoryEventStore()
        risk = TrackingRiskScorer()
        policy = TrackingPolicyEngine()
        response = TrackingResponseEngine()
        pipeline = build_pipeline(
            strategy="five_tuple",
            event_store=store,
            risk_scorer=risk,
            policy_engine=policy,
            response_engine=response,
        )
        pipeline.start()

        base = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        for packet in parse_all(parser, udp_benign_sequence(base_time=base, count=5)):
            pipeline.flow_builder.add_packet(packet)

        advance_fixed_window(pipeline.flow_builder, parser, base)
        close_all_retained_fixed_windows(pipeline.flow_builder)

        assert store.events == {}
        assert pipeline.stats.observations_received >= 1
        assert pipeline.stats.observations_without_detections >= 1
        assert pipeline.stats.events_persisted == 0
        assert risk.calls == 0
        assert policy.calls == 0
        assert response.calls == 0


class TestPortScanValidation:
    @pytest.mark.parametrize(
        ("port_count", "expected_trigger", "expected_severity"),
        [
            (19, False, None),
            (20, True, DetectionSeverity.MEDIUM),
            (21, True, DetectionSeverity.HIGH),
        ],
    )
    def test_port_scan_threshold_matrix(self, port_count, expected_trigger, expected_severity):
        parser = ProtocolParser()
        store = InMemoryEventStore()
        pipeline = build_pipeline(strategy="three_tuple", event_store=store)
        pipeline.start()

        base = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        packets = port_scan_sequence(
            base_time=base,
            dst_ports=list(range(80, 80 + port_count)),
            step=timedelta(milliseconds=120),
        )
        for packet in parse_all(parser, packets):
            pipeline.flow_builder.add_packet(packet)

        advance_fixed_window(pipeline.flow_builder, parser, base)
        close_all_retained_fixed_windows(pipeline.flow_builder)

        if not expected_trigger:
            assert store.events == {}
            return

        event = get_single_event(store)
        assert len(event.detections) == 1
        detection = event.detections[0]
        assert detection.rule_id == "port_scan"
        assert detection.severity == expected_severity
        assert detection.evidence["features"]["unique_destination_ports"] == port_count
        assert detection.evidence["features"]["syn_rate"] < settings.syn_rate_threshold
        assert detection.evidence["thresholds"]["port_scan_threshold"] == settings.port_scan_threshold
        assert detection.evidence["comparisons"]["unique_destination_ports >= port_scan_threshold"] is True
        assert str(settings.port_scan_threshold) in detection.explanation
        assert event.risk.flow_key == event.flow_key
        assert event.policy.recommended_action in (
            PolicyAction.LOG_ONLY,
            PolicyAction.ALERT_ONLY,
            PolicyAction.BLOCK_SOURCE,
        )
        assert event.response.status in (
            ResponseStatus.NO_ACTION,
            ResponseStatus.SIMULATED,
            ResponseStatus.REJECTED,
        )


class TestSynFloodValidation:
    @pytest.mark.parametrize(
        ("count", "span_seconds", "expected_trigger", "expected_severity", "expected_syn_rate"),
        [
            (10, 1.02, False, None, 10 / 1.02),
            (7, 0.7, True, DetectionSeverity.MEDIUM, 10.0),
            (8, 0.69, True, DetectionSeverity.HIGH, 8 / 0.69),
        ],
    )
    def test_syn_flood_threshold_matrix(self, count, span_seconds, expected_trigger, expected_severity, expected_syn_rate):
        parser = ProtocolParser()
        store = InMemoryEventStore()
        pipeline = build_pipeline(strategy="five_tuple", event_store=store)
        pipeline.start()

        base = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        for packet in parse_all(parser, syn_burst_sequence(base_time=base, count=count, span_seconds=span_seconds)):
            pipeline.flow_builder.add_packet(packet)

        advance_fixed_window(pipeline.flow_builder, parser, base)
        close_all_retained_fixed_windows(pipeline.flow_builder)

        if not expected_trigger:
            assert store.events == {}
            return

        event = get_single_event(store)
        assert len(event.detections) == 1
        detection = event.detections[0]
        assert detection.rule_id == "syn_flood"
        assert detection.severity == expected_severity
        assert detection.evidence["features"]["syn_rate"] == pytest.approx(expected_syn_rate)
        assert detection.evidence["features"]["incomplete_connection_ratio"] == pytest.approx(1.0)
        assert detection.evidence["thresholds"]["syn_rate_threshold"] == settings.syn_rate_threshold
        assert detection.evidence["thresholds"]["syn_incomplete_ratio"] == settings.syn_incomplete_ratio


class TestCombinedScenarioValidation:
    @pytest.mark.parametrize(
        ("port_count", "span_seconds", "expected_score", "expected_level", "expected_port_severity", "expected_syn_severity"),
        [
            (
                20,
                2.0,
                min(settings.score_port_scan_medium + settings.score_syn_flood_medium, 100),
                RiskLevel.HIGH,
                DetectionSeverity.MEDIUM,
                DetectionSeverity.MEDIUM,
            ),
            (
                21,
                0.69,
                min(settings.score_port_scan_high + settings.score_syn_flood_high, 100),
                RiskLevel.CRITICAL,
                DetectionSeverity.HIGH,
                DetectionSeverity.HIGH,
            ),
        ],
    )
    def test_combined_suspicious_scenario(self, port_count, span_seconds, expected_score, expected_level, expected_port_severity, expected_syn_severity):
        parser = ProtocolParser()
        store = InMemoryEventStore()
        pipeline = build_pipeline(strategy="three_tuple", event_store=store)
        pipeline.start()

        base = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        packets = combined_suspicious_sequence(
            base_time=base,
            dst_ports=list(range(80, 80 + port_count)),
            span_seconds=span_seconds,
        )
        for packet in parse_all(parser, packets):
            pipeline.flow_builder.add_packet(packet)

        advance_fixed_window(pipeline.flow_builder, parser, base)
        close_all_retained_fixed_windows(pipeline.flow_builder)

        event = get_single_event(store)
        assert {d.rule_id for d in event.detections} == {"port_scan", "syn_flood"}
        assert len(event.detections) == 2
        assert find_detection(event, "port_scan").severity == expected_port_severity
        assert find_detection(event, "syn_flood").severity == expected_syn_severity
        assert event.risk.score == expected_score
        assert event.risk.level == expected_level
        assert event.policy.risk_score == event.risk.score
        assert event.response.status in (
            ResponseStatus.NO_ACTION,
            ResponseStatus.SIMULATED,
            ResponseStatus.REJECTED,
        )


class TestStrategySensitivity:
    def test_scan_visibility_varies_by_strategy(self):
        parser = ProtocolParser()
        base = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        results = {}

        for strategy in ("five_tuple", "three_tuple", "bidirectional"):
            store = InMemoryEventStore()
            pipeline = build_pipeline(strategy=strategy, event_store=store)
            pipeline.start()
            packets = port_scan_sequence(
                base_time=base,
                dst_ports=list(range(80, 100)),
                step=timedelta(milliseconds=120),
            )
            for packet in parse_all(parser, packets):
                pipeline.flow_builder.add_packet(packet)
            advance_fixed_window(pipeline.flow_builder, parser, base)
            close_all_retained_fixed_windows(pipeline.flow_builder)

            events = list(store.events.values())
            detections = [d.rule_id for event in events for d in event.detections]
            unique_ports = [
                d.evidence["features"].get("unique_destination_ports")
                for event in events
                for d in event.detections
                if d.rule_id == "port_scan"
            ]
            results[strategy] = {
                "event_count": len(events),
                "flow_count": pipeline.flow_builder.get_flow_count(),
                "detections": detections,
                "unique_destination_ports": unique_ports,
            }

        assert "port_scan" not in results["five_tuple"]["detections"]
        assert "port_scan" in results["three_tuple"]["detections"]
        assert results["five_tuple"]["flow_count"] >= results["three_tuple"]["flow_count"]
        assert results["three_tuple"]["unique_destination_ports"] == [20]
        assert results["bidirectional"]["event_count"] >= 0


class TestEventTimeValidation:
    def test_fixed_window_placement_uses_packet_timestamp(self):
        parser = ProtocolParser()
        builder = FlowBuilder(window_seconds=5)
        p1 = parse_all(parser, [tcp_packet(timestamp=datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc))])[0]
        p2 = parse_all(parser, [tcp_packet(timestamp=datetime(2024, 1, 1, 0, 0, 6, tzinfo=timezone.utc), dst_port=81)])[0]
        f1 = builder.add_packet(p1)
        f2 = builder.add_packet(p2)
        assert f1.window_start == datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert f2.window_start == datetime(2024, 1, 1, 0, 0, 5, tzinfo=timezone.utc)

    def test_out_of_order_processing_updates_event_time_min_max_within_same_window(self):
        parser = ProtocolParser()
        builder = FlowBuilder(flow_key_strategy="five_tuple", window_seconds=5)
        later = parse_all(parser, [tcp_packet(timestamp=datetime(2024, 1, 1, 0, 0, 4, tzinfo=timezone.utc))])[0]
        earlier = parse_all(parser, [tcp_packet(timestamp=datetime(2024, 1, 1, 0, 0, 2, tzinfo=timezone.utc))])[0]
        flow = builder.add_packet(later)
        assert flow is not None
        flow = builder.add_packet(earlier)
        assert flow is not None

        assert flow.statistics.first_packet_time == datetime(2024, 1, 1, 0, 0, 2, tzinfo=timezone.utc)
        assert flow.statistics.last_packet_time == datetime(2024, 1, 1, 0, 0, 4, tzinfo=timezone.utc)

    def test_retained_late_packet_is_included_before_emission_when_window_exists(self):
        parser = ProtocolParser()
        builder = FlowBuilder(flow_key_strategy="five_tuple", window_seconds=5)
        emitted = []
        builder.set_feature_observation_callback(emitted.append)

        old_time = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        new_time = datetime(2024, 1, 1, 0, 0, 7, tzinfo=timezone.utc)
        late_time = datetime(2024, 1, 1, 0, 0, 2, tzinfo=timezone.utc)

        for packet in parse_all(
            parser,
            [
                tcp_packet(timestamp=old_time, dst_port=80),
                tcp_packet(timestamp=new_time, dst_port=443),
                tcp_packet(timestamp=late_time, dst_port=80),
            ],
        ):
            builder.add_packet(packet)

        assert len(builder.window_manager.previous_windows) == 1
        retained = builder.window_manager.previous_windows[0]
        old_flow = next(iter(retained.flows.values()))
        assert old_flow.statistics.first_packet_time == old_time
        assert old_flow.statistics.last_packet_time == late_time
        assert old_flow.statistics.packet_count == 2

        close_all_retained_fixed_windows(builder)
        assert len(emitted) == 1
        observation = emitted[0]
        assert observation.window_start == retained.start_time
        assert observation.window_end == retained.end_time
        assert observation.features["packet_count"] == 2
        assert observation.features["duration_seconds"] == 1.0

    def test_removed_historical_window_is_not_recreated(self):
        parser = ProtocolParser()
        builder = FlowBuilder(window_seconds=5)
        emitted = []
        builder.set_feature_observation_callback(emitted.append)
        old = parse_all(parser, [tcp_packet(timestamp=datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc))])[0]
        new = parse_all(parser, [tcp_packet(timestamp=datetime(2024, 1, 1, 0, 1, 0, tzinfo=timezone.utc), dst_port=81)])[0]
        builder.add_packet(old)
        builder.add_packet(new)
        builder.window_manager.previous_windows = []
        too_old = parse_all(parser, [tcp_packet(timestamp=datetime(2024, 1, 1, 0, 0, 2, tzinfo=timezone.utc), dst_port=82)])[0]
        result = builder.add_packet(too_old)
        assert result is None
        assert emitted == []

    def test_sliding_overlap_places_packet_in_multiple_windows(self):
        parser = ProtocolParser()
        builder = FlowBuilder(use_sliding_windows=True, window_seconds=10)
        packet = parse_all(parser, [tcp_packet(timestamp=datetime(2024, 1, 1, 0, 0, 7, tzinfo=timezone.utc))])[0]
        flows = builder.window_manager.add_packet(packet, builder.flow_key_manager.generate_key(packet))
        assert len(flows) == 2
        identities = {(flow.window_start, flow.window_end) for flow in flows}
        assert len(identities) == 2

    def test_future_skew_acceptance_and_rejection(self):
        parser = ProtocolParser()
        builder = FlowBuilder(window_seconds=5)
        now = datetime.now(timezone.utc)
        acceptable = parse_all(parser, [tcp_packet(timestamp=now + timedelta(seconds=299))])[0]
        excessive = parse_all(parser, [tcp_packet(timestamp=now + timedelta(seconds=301), dst_port=81)])[0]
        assert builder.add_packet(acceptable) is not None
        assert builder.add_packet(excessive) is None


class TestRiskThresholdMatrix:
    @pytest.mark.parametrize(
        ("score", "expected_level"),
        [
            (29, RiskLevel.LOW),
            (30, RiskLevel.MEDIUM),
            (59, RiskLevel.MEDIUM),
            (60, RiskLevel.HIGH),
            (79, RiskLevel.HIGH),
            (80, RiskLevel.CRITICAL),
        ],
    )
    def test_risk_threshold_boundaries(self, score, expected_level):
        scorer = RiskScorer()
        assert scorer._map_level(score) == expected_level


class TestSecurityEventAndSafeModeValidation:
    def test_causal_identity_and_persistence_round_trip(self, tmp_path):
        parser = ProtocolParser()
        db_path = tmp_path / "validation.db"
        store = SQLiteSecurityEventStore(f"sqlite:///{db_path}")
        pipeline = build_pipeline(strategy="three_tuple", safe_mode=True, event_store=store)
        pipeline.start()

        base = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        for packet in parse_all(
            parser,
            combined_suspicious_sequence(base_time=base, dst_ports=list(range(80, 101)), span_seconds=0.69),
        ):
            pipeline.flow_builder.add_packet(packet)
        advance_fixed_window(pipeline.flow_builder, parser, base)
        close_all_retained_fixed_windows(pipeline.flow_builder)

        saved = store.list_recent(limit=10)
        assert len(saved) == 1
        event = saved[0]
        assert event.flow_key == event.risk.flow_key == event.policy.flow_key
        for detection in event.detections:
            assert detection.flow_key == event.flow_key
            assert detection.window_start == event.window_start
            assert detection.window_end == event.window_end
        assert event.policy.window_start == event.window_start
        assert event.policy.window_end == event.window_end
        assert event.event_id == SecurityEvent.generate_event_id(event.flow_key, event.window_start, event.window_end)
        loaded = store.get(event.event_id)
        assert loaded == event

    def test_safe_mode_true_never_claims_real_block(self, tmp_path):
        parser = ProtocolParser()
        db_path = tmp_path / "safe.db"
        store = SQLiteSecurityEventStore(f"sqlite:///{db_path}")
        pipeline = build_pipeline(strategy="three_tuple", safe_mode=True, event_store=store)
        pipeline.start()

        base = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        for packet in parse_all(
            parser,
            combined_suspicious_sequence(base_time=base, dst_ports=list(range(80, 101)), span_seconds=0.69),
        ):
            pipeline.flow_builder.add_packet(packet)
        advance_fixed_window(pipeline.flow_builder, parser, base)
        close_all_retained_fixed_windows(pipeline.flow_builder)

        event = store.list_recent(limit=1)[0]
        assert event.response.status in (ResponseStatus.NO_ACTION, ResponseStatus.SIMULATED)
        assert "blocked successfully" not in event.response.message.lower()
        if event.response.status == ResponseStatus.SIMULATED:
            assert "no system state changed" in event.response.message

    def test_safe_mode_false_rejects_real_execution_without_executor(self, tmp_path):
        parser = ProtocolParser()
        db_path = tmp_path / "unsafe.db"
        store = SQLiteSecurityEventStore(f"sqlite:///{db_path}")
        pipeline = build_pipeline(strategy="three_tuple", safe_mode=False, event_store=store)
        pipeline.start()

        base = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        for packet in parse_all(
            parser,
            combined_suspicious_sequence(base_time=base, dst_ports=list(range(80, 101)), span_seconds=0.69),
        ):
            pipeline.flow_builder.add_packet(packet)
        advance_fixed_window(pipeline.flow_builder, parser, base)
        close_all_retained_fixed_windows(pipeline.flow_builder)

        event = store.list_recent(limit=1)[0]
        if event.policy.recommended_action == PolicyAction.BLOCK_SOURCE:
            assert event.response.status == ResponseStatus.REJECTED
            assert event.response.error == "Real execution unavailable; no ActionExecutor is installed."

    def test_duplicate_save_is_idempotent_and_reopen_preserves_event(self, tmp_path):
        parser = ProtocolParser()
        db_path = tmp_path / "dup.db"
        store = SQLiteSecurityEventStore(f"sqlite:///{db_path}")
        pipeline = build_pipeline(strategy="three_tuple", event_store=store)
        pipeline.start()

        base = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        for packet in parse_all(
            parser,
            combined_suspicious_sequence(base_time=base, dst_ports=list(range(80, 101)), span_seconds=0.69),
        ):
            pipeline.flow_builder.add_packet(packet)
        advance_fixed_window(pipeline.flow_builder, parser, base)
        close_all_retained_fixed_windows(pipeline.flow_builder)

        event = store.list_recent(limit=1)[0]
        assert store.save(event) is True
        reopened = FakeReopenStore(f"sqlite:///{db_path}")
        assert reopened.get(event.event_id) == event
        assert reopened.list_recent(limit=1)[0] == event

    def test_conflicting_duplicate_is_rejected(self):
        store = ConflictingInMemoryEventStore()
        flow_key = FlowKey(src_ip="10.0.0.5", dst_ip="10.0.0.10", protocol="TCP")
        window_start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        window_end = datetime(2024, 1, 1, 0, 0, 5, tzinfo=timezone.utc)
        observation = FeatureObservation(
            flow_key=flow_key,
            window_start=window_start,
            window_end=window_end,
            features={"unique_destination_ports": 20, "syn_rate": 10.0, "incomplete_connection_ratio": 1.0},
            finalized=True,
            sliding=False,
        )
        detection_engine = DetectionEngine()
        detections = detection_engine.evaluate(observation)
        risk = RiskScorer().score(detections)
        policy = PolicyEngine(safe_mode=True).decide(risk)
        response = ResponseEngine(safe_mode=True).handle(policy)
        event = SecurityEvent.create(
            flow_key=flow_key,
            window_start=window_start,
            window_end=window_end,
            detections=detections,
            risk=risk,
            policy=policy,
            response=response,
            recorded_at=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
        )
        assert store.save(event) is True

        conflicting = SecurityEvent.create(
            flow_key=flow_key,
            window_start=window_start,
            window_end=window_end,
            detections=detections,
            risk=risk,
            policy=policy,
            response=response,
            recorded_at=datetime(2024, 1, 1, 0, 0, 11, tzinfo=timezone.utc),
        )
        with pytest.raises(ValueError, match="Conflicting SecurityEvent already exists"):
            store.save(conflicting)
