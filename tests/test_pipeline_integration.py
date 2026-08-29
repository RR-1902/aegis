"""Deterministic end-to-end pipeline integration tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest
from scapy.all import Ether, IP, TCP, UDP

from app.detection.engine import DetectionEngine
from app.flows.flow_builder import FlowBuilder
from app.models.detection import DetectionResult, DetectionSeverity
from app.models.flow import FeatureObservation, FlowKey
from app.models.policy import ExecutionMode, PolicyAction, ResponseDecision, ResponseTarget
from app.models.response import ResponseResult, ResponseStatus
from app.models.risk import RiskLevel, RiskScore
from app.models.security_event import SecurityEvent
from app.pipeline import AEGISPipeline
from app.policy.engine import PolicyEngine
from app.protocols.parser import ProtocolParser
from app.response.engine import ResponseEngine
from app.scoring.risk_scorer import RiskScorer


class InMemoryEventStore:
    def __init__(self):
        self.events = {}
        self.save_calls = []

    def save(self, event: SecurityEvent) -> bool:
        self.save_calls.append(event.event_id)
        self.events[event.event_id] = event
        return True

    def get(self, event_id: str):
        return self.events.get(event_id)

    def list_recent(self, limit: int = 100):
        events = sorted(self.events.values(), key=lambda e: (e.recorded_at, e.event_id), reverse=True)
        return events[:limit]


class FakePacketCapture:
    def __init__(self, start_result=True):
        self.packet_callback = None
        self.started = False
        self.stopped = False
        self.start_result = start_result

    def start(self):
        self.started = self.start_result
        return self.start_result

    def stop(self):
        self.stopped = True
        self.started = False

    def get_statistics(self):
        return {"started": self.started, "stopped": self.stopped}


def make_tcp_packet(*, src_ip="10.0.0.5", dst_ip="10.0.0.10", src_port=12345, dst_port=80, flags="S", event_time=None):
    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags=flags)
    pkt.time = float((event_time or datetime.now(timezone.utc)).timestamp())
    return pkt


def make_udp_packet(*, src_ip="10.0.0.5", dst_ip="10.0.0.10", src_port=12345, dst_port=53, event_time=None):
    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port)
    pkt.time = float((event_time or datetime.now(timezone.utc)).timestamp())
    return pkt


def expire_sliding_windows(builder: FlowBuilder, now: datetime) -> None:
    if hasattr(builder.window_manager, "_cleanup_expired_windows"):
        builder.window_manager._cleanup_expired_windows(now)


def close_all_retained_fixed_windows(builder: FlowBuilder) -> None:
    manager = builder.window_manager
    previous = list(getattr(manager, "previous_windows", []))
    for window in previous:
        manager._close_window(window)
    manager.previous_windows = []


class FailingDetectionEngine:
    def evaluate(self, observation):
        raise RuntimeError("detection boom")


class FailingRiskScorer:
    def score(self, detections):
        raise RuntimeError("scoring boom")


class FailingPolicyEngine:
    def decide(self, risk_score):
        raise RuntimeError("policy boom")


class FailingResponseEngine:
    def handle(self, decision):
        raise RuntimeError("response boom")


class FailingEventStore(InMemoryEventStore):
    def save(self, event):
        raise RuntimeError("persistence boom")


class TestAEGISPipelineLifecycle:
    def test_start_wires_callbacks_and_starts_capture(self):
        capture = FakePacketCapture()
        builder = FlowBuilder(window_seconds=5)
        pipeline = AEGISPipeline(packet_capture=capture, flow_builder=builder, event_store=InMemoryEventStore())

        assert pipeline.start() is True
        assert pipeline.is_running is True
        assert capture.started is True
        assert capture.packet_callback == builder.add_packet
        assert builder.feature_observation_callback == pipeline._handle_feature_observation

    def test_stop_stops_capture(self):
        capture = FakePacketCapture()
        pipeline = AEGISPipeline(packet_capture=capture, flow_builder=FlowBuilder(window_seconds=5), event_store=InMemoryEventStore())
        pipeline.start()
        pipeline.stop()
        assert pipeline.is_running is False
        assert capture.stopped is True

    def test_repeated_stop_is_safe(self):
        capture = FakePacketCapture()
        pipeline = AEGISPipeline(packet_capture=capture, flow_builder=FlowBuilder(window_seconds=5), event_store=InMemoryEventStore())
        pipeline.start()
        pipeline.stop()
        pipeline.stop()
        assert capture.stopped is True

    def test_startup_failure_is_surfaced(self):
        capture = FakePacketCapture(start_result=False)
        pipeline = AEGISPipeline(packet_capture=capture, flow_builder=FlowBuilder(window_seconds=5), event_store=InMemoryEventStore())
        assert pipeline.start() is False
        assert pipeline.is_running is False

    def test_no_new_observation_processing_begins_after_shutdown(self):
        capture = FakePacketCapture()
        store = InMemoryEventStore()
        pipeline = AEGISPipeline(packet_capture=capture, flow_builder=FlowBuilder(window_seconds=5), event_store=store)
        pipeline.start()
        pipeline.stop()

        observation = FeatureObservation(
            flow_key=FlowKey(src_ip="10.0.0.5", dst_ip="10.0.0.10", protocol="TCP", src_port=1, dst_port=2),
            window_start=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
            features={"unique_destination_ports": 25},
            finalized=True,
            sliding=False,
        )
        pipeline._handle_feature_observation(observation)
        assert store.events == {}


class TestAEGISPipelineIntegration:
    def test_detected_observation_traverses_full_chain_and_persists_event(self):
        parser = ProtocolParser()
        store = InMemoryEventStore()
        capture = FakePacketCapture()
        builder = FlowBuilder(flow_key_strategy="three_tuple", window_seconds=5)
        pipeline = AEGISPipeline(
            packet_capture=capture,
            flow_builder=builder,
            detection_engine=DetectionEngine(),
            risk_scorer=RiskScorer(),
            policy_engine=PolicyEngine(safe_mode=True),
            response_engine=ResponseEngine(safe_mode=True),
            event_store=store,
            flow_key_strategy="three_tuple",
        )
        pipeline.start()

        base = datetime.now(timezone.utc)
        for offset, dst_port in enumerate(range(80, 100)):
            raw = make_tcp_packet(dst_port=dst_port, flags="S", event_time=base + timedelta(milliseconds=offset))
            parsed = parser.parse_packet(raw)
            assert parsed is not None
            builder.add_packet(parsed)

        future_packet = parser.parse_packet(
            make_tcp_packet(dst_port=443, flags="A", event_time=base + timedelta(seconds=6))
        )
        assert future_packet is not None
        builder.add_packet(future_packet)
        close_all_retained_fixed_windows(builder)

        assert len(store.events) == 1
        event = next(iter(store.events.values()))
        assert event.flow_key.protocol == "TCP"
        assert event.window_start < event.window_end
        assert len(event.detections) >= 1
        assert event.risk.score >= 0
        assert event.policy.recommended_action in (PolicyAction.ALERT_ONLY, PolicyAction.BLOCK_SOURCE, PolicyAction.LOG_ONLY)
        assert event.response.status in (ResponseStatus.SIMULATED, ResponseStatus.REJECTED, ResponseStatus.NO_ACTION)
        assert event.event_id == SecurityEvent.generate_event_id(event.flow_key, event.window_start, event.window_end)
        assert pipeline.stats.events_persisted == 1

    def test_zero_detections_do_not_persist_security_event(self):
        store = InMemoryEventStore()
        capture = FakePacketCapture()
        builder = FlowBuilder(window_seconds=5)
        pipeline = AEGISPipeline(packet_capture=capture, flow_builder=builder, event_store=store)
        pipeline.start()

        observation = FeatureObservation(
            flow_key=FlowKey(src_ip="10.0.0.5", dst_ip="10.0.0.10", protocol="UDP", src_port=12345, dst_port=53),
            window_start=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
            features={"unique_destination_ports": 1, "syn_rate": 0.0, "incomplete_connection_ratio": 0.0},
            finalized=True,
            sliding=False,
        )
        pipeline._handle_feature_observation(observation)
        assert store.events == {}
        assert pipeline.stats.observations_without_detections == 1

    def test_detection_failure_does_not_kill_pipeline(self):
        store = InMemoryEventStore()
        pipeline = AEGISPipeline(
            packet_capture=FakePacketCapture(),
            flow_builder=FlowBuilder(window_seconds=5),
            detection_engine=FailingDetectionEngine(),
            event_store=store,
        )
        pipeline.start()
        observation = FeatureObservation(
            flow_key=FlowKey(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP"),
            window_start=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
            features={"unique_destination_ports": 25},
            finalized=True,
            sliding=False,
        )
        pipeline._handle_feature_observation(observation)
        assert pipeline.is_running is True
        assert pipeline.stats.detection_failures == 1
        assert store.events == {}

    def test_scoring_failure_does_not_kill_pipeline(self):
        store = InMemoryEventStore()
        pipeline = AEGISPipeline(
            packet_capture=FakePacketCapture(),
            flow_builder=FlowBuilder(window_seconds=5),
            risk_scorer=FailingRiskScorer(),
            event_store=store,
        )
        pipeline.start()
        observation = FeatureObservation(
            flow_key=FlowKey(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP"),
            window_start=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
            features={"unique_destination_ports": 25},
            finalized=True,
            sliding=False,
        )
        pipeline._handle_feature_observation(observation)
        assert pipeline.stats.scoring_failures == 1
        assert store.events == {}

    def test_policy_failure_does_not_kill_pipeline(self):
        store = InMemoryEventStore()
        pipeline = AEGISPipeline(
            packet_capture=FakePacketCapture(),
            flow_builder=FlowBuilder(window_seconds=5),
            policy_engine=FailingPolicyEngine(),
            event_store=store,
        )
        pipeline.start()
        observation = FeatureObservation(
            flow_key=FlowKey(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP"),
            window_start=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
            features={"unique_destination_ports": 25},
            finalized=True,
            sliding=False,
        )
        pipeline._handle_feature_observation(observation)
        assert pipeline.stats.policy_failures == 1
        assert store.events == {}

    def test_response_failure_does_not_kill_pipeline(self):
        store = InMemoryEventStore()
        pipeline = AEGISPipeline(
            packet_capture=FakePacketCapture(),
            flow_builder=FlowBuilder(window_seconds=5),
            response_engine=FailingResponseEngine(),
            event_store=store,
        )
        pipeline.start()
        observation = FeatureObservation(
            flow_key=FlowKey(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP"),
            window_start=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
            features={"unique_destination_ports": 25},
            finalized=True,
            sliding=False,
        )
        pipeline._handle_feature_observation(observation)
        assert pipeline.stats.response_failures == 1
        assert store.events == {}

    def test_event_construction_failure_does_not_kill_pipeline(self):
        store = InMemoryEventStore()
        pipeline = AEGISPipeline(packet_capture=FakePacketCapture(), flow_builder=FlowBuilder(window_seconds=5), event_store=store)
        pipeline.start()

        observation = FeatureObservation(
            flow_key=FlowKey(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP"),
            window_start=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
            features={"unique_destination_ports": 25},
            finalized=True,
            sliding=False,
        )
        original_create = SecurityEvent.create
        try:
            SecurityEvent.create = classmethod(lambda cls, **kwargs: (_ for _ in ()).throw(ValueError("event boom")))
            pipeline._handle_feature_observation(observation)
        finally:
            SecurityEvent.create = original_create
        assert pipeline.stats.event_construction_failures == 1
        assert store.events == {}

    def test_persistence_failure_does_not_kill_pipeline(self):
        pipeline = AEGISPipeline(
            packet_capture=FakePacketCapture(),
            flow_builder=FlowBuilder(window_seconds=5),
            event_store=FailingEventStore(),
        )
        pipeline.start()
        observation = FeatureObservation(
            flow_key=FlowKey(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP"),
            window_start=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
            features={"unique_destination_ports": 25},
            finalized=True,
            sliding=False,
        )
        pipeline._handle_feature_observation(observation)
        assert pipeline.stats.persistence_failures == 1
        assert pipeline.is_running is True

    def test_multiple_finalized_observations_are_processed_independently(self):
        store = InMemoryEventStore()
        pipeline = AEGISPipeline(packet_capture=FakePacketCapture(), flow_builder=FlowBuilder(window_seconds=5), event_store=store)
        pipeline.start()

        first = FeatureObservation(
            flow_key=FlowKey(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP"),
            window_start=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
            features={"unique_destination_ports": 25},
            finalized=True,
            sliding=False,
        )
        second = FeatureObservation(
            flow_key=FlowKey(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP"),
            window_start=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 0, 0, 20, tzinfo=timezone.utc),
            features={"unique_destination_ports": 25},
            finalized=True,
            sliding=False,
        )
        pipeline._handle_feature_observation(first)
        pipeline._handle_feature_observation(second)
        assert len(store.events) == 2

    def test_two_sliding_window_observations_remain_separate(self):
        store = InMemoryEventStore()
        pipeline = AEGISPipeline(packet_capture=FakePacketCapture(), flow_builder=FlowBuilder(use_sliding_windows=True, window_seconds=10), event_store=store, use_sliding_windows=True)
        pipeline.start()

        first = FeatureObservation(
            flow_key=FlowKey(src_ip="10.0.0.5", dst_ip="10.0.0.10", protocol="TCP", src_port=12345, dst_port=80),
            window_start=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
            features={"unique_destination_ports": 25},
            finalized=True,
            sliding=True,
        )
        second = FeatureObservation(
            flow_key=FlowKey(src_ip="10.0.0.5", dst_ip="10.0.0.10", protocol="TCP", src_port=12345, dst_port=80),
            window_start=datetime(2024, 1, 1, 0, 0, 5, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 0, 0, 15, tzinfo=timezone.utc),
            features={"unique_destination_ports": 25},
            finalized=True,
            sliding=True,
        )
        pipeline._handle_feature_observation(first)
        pipeline._handle_feature_observation(second)

        events = store.list_recent(limit=10)
        assert len(events) == 2
        identities = {(e.flow_key, e.window_start, e.window_end) for e in events}
        assert len(identities) == 2

    def test_exact_observation_identity_is_preserved_through_to_security_event(self):
        store = InMemoryEventStore()
        pipeline = AEGISPipeline(packet_capture=FakePacketCapture(), flow_builder=FlowBuilder(window_seconds=5), event_store=store)
        pipeline.start()

        observation = FeatureObservation(
            flow_key=FlowKey(src_ip="9.9.9.9", dst_ip="8.8.8.8", protocol="TCP", src_port=50000, dst_port=80),
            window_start=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
            features={"unique_destination_ports": 25},
            finalized=True,
            sliding=False,
        )
        pipeline._handle_feature_observation(observation)
        event = next(iter(store.events.values()))
        assert event.flow_key == observation.flow_key
        assert event.window_start == observation.window_start
        assert event.window_end == observation.window_end

    def test_injected_fake_components_are_used(self):
        store = InMemoryEventStore()
        capture = FakePacketCapture()
        builder = FlowBuilder(window_seconds=5)
        detection = DetectionEngine()
        scorer = RiskScorer()
        policy = PolicyEngine(safe_mode=True)
        response = ResponseEngine(safe_mode=True)
        pipeline = AEGISPipeline(
            packet_capture=capture,
            flow_builder=builder,
            detection_engine=detection,
            risk_scorer=scorer,
            policy_engine=policy,
            response_engine=response,
            event_store=store,
        )
        assert pipeline.packet_capture is capture
        assert pipeline.flow_builder is builder
        assert pipeline.detection_engine is detection
        assert pipeline.risk_scorer is scorer
        assert pipeline.policy_engine is policy
        assert pipeline.response_engine is response
        assert pipeline.event_store is store
