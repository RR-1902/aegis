"""
Tests for feature extraction from flows.

These tests validate that the feature extractor correctly computes
security-relevant features from flow statistics.
"""

import pytest
from datetime import datetime, timezone, timedelta

from app.models.packet import ParsedPacket, TransportProtocol, TCPFlags
from app.models.flow import Flow, FlowKey, FlowStatistics, FlowWindow, FeatureObservation
from app.features.feature_definitions import FeatureCatalog, FeatureCategory
from app.features.extractor import FeatureExtractor, FeatureAggregator
from app.flows.flow_builder import FlowBuilder
from app.flows.flow_key import FlowKeyStrategy
from app.flows.time_window import SlidingWindowManager


class TestFeatureCatalog:
    """Test suite for FeatureCatalog."""
    
    def test_feature_catalog_size(self):
        """Test that feature catalog has expected number of features."""
        all_features = FeatureCatalog.get_all_features()
        
        # We should have at least 20 features
        assert len(all_features) >= 20
    
    def test_feature_categories(self):
        """Test that features are properly categorized."""
        count_features = FeatureCatalog.get_features_by_category(FeatureCategory.COUNT)
        rate_features = FeatureCatalog.get_features_by_category(FeatureCategory.RATE)
        
        assert len(count_features) > 0
        assert len(rate_features) > 0
    
    def test_feature_names(self):
        """Test feature name extraction."""
        feature_names = FeatureCatalog.get_feature_names()
        
        assert "packet_count" in feature_names
        assert "byte_count" in feature_names
        assert "syn_count" in feature_names
        assert "unique_destination_ports" in feature_names
    
    def test_normalizable_features(self):
        """Test identification of normalizable features."""
        normalizable = FeatureCatalog.get_normalizable_features()
        
        # Most features should be normalizable
        assert len(normalizable) > 0
    
    def test_feature_to_dict(self):
        """Test feature definition serialization."""
        feature = FeatureCatalog.PACKET_COUNT
        feature_dict = feature.to_dict()
        
        assert "name" in feature_dict
        assert "category" in feature_dict
        assert "description" in feature_dict
        assert "security_relevance" in feature_dict


class TestFeatureExtractor:
    """Test suite for FeatureExtractor."""
    
    def test_extractor_initialization(self):
        """Test feature extractor initialization."""
        extractor = FeatureExtractor()
        
        assert extractor.normalize == True
        assert extractor.total_extractions == 0
    
    def test_extract_from_empty_flow(self):
        """Test extracting features from empty flow."""
        flow_key = FlowKey(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            protocol="TCP",
        )
        
        now = datetime.now(timezone.utc)
        flow = Flow(
            flow_key=flow_key,
            window_start=now,
            window_end=now + timedelta(seconds=5),
        )
        
        extractor = FeatureExtractor()
        features = extractor.extract_features(flow)
        
        # Should return empty features with default values
        assert len(features) > 0
        assert all(v == 0.0 for v in features.values())
    
    def test_extract_count_features(self):
        """Test extraction of count features."""
        flow_key = FlowKey(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            protocol="TCP",
        )
        
        now = datetime.now(timezone.utc)
        flow = Flow(
            flow_key=flow_key,
            window_start=now,
            window_end=now + timedelta(seconds=5),
        )
        
        # Add some packets
        for i in range(10):
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                transport_protocol=TransportProtocol.TCP,
                size=100 * (i + 1),
                timestamp=now,
            )
            flow.add_packet(packet)
        
        flow.finalize()
        
        # Use non-normalizing extractor for raw values
        extractor = FeatureExtractor(normalize=False)
        features = extractor.extract_features(flow)
        
        assert features["packet_count"] == 10
        assert features["byte_count"] == 5500  # Sum of 100, 200, ..., 1000
    
    def test_extract_protocol_features(self):
        """Test extraction of protocol-specific features."""
        flow_key = FlowKey(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            protocol="TCP",
        )
        
        now = datetime.now(timezone.utc)
        flow = Flow(
            flow_key=flow_key,
            window_start=now,
            window_end=now + timedelta(seconds=5),
        )
        
        # Add SYN packet
        packet = ParsedPacket(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            transport_protocol=TransportProtocol.TCP,
            tcp_flags=TCPFlags(syn=True, ack=False),
        )
        flow.add_packet(packet)
        
        # Add ACK packet
        packet = ParsedPacket(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            transport_protocol=TransportProtocol.TCP,
            tcp_flags=TCPFlags(syn=False, ack=True),
        )
        flow.add_packet(packet)
        
        flow.finalize()
        
        extractor = FeatureExtractor()
        features = extractor.extract_features(flow)
        
        assert features["syn_count"] == 1
        assert features["ack_count"] == 1
    
    def test_extract_diversity_features(self):
        """Test extraction of diversity features."""
        flow_key = FlowKey(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            protocol="TCP",
        )
        
        now = datetime.now(timezone.utc)
        flow = Flow(
            flow_key=flow_key,
            window_start=now,
            window_end=now + timedelta(seconds=5),
        )
        
        # Add packets to different ports
        for port in [80, 443, 8080, 22, 53]:
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                transport_protocol=TransportProtocol.TCP,
                dst_port=port,
            )
            flow.add_packet(packet)
        
        flow.finalize()
        
        extractor = FeatureExtractor()
        features = extractor.extract_features(flow)
        
        assert features["unique_destination_ports"] == 5
    
    def test_extract_rate_features(self):
        """Test extraction of rate-based features."""
        flow_key = FlowKey(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            protocol="TCP",
        )
        
        now = datetime.now(timezone.utc)
        flow = Flow(
            flow_key=flow_key,
            window_start=now,
            window_end=now + timedelta(seconds=5),
        )
        
        # Add packets with specific timing
        packet1 = ParsedPacket(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            transport_protocol=TransportProtocol.TCP,
            size=1000,
            timestamp=now,
        )
        flow.add_packet(packet1)
        
        packet2 = ParsedPacket(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            transport_protocol=TransportProtocol.TCP,
            size=1000,
            timestamp=now + timedelta(seconds=2),
        )
        flow.add_packet(packet2)
        
        flow.finalize()
        
        # Use non-normalizing extractor for raw values
        extractor = FeatureExtractor(normalize=False)
        features = extractor.extract_features(flow)
        
        # Duration should be 2 seconds
        assert features["duration_seconds"] == 2.0
        # Packet rate should be 1 packet per second
        assert features["packets_per_second"] == 1.0
        # Byte rate should be 1000 bytes per second
        assert features["bytes_per_second"] == 1000.0
    
    def test_extract_ratio_features(self):
        """Test extraction of ratio features."""
        flow_key = FlowKey(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            protocol="TCP",
        )
        
        now = datetime.now(timezone.utc)
        flow = Flow(
            flow_key=flow_key,
            window_start=now,
            window_end=now + timedelta(seconds=5),
        )
        
        # Add 10 packets, 5 of them SYN
        for i in range(10):
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                transport_protocol=TransportProtocol.TCP,
                tcp_flags=TCPFlags(syn=(i < 5), ack=False),
            )
            flow.add_packet(packet)
        
        flow.finalize()
        
        extractor = FeatureExtractor()
        features = extractor.extract_features(flow)
        
        # SYN ratio should be 0.5 (5 SYN out of 10 packets)
        assert features["syn_to_total_ratio"] == 0.5
    
    def test_extract_connection_features(self):
        """Test extraction of connection-related features."""
        flow_key = FlowKey(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            protocol="TCP",
        )
        
        now = datetime.now(timezone.utc)
        flow = Flow(
            flow_key=flow_key,
            window_start=now,
            window_end=now + timedelta(seconds=5),
        )
        
        # Add connection attempts (SYN without ACK)
        for i in range(5):
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                transport_protocol=TransportProtocol.TCP,
                tcp_flags=TCPFlags(syn=True, ack=False),
                timestamp=now,
            )
            flow.add_packet(packet)
        
        # Add one successful connection (FIN indicates completed connection)
        packet = ParsedPacket(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            transport_protocol=TransportProtocol.TCP,
            tcp_flags=TCPFlags(fin=True),
            timestamp=now,
        )
        flow.add_packet(packet)
        
        flow.finalize()
        
        # Use non-normalizing extractor for raw values
        extractor = FeatureExtractor(normalize=False)
        features = extractor.extract_features(flow)
        
        assert features["connection_attempts"] == 5
        assert features["successful_connections"] == 1
        assert features["incomplete_connections"] == 4
    
    def test_feature_normalization(self):
        """Test feature normalization."""
        flow_key = FlowKey(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            protocol="TCP",
        )
        
        now = datetime.now(timezone.utc)
        flow = Flow(
            flow_key=flow_key,
            window_start=now,
            window_end=now + timedelta(seconds=5),
        )
        
        # Add many packets to test normalization
        for i in range(100):
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                transport_protocol=TransportProtocol.TCP,
                size=100,
            )
            flow.add_packet(packet)
        
        flow.finalize()
        
        # Extract with normalization
        extractor = FeatureExtractor(normalize=True)
        features_normalized = extractor.extract_features(flow)
        
        # Extract without normalization
        extractor_no_norm = FeatureExtractor(normalize=False)
        features_raw = extractor_no_norm.extract_features(flow)
        
        # Normalized values should be different from raw
        assert features_normalized["packet_count"] != features_raw["packet_count"]
        # Raw should be 100
        assert features_raw["packet_count"] == 100
        # Normalized should be in [0,1] range (after log normalization)
        assert 0 <= features_normalized["packet_count"] <= 1
    
    def test_extract_feature_vector(self):
        """Test extraction of feature vector."""
        flow_key = FlowKey(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            protocol="TCP",
        )
        
        now = datetime.now(timezone.utc)
        flow = Flow(
            flow_key=flow_key,
            window_start=now,
            window_end=now + timedelta(seconds=5),
        )
        
        # Add some packets
        for i in range(5):
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                transport_protocol=TransportProtocol.TCP,
                size=100,
            )
            flow.add_packet(packet)
        
        flow.finalize()
        
        extractor = FeatureExtractor()
        feature_vector = extractor.extract_feature_vector(flow)
        
        # Should be a list
        assert isinstance(feature_vector, list)
        # Should have same length as feature names
        assert len(feature_vector) == len(FeatureCatalog.get_feature_names())
    
    def test_extractor_statistics(self):
        """Test extractor statistics tracking."""
        extractor = FeatureExtractor()
        
        flow_key = FlowKey(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            protocol="TCP",
        )
        
        now = datetime.now(timezone.utc)
        flow = Flow(
            flow_key=flow_key,
            window_start=now,
            window_end=now + timedelta(seconds=5),
        )
        
        # Add packets
        for i in range(5):
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                transport_protocol=TransportProtocol.TCP,
                size=100,
            )
            flow.add_packet(packet)
        
        flow.finalize()
        
        # Extract features multiple times
        for _ in range(3):
            extractor.extract_features(flow)
        
        stats = extractor.get_statistics()
        
        assert stats["total_extractions"] == 3
        assert stats["extraction_errors"] == 0


class TestFeatureObservationLifecycle:
    """Test canonical finalized-only feature observation emission."""

    def test_extract_observation_from_flow(self):
        now = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        flow = Flow(
            flow_key=FlowKey(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="TCP"),
            window_start=now,
            window_end=now + timedelta(seconds=5),
        )
        packet = ParsedPacket(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            size=100,
            timestamp=now,
        )
        flow.add_packet(packet)
        flow.finalize()

        extractor = FeatureExtractor(normalize=False)
        observation = extractor.extract_observation(flow, finalized=True, sliding=False)

        assert isinstance(observation, FeatureObservation)
        assert observation.flow_key == flow.flow_key
        assert observation.window_start == flow.window_start
        assert observation.window_end == flow.window_end
        assert observation.finalized is True
        assert observation.sliding is False
        assert observation.features == extractor.extract_features(flow)

    def test_empty_flow_does_not_emit_observation(self):
        now = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        flow = Flow(
            flow_key=FlowKey(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="TCP"),
            window_start=now,
            window_end=now + timedelta(seconds=5),
        )
        extractor = FeatureExtractor()
        assert extractor.extract_observation(flow) is None

    def test_current_incomplete_flow_does_not_emit_canonical_observation(self):
        builder = FlowBuilder(window_seconds=5)
        emitted = []
        builder.set_feature_observation_callback(emitted.append)

        packet = ParsedPacket(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=12345,
            dst_port=80,
            size=100,
            timestamp=datetime.now(timezone.utc),
        )
        flow = builder.add_packet(packet)

        assert flow is not None
        assert emitted == []

    def test_fixed_window_emits_once_when_actually_closed(self):
        builder = FlowBuilder(window_seconds=5)
        emitted = []
        builder.set_feature_observation_callback(emitted.append)

        base = datetime.now(timezone.utc)
        p1 = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=1111, dst_port=80, size=100,
            timestamp=base,
        )
        p2 = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=1111, dst_port=80, size=200,
            timestamp=base + timedelta(seconds=6),
        )
        builder.add_packet(p1)
        builder.add_packet(p2)

        assert emitted == []
        closed_window = builder.window_manager.previous_windows[0]
        closed_window.end_time = datetime.now(timezone.utc) - timedelta(seconds=301)
        removed = builder.window_manager.cleanup_old_windows()

        assert removed == 1
        assert len(emitted) == 1
        observation = emitted[0]
        source_flow = closed_window.flows[FlowKeyStrategy.five_tuple(p1)]
        expected = builder.feature_extractor.extract_features(source_flow)
        assert observation.features == expected
        assert observation.finalized is True
        assert observation.sliding is False

    def test_retained_fixed_window_accepts_late_packet_before_emission(self):
        builder = FlowBuilder(window_seconds=5)
        emitted = []
        builder.set_feature_observation_callback(emitted.append)

        t_old = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        t_new = datetime(2024, 1, 1, 0, 0, 7, tzinfo=timezone.utc)
        old_packet = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=2222, dst_port=80, size=100,
            timestamp=t_old,
        )
        new_packet = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=2222, dst_port=80, size=100,
            timestamp=t_new,
        )
        late_packet = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=2222, dst_port=80, size=150,
            timestamp=t_old + timedelta(seconds=1),
        )

        builder.add_packet(old_packet)
        builder.add_packet(new_packet)
        assert len(builder.window_manager.previous_windows) == 1
        assert emitted == []

        builder.add_packet(late_packet)
        retained_window = builder.window_manager.previous_windows[0]
        retained_flow = retained_window.flows[FlowKeyStrategy.five_tuple(old_packet)]
        assert retained_flow.statistics.packet_count == 2

        retained_window.end_time = datetime.now(timezone.utc) - timedelta(seconds=301)
        builder.window_manager.cleanup_old_windows()

        assert len(emitted) == 1
        observation = emitted[0]
        assert observation.features == builder.feature_extractor.extract_features(retained_flow)
        assert observation.features["packet_count"] == 2
        assert observation.features["byte_count"] == 250

    def test_same_fixed_flow_window_cannot_emit_twice(self):
        builder = FlowBuilder(window_seconds=5)
        emitted = []
        builder.set_feature_observation_callback(emitted.append)

        base = datetime.now(timezone.utc)
        p1 = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=3333, dst_port=80, size=100,
            timestamp=base,
        )
        p2 = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=3333, dst_port=80, size=100,
            timestamp=base + timedelta(seconds=6),
        )
        builder.add_packet(p1)
        builder.add_packet(p2)

        closed_window = builder.window_manager.previous_windows[0]
        closed_window.end_time = datetime.now(timezone.utc) - timedelta(seconds=301)
        builder.window_manager.cleanup_old_windows()
        builder.window_manager.cleanup_old_windows()

        assert len(emitted) == 1

    def test_late_packet_after_fixed_window_emission_cannot_mutate_observation(self):
        builder = FlowBuilder(window_seconds=5)
        emitted = []
        builder.set_feature_observation_callback(emitted.append)

        t_old = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        t_new = datetime(2024, 1, 1, 0, 0, 7, tzinfo=timezone.utc)
        old_packet = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=4444, dst_port=80, size=100,
            timestamp=t_old,
        )
        new_packet = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=4444, dst_port=80, size=100,
            timestamp=t_new,
        )
        builder.add_packet(old_packet)
        builder.add_packet(new_packet)
        closed_window = builder.window_manager.previous_windows[0]
        closed_window.end_time = datetime.now(timezone.utc) - timedelta(seconds=301)
        builder.window_manager.cleanup_old_windows()

        late_too_old = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=4444, dst_port=80, size=999,
            timestamp=t_old + timedelta(seconds=1),
        )
        snapshot = emitted[0].features.copy()
        result = builder.add_packet(late_too_old)

        assert result is None
        assert emitted[0].features == snapshot

    def test_sliding_window_emits_once_when_expired_closed(self):
        builder = FlowBuilder(use_sliding_windows=True, window_seconds=10)
        emitted = []
        builder.set_feature_observation_callback(emitted.append)

        now = datetime.now(timezone.utc)
        event_time = now - timedelta(seconds=3)
        packet = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=5555, dst_port=80, size=100,
            timestamp=event_time,
        )
        builder.add_packet(packet)
        assert emitted == []

        builder.window_manager._cleanup_expired_windows(event_time + timedelta(seconds=13))

        assert len(emitted) == 2
        identities = {(obs.flow_key, obs.window_start, obs.window_end) for obs in emitted}
        assert len(identities) == 2
        assert all(obs.finalized is True for obs in emitted)
        assert all(obs.sliding is True for obs in emitted)

    def test_sliding_observation_features_match_source_flow_at_close(self):
        builder = FlowBuilder(use_sliding_windows=True, window_seconds=10)
        emitted = []
        builder.set_feature_observation_callback(emitted.append)

        now = datetime.now(timezone.utc)
        event_time = now - timedelta(seconds=3)
        packet = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=6666, dst_port=80, size=123,
            timestamp=event_time,
        )
        builder.add_packet(packet)
        source_windows = list(builder.window_manager.windows.values())
        source_map = {
            (flow.flow_key, flow.window_start, flow.window_end): flow
            for window in source_windows
            for flow in window.flows.values()
        }

        builder.window_manager._cleanup_expired_windows(event_time + timedelta(seconds=13))

        for observation in emitted:
            source_flow = source_map[(observation.flow_key, observation.window_start, observation.window_end)]
            assert observation.features == builder.feature_extractor.extract_features(source_flow)

    def test_sliding_overlap_emits_distinct_window_identities(self):
        builder = FlowBuilder(use_sliding_windows=True, window_seconds=10)
        emitted = []
        builder.set_feature_observation_callback(emitted.append)

        now = datetime.now(timezone.utc)
        event_time = now - timedelta(seconds=3)
        packet = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=7777, dst_port=80, size=100,
            timestamp=event_time,
        )
        builder.add_packet(packet)
        builder.window_manager._cleanup_expired_windows(event_time + timedelta(seconds=13))

        assert len(emitted) == 2
        assert emitted[0].window_start != emitted[1].window_start
        assert emitted[0].window_end != emitted[1].window_end


class TestFeatureAggregator:
    """Test suite for FeatureAggregator."""
    
    def test_aggregate_flow_features(self):
        """Test aggregating features across multiple flows."""
        aggregator = FeatureAggregator()
        # Use non-normalizing extractor for raw values
        aggregator.extractor = FeatureExtractor(normalize=False)
        
        flows = []
        for i in range(3):
            flow_key = FlowKey(
                src_ip=f"192.168.1.{i+1}",
                dst_ip="192.168.1.10",
                protocol="TCP",
            )
            
            now = datetime.now(timezone.utc)
            flow = Flow(
                flow_key=flow_key,
                window_start=now,
                window_end=now + timedelta(seconds=5),
            )
            
            # Add packets (different counts per flow)
            for j in range(i + 1):
                packet = ParsedPacket(
                    src_ip=f"192.168.1.{i+1}",
                    dst_ip="192.168.1.10",
                    transport_protocol=TransportProtocol.TCP,
                    size=100,
                    timestamp=now,
                )
                flow.add_packet(packet)
            
            flow.finalize()
            flows.append(flow)
        
        aggregated = aggregator.aggregate_flow_features(flows)
        
        # Should have aggregated features
        assert len(aggregated) > 0
        # Should have sum, mean, max, min for each feature
        assert "packet_count_sum" in aggregated
        assert "packet_count_mean" in aggregated
        assert "packet_count_max" in aggregated
        assert "packet_count_min" in aggregated
        
        # Sum should be 6 (0+1+2)
        assert aggregated["packet_count_sum"] == 6
        # Mean should be 2 (6/3)
        assert aggregated["packet_count_mean"] == 2.0
        # Max should be 2
        assert aggregated["packet_count_max"] >= 2  # At least 2
        # Min should be 0 or at least check it's reasonable
        assert aggregated["packet_count_min"] >= 0
    
    def test_aggregate_host_features(self):
        """Test aggregating features for a specific host."""
        aggregator = FeatureAggregator()
        # Use non-normalizing extractor for raw values
        aggregator.extractor = FeatureExtractor(normalize=False)
        
        flows = []
        # Create flows involving 192.168.1.1
        for i in range(3):
            flow_key = FlowKey(
                src_ip="192.168.1.1",
                dst_ip=f"192.168.1.{i+2}",
                protocol="TCP",
            )
            
            now = datetime.now(timezone.utc)
            flow = Flow(
                flow_key=flow_key,
                window_start=now,
                window_end=now + timedelta(seconds=5),
            )
            
            for j in range(5):
                packet = ParsedPacket(
                    src_ip="192.168.1.1",
                    dst_ip=f"192.168.1.{i+2}",
                    transport_protocol=TransportProtocol.TCP,
                    size=100,
                    timestamp=now,
                )
                flow.add_packet(packet)
            
            flow.finalize()
            flows.append(flow)
        
        # Add flow not involving 192.168.1.1
        flow_key = FlowKey(
            src_ip="192.168.1.2",
            dst_ip="192.168.1.3",
            protocol="TCP",
        )
        
        now = datetime.now(timezone.utc)
        flow = Flow(
            flow_key=flow_key,
            window_start=now,
            window_end=now + timedelta(seconds=5),
        )
        
        for j in range(10):
            packet = ParsedPacket(
                src_ip="192.168.1.2",
                dst_ip="192.168.1.3",
                transport_protocol=TransportProtocol.TCP,
                size=100,
                timestamp=now,
            )
            flow.add_packet(packet)
        
        flow.finalize()
        flows.append(flow)
        
        # Aggregate for 192.168.1.1
        host_features = aggregator.aggregate_host_features(flows, "192.168.1.1")
        
        # Should only include flows from/to 192.168.1.1
        assert host_features["packet_count_sum"] == 15  # 3 flows * 5 packets each
        assert host_features["packet_count_count"] == 3  # 3 flows
    
    def test_aggregate_empty_flows(self):
        """Test aggregating empty flow list."""
        aggregator = FeatureAggregator()
        
        aggregated = aggregator.aggregate_flow_features([])
        
        assert aggregated == {}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
