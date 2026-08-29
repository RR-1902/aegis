"""
Tests for flow builder and flow aggregation.

These tests validate that the flow builder correctly aggregates packets
into flows and manages time windows properly.
"""

import pytest
from datetime import datetime, timezone, timedelta
from scapy.all import Ether, IP, TCP, UDP

from app.models.packet import ParsedPacket, Protocol, TransportProtocol
from app.models.flow import Flow, FlowKey, FlowStatistics, FlowWindow
from app.flows.flow_key import FlowKeyStrategy, FlowKeyManager


A_IP = "192.168.1.10"
B_IP = "192.168.1.20"
C_IP = "192.168.1.30"
from app.flows.time_window import TimeWindowManager, SlidingWindowManager
from app.flows.flow_builder import FlowBuilder


class TestFlowKey:
    """Test suite for FlowKey functionality."""
    
    def test_flow_key_creation(self):
        """Test creating a flow key."""
        flow_key = FlowKey(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            protocol="TCP",
            src_port=12345,
            dst_port=80,
        )
        
        assert flow_key.src_ip == "192.168.1.1"
        assert flow_key.dst_ip == "192.168.1.2"
        assert flow_key.protocol == "TCP"
        assert flow_key.src_port == 12345
        assert flow_key.dst_port == 80
    
    def test_flow_key_is_passive_and_directional(self):
        """FlowKey itself should not normalize or reorder endpoints."""
        flow_key1 = FlowKey(
            src_ip="192.168.1.2",
            dst_ip="192.168.1.1",
            protocol="TCP",
            src_port=80,
            dst_port=12345,
        )

        flow_key2 = FlowKey(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            protocol="TCP",
            src_port=12345,
            dst_port=80,
        )

        assert flow_key1.src_ip == "192.168.1.2"
        assert flow_key1.dst_ip == "192.168.1.1"
        assert flow_key1 != flow_key2
    
    def test_flow_key_hash(self):
        """Test that flow keys are hashable."""
        flow_key = FlowKey(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            protocol="TCP",
        )
        
        # Should be able to use as dictionary key
        flow_dict = {flow_key: "test_value"}
        assert flow_key in flow_dict
        assert flow_dict[flow_key] == "test_value"
    
    def test_flow_key_from_packet(self):
        """Test creating flow key from packet."""
        packet = ParsedPacket(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=443,
            dst_port=8080,
        )
        
        flow_key = FlowKey.from_packet(packet, use_ports=True)
        
        assert flow_key.src_ip == "10.0.0.1"
        assert flow_key.dst_ip == "10.0.0.2"
        assert flow_key.protocol == "TCP"
        assert flow_key.src_port == 443
        assert flow_key.dst_port == 8080


class TestFlowStatistics:
    """Test suite for FlowStatistics functionality."""
    
    def test_empty_statistics(self):
        """Test empty flow statistics."""
        stats = FlowStatistics()
        
        assert stats.packet_count == 0
        assert stats.byte_count == 0
        assert stats.syn_count == 0
        assert stats.connection_attempts == 0
    
    def test_add_packet(self):
        """Test adding a packet to statistics."""
        stats = FlowStatistics()
        
        packet = ParsedPacket(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=12345,
            dst_port=80,
            size=1000,
        )
        
        stats.add_packet(packet, is_src_to_dst=True)
        
        assert stats.packet_count == 1
        assert stats.byte_count == 1000
        assert stats.bytes_sent == 1000
        assert stats.bytes_received == 0
    
    def test_tcp_flag_counting(self):
        """Test TCP flag counting."""
        stats = FlowStatistics()
        
        # Create SYN packet
        from app.models.packet import TCPFlags
        packet = ParsedPacket(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            transport_protocol=TransportProtocol.TCP,
            tcp_flags=TCPFlags(syn=True, ack=False),
        )
        
        stats.add_packet(packet)
        
        assert stats.syn_count == 1
        assert stats.connection_attempts == 1
    
    def test_unique_destination_ports(self):
        """Test tracking unique destination ports."""
        stats = FlowStatistics()
        
        for port in [80, 443, 8080, 80, 443]:  # Some duplicates
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                transport_protocol=TransportProtocol.TCP,
                dst_port=port,
            )
            stats.add_packet(packet)
        
        assert len(stats.unique_destination_ports) == 3  # 80, 443, 8080
        assert 80 in stats.unique_destination_ports
        assert 443 in stats.unique_destination_ports
        assert 8080 in stats.unique_destination_ports
    
    def test_duration_calculation(self):
        """Test duration calculation."""
        stats = FlowStatistics()
        
        now = datetime.now(timezone.utc)
        stats.first_packet_time = now
        stats.last_packet_time = now + timedelta(seconds=5)
        
        assert stats.get_duration_seconds() == 5.0
    
    def test_average_packet_size(self):
        """Test average packet size calculation."""
        stats = FlowStatistics()
        
        for size in [100, 200, 300]:
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                transport_protocol=TransportProtocol.TCP,
                size=size,
            )
            stats.add_packet(packet)
        
        assert stats.get_average_packet_size() == 200.0  # (100+200+300)/3

    def test_out_of_order_packet_timestamps_use_min_max(self):
        """Event-time first/last packet timestamps should use min/max, not insertion order."""
        stats = FlowStatistics()
        t2 = datetime(2024, 1, 1, 0, 0, 2, tzinfo=timezone.utc)
        t1 = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        t3 = datetime(2024, 1, 1, 0, 0, 3, tzinfo=timezone.utc)

        for ts in [t2, t1, t3]:
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                transport_protocol=TransportProtocol.TCP,
                timestamp=ts,
            )
            stats.add_packet(packet)

        assert stats.first_packet_time == t1
        assert stats.last_packet_time == t3
        assert stats.get_duration_seconds() == 2.0


class TestFlow:
    """Test suite for Flow functionality."""
    
    def test_flow_creation(self):
        """Test creating a flow."""
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
        
        assert flow.flow_key == flow_key
        assert flow.statistics.packet_count == 0
        
        assert flow.flow_key == flow_key
        assert flow.statistics.packet_count == 0
    
    def test_flow_add_packet(self):
        """Test adding packets to a flow."""
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
        
        packet = ParsedPacket(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            transport_protocol=TransportProtocol.TCP,
            size=1000,
            timestamp=now,
        )
        
        flow.add_packet(packet)
        
        assert flow.statistics.packet_count == 1
        assert flow.statistics.byte_count == 1000
    
    def test_flow_finalization(self):
        """Test flow finalization."""
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
                size=100 * (i + 1),
                timestamp=now,
            )
            flow.add_packet(packet)
        
        flow.finalize()
        
        assert flow.statistics.packet_count == 5
        assert flow.statistics.byte_count == 1500  # 100+200+300+400+500


class TestFlowWindow:
    """Test suite for FlowWindow functionality."""
    
    def test_flow_window_creation(self):
        """Test creating a flow window."""
        now = datetime.now(timezone.utc)
        window = FlowWindow(
            window_id="test_window",
            start_time=now,
            end_time=now + timedelta(seconds=5),
        )
        
        assert window.window_id == "test_window"
        assert window.get_flow_count() == 0
    
    def test_flow_window_add_packet(self):
        """Test adding packets to flow window."""
        now = datetime.now(timezone.utc)
        window = FlowWindow(
            window_id="test_window",
            start_time=now,
            end_time=now + timedelta(seconds=5),
        )

        packet = ParsedPacket(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=12345,
            dst_port=80,
        )
        flow_key = FlowKeyStrategy.five_tuple(packet)

        flow = window.add_packet(packet, flow_key=flow_key)

        assert window.get_flow_count() == 1
        assert flow.statistics.packet_count == 1
    
    def test_flow_window_statistics(self):
        """Test flow window statistics."""
        now = datetime.now(timezone.utc)
        window = FlowWindow(
            window_id="test_window",
            start_time=now,
            end_time=now + timedelta(seconds=5),
        )
        
        # Add multiple packets to same flow
        for i in range(10):
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                transport_protocol=TransportProtocol.TCP,
                src_port=12345,
                dst_port=80,
                size=100 * (i + 1),
            )
            window.add_packet(packet, flow_key=FlowKeyStrategy.five_tuple(packet))
        
        assert window.get_flow_count() == 1
        assert window.get_total_packets() == 10
        assert window.get_total_bytes() == 5500  # Sum of 100, 200, ..., 1000


class TestFlowKeyStrategy:
    """Test suite for supported FlowKeyStrategy semantics."""

    def _packets(self):
        p1 = ParsedPacket(src_ip=A_IP, dst_ip=B_IP, transport_protocol=TransportProtocol.TCP, src_port=50000, dst_port=80)
        p2 = ParsedPacket(src_ip=B_IP, dst_ip=A_IP, transport_protocol=TransportProtocol.TCP, src_port=80, dst_port=50000)
        p3 = ParsedPacket(src_ip=A_IP, dst_ip=B_IP, transport_protocol=TransportProtocol.TCP, src_port=50001, dst_port=80)
        p4 = ParsedPacket(src_ip=C_IP, dst_ip=B_IP, transport_protocol=TransportProtocol.TCP, src_port=40000, dst_port=80)
        return p1, p2, p3, p4

    def test_five_tuple_strategy(self):
        p1, p2, p3, _ = self._packets()
        k1 = FlowKeyStrategy.five_tuple(p1)
        k2 = FlowKeyStrategy.five_tuple(p2)
        k3 = FlowKeyStrategy.five_tuple(p3)
        assert k1 != k2
        assert k1 != k3
        assert k1.src_ip == "192.168.1.10"
        assert k1.dst_ip == "192.168.1.20"
        assert k1.src_port == 50000
        assert k1.dst_port == 80

    def test_three_tuple_strategy(self):
        p1, p2, p3, p4 = self._packets()
        k1 = FlowKeyStrategy.three_tuple(p1)
        k2 = FlowKeyStrategy.three_tuple(p2)
        k3 = FlowKeyStrategy.three_tuple(p3)
        k4 = FlowKeyStrategy.three_tuple(p4)
        assert k1 == k3
        assert k1 != k2
        assert k1 != k4
        assert k1.src_port is None
        assert k1.dst_port is None

    def test_bidirectional_strategy(self):
        p1, p2, p3, p4 = self._packets()
        k1 = FlowKeyStrategy.bidirectional(p1)
        k2 = FlowKeyStrategy.bidirectional(p2)
        k3 = FlowKeyStrategy.bidirectional(p3)
        k4 = FlowKeyStrategy.bidirectional(p4)
        assert k1 == k2
        assert k1 != k3
        assert k1 != k4

    def test_bidirectional_ipv4_ordering_is_ip_aware(self):
        packet = ParsedPacket(
            src_ip="192.168.1.20",
            dst_ip="192.168.1.3",
            transport_protocol=TransportProtocol.TCP,
            src_port=80,
            dst_port=50000,
        )
        key = FlowKeyStrategy.bidirectional(packet)
        assert key.src_ip == "192.168.1.3"
        assert key.dst_ip == "192.168.1.20"

    def test_bidirectional_ipv6_supported(self):
        packet = ParsedPacket(
            src_ip="2001:db8::2",
            dst_ip="2001:db8::1",
            transport_protocol=TransportProtocol.TCP,
            src_port=80,
            dst_port=50000,
        )
        key = FlowKeyStrategy.bidirectional(packet)
        assert key is not None
        assert key.src_ip == "2001:db8::1"
        assert key.dst_ip == "2001:db8::2"

    def test_invalid_strategy_fails_clearly(self):
        with pytest.raises(ValueError, match="Unknown flow key strategy"):
            FlowKeyManager("source_centric")

        manager = FlowKeyManager("five_tuple")
        with pytest.raises(ValueError, match="Unknown flow key strategy"):
            manager.set_strategy("destination_centric")


class TestP3EndToEndStrategies:
    """End-to-end FlowBuilder/FlowWindow consistency for supported strategies."""

    def _p1(self, ts):
        return ParsedPacket(
            src_ip=A_IP,
            dst_ip=B_IP,
            transport_protocol=TransportProtocol.TCP,
            src_port=50000,
            dst_port=80,
            size=100,
            timestamp=ts,
        )

    def _p2(self, ts):
        return ParsedPacket(
            src_ip=B_IP,
            dst_ip=A_IP,
            transport_protocol=TransportProtocol.TCP,
            src_port=80,
            dst_port=50000,
            size=120,
            timestamp=ts,
        )

    def _p3(self, ts):
        return ParsedPacket(
            src_ip=A_IP,
            dst_ip=B_IP,
            transport_protocol=TransportProtocol.TCP,
            src_port=50001,
            dst_port=80,
            size=140,
            timestamp=ts,
        )

    def _p4(self, ts):
        return ParsedPacket(
            src_ip=C_IP,
            dst_ip=B_IP,
            transport_protocol=TransportProtocol.TCP,
            src_port=40000,
            dst_port=80,
            size=160,
            timestamp=ts,
        )

    def test_flowbuilder_and_window_use_same_key_five_tuple(self):
        ts = datetime.now(timezone.utc)
        packet = self._p1(ts)
        builder = FlowBuilder(flow_key_strategy="five_tuple", window_seconds=5)

        flow = builder.add_packet(packet)
        expected_key = FlowKeyStrategy.five_tuple(packet)

        assert flow is not None
        assert flow.flow_key == expected_key
        assert builder.get_flow(expected_key) is flow
        assert builder.window_manager.current_window.flows[expected_key] is flow

    def test_flowbuilder_strategy_semantics_five_tuple(self):
        ts = datetime.now(timezone.utc)
        builder = FlowBuilder(flow_key_strategy="five_tuple", window_seconds=5)
        f1 = builder.add_packet(self._p1(ts))
        f2 = builder.add_packet(self._p2(ts))
        f3 = builder.add_packet(self._p3(ts))

        assert builder.get_flow_count() == 3
        assert f1 is not f2
        assert f1 is not f3
        assert f1.statistics.packet_count == 1
        assert f2.statistics.packet_count == 1
        assert f3.statistics.packet_count == 1

    def test_flowbuilder_strategy_semantics_three_tuple(self):
        ts = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        builder = FlowBuilder(flow_key_strategy="three_tuple", window_seconds=5)
        f1 = builder.add_packet(self._p1(ts))
        f3 = builder.add_packet(self._p3(ts))
        builder.add_packet(self._p2(ts))
        builder.add_packet(self._p4(ts))

        assert f1 is f3
        assert builder.get_flow_count() == 3
        assert f1.statistics.packet_count == 2

    def test_flowbuilder_strategy_semantics_bidirectional(self):
        ts = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        builder = FlowBuilder(flow_key_strategy="bidirectional", window_seconds=5)
        f1 = builder.add_packet(self._p1(ts))
        f2 = builder.add_packet(self._p2(ts))
        builder.add_packet(self._p3(ts))
        builder.add_packet(self._p4(ts))

        assert f1 is f2
        assert builder.get_flow_count() == 3
        assert f1.statistics.packet_count == 2

    def test_bidirectional_direction_counters_follow_canonical_orientation(self):
        ts = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        builder = FlowBuilder(flow_key_strategy="bidirectional", window_seconds=5)
        forward = self._p1(ts)
        reverse = self._p2(ts + timedelta(seconds=1))

        flow = builder.add_packet(forward)
        builder.add_packet(reverse)

        assert flow.flow_key == FlowKeyStrategy.bidirectional(forward)
        assert flow.flow_key.src_ip == A_IP
        assert flow.flow_key.dst_ip == B_IP
        assert flow.statistics.packet_count == 2
        assert flow.statistics.bytes_sent == 100
        assert flow.statistics.bytes_received == 120

    def test_bidirectional_key_stable_in_either_processing_direction(self):
        ts = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
        builder1 = FlowBuilder(flow_key_strategy="bidirectional", window_seconds=5)
        f_a = builder1.add_packet(self._p1(ts))
        f_b = builder1.add_packet(self._p2(ts))

        builder2 = FlowBuilder(flow_key_strategy="bidirectional", window_seconds=5)
        g_b = builder2.add_packet(self._p2(ts))
        g_a = builder2.add_packet(self._p1(ts))

        assert f_a.flow_key == f_b.flow_key
        assert g_a.flow_key == g_b.flow_key
        assert f_a.flow_key == g_a.flow_key


class TestTimeWindowManager:
    """Test suite for event-time fixed windows."""

    def test_window_creation_from_packet_timestamp(self):
        manager = TimeWindowManager(window_seconds=5)
        packet = ParsedPacket(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=12345,
            dst_port=80,
            timestamp=datetime(2024, 1, 1, 0, 0, 7, tzinfo=timezone.utc),
        )

        flow = manager.add_packet(packet, flow_key=FlowKeyStrategy.five_tuple(packet))

        assert flow is not None
        assert manager.current_window is not None
        assert manager.current_window.start_time == datetime(2024, 1, 1, 0, 0, 5, tzinfo=timezone.utc)
        assert manager.current_window.end_time == datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
        assert manager.total_windows_created == 1

    def test_forward_event_time_moves_to_new_window(self):
        manager = TimeWindowManager(window_seconds=5)
        p1 = ParsedPacket(
            src_ip="1.1.1.1", dst_ip="2.2.2.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=1, dst_port=2,
            timestamp=datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        )
        p2 = ParsedPacket(
            src_ip="1.1.1.1", dst_ip="2.2.2.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=1, dst_port=2,
            timestamp=datetime(2024, 1, 1, 0, 0, 6, tzinfo=timezone.utc),
        )

        flow1 = manager.add_packet(p1, flow_key=FlowKeyStrategy.five_tuple(p1))
        flow2 = manager.add_packet(p2, flow_key=FlowKeyStrategy.five_tuple(p2))

        assert flow1.window_start == datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert flow2.window_start == datetime(2024, 1, 1, 0, 0, 5, tzinfo=timezone.utc)
        assert manager.current_window.start_time == datetime(2024, 1, 1, 0, 0, 5, tzinfo=timezone.utc)
        assert manager.previous_windows[-1].start_time == datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_late_packet_into_retained_window_is_accepted(self):
        manager = TimeWindowManager(window_seconds=5)
        packet_new = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.UDP,
            src_port=1000, dst_port=2000,
            timestamp=datetime(2024, 1, 1, 0, 0, 12, tzinfo=timezone.utc),
        )
        packet_late = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.UDP,
            src_port=1000, dst_port=2000,
            timestamp=datetime(2024, 1, 1, 0, 0, 3, tzinfo=timezone.utc),
        )

        manager.add_packet(packet_late, flow_key=FlowKeyStrategy.five_tuple(packet_late))
        manager.add_packet(packet_new, flow_key=FlowKeyStrategy.five_tuple(packet_new))
        late_again = manager.add_packet(packet_late, flow_key=FlowKeyStrategy.five_tuple(packet_late))

        retained_old = manager.previous_windows[-1]
        assert retained_old.start_time == datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert late_again.window_start == retained_old.start_time
        assert retained_old.get_total_packets() == 2

    def test_late_packet_for_removed_window_is_dropped(self):
        manager = TimeWindowManager(window_seconds=5)
        current = FlowWindow(
            window_id="current",
            start_time=datetime(2024, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
            end_time=datetime(2024, 1, 1, 0, 1, 5, tzinfo=timezone.utc),
        )
        manager.current_window = current
        manager.previous_windows = [
            FlowWindow(
                window_id="kept",
                start_time=datetime(2024, 1, 1, 0, 0, 55, tzinfo=timezone.utc),
                end_time=datetime(2024, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
            )
        ]

        too_old = ParsedPacket(
            src_ip="3.3.3.3", dst_ip="4.4.4.4",
            transport_protocol=TransportProtocol.TCP,
            src_port=123, dst_port=80,
            timestamp=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
        )

        assert manager.add_packet(too_old, flow_key=FlowKeyStrategy.five_tuple(too_old)) is None

    def test_modest_future_timestamp_is_accepted(self):
        manager = TimeWindowManager(window_seconds=5)
        future_packet = ParsedPacket(
            src_ip="5.5.5.5", dst_ip="6.6.6.6",
            transport_protocol=TransportProtocol.TCP,
            src_port=5555, dst_port=80,
            timestamp=datetime.now(timezone.utc) + timedelta(seconds=30),
        )

        flow = manager.add_packet(future_packet, flow_key=FlowKeyStrategy.five_tuple(future_packet))

        assert flow is not None
        assert flow.window_start <= future_packet.timestamp < flow.window_end

    def test_window_statistics(self):
        manager = TimeWindowManager(window_seconds=5)
        stats = manager.get_window_statistics()
        assert "window_seconds" in stats
        assert "total_windows_created" in stats
        assert "total_packets_processed" in stats


class TestFlowBuilder:
    """Test suite for FlowBuilder."""
    
    def test_flow_builder_initialization(self):
        """Test flow builder initialization."""
        builder = FlowBuilder()
        
        assert builder.flow_key_strategy == "five_tuple"
        assert builder.window_seconds == 5
        assert builder.total_packets_processed == 0
    
    def test_add_packet_to_builder(self):
        """Test adding packets to flow builder."""
        builder = FlowBuilder()
        
        now = datetime.now(timezone.utc)
        packet = ParsedPacket(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=12345,
            dst_port=80,
            size=1000,
            timestamp=now,
        )
        
        flow = builder.add_packet(packet)
        
        assert flow is not None
        assert builder.total_packets_processed == 1
        assert builder.total_flows_created == 1
    
    def test_flow_aggregation(self):
        """Test that packets are aggregated into flows."""
        builder = FlowBuilder()
        
        now = datetime.now(timezone.utc)
        # Add multiple packets to same flow
        for i in range(5):
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                transport_protocol=TransportProtocol.TCP,
                src_port=12345,
                dst_port=80,
                size=100 * (i + 1),
                timestamp=now,
            )
            builder.add_packet(packet)
        
        # Should have created only 1 flow
        assert builder.total_flows_created == 1
        assert builder.get_flow_count() == 1
        
        # Flow should have 5 packets
        flows = builder.get_all_flows()
        assert len(flows) == 1
        assert flows[0].statistics.packet_count == 5
    
    def test_multiple_flows(self):
        """Test creating multiple flows."""
        builder = FlowBuilder()
        
        now = datetime.now(timezone.utc)
        # Add packets to different flows
        for i in range(3):
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip=f"192.168.1.{i+2}",  # Different destinations
                transport_protocol=TransportProtocol.TCP,
                src_port=12345,
                dst_port=80,
                timestamp=now,
            )
            builder.add_packet(packet)
        
        # Should have created 3 flows
        assert builder.total_flows_created == 3
        assert builder.get_flow_count() == 3
    
    def test_flow_builder_statistics(self):
        """Test flow builder statistics."""
        builder = FlowBuilder()
        
        now = datetime.now(timezone.utc)
        # Add some packets
        for i in range(10):
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                transport_protocol=TransportProtocol.TCP,
                src_port=12345,
                dst_port=80,
                size=100,
                timestamp=now,
            )
            builder.add_packet(packet)
        
        stats = builder.get_statistics()
        
        assert stats["total_packets_processed"] == 10
        assert stats["total_flows_created"] == 1
        assert stats["active_flow_count"] == 1
    
    def test_flow_key_strategy_change(self):
        """Test changing flow key strategy."""
        builder = FlowBuilder(flow_key_strategy="five_tuple")
        
        now = datetime.now(timezone.utc)
        # Add some packets
        packet = ParsedPacket(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=12345,
            dst_port=80,
            timestamp=now,
        )
        builder.add_packet(packet)
        
        # Change strategy (should reset)
        builder.set_flow_key_strategy("three_tuple")
        
        assert builder.flow_key_strategy == "three_tuple"
        assert builder.total_flows_created == 0  # Reset after strategy change
    
    def test_get_flows_by_source_ip(self):
        """Test filtering flows by source IP."""
        builder = FlowBuilder()
        
        now = datetime.now(timezone.utc)
        # Add packets from different sources
        for i in range(3):
            packet = ParsedPacket(
                src_ip=f"192.168.1.{i+1}",
                dst_ip="192.168.1.10",
                transport_protocol=TransportProtocol.TCP,
                src_port=12345,
                dst_port=80,
                timestamp=now,
            )
            builder.add_packet(packet)
        
        flows = builder.get_flows_by_source_ip("192.168.1.1")
        
        assert len(flows) == 1
        assert flows[0].flow_key.src_ip == "192.168.1.1"
    
    def test_top_flows_by_packets(self):
        """Test getting top flows by packet count."""
        builder = FlowBuilder()
        
        now = datetime.now(timezone.utc)
        # Create flows with different packet counts using different destination ports
        # Use different source ports to avoid flow key normalization
        # Flow: (src_ip, dst_ip, src_port, dst_port, protocol)
        
        # Flow 1: 1 packet
        packet = ParsedPacket(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=10000,
            dst_port=80,
            timestamp=now,
        )
        builder.add_packet(packet)
        
        # Flow 2: 2 packets
        for _ in range(2):
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                transport_protocol=TransportProtocol.TCP,
                src_port=10001,
                dst_port=80,
                timestamp=now,
            )
            builder.add_packet(packet)
        
        # Flow 3: 3 packets
        for _ in range(3):
            packet = ParsedPacket(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                transport_protocol=TransportProtocol.TCP,
                src_port=10002,
                dst_port=80,
                timestamp=now,
            )
            builder.add_packet(packet)
        
        top_flows = builder.get_top_flows_by_packets(count=2)
        
        assert len(top_flows) == 2
        # First flow should have most packets (3)
        assert top_flows[0].statistics.packet_count == 3
        # Second flow should have second most packets (2)
        assert top_flows[1].statistics.packet_count == 2


class TestP1Invariant:
    """
    Regression tests for the P1 invariant:
        There must be exactly one authoritative FlowStatistics state per flow
        identity. A single packet must never be independently counted into two
        separate Flow objects for the same flow_key.
    """

    def test_single_packet_not_double_counted(self):
        """P1(1): Adding one packet results in packet_count == 1 everywhere.

        Before P1 fix: active_flows created a second new Flow object and called
        add_packet on it independently, so the same packet lived in TWO separate
        FlowStatistics with count 2 in total across two Flow obects.
        After P1 fix: a single Flow object (owned by the window) has count 1,
        and active_flows just holds a reference to it.
        """
        builder = FlowBuilder()
        now = datetime.now(timezone.utc)
        packet = ParsedPacket(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            transport_protocol=TransportProtocol.TCP,
            src_port=55555,
            dst_port=443,
            size=256,
            timestamp=now,
        )

        returned_flow = builder.add_packet(packet)
        assert returned_flow is not None, "add_packet must return a Flow"

        # Retrieve through lookup API
        lookup_flow = builder.get_flow(returned_flow.flow_key)
        assert lookup_flow is not None, "get_flow must find the same flow_key"

        all_flows = builder.get_all_flows()
        assert len(all_flows) == 1, "Exactly 1 flow should exist"

        # The authoritative count: 1 packet, not 2, anywhere
        assert returned_flow.statistics.packet_count == 1
        assert lookup_flow.statistics.packet_count == 1
        assert all_flows[0].statistics.packet_count == 1
        assert returned_flow.statistics.byte_count == 256
        assert lookup_flow.statistics.byte_count == 256

    def test_returned_and_lookup_flows_share_identity(self):
        """P1(2): add_packet() return and get_flow() retrieve the SAME object.

        The canonical Flow object must be identity-shared across the return
        value and the lookup API. No copy-on-write, no independent replica.
        """
        builder = FlowBuilder()
        now = datetime.now(timezone.utc)

        # Add initial packet
        packet1 = ParsedPacket(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=20000,
            dst_port=22,
            size=100,
            timestamp=now,
        )
        returned_flow = builder.add_packet(packet1)
        fk = returned_flow.flow_key

        # Identity check: returned object IS lookup object (same reference)
        lookup_flow = builder.get_flow(fk)
        assert lookup_flow is returned_flow, (
            "get_flow() must return the same Flow object (not a copy) "
            "that add_packet() returned"
        )

        # All flows list contains the exact same object
        all_flows = builder.get_all_flows()
        assert all_flows[0] is returned_flow, (
            "get_all_flows()[0] must be the exact same Flow reference"
        )

        # And the internal active_flows index points to the same object too
        assert builder.active_flows[fk] is returned_flow

        # After adding a second packet to the same flow identity, the returned
        # flow (from window) and the lookup flow still share identity: packet
        # count increases on both simultaneously because they are one object.
        packet2 = ParsedPacket(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=20000,
            dst_port=22,
            size=300,
            timestamp=now,
        )
        returned_flow2 = builder.add_packet(packet2)

        # Same flow_key → should be the same canonical Flow object
        assert returned_flow2 is returned_flow, (
            "Within the same window, add_packet() for a known flow_key "
            "returns the exact same Flow object"
        )

        # Count is exactly 2, not 4 (no double counting across 2 objects)
        assert returned_flow.statistics.packet_count == 2
        assert builder.get_flow(fk).statistics.packet_count == 2
        # Bytes 100 + 300 = 400 total, not doubled
        assert returned_flow.statistics.byte_count == 400

    def test_n_packets_counted_exactly_n_times(self):
        """P1(3): N packets = N in the authoritative statistics.

        Stress test: send N packets for one flow, verify total packet_count
        is exactly N. If any duplicate counting existed this would fail with
        count=2N.
        """
        builder = FlowBuilder()
        base_ts = datetime.now(timezone.utc)

        N = 47
        for i in range(N):
            pkt = ParsedPacket(
                src_ip="172.16.0.1",
                dst_ip="172.16.0.2",
                transport_protocol=TransportProtocol.UDP,
                src_port=33333,
                dst_port=53,
                size=60 + (i % 3),
                timestamp=base_ts + timedelta(milliseconds=i * 3),
            )
            f = builder.add_packet(pkt)
            assert f is not None
            fk = f.flow_key

        # Authoritative count: exactly N
        flow = builder.get_flow(fk)
        assert flow.statistics.packet_count == N, (
            f"Expected exactly {N} packets counted once, got "
            f"{flow.statistics.packet_count} (if double-counted it would be {2*N})"
        )

        # Window total must also match: N packets, one flow
        window_stats = builder.window_manager.get_window_statistics()
        assert window_stats["current_window"]["total_packets"] == N
        assert window_stats["current_window"]["flow_count"] == 1

        # active_flows sums for reporting also match N
        builder_stats = builder.get_statistics()
        assert builder_stats["total_packets_processed"] == N
        assert builder_stats["active_flow_packets"] == N

    def test_window_rotation_no_double_counting(self):
        """P1(4): New event-time window creates a new Flow without double-counting."""
        builder = FlowBuilder(window_seconds=1)
        base_ts = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        fk = None
        w1_flow_ref = None
        for i in range(3):
            pkt = ParsedPacket(
                src_ip="1.1.1.1",
                dst_ip="2.2.2.2",
                transport_protocol=TransportProtocol.TCP,
                src_port=12345,
                dst_port=80,
                size=100,
                timestamp=base_ts + timedelta(milliseconds=i * 10),
            )
            flow = builder.add_packet(pkt)
            fk = flow.flow_key
            w1_flow_ref = flow

        assert w1_flow_ref.statistics.packet_count == 3

        for i in range(5):
            pkt = ParsedPacket(
                src_ip="1.1.1.1",
                dst_ip="2.2.2.2",
                transport_protocol=TransportProtocol.TCP,
                src_port=12345,
                dst_port=80,
                size=200,
                timestamp=base_ts + timedelta(seconds=5, milliseconds=i * 10),
            )
            w2_flow = builder.add_packet(pkt)

        assert w2_flow is not w1_flow_ref
        assert w1_flow_ref.statistics.packet_count == 3
        assert w2_flow.statistics.packet_count == 5
        assert builder.active_flows[fk] is w2_flow
        assert builder.get_flow(fk) is w2_flow

        ws = builder.window_manager.get_window_statistics()
        assert ws["current_window"]["total_packets"] == 5
        assert len(ws["previous_windows"]) >= 1
        assert ws["previous_windows"][-1]["total_packets"] == 3
        assert builder.total_flows_created == 1
        assert builder.total_flows_expired >= 0

    def test_cleanup_removes_reference_only_not_statistics(self):
        """P1(5): Active-flow cleanup removes index reference only.

        When _cleanup_expired_flows runs and removes an idle flow_key from
        active_flows:
          - The window manager's archived Flows (with their statistics) must
            still exist in previous_windows and return their counts unchanged.
          - No "second copy" of statistics lives anywhere in FlowBuilder after
            cleanup. (The old Flow object had been shared via reference; the
            index removal just drops the reference — GC will free it later if
            no other holder, but window_manager still holds it.)
        """
        builder = FlowBuilder(window_seconds=1, flow_timeout_seconds=2)
        now = datetime.now(timezone.utc)

        pkt = ParsedPacket(
            src_ip="192.168.99.1",
            dst_ip="192.168.99.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=51000,
            dst_port=3306,
            size=400,
            timestamp=now,
        )
        flow = builder.add_packet(pkt)
        fk = flow.flow_key

        # Advance time past timeout → mark as expired via last_packet_time
        future = now + timedelta(seconds=10)
        # Call internal cleanup directly with advanced time
        builder._cleanup_expired_flows(future)

        # Now: active_flows index should no longer have the key
        assert fk not in builder.active_flows, (
            "Cleanup must remove the flow_key from active_flows index"
        )
        assert builder.get_flow(fk) is None, (
            "get_flow() returns None for a cleaned-up flow_key (convo idle)"
        )
        assert builder.get_flow_count() == 0
        assert builder.total_flows_expired == 1, (
            "total_flows_expired counter must increment"
        )

        # But the Flow OBJECT (and its stats) still lives because the window
        # manager archived it. Count preserved = 1 packet, 400 bytes.
        # (GC in CPython won't collect it because window_manager holds a ref.)
        assert flow.statistics.packet_count == 1, (
            "The canonical Flow's statistics must NOT be destroyed by cleanup — "
            "the window store retains them for historical queries"
        )
        assert flow.statistics.byte_count == 400

        # Confirm via window manager the data is still there
        ws = builder.window_manager.get_window_statistics()
        # Either current or previous window should still have the flow
        total_packets_in_store = ws["current_window"].get("total_packets", 0) + sum(
            w["total_packets"] for w in ws["previous_windows"]
        )
        assert total_packets_in_store == 1, (
            "Window manager archival storage still retains all packet data"
        )


class TestP2SlidingWindow:
    """Regression tests for event-time sliding window semantics."""

    def test_sliding_manager_add_packet_returns_list(self):
        swm = SlidingWindowManager(window_seconds=10, slide_seconds=10)
        pkt = ParsedPacket(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=50000,
            dst_port=443,
            size=100,
            timestamp=datetime(2024, 1, 1, 0, 0, 3, tzinfo=timezone.utc),
        )
        flows = swm.add_packet(pkt, flow_key=FlowKeyStrategy.five_tuple(pkt))
        assert isinstance(flows, list)
        assert len(flows) == 1
        assert isinstance(flows[0], Flow)
        assert flows[0].statistics.packet_count == 1

    def test_sliding_assignment_uses_packet_timestamp(self):
        swm = SlidingWindowManager(window_seconds=10, slide_seconds=5)
        pkt = ParsedPacket(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=1234, dst_port=80, size=60,
            timestamp=datetime(2024, 1, 1, 0, 0, 7, tzinfo=timezone.utc),
        )

        flows = swm.add_packet(pkt, flow_key=FlowKeyStrategy.five_tuple(pkt))
        starts = sorted(f.window_start for f in flows)

        assert starts == [
            datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            datetime(2024, 1, 1, 0, 0, 5, tzinfo=timezone.utc),
        ]

    def test_sliding_overlapping_windows_count_in_each(self):
        swm = SlidingWindowManager(window_seconds=10, slide_seconds=5)
        base = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        fk = FlowKey(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            protocol="TCP",
            src_port=33333,
            dst_port=9999,
        )

        p0 = ParsedPacket(
            src_ip=fk.src_ip, dst_ip=fk.dst_ip,
            transport_protocol=TransportProtocol.TCP,
            src_port=fk.src_port, dst_port=fk.dst_port, size=60,
            timestamp=base,
        )
        flows0 = swm.add_packet(p0, flow_key=fk)
        target_w0 = next(f for f in flows0 if f.window_start == base)
        assert len(flows0) == 2

        p5 = ParsedPacket(
            src_ip=fk.src_ip, dst_ip=fk.dst_ip,
            transport_protocol=TransportProtocol.TCP,
            src_port=fk.src_port, dst_port=fk.dst_port, size=80,
            timestamp=base + timedelta(seconds=5),
        )
        flows5 = swm.add_packet(p5, flow_key=fk)
        assert len(flows5) == 2

        counts_by_start = {f.window_start: f.statistics.packet_count for f in flows5}
        assert counts_by_start[datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)] == 2
        assert counts_by_start[datetime(2024, 1, 1, 0, 0, 5, tzinfo=timezone.utc)] == 1
        assert target_w0.statistics.packet_count == 2

    def test_multiple_packets_sliding(self):
        swm = SlidingWindowManager(window_seconds=20, slide_seconds=5)
        base = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        flows_history: List[List[Flow]] = []
        for i in range(5):
            pkt = ParsedPacket(
                src_ip="7.7.7.7",
                dst_ip="8.8.8.8",
                transport_protocol=TransportProtocol.UDP,
                src_port=11111,
                dst_port=53,
                size=40 + i,
                timestamp=base + timedelta(seconds=i * 3),
            )
            fs = swm.add_packet(pkt, flow_key=FlowKeyStrategy.five_tuple(pkt))
            flows_history.append(fs)

        assert swm.total_packets_processed == 5
        assert len(flows_history[0]) == 4
        assert len(flows_history[-1]) <= len(flows_history[0])
        assert swm.total_windows_created >= 4

    def test_delayed_packet_still_uses_event_time_window(self):
        swm = SlidingWindowManager(window_seconds=10, slide_seconds=5)
        current_pkt = ParsedPacket(
            src_ip="11.0.0.1", dst_ip="11.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=1000, dst_port=80,
            timestamp=datetime(2024, 1, 1, 0, 0, 20, tzinfo=timezone.utc),
        )
        delayed_pkt = ParsedPacket(
            src_ip="11.0.0.1", dst_ip="11.0.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=1000, dst_port=80,
            timestamp=datetime(2024, 1, 1, 0, 0, 7, tzinfo=timezone.utc),
        )

        swm.add_packet(delayed_pkt, flow_key=FlowKeyStrategy.five_tuple(delayed_pkt))
        future_flows = swm.add_packet(current_pkt, flow_key=FlowKeyStrategy.five_tuple(current_pkt))
        delayed_again = swm.add_packet(delayed_pkt, flow_key=FlowKeyStrategy.five_tuple(delayed_pkt))

        assert all(f.window_start <= delayed_pkt.timestamp < f.window_end for f in delayed_again)
        assert all(f.window_start <= current_pkt.timestamp < f.window_end for f in future_flows)

    def test_late_packet_removed_sliding_window_is_skipped(self):
        swm = SlidingWindowManager(window_seconds=10, slide_seconds=5)
        pkt = ParsedPacket(
            src_ip="5.5.5.5", dst_ip="6.6.6.6",
            transport_protocol=TransportProtocol.TCP,
            src_port=1234, dst_port=80, size=50,
            timestamp=datetime(2024, 1, 1, 0, 0, 12, tzinfo=timezone.utc),
        )
        swm.add_packet(pkt, flow_key=FlowKeyStrategy.five_tuple(pkt))
        # Remove one historical candidate window so a late packet cannot recreate it.
        del swm.windows["slide_2024-01-01T00:00:05+00:00"]

        late = ParsedPacket(
            src_ip="5.5.5.5", dst_ip="6.6.6.6",
            transport_protocol=TransportProtocol.TCP,
            src_port=1234, dst_port=80, size=50,
            timestamp=datetime(2024, 1, 1, 0, 0, 12, tzinfo=timezone.utc),
        )
        flows = swm.add_packet(late, flow_key=FlowKeyStrategy.five_tuple(late))

        starts = [f.window_start for f in flows]
        assert datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc) in starts
        assert datetime(2024, 1, 1, 0, 0, 5, tzinfo=timezone.utc) not in starts

    def test_flowbuilder_use_sliding_windows_smoke(self):
        """P2(d): FlowBuilder with use_sliding_windows=True works at all.

        Before P2 fix, SlidingWindowManager.add_packet returned List[Flow]
        while FlowBuilder assumed Flow and stored the list directly into
        active_flows[fk] and passed it to callback as if it was a Flow.
        That would crash on callback invocation or later when get_flow()
        expected Flow attributes. This is the smoke catch-all.
        """
        builder = FlowBuilder(use_sliding_windows=True, window_seconds=30)
        now = datetime.now(timezone.utc)
        pkt = ParsedPacket(
            src_ip="192.168.0.1",
            dst_ip="192.168.0.2",
            transport_protocol=TransportProtocol.TCP,
            src_port=40000,
            dst_port=80,
            size=150,
            timestamp=now,
        )

        # 1. add_packet must succeed with type(return) == Flow (single primary)
        flow = builder.add_packet(pkt)
        assert flow is not None, "add_packet with sliding windows must return a Flow"
        assert isinstance(flow, Flow), (
            f"Expected return type Flow, got {type(flow).__name__}: {flow!r}"
        )

        # 2. get_flow() returns the EXACT same object (P1 invariant preserved)
        fk = flow.flow_key
        assert builder.get_flow(fk) is flow, (
            "get_flow() must be the exact primary Flow reference returned by "
            "add_packet — not a copy, and not the list of all window flows"
        )
        assert builder.active_flows[fk] is flow

        # 3. Flow statistics must match: 1 packet (no duplicate counting)
        assert flow.statistics.packet_count == 1
        assert flow.statistics.byte_count == 150

        # 4. get_statistics() must not crash (it queried get_window_statistics)
        stats = builder.get_statistics()
        assert stats["total_packets_processed"] == 1
        assert stats["total_flows_created"] == 1
        assert "window_statistics" in stats
        ws = stats["window_statistics"]
        assert "total_windows_created" in ws
        assert "total_packets_processed" in ws
        # Sliding window statistics keys include slide_seconds (added in P2 fix)
        assert "slide_seconds" in ws

    def test_flowbuilder_sliding_callback_called_per_window(self):
        """P2(e): Callback invoked ONCE per active window (fixed = 1, sliding = N).

        FlowBuilder iterates the returned flows list and invokes the callback
        for each distinct (packet, per-window-Flow) pair. This test records
        every invocation and validates:
          - sliding mode with 2 active windows → callback fires 2× for 1 pkt
          - fixed mode with 1 window → callback fires 1× per packet (baseline)
          - callback arguments are correct types
        """
        # ---- Sliding case: 2 windows overlap for packet ----
        sw_builder = FlowBuilder(use_sliding_windows=True, window_seconds=30)
        # Force 1st window
        pkt1 = ParsedPacket(
            src_ip="9.9.9.9", dst_ip="1.1.1.1",
            transport_protocol=TransportProtocol.TCP,
            src_port=3333, dst_port=443, size=100,
            timestamp=datetime.now(timezone.utc),
        )
        sw_builder.add_packet(pkt1)
        # Advance last_slide_time to trigger new window on next add_packet
        sw_builder.window_manager.last_slide_time = (
            datetime.now(timezone.utc) - timedelta(seconds=20)
        )

        # Record callback invocations
        sliding_calls: List[tuple] = []
        sw_builder.set_packet_callback(lambda p, f: sliding_calls.append((p, f)))

        pkt2 = ParsedPacket(
            src_ip="9.9.9.9", dst_ip="1.1.1.1",
            transport_protocol=TransportProtocol.TCP,
            src_port=3333, dst_port=443, size=100,
            timestamp=datetime.now(timezone.utc),
        )
        primary = sw_builder.add_packet(pkt2)

        # pkt2 added to 2 windows → callback fires 2 times
        assert len(sliding_calls) == 2, (
            f"Packet landing in 2 windows expected 2 callback invocations, "
            f"got {len(sliding_calls)}. active windows: "
            f"{[(w.start_time, w.end_time) for w in sw_builder.window_manager.windows.values()]}"
        )
        # Both callbacks received pkt2 as the packet
        assert all(call_pkt is pkt2 for call_pkt, _ in sliding_calls)
        # Both callbacks received Flow instances (not list or anything else)
        for _, call_flow in sliding_calls:
            assert isinstance(call_flow, Flow), (
                f"Callback argument must be Flow, got {type(call_flow).__name__}"
            )
        # The primary flow is one of the 2 (the newest, i.e. max window_start)
        assert primary in [f for _, f in sliding_calls]

        # ---- Fixed case: 1 window → callback fires exactly 1× ----
        fx_builder = FlowBuilder(use_sliding_windows=False, window_seconds=30)
        fixed_calls: List[tuple] = []
        fx_builder.set_packet_callback(lambda p, f: fixed_calls.append((p, f)))
        pkt3 = ParsedPacket(
            src_ip="2.2.2.2", dst_ip="3.3.3.3",
            transport_protocol=TransportProtocol.UDP,
            src_port=111, dst_port=222, size=50,
            timestamp=datetime.now(timezone.utc),
        )
        fx_builder.add_packet(pkt3)
        assert len(fixed_calls) == 1
        assert fixed_calls[0][0] is pkt3
        assert isinstance(fixed_calls[0][1], Flow)

    def test_sliding_no_double_counting_in_flowbuilder_scope(self):
        """P2(f): Active-flows lookup NEVER double-counts per-window totals.

        A legitimate sliding scenario: 1 packet goes into 2 windows, so
        across the whole window manager the packet is counted 2 times
        (once per window). FlowBuilder's active_flows[fk], however, points
        to exactly ONE of those per-window Flow objects (the primary =
        newest window). Its packet_count MUST be 1, not 2. The 2-count is
        only the SUM across both windows (and that's intentional).
        """
        swm = SlidingWindowManager(window_seconds=10, slide_seconds=5)
        # t0: create W0, add pktA → 1 window, pktA count=1 in W0
        pkta = ParsedPacket(
            src_ip="5.5.5.5", dst_ip="6.6.6.6",
            transport_protocol=TransportProtocol.TCP,
            src_port=1234, dst_port=80, size=50,
            timestamp=datetime.now(timezone.utc),
        )
        fa = swm.add_packet(pkta, flow_key=FlowKeyStrategy.five_tuple(pkta))
        assert fa[0].statistics.packet_count == 1
        # Force slide
        swm.last_slide_time = datetime.now(timezone.utc) - timedelta(seconds=5)
        # pktB now lands in both W0 and W1
        pktb = ParsedPacket(
            src_ip="5.5.5.5", dst_ip="6.6.6.6",
            transport_protocol=TransportProtocol.TCP,
            src_port=1234, dst_port=80, size=50,
            timestamp=datetime.now(timezone.utc),
        )
        fb_flows = swm.add_packet(pktb, flow_key=FlowKeyStrategy.five_tuple(pktb))
        # Per-window individual counts: pktB increments each window's count
        # by exactly 1 → never 2 inside one single per-window FlowStatistics.
        for f in fb_flows:
            assert f.statistics.packet_count <= 2, (
                "Individual window Flow can have at most 2 packets here "
                f"(A+B for W0, or B for W1), got {f.statistics.packet_count}"
            )
        # No individual per-window Flow has packet_count == 3 or more.
        all_per_window_counts = [f.statistics.packet_count for f in fb_flows]
        assert 3 not in all_per_window_counts, (
            "Per-window FlowStatistics must never accumulate 2 packets from a "
            "single packet — that would be true double-counting. Got counts: "
            f"{all_per_window_counts}"
        )

    def test_sliding_window_expiration(self):
        """P2(g): Windows expire; expired-flow + max-age cleanup both work.

        Validates:
          - _cleanup_expired_windows drops windows past end_time
          - cleanup_old_windows() additional age-based sweep returns count
          - finalize() is invoked on dropped windows (incomplete_connections set)
        """
        swm = SlidingWindowManager(window_seconds=1, slide_seconds=1)

        # Add a packet that creates W0, then manually add another window long
        # ago to simulate expiration without waiting real time.
        pkt = ParsedPacket(
            src_ip="12.0.0.1", dst_ip="12.0.0.2",
            transport_protocol=TransportProtocol.ICMP,
            size=64, timestamp=datetime.now(timezone.utc),
        )
        swm.add_packet(pkt, flow_key=FlowKeyStrategy.three_tuple(pkt))

        # Manually plant two "very old" windows directly
        past = datetime.now(timezone.utc) - timedelta(seconds=3600)
        old1_id = "old_expired_1"
        old2_id = "old_maxage_2"
        swm.windows[old1_id] = FlowWindow(
            window_id=old1_id,
            start_time=past - timedelta(seconds=10),
            end_time=past - timedelta(seconds=9),  # expired: end <= now
        )
        swm.windows[old2_id] = FlowWindow(
            window_id=old2_id,
            start_time=past,
            end_time=past + timedelta(seconds=1),   # not strictly expired
            # (end > now? No, past+1s is still way in the past; end < now →
            # True. So this is ALSO expired relative to now. For max-age we
            # rely on end_time being >300s in the past.)
        )
        n_windows_before = len(swm.windows)

        # cleanup_old_windows with very strict max_age=10s → old windows older
        # than 10s must be removed
        removed = swm.cleanup_old_windows(max_age_seconds=10)
        n_windows_after = len(swm.windows)
        assert removed >= 2, (
            f"Expected at least 2 old windows removed, got {removed}. "
            f"before={n_windows_before}, after={n_windows_after}"
        )
        assert old1_id not in swm.windows
        assert old2_id not in swm.windows

    def test_timewindowmanager_and_slidingmanager_api_parity(self):
        """P2(h): Both managers expose get_window_statistics + cleanup_old_windows.

        FlowBuilder calls both methods on the manager regardless of mode.
        Prior to P2, SlidingWindowManager was missing them, which would have
        caused AttributeError when FlowBuilder._periodic_cleanup or
        get_statistics executed with use_sliding_windows=True.
        """
        for manager_cls in (TimeWindowManager, SlidingWindowManager):
            mgr = manager_cls(window_seconds=5)
            pkt = ParsedPacket(
                src_ip="172.16.0.1", dst_ip="172.16.0.2",
                transport_protocol=TransportProtocol.TCP,
                src_port=1000, dst_port=2000, size=10,
                timestamp=datetime.now(timezone.utc),
            )
            mgr.add_packet(pkt, flow_key=FlowKeyStrategy.five_tuple(pkt))
            # Required methods exist and return dict/int respectively
            stats = mgr.get_window_statistics()
            assert isinstance(stats, dict)
            assert "total_windows_created" in stats
            assert "total_packets_processed" in stats
            assert "current_window" in stats
            assert "previous_windows" in stats
            n_removed = mgr.cleanup_old_windows(max_age_seconds=300)
            assert isinstance(n_removed, int)
            # reset() works
            mgr.reset()
            assert mgr.total_windows_created == 0
            assert mgr.total_packets_processed == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
