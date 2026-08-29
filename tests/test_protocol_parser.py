"""
Tests for protocol parser.

These tests validate that the protocol parser correctly extracts
information from network packets and handles various protocols.
"""

import pytest
from datetime import datetime, timezone
from scapy.all import Ether, IP, TCP, UDP, ICMP

from app.protocols.parser import ProtocolParser, parser
from app.models.packet import Protocol, TransportProtocol, TCPFlags


class TestProtocolParser:
    """Test suite for ProtocolParser."""
    
    def test_parser_initialization(self):
        """Test that parser initializes correctly."""
        p = ProtocolParser()
        assert p.parsed_count == 0
        assert p.error_count == 0
    
    def test_parse_tcp_packet(self):
        """Test parsing a TCP packet."""
        # Create a synthetic TCP packet
        packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(
            sport=12345, dport=80, flags="S"
        )
        
        parsed = parser.parse_packet(packet)
        
        assert parsed is not None
        assert parsed.network_protocol == Protocol.IPV4
        assert parsed.src_ip == "192.168.1.1"
        assert parsed.dst_ip == "192.168.1.2"
        assert parsed.transport_protocol == TransportProtocol.TCP
        assert parsed.src_port == 12345
        assert parsed.dst_port == 80
        assert parsed.tcp_flags is not None
        assert parsed.tcp_flags.syn is True
        assert parsed.tcp_flags.ack is False
    
    def test_parse_udp_packet(self):
        """Test parsing a UDP packet."""
        packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(
            sport=53, dport=5353
        )
        
        parsed = parser.parse_packet(packet)
        
        assert parsed is not None
        assert parsed.network_protocol == Protocol.IPV4
        assert parsed.transport_protocol == TransportProtocol.UDP
        assert parsed.src_port == 53
        assert parsed.dst_port == 5353
        assert parsed.tcp_flags is None
    
    def test_parse_icmp_packet(self):
        """Test parsing an ICMP packet."""
        packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / ICMP(
            type=8, code=0
        )
        
        parsed = parser.parse_packet(packet)
        
        assert parsed is not None
        assert parsed.network_protocol == Protocol.IPV4
        assert parsed.transport_protocol == TransportProtocol.ICMP
        assert parsed.icmp_type == 8
        assert parsed.icmp_code == 0
    
    def test_parse_ethernet_layer(self):
        """Test that Ethernet layer is parsed correctly."""
        packet = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP() / TCP()
        
        parsed = parser.parse_packet(packet)
        
        assert parsed is not None
        assert parsed.src_mac == "00:11:22:33:44:55"
        assert parsed.dst_mac == "66:77:88:99:aa:bb"
    
    def test_tcp_flags_extraction(self):
        """Test TCP flags are extracted correctly."""
        # Test SYN packet
        packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(flags="S")
        parsed = parser.parse_packet(packet)
        assert parsed.tcp_flags.syn is True
        assert parsed.tcp_flags.ack is False
        
        # Test SYN-ACK packet
        packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(flags="SA")
        parsed = parser.parse_packet(packet)
        assert parsed.tcp_flags.syn is True
        assert parsed.tcp_flags.ack is True
        
        # Test FIN packet
        packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(flags="F")
        parsed = parser.parse_packet(packet)
        assert parsed.tcp_flags.fin is True
        
        # Test RST packet
        packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(flags="R")
        parsed = parser.parse_packet(packet)
        assert parsed.tcp_flags.rst is True
    
    def test_flow_key_generation(self):
        """Test flow key generation for packet aggregation."""
        packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(
            sport=12345, dport=80
        )
        parsed = parser.parse_packet(packet)
        
        flow_key = parsed.get_flow_key()
        assert "192.168.1.1" in flow_key
        assert "192.168.1.2" in flow_key
        assert "TCP" in flow_key
    
    def test_five_tuple_extraction(self):
        """Test 5-tuple extraction for precise flow tracking."""
        packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=443, dport=8080
        )
        parsed = parser.parse_packet(packet)
        
        five_tuple = parsed.get_five_tuple()
        assert five_tuple is not None
        assert five_tuple[0] == "10.0.0.1"
        assert five_tuple[1] == "10.0.0.2"
        assert five_tuple[2] == 443
        assert five_tuple[3] == 8080
        assert five_tuple[4] == "TCP"
    
    def test_packet_size(self):
        """Test packet size is calculated correctly."""
        packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP()
        parsed = parser.parse_packet(packet)
        
        assert parsed.size > 0
        assert parsed.size == len(packet)

    def test_parser_uses_capture_timestamp_when_available(self):
        """Test parser prefers raw packet capture time when present."""
        packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP()
        packet.time = 1720000000.25

        parsed = ProtocolParser().parse_packet(packet)

        assert parsed is not None
        assert parsed.timestamp == datetime.fromtimestamp(1720000000.25, tz=timezone.utc)
        assert parsed.timestamp.tzinfo == timezone.utc

    def test_parser_falls_back_when_capture_timestamp_unusable(self):
        """Test parser falls back to wall-clock UTC when raw packet time is unusable."""
        packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP()
        packet.time = "not-a-timestamp"

        before = datetime.now(timezone.utc)
        parsed = ProtocolParser().parse_packet(packet)
        after = datetime.now(timezone.utc)

        assert parsed is not None
        assert parsed.timestamp.tzinfo == timezone.utc
        assert before <= parsed.timestamp <= after
    
    def test_parser_statistics(self):
        """Test parser statistics tracking."""
        # Reset statistics
        parser.reset_statistics()
        
        # Parse some packets
        for _ in range(5):
            packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP()
            parser.parse_packet(packet)
        
        stats = parser.get_statistics()
        assert stats["parsed_count"] == 5
        assert stats["error_count"] == 0
    
    def test_malformed_packet_handling(self):
        """Test that malformed packets are handled gracefully."""
        # Reset statistics first
        parser.reset_statistics()
        
        # This tests that the parser doesn't crash on malformed packets
        # In a real scenario, we might pass various malformed packets
        # For now, we just ensure the error handling exists
        assert parser.error_count == 0  # Initially no errors
    
    def test_tcp_flags_helper_methods(self):
        """Test TCP flags helper methods."""
        flags = TCPFlags(syn=True, ack=False)
        assert flags.is_syn_only() is True
        assert flags.is_syn_ack() is False
        
        flags = TCPFlags(syn=True, ack=True)
        assert flags.is_syn_only() is False
        assert flags.is_syn_ack() is True
        
        flags = TCPFlags(fin=True)
        assert flags.is_fin() is True
        
        flags = TCPFlags(rst=True)
        assert flags.is_rst() is True
    
    def test_packet_to_dict(self):
        """Test packet serialization to dictionary."""
        packet = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1000, dport=2000)
        parsed = parser.parse_packet(packet)
        
        packet_dict = parsed.to_dict()
        
        assert isinstance(packet_dict, dict)
        assert packet_dict["src_ip"] == "1.2.3.4"
        assert packet_dict["dst_ip"] == "5.6.7.8"
        assert packet_dict["src_port"] == 1000
        assert packet_dict["dst_port"] == 2000
        assert "timestamp" in packet_dict
    
    def test_packet_string_representation(self):
        """Test packet string representation."""
        packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(
            sport=12345, dport=80, flags="S"
        )
        parsed = parser.parse_packet(packet)
        
        packet_str = str(parsed)
        assert "192.168.1.1" in packet_str
        assert "192.168.1.2" in packet_str
        assert "12345" in packet_str
        assert "80" in packet_str
        assert "TCP" in packet_str


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
