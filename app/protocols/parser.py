"""
Protocol parser for extracting structured information from network packets.

This module demonstrates understanding of:
- Ethernet frame structure
- IP packet headers (IPv4)
- TCP segment structure and flags
- UDP datagram structure
- ICMP message types

The parser extracts security-relevant information without storing payload data.
"""

from typing import Optional, Any
from datetime import datetime, timezone
import logging

from scapy.all import Packet, Ether, IP, TCP, UDP, ICMP, IPv6, ARP
from scapy.fields import FlagsField

from app.models.packet import (
    ParsedPacket,
    Protocol,
    TransportProtocol,
    TCPFlags,
)

logger = logging.getLogger(__name__)


class ProtocolParser:
    """
    Parses network packets and extracts structured protocol information.
    
    This parser handles the core networking protocols that are most relevant
    for security monitoring:
    - Ethernet (Layer 2)
    - IPv4/IPv6 (Layer 3)
    - TCP/UDP/ICMP (Layer 4)
    
    The parser is designed to be:
    1. Safe: Never extracts or stores payload data
    2. Robust: Handles malformed or incomplete packets gracefully
    3. Performant: Minimal overhead for real-time processing
    """
    
    def __init__(self):
        """Initialize the protocol parser."""
        self.parsed_count = 0
        self.error_count = 0
    
    def _extract_packet_timestamp(self, raw_packet: Packet) -> datetime:
        """Extract event timestamp from a raw packet, normalized to UTC."""
        packet_time = getattr(raw_packet, "time", None)
        if packet_time is None:
            return datetime.now(timezone.utc)

        try:
            return datetime.fromtimestamp(float(packet_time), tz=timezone.utc)
        except Exception:
            logger.debug("Raw packet had unusable time attribute; falling back to wall-clock UTC")
            return datetime.now(timezone.utc)

    def parse_packet(self, raw_packet: Packet) -> Optional[ParsedPacket]:
        """
        Parse a raw Scapy packet into a structured ParsedPacket.
        
        Args:
            raw_packet: Scapy Packet object
            
        Returns:
            ParsedPacket with extracted protocol information, or None if parsing fails
        """
        try:
            parsed = ParsedPacket(timestamp=self._extract_packet_timestamp(raw_packet))
            parsed.raw_packet = raw_packet
            
            # Parse Layer 2 - Ethernet
            self._parse_ethernet(raw_packet, parsed)
            
            # Parse Layer 3 - Network
            self._parse_network_layer(raw_packet, parsed)
            
            # Parse Layer 4 - Transport
            self._parse_transport_layer(raw_packet, parsed)
            
            # Set packet size
            parsed.size = len(raw_packet)
            
            self.parsed_count += 1
            return parsed
            
        except Exception as e:
            self.error_count += 1
            logger.debug(f"Failed to parse packet: {e}")
            return None
    
    def _parse_ethernet(self, packet: Packet, parsed: ParsedPacket) -> None:
        """
        Parse Ethernet layer (Layer 2).
        
        Ethernet frame structure:
        - Destination MAC (6 bytes)
        - Source MAC (6 bytes)
        - EtherType (2 bytes) - indicates the next layer protocol
        
        Common EtherTypes:
        - 0x0800: IPv4
        - 0x86DD: IPv6
        - 0x0806: ARP
        - 0x8100: 802.1Q VLAN tag
        """
        if Ether in packet:
            eth_layer = packet[Ether]
            parsed.src_mac = eth_layer.src
            parsed.dst_mac = eth_layer.dst
            parsed.ethertype = eth_layer.type
    
    def _parse_network_layer(self, packet: Packet, parsed: ParsedPacket) -> None:
        """
        Parse network layer (Layer 3) - IP protocols.
        
        IPv4 header structure:
        - Version (4 bits) - Protocol version (4 for IPv4)
        - IHL (4 bits) - Header length in 32-bit words
        - TOS (8 bits) - Type of Service
        - Total Length (16 bits) - Total packet length
        - Identification (16 bits) - Fragment identification
        - Flags (3 bits) - Fragmentation flags
        - Fragment Offset (13 bits) - Fragment position
        - TTL (8 bits) - Time To Live (decremented at each router)
        - Protocol (8 bits) - Next layer protocol (6=TCP, 17=UDP, 1=ICMP)
        - Header Checksum (16 bits)
        - Source IP (32 bits)
        - Destination IP (32 bits)
        
        TTL is important for security - very low TTL can indicate
        traceroute or network mapping attempts.
        """
        if IP in packet:
            ip_layer = packet[IP]
            parsed.network_protocol = Protocol.IPV4
            parsed.src_ip = ip_layer.src or "0.0.0.0"
            parsed.dst_ip = ip_layer.dst or "0.0.0.0"
            parsed.ttl = ip_layer.ttl
            
        elif IPv6 in packet:
            ipv6_layer = packet[IPv6]
            parsed.network_protocol = Protocol.IPV6
            parsed.src_ip = ipv6_layer.src or "::"
            parsed.dst_ip = ipv6_layer.dst or "::"
            parsed.ttl = ipv6_layer.hlim  # Hop Limit is IPv6 equivalent of TTL
            
        elif ARP in packet:
            parsed.network_protocol = Protocol.ARP
            # ARP doesn't have IP addresses in the same sense
            # We could extract the protocol addresses if needed
        else:
            # If no network layer found, set defaults to avoid None
            parsed.network_protocol = Protocol.UNKNOWN
            parsed.src_ip = "0.0.0.0"
            parsed.dst_ip = "0.0.0.0"
    
    def _parse_transport_layer(self, packet: Packet, parsed: ParsedPacket) -> None:
        """
        Parse transport layer (Layer 4) - TCP, UDP, ICMP.
        
        TCP header structure:
        - Source Port (16 bits)
        - Destination Port (16 bits)
        - Sequence Number (32 bits)
        - Acknowledgment Number (32 bits)
        - Data Offset (4 bits) - Header length
        - Reserved (3 bits)
        - Flags (9 bits) - SYN, ACK, FIN, RST, etc.
        - Window Size (16 bits)
        - Checksum (16 bits)
        - Urgent Pointer (16 bits)
        
        TCP Flags are critical for security:
        - SYN: Synchronize - initiates connection
        - ACK: Acknowledgment - confirms receipt
        - FIN: Finish - closes connection
        - RST: Reset - aborts connection
        - PSH: Push - deliver data immediately
        - URG: Urgent - priority data
        
        UDP header structure:
        - Source Port (16 bits)
        - Destination Port (16 bits)
        - Length (16 bits)
        - Checksum (16 bits)
        
        UDP is connectionless and simpler than TCP, making it harder
        to track connection state but still important for security monitoring.
        
        ICMP header structure:
        - Type (8 bits) - Message type
        - Code (8 bits) - Message subtype
        - Checksum (16 bits)
        - Rest of header (variable)
        
        ICMP is used for diagnostics (ping, traceroute) and error reporting.
        Certain ICMP types can indicate network reconnaissance.
        """
        if TCP in packet:
            tcp_layer = packet[TCP]
            parsed.transport_protocol = TransportProtocol.TCP
            parsed.src_port = tcp_layer.sport
            parsed.dst_port = tcp_layer.dport
            parsed.tcp_seq = tcp_layer.seq
            parsed.tcp_ack = tcp_layer.ack
            parsed.tcp_window = tcp_layer.window
            
            # Parse TCP flags
            parsed.tcp_flags = TCPFlags(
                syn=tcp_layer.flags.S,
                ack=tcp_layer.flags.A,
                fin=tcp_layer.flags.F,
                rst=tcp_layer.flags.R,
                psh=tcp_layer.flags.P,
                urg=tcp_layer.flags.U,
                ece=tcp_layer.flags.E,
                cwr=tcp_layer.flags.C,
            )
            
        elif UDP in packet:
            udp_layer = packet[UDP]
            parsed.transport_protocol = TransportProtocol.UDP
            parsed.src_port = udp_layer.sport
            parsed.dst_port = udp_layer.dport
            
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            parsed.transport_protocol = TransportProtocol.ICMP
            parsed.icmp_type = icmp_layer.type
            parsed.icmp_code = icmp_layer.code
    
    def get_statistics(self) -> dict:
        """Get parser statistics."""
        return {
            "parsed_count": self.parsed_count,
            "error_count": self.error_count,
            "error_rate": self.error_count / max(1, self.parsed_count + self.error_count),
        }
    
    def reset_statistics(self) -> None:
        """Reset parser statistics."""
        self.parsed_count = 0
        self.error_count = 0


# Global parser instance
parser = ProtocolParser()
