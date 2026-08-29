"""
Packet data models representing structured network packet information.

These models represent the data extracted from raw packets after parsing.
They demonstrate understanding of protocol headers and networking concepts.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from enum import Enum


class Protocol(Enum):
    """Network layer protocols."""
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    ARP = "ARP"
    ICMP = "ICMP"
    UNKNOWN = "UNKNOWN"


class TransportProtocol(Enum):
    """Transport layer protocols."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    UNKNOWN = "UNKNOWN"


@dataclass
class TCPFlags:
    """
    TCP flag bits extracted from TCP header.
    
    Understanding TCP flags is fundamental to network security:
    - SYN: Synchronize, initiates connection
    - ACK: Acknowledgment, confirms receipt
    - FIN: Finish, closes connection
    - RST: Reset, aborts connection
    - PSH: Push, deliver data to application immediately
    - URG: Urgent, priority data
    - ECE: ECN-Echo, congestion notification
    - CWR: Congestion Window Reduced
    """
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False
    urg: bool = False
    ece: bool = False
    cwr: bool = False
    
    def is_syn_only(self) -> bool:
        """Check if this is a SYN-only packet (connection initiation)."""
        return self.syn and not (self.ack or self.fin or self.rst)
    
    def is_syn_ack(self) -> bool:
        """Check if this is a SYN-ACK packet (connection response)."""
        return self.syn and self.ack and not (self.fin or self.rst)
    
    def is_ack_only(self) -> bool:
        """Check if this is an ACK-only packet (data acknowledgment)."""
        return self.ack and not (self.syn or self.fin or self.rst)
    
    def is_fin(self) -> bool:
        """Check if this is a FIN packet (connection termination)."""
        return self.fin
    
    def is_rst(self) -> bool:
        """Check if this is a RST packet (connection reset)."""
        return self.rst
    
    def to_dict(self) -> Dict[str, bool]:
        """Convert to dictionary for serialization."""
        return {
            "syn": self.syn,
            "ack": self.ack,
            "fin": self.fin,
            "rst": self.rst,
            "psh": self.psh,
            "urg": self.urg,
            "ece": self.ece,
            "cwr": self.cwr,
        }


@dataclass
class ParsedPacket:
    """
    Structured representation of a parsed network packet.
    
    This model demonstrates understanding of:
    - Layer 2 (Ethernet): MAC addresses
    - Layer 3 (IP): Source/destination IPs, protocol
    - Layer 4 (TCP/UDP): Ports, flags for TCP
    - Packet metadata: Size, timestamp
    
    The packet captures the essential information needed for security analysis
    without storing sensitive payload data.
    """
    
    # Layer 2 - Ethernet
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    ethertype: Optional[int] = None
    
    # Layer 3 - Network
    network_protocol: Protocol = Protocol.UNKNOWN
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: Optional[int] = None
    
    # Layer 4 - Transport
    transport_protocol: TransportProtocol = TransportProtocol.UNKNOWN
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    
    # TCP-specific
    tcp_flags: Optional[TCPFlags] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_window: Optional[int] = None
    
    # ICMP-specific
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    
    # Packet metadata
    size: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Raw packet reference (for debugging, not stored)
    raw_packet: Optional[Any] = None
    
    def is_tcp(self) -> bool:
        """Check if this is a TCP packet."""
        return self.transport_protocol == TransportProtocol.TCP
    
    def is_udp(self) -> bool:
        """Check if this is a UDP packet."""
        return self.transport_protocol == TransportProtocol.UDP
    
    def is_icmp(self) -> bool:
        """Check if this is an ICMP packet."""
        return self.transport_protocol == TransportProtocol.ICMP
    
    def is_ipv4(self) -> bool:
        """Check if this is an IPv4 packet."""
        return self.network_protocol == Protocol.IPV4
    
    def is_ipv6(self) -> bool:
        """Check if this is an IPv6 packet."""
        return self.network_protocol == Protocol.IPV6
    
    def get_flow_key(self) -> str:
        """
        Generate a legacy directional packet key string.

        This helper is retained for compatibility with older code paths and is
        intentionally simpler than the configurable FlowKeyStrategy-based flow
        identity used by FlowBuilder.
        """
        if not self.src_ip or not self.dst_ip:
            return f"unknown_{self.timestamp.timestamp()}"

        return f"{self.src_ip}_{self.dst_ip}_{self.transport_protocol.value}"
    
    def get_five_tuple(self) -> Optional[tuple]:
        """
        Get the 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol).
        
        The 5-tuple uniquely identifies a connection in TCP/IP networking.
        Used for precise flow tracking when port-level granularity is needed.
        """
        if not all([self.src_ip, self.dst_ip, self.src_port, self.dst_port]):
            return None
        
        return (
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.transport_protocol.value
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "ethertype": self.ethertype,
            "network_protocol": self.network_protocol.value,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ttl": self.ttl,
            "transport_protocol": self.transport_protocol.value,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": self.tcp_flags.to_dict() if self.tcp_flags else None,
            "tcp_seq": self.tcp_seq,
            "tcp_ack": self.tcp_ack,
            "tcp_window": self.tcp_window,
            "icmp_type": self.icmp_type,
            "icmp_code": self.icmp_code,
            "size": self.size,
            "timestamp": self.timestamp.isoformat(),
        }
    
    def __str__(self) -> str:
        """Human-readable string representation."""
        proto = self.transport_protocol.value
        if self.is_tcp():
            return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} {proto} {self.tcp_flags}"
        elif self.is_udp():
            return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} {proto}"
        else:
            return f"{self.src_ip} -> {self.dst_ip} {proto}"
