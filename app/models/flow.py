"""
Flow data models for AEGIS.

Flow models represent aggregated network traffic between endpoints over time windows.
This is where individual packets are transformed into meaningful behavior patterns.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Any
from collections import defaultdict
import time

from app.models.packet import ParsedPacket, TCPFlags


@dataclass(frozen=True)
class FlowKey:
    """
    Immutable key for identifying flows.
    
    A flow key uniquely identifies a conversation between two endpoints.
    Different flow key strategies provide different levels of granularity:
    
    - 5-tuple: Most precise (src_ip, dst_ip, src_port, dst_port, protocol)
    - 3-tuple: Broader (src_ip, dst_ip, protocol)
    - Bidirectional: Normalized for conversation tracking
    """
    
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    

    def __hash__(self):
        """Make FlowKey hashable for use as dictionary keys."""
        return hash((
            self.src_ip, self.dst_ip, self.protocol,
            self.src_port, self.dst_port
        ))
    
    def __eq__(self, other):
        """Compare flow keys."""
        if not isinstance(other, FlowKey):
            return False
        return (
            self.src_ip == other.src_ip and
            self.dst_ip == other.dst_ip and
            self.protocol == other.protocol and
            self.src_port == other.src_port and
            self.dst_port == other.dst_port
        )
    
    def __str__(self):
        """String representation of flow key."""
        if self.src_port and self.dst_port:
            return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} {self.protocol}"
        else:
            return f"{self.src_ip} -> {self.dst_ip} {self.protocol}"
    
    def to_tuple(self) -> tuple:
        """Convert to tuple for serialization."""
        return (
            self.src_ip, self.dst_ip, self.protocol,
            self.src_port, self.dst_port
        )
    
    @classmethod
    def from_packet(cls, packet: ParsedPacket, use_ports: bool = True) -> "FlowKey":
        """Create a plain directional FlowKey from a packet.

        This helper is intentionally strategy-agnostic. Richer flow identity
        semantics belong in app.flows.flow_key.FlowKeyStrategy.
        """
        if use_ports and packet.src_port and packet.dst_port:
            return cls(
                src_ip=packet.src_ip or "0.0.0.0",
                dst_ip=packet.dst_ip or "0.0.0.0",
                protocol=packet.transport_protocol.value,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
            )
        return cls(
            src_ip=packet.src_ip or "0.0.0.0",
            dst_ip=packet.dst_ip or "0.0.0.0",
            protocol=packet.transport_protocol.value,
        )


@dataclass
class FlowStatistics:
    """
    Aggregated statistics for a flow.
    
    These statistics are computed from packets within a time window
    and form the basis for feature extraction and detection.
    """
    
    # Basic counts
    packet_count: int = 0
    byte_count: int = 0
    
    # Directional counts (bytes sent/received from flow key perspective)
    bytes_sent: int = 0
    bytes_received: int = 0
    
    # Protocol-specific counts
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    
    # Connection tracking
    connection_attempts: int = 0
    successful_connections: int = 0
    failed_connections: int = 0
    incomplete_connections: int = 0
    
    # Diversity metrics
    unique_destination_ports: Set[int] = field(default_factory=set)
    unique_destination_ips: Set[str] = field(default_factory=set)
    
    # Timing
    first_packet_time: Optional[datetime] = None
    last_packet_time: Optional[datetime] = None
    
    # Packet size statistics
    min_packet_size: int = float('inf')
    max_packet_size: int = 0
    total_packet_size: int = 0
    
    def add_packet(self, packet: ParsedPacket, is_src_to_dst: bool = True) -> None:
        """
        Add a packet to the flow statistics.
        
        Args:
            packet: Parsed packet to add
            is_src_to_dst: Whether packet is in src->dst direction (from flow key perspective)
        """
        self.packet_count += 1
        packet_size = packet.size
        self.byte_count += packet_size
        self.total_packet_size += packet_size
        
        # Update directional byte counts
        if is_src_to_dst:
            self.bytes_sent += packet_size
        else:
            self.bytes_received += packet_size
        
        # Update packet size statistics
        self.min_packet_size = min(self.min_packet_size, packet_size)
        self.max_packet_size = max(self.max_packet_size, packet_size)
        
        # Update timing from event time, not insertion order
        if self.first_packet_time is None or packet.timestamp < self.first_packet_time:
            self.first_packet_time = packet.timestamp
        if self.last_packet_time is None or packet.timestamp > self.last_packet_time:
            self.last_packet_time = packet.timestamp
        
        # Protocol-specific counting
        if packet.tcp_flags:
            if packet.tcp_flags.syn:
                self.syn_count += 1
                # SYN without ACK is a connection attempt
                if not packet.tcp_flags.ack:
                    self.connection_attempts += 1
            if packet.tcp_flags.ack:
                self.ack_count += 1
            if packet.tcp_flags.fin:
                self.fin_count += 1
                self.successful_connections += 1
            if packet.tcp_flags.rst:
                self.rst_count += 1
                self.failed_connections += 1
            if packet.tcp_flags.psh:
                self.psh_count += 1
        
        # Track unique destination ports (for port scan detection)
        if packet.dst_port:
            self.unique_destination_ports.add(packet.dst_port)
        
        # Track unique destination IPs
        if packet.dst_ip:
            self.unique_destination_ips.add(packet.dst_ip)
    
    def finalize(self) -> None:
        """
        Finalize flow statistics after time window closes.
        
        Calculates derived statistics and handles edge cases.
        """
        # Calculate incomplete connections (SYN without corresponding completion)
        # This is approximate - in a real system, you'd track connection state more carefully
        self.incomplete_connections = max(0, self.connection_attempts - self.successful_connections)
        
        # Handle case where no packets were received
        if self.min_packet_size == float('inf'):
            self.min_packet_size = 0
    
    def get_duration_seconds(self) -> float:
        """Get flow duration in seconds."""
        if self.first_packet_time and self.last_packet_time:
            return (self.last_packet_time - self.first_packet_time).total_seconds()
        return 0.0
    
    def get_average_packet_size(self) -> float:
        """Get average packet size."""
        if self.packet_count > 0:
            return self.total_packet_size / self.packet_count
        return 0.0
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "psh_count": self.psh_count,
            "connection_attempts": self.connection_attempts,
            "successful_connections": self.successful_connections,
            "failed_connections": self.failed_connections,
            "incomplete_connections": self.incomplete_connections,
            "unique_destination_ports": len(self.unique_destination_ports),
            "unique_destination_ips": len(self.unique_destination_ips),
            "duration_seconds": self.get_duration_seconds(),
            "average_packet_size": self.get_average_packet_size(),
            "min_packet_size": self.min_packet_size if self.min_packet_size != float('inf') else 0,
            "max_packet_size": self.max_packet_size,
        }


@dataclass
class Flow:
    """
    Complete flow representation with metadata and statistics.
    
    A flow represents network traffic between two endpoints over a specific
    time window, with aggregated statistics ready for feature extraction.
    """
    
    # Flow identification
    flow_key: FlowKey
    
    # Time window
    window_start: datetime
    window_end: datetime
    
    # Aggregated statistics
    statistics: FlowStatistics = field(default_factory=FlowStatistics)
    
    # Flow metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def add_packet(self, packet: ParsedPacket) -> None:
        """
        Add a packet to the flow.
        
        Args:
            packet: Parsed packet to add
        """
        # Determine direction based on flow key
        is_src_to_dst = (
            packet.src_ip == self.flow_key.src_ip and
            packet.dst_ip == self.flow_key.dst_ip
        )
        
        # For port-based flows, also check ports
        if self.flow_key.src_port and self.flow_key.dst_port:
            is_src_to_dst = (
                is_src_to_dst and
                packet.src_port == self.flow_key.src_port and
                packet.dst_port == self.flow_key.dst_port
            )
        
        self.statistics.add_packet(packet, is_src_to_dst)
    
    def finalize(self) -> None:
        """Finalize the flow and calculate derived statistics."""
        self.statistics.finalize()
    
    def get_duration_seconds(self) -> float:
        """Get flow duration in seconds."""
        return self.statistics.get_duration_seconds()
    
    def is_expired(self, current_time: datetime, timeout_seconds: int) -> bool:
        """
        Check if flow is expired based on timeout.
        
        Args:
            current_time: Current timestamp
            timeout_seconds: Timeout in seconds
            
        Returns:
            True if flow is expired
        """
        if self.statistics.last_packet_time:
            age = (current_time - self.statistics.last_packet_time).total_seconds()
            return age > timeout_seconds
        return True
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "flow_key": str(self.flow_key),
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "statistics": self.statistics.to_dict(),
            "created_at": self.created_at.isoformat(),
        }
    
    def __str__(self) -> str:
        """String representation of flow."""
        return (
            f"Flow({self.flow_key}, "
            f"packets={self.statistics.packet_count}, "
            f"bytes={self.statistics.byte_count}, "
            f"duration={self.get_duration_seconds():.2f}s)"
        )


@dataclass(frozen=True)
class FeatureObservation:
    """Immutable finalized feature observation for a per-window flow."""

    flow_key: FlowKey
    window_start: datetime
    window_end: datetime
    features: Dict[str, Any]
    finalized: bool
    sliding: bool


@dataclass
class FlowWindow:
    """
    A time window for flow aggregation.
    
    Flows are aggregated within fixed time windows to enable
    time-series analysis and rate-based detection.
    """
    
    window_id: str
    start_time: datetime
    end_time: datetime
    flows: Dict[FlowKey, Flow] = field(default_factory=dict)
    
    def add_packet(self, packet: ParsedPacket, flow_key: FlowKey) -> Flow:
        """Add a packet to the provided flow identity in this window."""
        if flow_key not in self.flows:
            self.flows[flow_key] = Flow(
                flow_key=flow_key,
                window_start=self.start_time,
                window_end=self.end_time,
            )

        self.flows[flow_key].add_packet(packet)
        return self.flows[flow_key]
    
    def finalize(self) -> None:
        """Finalize all flows in this window."""
        for flow in self.flows.values():
            flow.finalize()
    
    def get_flow_count(self) -> int:
        """Get number of flows in this window."""
        return len(self.flows)
    
    def get_total_packets(self) -> int:
        """Get total packets across all flows."""
        return sum(flow.statistics.packet_count for flow in self.flows.values())
    
    def get_total_bytes(self) -> int:
        """Get total bytes across all flows."""
        return sum(flow.statistics.byte_count for flow in self.flows.values())
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "window_id": self.window_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "flow_count": self.get_flow_count(),
            "total_packets": self.get_total_packets(),
            "total_bytes": self.get_total_bytes(),
            "flows": {str(k): v.to_dict() for k, v in self.flows.items()},
        }
