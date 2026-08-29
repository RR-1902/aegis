"""
Flow key definitions and management for AEGIS.

This module provides different flow key strategies for various levels
of aggregation granularity.
"""

from typing import Optional, Tuple
import ipaddress
from app.models.packet import ParsedPacket
from app.models.flow import FlowKey


class FlowKeyStrategy:
    """Strategy pattern for supported flow key generation methods."""

    @staticmethod
    def _ip_sort_key(ip: str) -> tuple:
        """Return an IP-aware deterministic sort key for IPv4/IPv6 addresses."""
        addr = ipaddress.ip_address(ip)
        return (addr.version, int(addr))

    @staticmethod
    def _canonicalize_endpoints(packet: ParsedPacket) -> Optional[tuple[tuple[str, int], tuple[str, int], str]]:
        """Canonicalize two (ip, port) endpoints for bidirectional identity."""
        if not all([packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port]):
            return None

        left = (packet.src_ip, packet.src_port)
        right = (packet.dst_ip, packet.dst_port)
        left_key = (FlowKeyStrategy._ip_sort_key(left[0]), left[1])
        right_key = (FlowKeyStrategy._ip_sort_key(right[0]), right[1])
        if left_key <= right_key:
            first, second = left, right
        else:
            first, second = right, left
        return first, second, packet.transport_protocol.value
    
    @staticmethod
    def five_tuple(packet: ParsedPacket) -> Optional[FlowKey]:
        """
        Generate a 5-tuple flow key (most precise).
        
        5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
        
        This provides the finest granularity and is useful for:
        - Precise connection tracking
        - Per-service analysis
        - Stateful firewall rules
        
        Args:
            packet: Parsed packet
            
        Returns:
            FlowKey or None if insufficient information
        """
        if not all([packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port]):
            return None
        
        return FlowKey(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            protocol=packet.transport_protocol.value,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
        )
    
    @staticmethod
    def three_tuple(packet: ParsedPacket) -> Optional[FlowKey]:
        """
        Generate a 3-tuple flow key (protocol-level aggregation).
        
        3-tuple: (src_ip, dst_ip, protocol)
        
        This provides broader aggregation and is useful for:
        - Host-to-host communication analysis
        - Protocol-level behavior analysis
        - Reducing flow table size
        
        Args:
            packet: Parsed packet
            
        Returns:
            FlowKey or None if insufficient information
        """
        if not all([packet.src_ip, packet.dst_ip]):
            return None
        
        return FlowKey(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            protocol=packet.transport_protocol.value,
        )
    
    @staticmethod
    def bidirectional(packet: ParsedPacket) -> Optional[FlowKey]:
        """
        Generate a bidirectional 5-tuple flow key.
        
        This normalizes the flow key so that traffic in both directions
        between the same endpoints is aggregated together.
        
        Useful for:
        - Conversation analysis
        - Total bandwidth measurement
        - Bidirectional session tracking
        
        Args:
            packet: Parsed packet
            
        Returns:
            FlowKey or None if insufficient information
        """
        canonical = FlowKeyStrategy._canonicalize_endpoints(packet)
        if canonical is None:
            return None

        (src_ip, src_port), (dst_ip, dst_port), protocol = canonical
        return FlowKey(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
        )


class FlowKeyManager:
    """
    Manages flow key generation with configurable strategy.
    
    This allows the system to switch between different aggregation
    granularities based on analysis needs.
    """
    
    def __init__(self, strategy: str = "five_tuple"):
        """
        Initialize flow key manager.
        
        Args:
            strategy: Flow key strategy to use
                - "five_tuple": Most precise (default)
                - "three_tuple": Protocol-level
                - "bidirectional": Direction-independent conversation-level
        """
        self.strategy = strategy
        self.strategy_map = {
            "five_tuple": FlowKeyStrategy.five_tuple,
            "three_tuple": FlowKeyStrategy.three_tuple,
            "bidirectional": FlowKeyStrategy.bidirectional,
        }
        
        if strategy not in self.strategy_map:
            raise ValueError(f"Unknown flow key strategy: {strategy}")
    
    def generate_key(self, packet: ParsedPacket) -> Optional[FlowKey]:
        """
        Generate a flow key using the configured strategy.
        
        Args:
            packet: Parsed packet
            
        Returns:
            FlowKey or None if insufficient information
        """
        strategy_func = self.strategy_map[self.strategy]
        return strategy_func(packet)
    
    def set_strategy(self, strategy: str) -> None:
        """
        Change the flow key strategy.
        
        Args:
            strategy: New strategy to use
        """
        if strategy not in self.strategy_map:
            raise ValueError(f"Unknown flow key strategy: {strategy}")
        self.strategy = strategy
    
    def get_strategy(self) -> str:
        """Get current strategy."""
        return self.strategy
