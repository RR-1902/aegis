"""
Feature definitions and catalog for AEGIS.

This module defines the complete set of features that can be extracted
from network flows for security analysis and detection.
"""

from dataclasses import dataclass
from typing import Dict, List, Any, Optional
from enum import Enum


class FeatureCategory(Enum):
    """Categories of features for organization and analysis."""
    
    COUNT = "count"                    # Simple count features
    RATE = "rate"                      # Rate-based features (per second)
    RATIO = "ratio"                    # Ratio/proportion features
    DIVERSITY = "diversity"            # Diversity/uniqueness features
    TEMPORAL = "temporal"              # Time-based features
    PROTOCOL = "protocol"              # Protocol-specific features
    CONNECTION = "connection"          # Connection state features
    SIZE = "size"                      # Packet/byte size features


@dataclass
class FeatureDefinition:
    """
    Definition of a single feature.
    
    Each feature has:
    - A unique name
    - A category for organization
    - A description of what it measures
    - Security relevance explanation
    - Data type
    - Normalization hints
    """
    
    name: str
    category: FeatureCategory
    description: str
    security_relevance: str
    data_type: type
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    normalize: bool = False  # Whether to normalize this feature for ML
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "security_relevance": self.security_relevance,
            "data_type": self.data_type.__name__,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "normalize": self.normalize,
        }


class FeatureCatalog:
    """
    Catalog of all available features.
    
    This catalog provides a comprehensive list of features that can be
    extracted from network flows, organized by category.
    """
    
    # Count Features
    PACKET_COUNT = FeatureDefinition(
        name="packet_count",
        category=FeatureCategory.COUNT,
        description="Total number of packets in the flow",
        security_relevance="High packet counts may indicate scanning, flooding, or data exfiltration",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    BYTE_COUNT = FeatureDefinition(
        name="byte_count",
        category=FeatureCategory.COUNT,
        description="Total number of bytes in the flow",
        security_relevance="High byte counts may indicate data exfiltration or DDoS attacks",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    SYN_COUNT = FeatureDefinition(
        name="syn_count",
        category=FeatureCategory.PROTOCOL,
        description="Number of TCP SYN packets",
        security_relevance="High SYN counts may indicate port scanning or SYN flood attacks",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    ACK_COUNT = FeatureDefinition(
        name="ack_count",
        category=FeatureCategory.PROTOCOL,
        description="Number of TCP ACK packets",
        security_relevance="ACK packet patterns can reveal connection behavior and potential scanning",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    FIN_COUNT = FeatureDefinition(
        name="fin_count",
        category=FeatureCategory.PROTOCOL,
        description="Number of TCP FIN packets",
        security_relevance="FIN patterns indicate connection termination behavior",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    RST_COUNT = FeatureDefinition(
        name="rst_count",
        category=FeatureCategory.PROTOCOL,
        description="Number of TCP RST packets",
        security_relevance="High RST counts may indicate connection rejection, scanning, or attacks",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    PSH_COUNT = FeatureDefinition(
        name="psh_count",
        category=FeatureCategory.PROTOCOL,
        description="Number of TCP PSH packets",
        security_relevance="PSH patterns can reveal data transfer timing and behavior",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    # Connection Features
    CONNECTION_ATTEMPTS = FeatureDefinition(
        name="connection_attempts",
        category=FeatureCategory.CONNECTION,
        description="Number of connection attempts (SYN without ACK)",
        security_relevance="High connection attempts may indicate port scanning or brute force attacks",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    SUCCESSFUL_CONNECTIONS = FeatureDefinition(
        name="successful_connections",
        category=FeatureCategory.CONNECTION,
        description="Number of successfully completed connections",
        security_relevance="Low success rates may indicate scanning or failed attacks",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    FAILED_CONNECTIONS = FeatureDefinition(
        name="failed_connections",
        category=FeatureCategory.CONNECTION,
        description="Number of failed connections (RST)",
        security_relevance="High failure rates may indicate scanning or blocked attacks",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    INCOMPLETE_CONNECTIONS = FeatureDefinition(
        name="incomplete_connections",
        category=FeatureCategory.CONNECTION,
        description="Number of incomplete connections (SYN without completion)",
        security_relevance="High incomplete connections are a strong indicator of SYN flood attacks",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    # Diversity Features
    UNIQUE_DST_PORTS = FeatureDefinition(
        name="unique_destination_ports",
        category=FeatureCategory.DIVERSITY,
        description="Number of unique destination ports contacted",
        security_relevance="High unique port counts are a strong indicator of port scanning",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    UNIQUE_DST_IPS = FeatureDefinition(
        name="unique_destination_ips",
        category=FeatureCategory.DIVERSITY,
        description="Number of unique destination IPs contacted",
        security_relevance="High unique IP counts may indicate scanning or worm propagation",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    # Rate Features
    PACKETS_PER_SECOND = FeatureDefinition(
        name="packets_per_second",
        category=FeatureCategory.RATE,
        description="Average packet rate (packets/second)",
        security_relevance="High packet rates may indicate flooding attacks or scanning",
        data_type=float,
        min_value=0,
        normalize=True,
    )
    
    BYTES_PER_SECOND = FeatureDefinition(
        name="bytes_per_second",
        category=FeatureCategory.RATE,
        description="Average byte rate (bytes/second)",
        security_relevance="High byte rates may indicate data exfiltration or DDoS attacks",
        data_type=float,
        min_value=0,
        normalize=True,
    )
    
    SYN_RATE = FeatureDefinition(
        name="syn_rate",
        category=FeatureCategory.RATE,
        description="SYN packet rate (SYN packets/second)",
        security_relevance="High SYN rates are a strong indicator of SYN flood attacks",
        data_type=float,
        min_value=0,
        normalize=True,
    )
    
    CONNECTION_RATE = FeatureDefinition(
        name="connection_rate",
        category=FeatureCategory.RATE,
        description="Connection attempt rate (attempts/second)",
        security_relevance="High connection rates may indicate brute force attacks or scanning",
        data_type=float,
        min_value=0,
        normalize=True,
    )
    
    # Ratio Features
    SYN_TO_TOTAL_RATIO = FeatureDefinition(
        name="syn_to_total_ratio",
        category=FeatureCategory.RATIO,
        description="Ratio of SYN packets to total packets",
        security_relevance="High SYN ratios may indicate scanning or SYN flood attacks",
        data_type=float,
        min_value=0,
        max_value=1,
        normalize=False,  # Already normalized
    )
    
    INCOMPLETE_CONNECTION_RATIO = FeatureDefinition(
        name="incomplete_connection_ratio",
        category=FeatureCategory.RATIO,
        description="Ratio of incomplete connections to total connection attempts",
        security_relevance="High incomplete ratios are a strong indicator of SYN flood attacks",
        data_type=float,
        min_value=0,
        max_value=1,
        normalize=False,  # Already normalized
    )
    
    SUCCESSFUL_CONNECTION_RATIO = FeatureDefinition(
        name="successful_connection_ratio",
        category=FeatureCategory.RATIO,
        description="Ratio of successful connections to total connection attempts",
        security_relevance="Low success ratios may indicate scanning or blocked attacks",
        data_type=float,
        min_value=0,
        max_value=1,
        normalize=False,  # Already normalized
    )
    
    RST_TO_TOTAL_RATIO = FeatureDefinition(
        name="rst_to_total_ratio",
        category=FeatureCategory.RATIO,
        description="Ratio of RST packets to total packets",
        security_relevance="High RST ratios may indicate connection rejection or scanning",
        data_type=float,
        min_value=0,
        max_value=1,
        normalize=False,  # Already normalized
    )
    
    # Temporal Features
    DURATION_SECONDS = FeatureDefinition(
        name="duration_seconds",
        category=FeatureCategory.TEMPORAL,
        description="Flow duration in seconds",
        security_relevance="Unusual durations may indicate long-lived attacks or beaconing",
        data_type=float,
        min_value=0,
        normalize=True,
    )
    
    # Size Features
    AVERAGE_PACKET_SIZE = FeatureDefinition(
        name="average_packet_size",
        category=FeatureCategory.SIZE,
        description="Average packet size in bytes",
        security_relevance="Unusual packet sizes may indicate tunneling or data exfiltration",
        data_type=float,
        min_value=0,
        normalize=True,
    )
    
    MIN_PACKET_SIZE = FeatureDefinition(
        name="min_packet_size",
        category=FeatureCategory.SIZE,
        description="Minimum packet size in bytes",
        security_relevance="Very small packets may indicate scanning or keep-alive traffic",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    MAX_PACKET_SIZE = FeatureDefinition(
        name="max_packet_size",
        category=FeatureCategory.SIZE,
        description="Maximum packet size in bytes",
        security_relevance="Very large packets may indicate data exfiltration or amplification attacks",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    # Directional Features
    BYTES_SENT = FeatureDefinition(
        name="bytes_sent",
        category=FeatureCategory.COUNT,
        description="Bytes sent from source to destination",
        security_relevance="Asymmetric byte ratios may indicate data exfiltration",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    BYTES_RECEIVED = FeatureDefinition(
        name="bytes_received",
        category=FeatureCategory.COUNT,
        description="Bytes received from destination to source",
        security_relevance="Asymmetric byte ratios may indicate data exfiltration",
        data_type=int,
        min_value=0,
        normalize=True,
    )
    
    BYTES_RATIO = FeatureDefinition(
        name="bytes_ratio",
        category=FeatureCategory.RATIO,
        description="Ratio of bytes sent to bytes received",
        security_relevance="Extreme ratios may indicate data exfiltration or one-sided attacks",
        data_type=float,
        min_value=0,
        normalize=False,  # Already normalized to [0,1] or can be >1
    )
    
    @classmethod
    def get_all_features(cls) -> List[FeatureDefinition]:
        """Get all feature definitions."""
        return [
            cls.PACKET_COUNT, cls.BYTE_COUNT,
            cls.SYN_COUNT, cls.ACK_COUNT, cls.FIN_COUNT, cls.RST_COUNT, cls.PSH_COUNT,
            cls.CONNECTION_ATTEMPTS, cls.SUCCESSFUL_CONNECTIONS, cls.FAILED_CONNECTIONS, cls.INCOMPLETE_CONNECTIONS,
            cls.UNIQUE_DST_PORTS, cls.UNIQUE_DST_IPS,
            cls.PACKETS_PER_SECOND, cls.BYTES_PER_SECOND, cls.SYN_RATE, cls.CONNECTION_RATE,
            cls.SYN_TO_TOTAL_RATIO, cls.INCOMPLETE_CONNECTION_RATIO, cls.SUCCESSFUL_CONNECTION_RATIO, cls.RST_TO_TOTAL_RATIO,
            cls.DURATION_SECONDS,
            cls.AVERAGE_PACKET_SIZE, cls.MIN_PACKET_SIZE, cls.MAX_PACKET_SIZE,
            cls.BYTES_SENT, cls.BYTES_RECEIVED, cls.BYTES_RATIO,
        ]
    
    @classmethod
    def get_features_by_category(cls, category: FeatureCategory) -> List[FeatureDefinition]:
        """Get features by category."""
        all_features = cls.get_all_features()
        return [f for f in all_features if f.category == category]
    
    @classmethod
    def get_feature_names(cls) -> List[str]:
        """Get all feature names."""
        return [f.name for f in cls.get_all_features()]
    
    @classmethod
    def get_normalizable_features(cls) -> List[FeatureDefinition]:
        """Get features that should be normalized for ML."""
        return [f for f in cls.get_all_features() if f.normalize]
    
    @classmethod
    def to_dict(cls) -> Dict[str, Dict[str, Any]]:
        """Convert catalog to dictionary."""
        return {f.name: f.to_dict() for f in cls.get_all_features()}
