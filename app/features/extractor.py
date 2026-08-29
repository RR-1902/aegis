"""
Feature extraction from network flows.

This module implements the logic to extract security-relevant features
from flow statistics for use in detection and analysis.
"""

import logging
from typing import Dict, List, Any, Optional
import math

from app.models.flow import Flow, FlowStatistics, FeatureObservation
from app.features.feature_definitions import FeatureCatalog, FeatureDefinition

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Extracts features from flow statistics.
    
    The feature extractor transforms raw flow statistics into a structured
    feature vector suitable for detection algorithms and analysis.
    """
    
    def __init__(self, normalize: bool = True):
        """
        Initialize the feature extractor.
        
        Args:
            normalize: Whether to normalize features (useful for ML)
        """
        self.normalize = normalize
        self.feature_catalog = FeatureCatalog()
        
        # Track extraction statistics
        self.total_extractions = 0
        self.extraction_errors = 0
    
    def extract_features(self, flow: Flow) -> Dict[str, Any]:
        """
        Extract all features from a flow.
        
        Args:
            flow: Flow to extract features from
            
        Returns:
            Dictionary of feature names to values
        """
        try:
            self.total_extractions += 1
            stats = flow.statistics
            
            # Ensure statistics are finalized
            if stats.packet_count == 0:
                return self._get_empty_features()
            
            features = {}
            
            # Extract count features
            self._extract_count_features(stats, features)
            
            # Extract protocol features
            self._extract_protocol_features(stats, features)
            
            # Extract connection features
            self._extract_connection_features(stats, features)
            
            # Extract diversity features
            self._extract_diversity_features(stats, features)
            
            # Extract rate features
            self._extract_rate_features(flow, stats, features)
            
            # Extract ratio features
            self._extract_ratio_features(stats, features)
            
            # Extract temporal features
            self._extract_temporal_features(flow, stats, features)
            
            # Extract size features
            self._extract_size_features(stats, features)
            
            # Extract directional features
            self._extract_directional_features(stats, features)
            
            # Normalize if requested
            if self.normalize:
                features = self._normalize_features(features)
            
            return features
            
        except Exception as e:
            self.extraction_errors += 1
            logger.error(f"Error extracting features from flow: {e}")
            return self._get_empty_features()
    
    def _extract_count_features(self, stats: FlowStatistics, features: Dict[str, Any]) -> None:
        """Extract simple count features."""
        features["packet_count"] = stats.packet_count
        features["byte_count"] = stats.byte_count
    
    def _extract_protocol_features(self, stats: FlowStatistics, features: Dict[str, Any]) -> None:
        """Extract protocol-specific features."""
        features["syn_count"] = stats.syn_count
        features["ack_count"] = stats.ack_count
        features["fin_count"] = stats.fin_count
        features["rst_count"] = stats.rst_count
        features["psh_count"] = stats.psh_count
    
    def _extract_connection_features(self, stats: FlowStatistics, features: Dict[str, Any]) -> None:
        """Extract connection-related features."""
        features["connection_attempts"] = stats.connection_attempts
        features["successful_connections"] = stats.successful_connections
        features["failed_connections"] = stats.failed_connections
        features["incomplete_connections"] = stats.incomplete_connections
    
    def _extract_diversity_features(self, stats: FlowStatistics, features: Dict[str, Any]) -> None:
        """Extract diversity/uniqueness features."""
        features["unique_destination_ports"] = len(stats.unique_destination_ports)
        features["unique_destination_ips"] = len(stats.unique_destination_ips)
    
    def _extract_rate_features(self, flow: Flow, stats: FlowStatistics, features: Dict[str, Any]) -> None:
        """Extract rate-based features (per second)."""
        duration = flow.get_duration_seconds()
        
        if duration > 0:
            features["packets_per_second"] = stats.packet_count / duration
            features["bytes_per_second"] = stats.byte_count / duration
            features["syn_rate"] = stats.syn_count / duration
            
            if stats.connection_attempts > 0:
                features["connection_rate"] = stats.connection_attempts / duration
            else:
                features["connection_rate"] = 0.0
        else:
            features["packets_per_second"] = 0.0
            features["bytes_per_second"] = 0.0
            features["syn_rate"] = 0.0
            features["connection_rate"] = 0.0
    
    def _extract_ratio_features(self, stats: FlowStatistics, features: Dict[str, Any]) -> None:
        """Extract ratio/proportion features."""
        total_packets = stats.packet_count
        
        if total_packets > 0:
            features["syn_to_total_ratio"] = stats.syn_count / total_packets
            features["rst_to_total_ratio"] = stats.rst_count / total_packets
        else:
            features["syn_to_total_ratio"] = 0.0
            features["rst_to_total_ratio"] = 0.0
        
        total_attempts = stats.connection_attempts
        if total_attempts > 0:
            features["incomplete_connection_ratio"] = stats.incomplete_connections / total_attempts
            features["successful_connection_ratio"] = stats.successful_connections / total_attempts
        else:
            features["incomplete_connection_ratio"] = 0.0
            features["successful_connection_ratio"] = 0.0
    
    def _extract_temporal_features(self, flow: Flow, stats: FlowStatistics, features: Dict[str, Any]) -> None:
        """Extract time-based features."""
        features["duration_seconds"] = flow.get_duration_seconds()
    
    def _extract_size_features(self, stats: FlowStatistics, features: Dict[str, Any]) -> None:
        """Extract packet size features."""
        features["average_packet_size"] = stats.get_average_packet_size()
        features["min_packet_size"] = stats.min_packet_size if stats.min_packet_size != float('inf') else 0
        features["max_packet_size"] = stats.max_packet_size
    
    def _extract_directional_features(self, stats: FlowStatistics, features: Dict[str, Any]) -> None:
        """Extract directional byte count features."""
        features["bytes_sent"] = stats.bytes_sent
        features["bytes_received"] = stats.bytes_received
        
        # Calculate bytes ratio
        total_bytes = stats.bytes_sent + stats.bytes_received
        if total_bytes > 0:
            features["bytes_ratio"] = stats.bytes_sent / total_bytes
        else:
            features["bytes_ratio"] = 0.0
    
    def _normalize_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize features to [0,1] range where appropriate.
        
        Args:
            features: Raw features dictionary
            
        Returns:
            Normalized features dictionary
        """
        normalized = features.copy()
        
        # Get normalizable features from catalog
        normalizable_features = self.feature_catalog.get_normalizable_features()
        
        for feature_def in normalizable_features:
            feature_name = feature_def.name
            if feature_name in features:
                value = features[feature_name]
                
                # Skip if value is None or already normalized
                if value is None or feature_def.normalize == False:
                    continue
                
                # Apply min-max normalization if bounds are defined
                if feature_def.min_value is not None and feature_def.max_value is not None:
                    if feature_def.max_value > feature_def.min_value:
                        normalized[feature_name] = (value - feature_def.min_value) / (feature_def.max_value - feature_def.min_value)
                    else:
                        normalized[feature_name] = 0.0
                
                # Logarithmic normalization for count features (handles wide ranges)
                elif feature_def.category.value in ["count", "rate"] and value > 0:
                    normalized[feature_name] = math.log1p(value) / 10.0  # Normalize log to roughly [0,1]
        
        return normalized
    
    def _get_empty_features(self) -> Dict[str, Any]:
        """Get empty feature dictionary with default values."""
        feature_names = self.feature_catalog.get_feature_names()
        return {name: 0.0 for name in feature_names}
    
    def extract_observation(self, flow: Flow, *, finalized: bool = True, sliding: bool = False) -> Optional[FeatureObservation]:
        """Convert a non-empty per-window Flow into a FeatureObservation."""
        if flow.statistics.packet_count == 0:
            return None

        features = self.extract_features(flow)
        return FeatureObservation(
            flow_key=flow.flow_key,
            window_start=flow.window_start,
            window_end=flow.window_end,
            features=features,
            finalized=finalized,
            sliding=sliding,
        )

    def extract_feature_vector(self, flow: Flow, feature_names: Optional[List[str]] = None) -> List[float]:
        """
        Extract features as a vector (list of floats).
        
        Args:
            flow: Flow to extract features from
            feature_names: List of feature names to extract (None for all)
            
        Returns:
            List of feature values in the specified order
        """
        features = self.extract_features(flow)
        
        if feature_names is None:
            feature_names = self.feature_catalog.get_feature_names()
        
        return [features.get(name, 0.0) for name in feature_names]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get extraction statistics."""
        error_rate = self.extraction_errors / max(1, self.total_extractions)
        
        return {
            "total_extractions": self.total_extractions,
            "extraction_errors": self.extraction_errors,
            "error_rate": error_rate,
        }
    
    def reset_statistics(self) -> None:
        """Reset extraction statistics."""
        self.total_extractions = 0
        self.extraction_errors = 0


class FeatureAggregator:
    """
    Aggregates features across multiple flows.
    
    This is useful for host-level or network-level analysis where
    you need to aggregate features across multiple flows.
    """
    
    def __init__(self):
        """Initialize the feature aggregator."""
        self.extractor = FeatureExtractor()
    
    def aggregate_flow_features(self, flows: List[Flow]) -> Dict[str, Any]:
        """
        Aggregate features across multiple flows.
        
        Args:
            flows: List of flows to aggregate
            
        Returns:
            Dictionary of aggregated features
        """
        if not flows:
            return {}
        
        # Extract features from all flows
        all_features = []
        for flow in flows:
            features = self.extractor.extract_features(flow)
            all_features.append(features)
        
        # Aggregate using sum, mean, max, min
        aggregated = {}
        
        for feature_name in self.extractor.feature_catalog.get_feature_names():
            values = [f.get(feature_name, 0.0) for f in all_features]
            
            if values:
                aggregated[f"{feature_name}_sum"] = sum(values)
                aggregated[f"{feature_name}_mean"] = sum(values) / len(values)
                aggregated[f"{feature_name}_max"] = max(values)
                aggregated[f"{feature_name}_min"] = min(values)
                aggregated[f"{feature_name}_count"] = len(values)
        
        return aggregated
    
    def aggregate_host_features(self, flows: List[Flow], host_ip: str) -> Dict[str, Any]:
        """
        Aggregate features for a specific host.
        
        Args:
            flows: List of flows
            host_ip: IP address of the host to aggregate for
            
        Returns:
            Dictionary of host-level aggregated features
        """
        # Filter flows for the specific host
        host_flows = [
            flow for flow in flows
            if flow.flow_key.src_ip == host_ip or flow.flow_key.dst_ip == host_ip
        ]
        
        return self.aggregate_flow_features(host_flows)


# Global feature extractor instance
feature_extractor = FeatureExtractor()
