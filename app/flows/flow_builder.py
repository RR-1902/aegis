"""
Flow builder for aggregating packets into flows.

This module is the core of the flow aggregation system, taking individual
packets and building meaningful flow representations for analysis.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, List, Callable
from collections import defaultdict

from app.models.packet import ParsedPacket
from app.models.flow import Flow, FlowKey, FlowStatistics, FlowWindow, FeatureObservation
from app.flows.flow_key import FlowKeyManager
from app.flows.time_window import TimeWindowManager, SlidingWindowManager
from app.config.settings import settings
from app.features.extractor import FeatureExtractor

logger = logging.getLogger(__name__)


class FlowBuilder:
    """
    Builds flows from individual packets with configurable strategies.
    
    The flow builder is responsible for:
    - Aggregating packets into flows based on flow keys
    - Managing time windows for time-series analysis
    - Tracking flow state and expiration
    - Providing statistics and metrics
    """
    
    def __init__(
        self,
        flow_key_strategy: str = "five_tuple",
        window_seconds: int = None,
        flow_timeout_seconds: int = None,
        use_sliding_windows: bool = False,
    ):
        """
        Initialize the flow builder.

        Args:
            flow_key_strategy: Strategy for generating flow keys
            window_seconds: Time window duration in seconds
            flow_timeout_seconds: Timeout for inactive flows
            use_sliding_windows: Whether to use sliding windows instead of fixed windows
        """
        self.flow_key_strategy = flow_key_strategy
        self.window_seconds = window_seconds or settings.flow_window_seconds
        self.flow_timeout_seconds = flow_timeout_seconds or settings.flow_timeout_seconds
        self.use_sliding_windows = use_sliding_windows

        # Initialize flow key manager
        self.flow_key_manager = FlowKeyManager(strategy=flow_key_strategy)

        # Initialize time window manager
        if use_sliding_windows:
            self.window_manager = SlidingWindowManager(
                window_seconds=self.window_seconds,
                slide_seconds=self.window_seconds // 2,  # Slide at half window duration
            )
        else:
            self.window_manager = TimeWindowManager(
                window_seconds=self.window_seconds,
            )

        # Active flows: references to CANONICAL Flow objects from the window manager.
        #
        # IMPORTANT INVARIANT (P1 fix):
        #   The window manager is the SOLE owner of Flow objects and FlowStatistics mutation.
        #   self.active_flows[flow_key] always points to the SAME Flow object
        #   (identity-wise) that the window manager most recently placed the packet
        #   into for this flow_key. FlowBuilder MUST NOT independently create a second
        #   Flow object nor independently mutate FlowStatistics for the same flow identity.
        self.active_flows: Dict[FlowKey, Flow] = {}

        # Flow expiration tracking
        self.last_cleanup_time: Optional[datetime] = None

        # Statistics
        self.total_packets_processed = 0
        self.total_flows_created = 0
        self.total_flows_expired = 0
        self._seen_flow_keys = set()

        # Packet callback for external processing
        self.packet_callback: Optional[Callable[[ParsedPacket, Flow], None]] = None

        # Finalized feature-observation emission
        self.feature_extractor = FeatureExtractor(normalize=False)
        self.feature_observation_callback: Optional[Callable[[FeatureObservation], None]] = None
        self.emitted_observation_keys = set()
        self.window_manager.window_close_callback = self._handle_closed_window
    
    def add_packet(self, packet: ParsedPacket) -> Optional[Flow]:
        """
        Add a packet to the flow builder.

        This is the main entry point for packet processing.

        P1 invariant:
            A packet is counted exactly once into FlowStatistics inside each
            canonical Flow object owned by the window manager. In sliding
            mode, one packet legitimately lands in MULTIPLE overlapping
            windows, producing one FlowStatistics update per window. That
            is correct (those are separate per-window observations). What
            must NOT happen is for FlowBuilder to independently create and
            add_packet() a second separate Flow object for the same packet
            in the same window scope.

        Args:
            packet: Parsed packet to add

        Returns:
            The PRIMARY canonical Flow that received the packet — defined
            as the Flow from the window with the latest start_time (i.e.,
            the "newest" active window). For fixed windows this is always
            the single current window. For sliding windows it's the Flow
            from the most recently-created overlapping window. All other
            per-window Flows are reachable via the packet callback (if
            registered) and via direct inspection of the window manager.
            Returns None if the packet couldn't be processed.
        """
        try:
            self.total_packets_processed += 1

            # Generate flow key (once, used consistently)
            flow_key = self.flow_key_manager.generate_key(packet)
            if flow_key is None:
                logger.debug("Could not generate flow key for packet")
                return None

            # Add to time window — this is the SOLE packet-counting location.
            #
            # NOTE: window_manager.add_packet has two possible return shapes:
            #   TimeWindowManager    -> Flow           (single current window)
            #   SlidingWindowManager -> List[Flow]     (all active windows)
            # We normalize to a list here so the rest of FlowBuilder can treat
            # both managers uniformly.
            window_flows = self.window_manager.add_packet(
                packet,
                flow_key=flow_key,
            )
            if isinstance(window_flows, list):
                flows = window_flows
            else:
                flows = [window_flows]
            if not flows:
                return None

            # Primary flow = newest-active-window Flow.
            # This is the flow stored in active_flows and returned to the caller.
            # For fixed windows the list length is always 1 so this is a no-op.
            primary_flow: Flow = max(flows, key=lambda f: f.window_start)

            # Track new-flow accounting by conversation key, independent of
            # which event-time window currently owns the active Flow reference.
            if flow_key not in self._seen_flow_keys:
                self.total_flows_created += 1
                self._seen_flow_keys.add(flow_key)

            # Store a reference only (NO packet counting here).
            # active_flows[flow_key] always points to the primary Flow object
            # returned above; identity-equality with get_flow() is guaranteed.
            self.active_flows[flow_key] = primary_flow

            # Call packet callback for EACH per-window flow the packet
            # was inserted into. Callers that only care about fixed windows
            # observe exactly one call (list length = 1). Sliding callers
            # observe one call per active window, each receiving its own
            # distinct Flow object with correctly-scoped stats, enabling
            # per-window analysis hooks (e.g., rate calculations).
            if self.packet_callback:
                for f in flows:
                    self.packet_callback(packet, f)

            # Periodic cleanup
            self._periodic_cleanup()

            return primary_flow

        except Exception as e:
            logger.error(f"Error adding packet to flow builder: {e}")
            return None
    
    def _periodic_cleanup(self) -> None:
        """Perform periodic cleanup of expired flows."""
        now = datetime.now(timezone.utc)
        
        # Run cleanup every 30 seconds
        if self.last_cleanup_time is None or (now - self.last_cleanup_time).total_seconds() >= 30:
            self._cleanup_expired_flows(now)
            self.window_manager.cleanup_old_windows()
            self.last_cleanup_time = now
    
    def _cleanup_expired_flows(self, now: datetime) -> None:
        """
        Remove expired flows from active tracking.
        
        Args:
            now: Current timestamp
        """
        expired_keys = []
        
        for flow_key, flow in self.active_flows.items():
            if flow.is_expired(now, self.flow_timeout_seconds):
                expired_keys.append(flow_key)
                self.total_flows_expired += 1
        
        for key in expired_keys:
            del self.active_flows[key]
        
        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired flows")
    
    def get_flow(self, flow_key: FlowKey) -> Optional[Flow]:
        """
        Get a specific flow by key.
        
        Args:
            flow_key: Flow key to look up
            
        Returns:
            Flow if found, None otherwise
        """
        return self.active_flows.get(flow_key)
    
    def get_all_flows(self) -> List[Flow]:
        """Get all active flows."""
        return list(self.active_flows.values())
    
    def get_flow_count(self) -> int:
        """Get number of active flows."""
        return len(self.active_flows)
    
    def _handle_closed_window(self, window: FlowWindow) -> None:
        """Emit finalized feature observations once per immutable flow-window."""
        for flow in window.flows.values():
            if flow.statistics.packet_count == 0:
                continue

            observation_key = (flow.flow_key, flow.window_start, flow.window_end)
            if observation_key in self.emitted_observation_keys:
                continue

            observation = self.feature_extractor.extract_observation(
                flow,
                finalized=True,
                sliding=self.use_sliding_windows,
            )
            if observation is None:
                continue

            self.emitted_observation_keys.add(observation_key)
            if self.feature_observation_callback:
                self.feature_observation_callback(observation)

    def get_statistics(self) -> dict:
        """
        Get flow builder statistics.
        
        Returns:
            Dictionary with flow builder statistics
        """
        window_stats = self.window_manager.get_window_statistics()
        
        # Calculate flow statistics
        total_flow_packets = sum(
            flow.statistics.packet_count for flow in self.active_flows.values()
        )
        total_flow_bytes = sum(
            flow.statistics.byte_count for flow in self.active_flows.values()
        )
        
        return {
            "flow_key_strategy": self.flow_key_strategy,
            "window_seconds": self.window_seconds,
            "flow_timeout_seconds": self.flow_timeout_seconds,
            "use_sliding_windows": self.use_sliding_windows,
            "total_packets_processed": self.total_packets_processed,
            "total_flows_created": self.total_flows_created,
            "total_flows_expired": self.total_flows_expired,
            "active_flow_count": len(self.active_flows),
            "active_flow_packets": total_flow_packets,
            "active_flow_bytes": total_flow_bytes,
            "window_statistics": window_stats,
        }
    
    def get_flows_by_source_ip(self, source_ip: str) -> List[Flow]:
        """
        Get all flows from a specific source IP.
        
        Args:
            source_ip: Source IP address
            
        Returns:
            List of flows from the specified source
        """
        return [
            flow for flow in self.active_flows.values()
            if flow.flow_key.src_ip == source_ip
        ]
    
    def get_flows_by_destination_ip(self, destination_ip: str) -> List[Flow]:
        """
        Get all flows to a specific destination IP.
        
        Args:
            destination_ip: Destination IP address
            
        Returns:
            List of flows to the specified destination
        """
        return [
            flow for flow in self.active_flows.values()
            if flow.flow_key.dst_ip == destination_ip
        ]
    
    def get_top_flows_by_packets(self, count: int = 10) -> List[Flow]:
        """
        Get top flows by packet count.
        
        Args:
            count: Number of top flows to return
            
        Returns:
            List of top flows by packet count
        """
        sorted_flows = sorted(
            self.active_flows.values(),
            key=lambda f: f.statistics.packet_count,
            reverse=True,
        )
        return sorted_flows[:count]
    
    def get_top_flows_by_bytes(self, count: int = 10) -> List[Flow]:
        """
        Get top flows by byte count.
        
        Args:
            count: Number of top flows to return
            
        Returns:
            List of top flows by byte count
        """
        sorted_flows = sorted(
            self.active_flows.values(),
            key=lambda f: f.statistics.byte_count,
            reverse=True,
        )
        return sorted_flows[:count]
    
    def set_packet_callback(self, callback: Callable[[ParsedPacket, Flow], None]) -> None:
        """
        Set a callback function to be called for each packet.
        
        Args:
            callback: Function to call with (packet, flow)
        """
        self.packet_callback = callback

    def set_feature_observation_callback(self, callback: Callable[[FeatureObservation], None]) -> None:
        """Set a callback for finalized per-window feature observations."""
        self.feature_observation_callback = callback
    
    def reset(self) -> None:
        """Reset the flow builder."""
        self.active_flows = {}
        self.total_packets_processed = 0
        self.total_flows_created = 0
        self.total_flows_expired = 0
        self._seen_flow_keys = set()
        self.emitted_observation_keys = set()
        self.last_cleanup_time = None
        self.window_manager.reset()
        self.window_manager.window_close_callback = self._handle_closed_window
    
    def set_flow_key_strategy(self, strategy: str) -> None:
        """
        Change the flow key strategy.
        
        Warning: This will reset the flow builder as existing flows
        will be incompatible with the new strategy.
        
        Args:
            strategy: New flow key strategy
        """
        self.flow_key_manager.set_strategy(strategy)
        self.flow_key_strategy = strategy
        self.reset()
        logger.info(f"Flow key strategy changed to {strategy}, flow builder reset")


# Global flow builder instance
flow_builder = FlowBuilder()
