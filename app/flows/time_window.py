"""
Time window management for flow aggregation.

This module handles the creation, rotation, and management of time windows
for aggregating network traffic into flows.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, List, Callable
import logging
import uuid

from app.models.flow import FlowWindow, Flow, FlowKey
from app.models.packet import ParsedPacket

logger = logging.getLogger(__name__)

MAX_FUTURE_SKEW_SECONDS = 300


class TimeWindowManager:
    """
    Manages time windows for flow aggregation.
    
    Time windows divide continuous traffic into discrete segments for analysis.
    This enables:
    - Rate-based calculations (packets/second, bytes/second)
    - Time-series analysis
    - Sliding window computations
    - Memory management (expire old windows)
    """
    
    def __init__(self, window_seconds: int = 5):
        """
        Initialize time window manager.
        
        Args:
            window_seconds: Duration of each time window in seconds
        """
        self.window_seconds = window_seconds
        self.current_window: Optional[FlowWindow] = None
        self.previous_windows: List[FlowWindow] = []
        self.max_previous_windows = 10  # Keep last N windows for analysis
        self.closed_windows: List[FlowWindow] = []
        self.window_close_callback: Optional[Callable[[FlowWindow], None]] = None

        # Statistics
        self.total_windows_created = 0
        self.total_packets_processed = 0
    
    def get_current_window(self) -> FlowWindow:
        """
        Get or create the current time window using wall clock.

        This method is preserved for compatibility, but packet placement uses
        packet.timestamp via add_packet().
        """
        now = datetime.now(timezone.utc)

        if self.current_window is None or now >= self.current_window.end_time:
            self._rotate_window(now)

        return self.current_window
    
    def _rotate_window(self, now: datetime) -> None:
        """
        Rotate to a new time window.
        
        Archives the current window and creates a new one.
        
        Args:
            now: Current timestamp
        """
        # Archive current window if it exists. Do not emit yet: retained
        # historical windows may still accept late packets under event-time
        # semantics until cleanup closes them.
        if self.current_window is not None:
            self.previous_windows.append(self.current_window)

            # Limit number of previous windows by closing oldest retained windows.
            while len(self.previous_windows) > self.max_previous_windows:
                oldest = self.previous_windows.pop(0)
                self._close_window(oldest)
        
        # Create new window aligned to window boundaries
        window_start = self._align_to_window_boundary(now)
        window_end = window_start + timedelta(seconds=self.window_seconds)
        
        self.current_window = FlowWindow(
            window_id=str(uuid.uuid4()),
            start_time=window_start,
            end_time=window_end,
        )
        
        self.total_windows_created += 1
    
    def _align_to_window_boundary(self, timestamp: datetime) -> datetime:
        """
        Align timestamp to window boundary.
        
        Args:
            timestamp: Input timestamp
            
        Returns:
            Timestamp aligned to window start
        """
        # Calculate seconds since epoch
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        seconds_since_epoch = (timestamp - epoch).total_seconds()
        
        # Align to window boundary
        aligned_seconds = (seconds_since_epoch // self.window_seconds) * self.window_seconds
        
        # Convert back to datetime
        return epoch + timedelta(seconds=aligned_seconds)
    
    def _get_retained_window_for_timestamp(self, timestamp: datetime) -> Optional[FlowWindow]:
        """Return an existing retained window that contains the event timestamp."""
        if self.current_window and self.current_window.start_time <= timestamp < self.current_window.end_time:
            return self.current_window

        for window in reversed(self.previous_windows):
            if window.start_time <= timestamp < window.end_time:
                return window

        return None

    def _create_window_for_timestamp(self, timestamp: datetime) -> FlowWindow:
        """Create a new fixed window aligned to the event timestamp."""
        window_start = self._align_to_window_boundary(timestamp)
        window_end = window_start + timedelta(seconds=self.window_seconds)
        window = FlowWindow(
            window_id=str(uuid.uuid4()),
            start_time=window_start,
            end_time=window_end,
        )
        self.total_windows_created += 1
        return window

    def add_packet(self, packet: ParsedPacket, flow_key: FlowKey) -> Optional[Flow]:
        """
        Add a packet to the event-time window that contains packet.timestamp.

        Policy:
        - forward movement creates/rotates to newer event-time windows
        - late packets are accepted if their target retained window still exists
        - packets for already-removed windows are dropped
        - modest future timestamps are accepted; extreme future skew is rejected
        """
        event_time = packet.timestamp
        now = datetime.now(timezone.utc)
        if event_time > now + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
            logger.warning("Dropping packet with excessive future timestamp: %s", event_time.isoformat())
            return None

        window = self._get_retained_window_for_timestamp(event_time)
        if window is None:
            target_start = self._align_to_window_boundary(event_time)

            if self.current_window is None:
                self.current_window = self._create_window_for_timestamp(event_time)
                window = self.current_window
            else:
                current_start = self.current_window.start_time
                if target_start > current_start:
                    self._rotate_window(event_time)
                    window = self.current_window
                elif target_start == current_start:
                    window = self.current_window
                else:
                    oldest_retained_start = None
                    if self.previous_windows:
                        oldest_retained_start = min(w.start_time for w in self.previous_windows)

                    if oldest_retained_start is not None and target_start >= oldest_retained_start:
                        # There is a gap inside the retained range; create the missing
                        # historical window and retain it for late event-time packets.
                        window = self._create_window_for_timestamp(event_time)
                        self.previous_windows.append(window)
                        self.previous_windows.sort(key=lambda w: w.start_time)
                        if len(self.previous_windows) > self.max_previous_windows:
                            self.previous_windows = self.previous_windows[-self.max_previous_windows:]
                    else:
                        logger.warning(
                            "Dropping late packet for removed window starting at %s",
                            target_start.isoformat(),
                        )
                        return None

        flow = window.add_packet(packet, flow_key=flow_key)
        self.total_packets_processed += 1
        return flow
    
    def get_window_statistics(self) -> dict:
        """
        Get statistics about time windows.
        
        Returns:
            Dictionary with window statistics
        """
        current_stats = {}
        if self.current_window:
            current_stats = {
                "window_id": self.current_window.window_id,
                "flow_count": self.current_window.get_flow_count(),
                "total_packets": self.current_window.get_total_packets(),
                "total_bytes": self.current_window.get_total_bytes(),
            }
        
        previous_stats = []
        for window in self.previous_windows:
            previous_stats.append({
                "window_id": window.window_id,
                "flow_count": window.get_flow_count(),
                "total_packets": window.get_total_packets(),
                "total_bytes": window.get_total_bytes(),
            })
        
        return {
            "window_seconds": self.window_seconds,
            "total_windows_created": self.total_windows_created,
            "total_packets_processed": self.total_packets_processed,
            "current_window": current_stats,
            "previous_windows_count": len(self.previous_windows),
            "previous_windows": previous_stats,
        }
    
    def _close_window(self, window: FlowWindow) -> None:
        """Make a retained fixed window immutable and notify listeners once."""
        if window in self.closed_windows:
            return
        window.finalize()
        self.closed_windows.append(window)
        if self.window_close_callback:
            self.window_close_callback(window)

    def cleanup_old_windows(self, max_age_seconds: int = 300) -> int:
        """
        Clean up windows older than specified age.

        Retained fixed windows remain mutable for accepted late packets until
        they age out of retention. Only at that point are they closed/finalized
        for canonical feature emission.
        """
        now = datetime.now(timezone.utc)
        cutoff_time = now - timedelta(seconds=max_age_seconds)

        kept_windows: List[FlowWindow] = []
        removed_count = 0
        for window in self.previous_windows:
            if window.end_time >= cutoff_time:
                kept_windows.append(window)
            else:
                self._close_window(window)
                removed_count += 1

        self.previous_windows = kept_windows
        return removed_count
    
    def get_recent_windows(self, count: int = 5) -> List[FlowWindow]:
        """
        Get the most recent windows.
        
        Args:
            count: Number of recent windows to return
            
        Returns:
            List of recent FlowWindows
        """
        # Combine current and previous windows
        all_windows = []
        if self.current_window:
            all_windows.append(self.current_window)
        all_windows.extend(self.previous_windows)
        
        # Return most recent
        return all_windows[-count:]
    
    def reset(self) -> None:
        """Reset the time window manager."""
        self.current_window = None
        self.previous_windows = []
        self.closed_windows = []
        self.window_close_callback = None
        self.total_windows_created = 0
        self.total_packets_processed = 0


class SlidingWindowManager:
    """
    Manages sliding time windows for real-time analysis.

    Unlike fixed windows, sliding windows provide continuous analysis
    over a moving time horizon. A single packet can belong to multiple
    overlapping windows simultaneously, which is intentional: each
    window represents a different temporal viewpoint on the traffic.

    Semantics of window creation (illustrated for window=10s, slide=5s):
        t=0  → W0 created: spans [0, 10)
        t=5  → W1 created: spans [5, 15)
        t=10 → W0 retired (end_time <= now); W2 created: spans [10, 20)
        t=15 → W1 retired;           W3 created: spans [15, 25)
    At t=7 a packet falls in BOTH W0 and W1; it is counted ONCE per
    window (two windows → two Flow objects; FlowStatistics updated
    once in each). This is NOT double counting: it's two legitimate
    per-window observations of the same event.
    """

    def __init__(self, window_seconds: int = 60, slide_seconds: int = 10):
        """
        Initialize sliding window manager.

        Args:
            window_seconds: Total window duration
            slide_seconds: Slide interval (how often the window moves)
        """
        self.window_seconds = window_seconds
        self.slide_seconds = slide_seconds
        self.windows: Dict[str, FlowWindow] = {}
        self.last_slide_time: Optional[datetime] = None
        self.window_close_callback: Optional[Callable[[FlowWindow], None]] = None

        # Statistics counters (kept in parallel with TimeWindowManager so
        # FlowBuilder.get_statistics() can query both managers uniformly).
        self.total_windows_created = 0
        self.total_packets_processed = 0

    def _align_to_slide_boundary(self, timestamp: datetime) -> datetime:
        """Align a timestamp to the sliding-window start grid."""
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        seconds_since_epoch = (timestamp - epoch).total_seconds()
        aligned_seconds = (seconds_since_epoch // self.slide_seconds) * self.slide_seconds
        return epoch + timedelta(seconds=aligned_seconds)

    def _window_id_for_start(self, window_start: datetime) -> str:
        return f"slide_{window_start.isoformat()}"

    def _get_window_by_start(self, window_start: datetime) -> Optional[FlowWindow]:
        return self.windows.get(self._window_id_for_start(window_start))

    def _ensure_window(self, window_start: datetime) -> FlowWindow:
        window_id = self._window_id_for_start(window_start)
        window = self.windows.get(window_id)
        if window is None:
            window = FlowWindow(
                window_id=window_id,
                start_time=window_start,
                end_time=window_start + timedelta(seconds=self.window_seconds),
            )
            self.windows[window_id] = window
            self.total_windows_created += 1
        return window

    def _get_candidate_window_starts(self, event_time: datetime) -> List[datetime]:
        latest_start = self._align_to_slide_boundary(event_time)
        earliest_start = event_time - timedelta(seconds=self.window_seconds) + timedelta(microseconds=1)
        earliest_aligned = self._align_to_slide_boundary(earliest_start)

        starts: List[datetime] = []
        current = earliest_aligned
        while current <= latest_start:
            if current <= event_time < current + timedelta(seconds=self.window_seconds):
                starts.append(current)
            current += timedelta(seconds=self.slide_seconds)
        return starts

    def add_packet(self, packet: ParsedPacket, flow_key: FlowKey) -> List[Flow]:
        """
        Add a packet to every retained event-time sliding window that covers it.

        Late packets are accepted if their target windows still exist; windows
        that have already been removed are not recreated. Modest future skew is
        accepted, but extreme future timestamps are dropped.
        """
        event_time = packet.timestamp
        now = datetime.now(timezone.utc)
        if event_time > now + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
            logger.warning("Dropping packet with excessive future timestamp: %s", event_time.isoformat())
            return []

        candidate_starts = self._get_candidate_window_starts(event_time)
        if not candidate_starts:
            return []

        retained_starts = {window.start_time for window in self.windows.values()}
        flows: List[Flow] = []

        missing_historical_starts = [
            start for start in candidate_starts
            if start not in retained_starts and start < max(candidate_starts)
        ]
        if missing_historical_starts:
            logger.warning(
                "Dropping late packet for removed sliding window(s): %s",
                ", ".join(start.isoformat() for start in missing_historical_starts),
            )

        for start in candidate_starts:
            existing = self._get_window_by_start(start)
            if existing is None:
                newer_window_exists = any(window.start_time > start for window in self.windows.values())
                if newer_window_exists and start < max(candidate_starts):
                    continue
                existing = self._ensure_window(start)

            flow = existing.add_packet(packet, flow_key=flow_key)
            flows.append(flow)

        if flows:
            self.last_slide_time = max(window.window_start for window in flows)
            self.total_packets_processed += 1

        return flows

    def _create_new_windows(self, now: datetime) -> None:
        """Compatibility shim retained for older tests/callers."""
        self._ensure_window(self._align_to_slide_boundary(now))
        self._cleanup_expired_windows(now)

    def _close_window(self, window: FlowWindow) -> None:
        """Finalize an expired sliding window and notify listeners once."""
        window.finalize()
        if self.window_close_callback:
            self.window_close_callback(window)

    def _cleanup_expired_windows(self, now: datetime) -> None:
        """
        Remove windows that have completely passed.

        A window is expired when window.end_time <= now — no future
        packet can land inside it; its flows are now immutable and eligible
        for canonical feature emission.
        """
        expired_keys = [
            key for key, window in self.windows.items()
            if window.end_time <= now
        ]

        for key in expired_keys:
            window = self.windows[key]
            self._close_window(window)
            del self.windows[key]

    def get_active_windows(self) -> List[FlowWindow]:
        """Get all currently retained sliding windows."""
        return sorted(self.windows.values(), key=lambda w: w.start_time)

    def get_window_statistics(self) -> dict:
        """
        Get statistics about sliding windows in a schema compatible
        with TimeWindowManager.get_window_statistics() so that
        FlowBuilder.get_statistics() works for both managers.
        """
        active_windows = self.get_active_windows()
        active_by_start = sorted(active_windows, key=lambda w: w.start_time)
        current_window = active_by_start[-1] if active_by_start else None

        current_stats = {}
        if current_window:
            current_stats = {
                "window_id": current_window.window_id,
                "flow_count": current_window.get_flow_count(),
                "total_packets": current_window.get_total_packets(),
                "total_bytes": current_window.get_total_bytes(),
            }

        previous_stats = []
        for window in sorted(self.windows.values(), key=lambda w: w.start_time):
            if window is current_window:
                continue
            previous_stats.append({
                "window_id": window.window_id,
                "flow_count": window.get_flow_count(),
                "total_packets": window.get_total_packets(),
                "total_bytes": window.get_total_bytes(),
            })

        return {
            "window_seconds": self.window_seconds,
            "slide_seconds": self.slide_seconds,
            "total_windows_created": self.total_windows_created,
            "total_packets_processed": self.total_packets_processed,
            "current_window": current_stats,
            "previous_windows_count": len(previous_stats),
            "previous_windows": previous_stats,
        }

    def cleanup_old_windows(self, max_age_seconds: int = 300) -> int:
        """
        Sliding-window equivalent of TimeWindowManager.cleanup_old_windows.

        Removes windows whose end_time is older than max_age_seconds.
        Because sliding windows auto-clean on every _create_new_windows
        call via _cleanup_expired_windows, this method additionally
        enforces an age-based upper bound for long-idle scenarios.

        Args:
            max_age_seconds: Maximum age (seconds since window end) to keep

        Returns:
            Number of windows removed
        """
        now = datetime.now(timezone.utc)
        cutoff_time = now - timedelta(seconds=max_age_seconds)

        old_keys = [
            key for key, window in self.windows.items()
            if window.end_time < cutoff_time
        ]
        for key in old_keys:
            window = self.windows[key]
            self._close_window(window)
            del self.windows[key]
        return len(old_keys)

    def reset(self) -> None:
        """Reset the sliding window manager."""
        self.windows = {}
        self.last_slide_time = None
        self.window_close_callback = None
        self.total_windows_created = 0
        self.total_packets_processed = 0
