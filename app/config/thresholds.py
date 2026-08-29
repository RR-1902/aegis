"""
Detection thresholds configuration with documentation.

All thresholds are documented with:
- What they measure
- Why this value
- Potential trade-offs
- How to tune
"""

from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class ThresholdConfig:
    """Container for all detection thresholds with documentation."""
    
    # Port Scan Detection
    port_scan_threshold: int = 20
    """
    Number of unique destination ports from a single source IP within the time window.
    
    Why: A legitimate host typically connects to few ports within a short window.
    Scanning tools often attempt connections to many ports rapidly.
    
    Trade-offs:
    - Lower: More sensitive, catches slow scans but may flag web crawlers
    - Higher: Fewer false positives but may miss slow/stealthy scans
    
    Tuning: Adjust based on normal traffic patterns. Web servers may legitimately
    connect to many backend services.
    """
    
    port_scan_time_window: int = 10
    """
    Time window in seconds for port scan detection.
    
    Why: Scans typically happen in bursts. This window balances detection speed
    with allowing legitimate port-hopping.
    
    Trade-offs:
    - Shorter: Faster detection but more false positives from normal activity
    - Longer: Fewer false positives but slower detection
    
    Tuning: Match to expected scan speed in your environment.
    """
    
    # SYN Flood Detection
    syn_rate_threshold: float = 10.0
    """
    SYN packets per second threshold.
    
    Why: Normal hosts establish connections at a moderate rate. Attackers send
    many SYNs to exhaust connection tables.
    
    Trade-offs:
    - Lower: Catches smaller floods but may flag busy legitimate servers
    - Higher: Tolerates busy servers but may miss smaller attacks
    
    Tuning: Baseline normal SYN rates for your environment.
    """
    
    syn_incomplete_ratio: float = 0.7
    """
    Ratio of incomplete connections (SYN without completion) to flag as SYN flood.
    
    Why: SYN floods send many SYNs but don't complete handshakes. Legitimate
    traffic typically completes most connections.
    
    Trade-offs:
    - Lower: More sensitive to incomplete connections
    - Higher: Requires more incomplete connections before flagging
    
    Tuning: Normal incomplete connection ratio is typically < 0.1.
    """
    
    # Traffic Anomaly Detection
    traffic_spike_multiplier: float = 3.0
    """
    Multiplier over baseline traffic rate to flag as anomaly.
    
    Why: Sudden traffic spikes can indicate DDoS, data exfiltration, or other attacks.
    
    Trade-offs:
    - Lower: More sensitive to smaller spikes
    - Higher: Only flags major anomalies
    
    Tuning: Set based on acceptable variance in normal traffic.
    """
    
    traffic_baseline_window: int = 60
    """
    Time window in seconds to calculate traffic baseline.
    
    Why: Need enough data to establish "normal" but not so much that it's slow to adapt.
    
    Trade-offs:
    - Shorter: Adapts quickly to changes but more variable baseline
    - Longer: Stable baseline but slow to adapt to legitimate changes
    
    Tuning: Balance stability vs adaptability for your environment.
    """
    
    # Authentication Abuse Detection
    auth_failure_threshold: int = 5
    """
    Number of failed authentication attempts within time window.
    
    Why: Brute force attacks try many credentials. Legitimate users rarely fail repeatedly.
    
    Trade-offs:
    - Lower: Catches brute force earlier but may flag forgetful users
    - Higher: More tolerant but slower detection
    
    Tuning: Consider user behavior and security requirements.
    """
    
    auth_failure_window: int = 60
    """
    Time window in seconds for authentication failure detection.
    
    Why: Brute force attacks happen in bursts. Window should match expected attack pattern.
    
    Trade-offs:
    - Shorter: Faster detection but may flag偶然 failures
    - Longer: More tolerant but slower detection
    
    Tuning: Match to expected brute force speed.
    """
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert thresholds to dictionary for serialization."""
        return {
            "port_scan_threshold": self.port_scan_threshold,
            "port_scan_time_window": self.port_scan_time_window,
            "syn_rate_threshold": self.syn_rate_threshold,
            "syn_incomplete_ratio": self.syn_incomplete_ratio,
            "traffic_spike_multiplier": self.traffic_spike_multiplier,
            "traffic_baseline_window": self.traffic_baseline_window,
            "auth_failure_threshold": self.auth_failure_threshold,
            "auth_failure_window": self.auth_failure_window,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThresholdConfig":
        """Create ThresholdConfig from dictionary."""
        return cls(
            port_scan_threshold=data.get("port_scan_threshold", 20),
            port_scan_time_window=data.get("port_scan_time_window", 10),
            syn_rate_threshold=data.get("syn_rate_threshold", 10.0),
            syn_incomplete_ratio=data.get("syn_incomplete_ratio", 0.7),
            traffic_spike_multiplier=data.get("traffic_spike_multiplier", 3.0),
            traffic_baseline_window=data.get("traffic_baseline_window", 60),
            auth_failure_threshold=data.get("auth_failure_threshold", 5),
            auth_failure_window=data.get("auth_failure_window", 60),
        )


# Global threshold configuration
thresholds = ThresholdConfig()
