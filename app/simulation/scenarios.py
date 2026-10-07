"""Attack simulations that run synthetic packets through the real AEGIS pipeline.

Each scenario builds packets in memory and feeds them to the same flow builder, rules, scorer,
policy engine, response engine and event store as the live runtime. The verdicts are the
engine's own; nothing about the stored event is written by hand. Source addresses come from
the documentation ranges in RFC 5737, which never appear on a real network, so simulated
events can always be told apart from captured ones.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional

from app.detection.engine import DetectionEngine
from app.flows.flow_builder import FlowBuilder
from app.models.security_event import SecurityEvent
from app.pipeline import AEGISPipeline
from app.policy.engine import PolicyEngine
from app.protocols.parser import ProtocolParser
from app.response.engine import ResponseEngine
from app.scoring.risk_scorer import RiskScorer
from app.simulation.traffic import dns_lookups, port_probe, syn_burst
from app.storage.security_event_store import SecurityEventStore


WINDOW_SECONDS = 5

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
]

# RFC 5737 documentation networks.
TEST_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")

PacketBuilder = Callable[[datetime, str], list]


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    summary: str
    flow_key_strategy: str
    target: str
    source_net: str
    build: PacketBuilder


SCENARIOS: Dict[str, Scenario] = {
    scenario.id: scenario
    for scenario in [
        Scenario(
            id="syn_flood",
            name="SYN flood",
            summary="60 SYN packets at one web port in 1.5 seconds, none of them completed.",
            flow_key_strategy="five_tuple",
            target="10.0.0.1",
            source_net="198.51.100.",
            build=lambda t, src: syn_burst(
                base_time=t, count=60, span_seconds=1.5, src_ip=src, dst_ip="10.0.0.1", src_port=54201, dst_port=80
            ),
        ),
        Scenario(
            id="port_scan",
            name="Port scan",
            summary="One host probes 32 ports on a server over 4.65 seconds.",
            flow_key_strategy="three_tuple",
            target="10.0.0.2",
            source_net="203.0.113.",
            build=lambda t, src: port_probe(
                base_time=t, dst_ports=list(range(1, 33)), span_seconds=4.65, src_ip=src, dst_ip="10.0.0.2", src_port_start=40000
            ),
        ),
        Scenario(
            id="fast_scan",
            name="Fast scan",
            summary="24 common ports probed in 0.8 seconds: a port scan and a SYN flood at once.",
            flow_key_strategy="three_tuple",
            target="10.0.0.4",
            source_net="203.0.113.",
            build=lambda t, src: port_probe(
                base_time=t, dst_ports=COMMON_PORTS, span_seconds=0.8, src_ip=src, dst_ip="10.0.0.4", src_port_start=50000
            ),
        ),
        Scenario(
            id="slow_scan",
            name="Slow scan",
            summary="Exactly 20 ports probed over 3.8 seconds, right on the port-scan threshold.",
            flow_key_strategy="three_tuple",
            target="10.0.0.12",
            source_net="192.0.2.",
            build=lambda t, src: port_probe(
                base_time=t, dst_ports=list(range(20, 40)), span_seconds=3.8, src_ip=src, dst_ip="10.0.0.12", src_port_start=40000
            ),
        ),
        Scenario(
            id="benign",
            name="Normal DNS lookups",
            summary="Five ordinary DNS queries. Nothing should fire and nothing is stored.",
            flow_key_strategy="five_tuple",
            target="10.0.0.53",
            source_net="192.0.2.",
            build=lambda t, src: dns_lookups(base_time=t, count=5, src_ip=src, dst_ip="10.0.0.53"),
        ),
    ]
}


@dataclass
class SimulationResult:
    scenario: Scenario
    source_ip: str
    packet_count: int
    events: List[SecurityEvent] = field(default_factory=list)


class _RecordingStore(SecurityEventStore):
    """Passes saves through to the real store and remembers what this run stored."""

    def __init__(self, inner: SecurityEventStore):
        self.inner = inner
        self.saved: List[SecurityEvent] = []

    def save(self, event: SecurityEvent) -> bool:
        stored = self.inner.save(event)
        self.saved.append(event)
        return stored

    def get(self, event_id: str):
        return self.inner.get(event_id)

    def list_recent(self, limit: int = 100):
        return self.inner.list_recent(limit=limit)


def is_simulated_source(ip: str) -> bool:
    return ip.startswith(TEST_NETS)


def last_closed_window_start(now: datetime) -> datetime:
    """Start of the most recent five-second window that has already closed, plus 100 ms."""
    epoch = int(now.timestamp()) // WINDOW_SECONDS * WINDOW_SECONDS - WINDOW_SECONDS
    return datetime.fromtimestamp(epoch, tz=timezone.utc) + timedelta(milliseconds=100)


def run_scenario(
    scenario_id: str,
    store: SecurityEventStore,
    *,
    now: Optional[datetime] = None,
    source_ip: Optional[str] = None,
    safe_mode: bool = True,
) -> SimulationResult:
    """Run one scenario through a fresh pipeline and return the events it stored."""
    scenario = SCENARIOS[scenario_id]
    source = source_ip or f"{scenario.source_net}{random.randint(2, 254)}"
    base_time = last_closed_window_start(now or datetime.now(timezone.utc))

    recorder = _RecordingStore(store)
    builder = FlowBuilder(
        flow_key_strategy=scenario.flow_key_strategy,
        window_seconds=WINDOW_SECONDS,
        use_sliding_windows=False,
    )
    pipeline = AEGISPipeline(
        packet_capture=None,
        flow_builder=builder,
        detection_engine=DetectionEngine(),
        risk_scorer=RiskScorer(),
        policy_engine=PolicyEngine(safe_mode=safe_mode),
        response_engine=ResponseEngine(safe_mode=safe_mode),
        event_store=recorder,
        flow_key_strategy=scenario.flow_key_strategy,
        use_sliding_windows=False,
    )

    # pipeline.start() would open a live capture; drive the processing path directly instead.
    pipeline._wire_callbacks()
    pipeline._accept_observations = True

    parser = ProtocolParser()
    packets = scenario.build(base_time, source)
    for raw in packets:
        parsed = parser.parse_packet(raw)
        if parsed is not None:
            pipeline.process_parsed_packet(parsed)

    # Close every window now instead of waiting for later traffic to rotate it out,
    # the same way the validation tests do.
    manager = builder.window_manager
    windows = list(manager.previous_windows)
    if manager.current_window is not None:
        windows.append(manager.current_window)
    for window in windows:
        manager._close_window(window)

    return SimulationResult(scenario=scenario, source_ip=source, packet_count=len(packets), events=recorder.saved)
