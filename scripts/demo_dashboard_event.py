from datetime import datetime, timedelta, timezone

from app.detection.engine import DetectionEngine
from app.flows.flow_builder import FlowBuilder
from app.pipeline import AEGISPipeline
from app.policy.engine import PolicyEngine
from app.protocols.parser import ProtocolParser
from app.response.engine import ResponseEngine
from app.scoring.risk_scorer import RiskScorer
from app.storage.security_event_store import SQLiteSecurityEventStore

from tests.helpers.traffic_factory import port_scan_sequence, tcp_packet


def main() -> None:
    parser = ProtocolParser()
    store = SQLiteSecurityEventStore("sqlite:///aegis.db")

    builder = FlowBuilder(
        flow_key_strategy="three_tuple",
        window_seconds=5,
        use_sliding_windows=False,
    )

    pipeline = AEGISPipeline(
        packet_capture=None,
        flow_builder=builder,
        detection_engine=DetectionEngine(),
        risk_scorer=RiskScorer(),
        policy_engine=PolicyEngine(safe_mode=True),
        response_engine=ResponseEngine(safe_mode=True),
        event_store=store,
        flow_key_strategy="three_tuple",
        use_sliding_windows=False,
    )

    # We deliberately do NOT call pipeline.start(), because that would
    # start live packet capture/Npcap. Instead, use the existing processing
    # path directly with deterministic in-memory packets.
    pipeline._wire_callbacks()

    base = datetime.now(timezone.utc) - timedelta(seconds=10)

    packets = port_scan_sequence(
        base_time=base,
        dst_ports=list(range(80, 101)),  # 21 unique ports
        step=timedelta(milliseconds=120),
    )

    for raw in packets:
        parsed = parser.parse_packet(raw)
        if parsed is not None:
            pipeline._accept_observations = True
            pipeline.process_parsed_packet(parsed)

    # Push event time into the next window so the first window is rotated.
    closing_raw = tcp_packet(
        src_ip="10.0.0.5",
        dst_ip="10.0.0.10",
        src_port=65000,
        dst_port=443,
        flags="A",
        timestamp=base + timedelta(seconds=6),
    )

    closing_packet = parser.parse_packet(closing_raw)
    if closing_packet is not None:
        pipeline.process_parsed_packet(closing_packet)

    # For this deterministic demo, explicitly close retained windows.
    previous = list(builder.window_manager.previous_windows)

    for window in previous:
        builder.window_manager._close_window(window)

    builder.window_manager.previous_windows = []

    events = store.list_recent(limit=10)

    print("\n" + "=" * 60)
    print("AEGIS DASHBOARD DEMO EVENT")
    print("=" * 60)

    if not events:
        print("No SecurityEvent was generated.")
        return

    event = events[0]

    print(f"Event ID:       {event.event_id}")
    print(f"Flow:           {event.flow_key}")
    print(f"Window:         {event.window_start} -> {event.window_end}")
    print(f"Risk:           {event.risk.score}/100")
    print(f"Risk Level:     {event.risk.level.value}")
    print(f"Policy:         {event.policy.recommended_action.value}")
    print(f"Execution:      {event.policy.execution_mode.value}")
    print(f"Response:       {event.response.status.value}")
    print(f"Lifecycle:      {event.lifecycle_status.value}")

    print("\nDetections:")
    for detection in event.detections:
        features = detection.evidence.get("features", {})
        print(f"  - {detection.rule_id}")
        print(f"    severity: {detection.severity.value}")
        print(
            "    unique destination ports:",
            features.get("unique_destination_ports"),
        )

    print("=" * 60)


if __name__ == "__main__":
    main()