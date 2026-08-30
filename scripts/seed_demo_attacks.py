"""Seed multiple realistic attack events (SYN Flood, Port Scan, ICMP Storm) into aegis.db."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models.detection import DetectionResult, DetectionSeverity
from app.models.flow import FlowKey
from app.models.policy import ExecutionMode, PolicyAction, ResponseDecision, ResponseTarget
from app.models.response import ResponseResult, ResponseStatus
from app.models.risk import RiskLevel, RiskScore
from app.models.security_event import SecurityEvent
from app.storage.security_event_store import SQLiteSecurityEventStore


def generate_seed_events() -> list[SecurityEvent]:
    now = datetime.now(timezone.utc)
    events: list[SecurityEvent] = []

    # 1. Critical SYN Flood
    t1_end = now - timedelta(minutes=2)
    t1_start = t1_end - timedelta(seconds=5)
    flow_1 = FlowKey(src_ip="198.51.100.44", dst_ip="10.0.0.1", protocol="TCP", src_port=54201, dst_port=80)

    det_1 = DetectionResult(
        rule_id="syn_flood",
        rule_name="SYN Flood Attack Signature",
        severity=DetectionSeverity.HIGH,
        flow_key=flow_1,
        window_start=t1_start,
        window_end=t1_end,
        evidence={"syn_rate": 182.4, "syn_ack_ratio": 0.994, "total_syn_pkts": 912},
        explanation="Abnormal volume of SYN packets without handshake completion observed.",
    )

    risk_1 = RiskScore(
        score=95,
        level=RiskLevel.CRITICAL,
        flow_key=flow_1,
        window_start=t1_start,
        window_end=t1_end,
        detections=[det_1],
        explanation="High packet velocity and extreme SYN:ACK ratio exceeded critical threshold.",
    )

    target_1 = ResponseTarget(ip="198.51.100.44", port=None, role="source")

    policy_1 = ResponseDecision(
        recommended_action=PolicyAction.BLOCK_SOURCE,
        allowed=True,
        execution_mode=ExecutionMode.SIMULATE,
        flow_key=flow_1,
        window_start=t1_start,
        window_end=t1_end,
        risk_score=95,
        risk_level=RiskLevel.CRITICAL,
        detection_ids=["syn_flood"],
        target=target_1,
        explanation="Safety rail active: Simulated iptables DROP for source IP 198.51.100.44.",
    )

    resp_1 = ResponseResult(
        action=PolicyAction.BLOCK_SOURCE,
        status=ResponseStatus.SIMULATED,
        simulated=True,
        target=target_1,
        message="Simulated firewall drop rule injected. No physical network disruption.",
        error=None,
        timestamp=t1_end + timedelta(milliseconds=120),
    )

    events.append(
        SecurityEvent.create(
            flow_key=flow_1,
            window_start=t1_start,
            window_end=t1_end,
            detections=[det_1],
            risk=risk_1,
            policy=policy_1,
            response=resp_1,
            recorded_at=t1_end,
        )
    )

    # 2. High Severity Horizontal Port Scan
    t2_end = now - timedelta(minutes=7)
    t2_start = t2_end - timedelta(seconds=10)
    flow_2 = FlowKey(src_ip="203.0.113.88", dst_ip="10.0.0.2", protocol="TCP", src_port=49812, dst_port=None)

    det_2 = DetectionResult(
        rule_id="port_scan",
        rule_name="Nmap Stealth SYN Port Scan",
        severity=DetectionSeverity.HIGH,
        flow_key=flow_2,
        window_start=t2_start,
        window_end=t2_end,
        evidence={"unique_destination_ports": 48, "scan_duration_ms": 1200},
        explanation="Probed 48 distinct destination ports in under 2.0 seconds.",
    )

    risk_2 = RiskScore(
        score=78,
        level=RiskLevel.HIGH,
        flow_key=flow_2,
        window_start=t2_start,
        window_end=t2_end,
        detections=[det_2],
        explanation="Reconnaissance probe detected across system service ports.",
    )

    target_2 = ResponseTarget(ip="203.0.113.88", port=None, role="source")

    policy_2 = ResponseDecision(
        recommended_action=PolicyAction.BLOCK_SOURCE,
        allowed=True,
        execution_mode=ExecutionMode.SIMULATE,
        flow_key=flow_2,
        window_start=t2_start,
        window_end=t2_end,
        risk_score=78,
        risk_level=RiskLevel.HIGH,
        detection_ids=["port_scan"],
        target=target_2,
        explanation="Applied simulated IP block on scanning host 203.0.113.88.",
    )

    resp_2 = ResponseResult(
        action=PolicyAction.BLOCK_SOURCE,
        status=ResponseStatus.SIMULATED,
        simulated=True,
        target=target_2,
        message="Simulated firewall drop rule injected for scanning host 203.0.113.88.",
        error=None,
        timestamp=t2_end + timedelta(milliseconds=85),
    )

    events.append(
        SecurityEvent.create(
            flow_key=flow_2,
            window_start=t2_start,
            window_end=t2_end,
            detections=[det_2],
            risk=risk_2,
            policy=policy_2,
            response=resp_2,
            recorded_at=t2_end,
        )
    )

    # 3. Medium Severity ICMP Blast
    t3_end = now - timedelta(minutes=14)
    t3_start = t3_end - timedelta(seconds=5)
    flow_3 = FlowKey(src_ip="192.0.2.15", dst_ip="10.0.0.255", protocol="ICMP", src_port=None, dst_port=None)

    det_3 = DetectionResult(
        rule_id="icmp_spike",
        rule_name="ICMP Broadcast Spike / Smurf Vector",
        severity=DetectionSeverity.MEDIUM,
        flow_key=flow_3,
        window_start=t3_start,
        window_end=t3_end,
        evidence={"icmp_rate": 140.2, "payload_size": 1024},
        explanation="High volume ICMP echo request storm targeting subnet broadcast.",
    )

    risk_3 = RiskScore(
        score=54,
        level=RiskLevel.MEDIUM,
        flow_key=flow_3,
        window_start=t3_start,
        window_end=t3_end,
        detections=[det_3],
        explanation="Medium anomalous bandwidth burst on ICMP protocol.",
    )

    policy_3 = ResponseDecision(
        recommended_action=PolicyAction.ALERT_ONLY,
        allowed=True,
        execution_mode=ExecutionMode.SIMULATE,
        flow_key=flow_3,
        window_start=t3_start,
        window_end=t3_end,
        risk_score=54,
        risk_level=RiskLevel.MEDIUM,
        detection_ids=["icmp_spike"],
        target=None,
        explanation="Policy configured for alert notification only.",
    )

    resp_3 = ResponseResult(
        action=PolicyAction.ALERT_ONLY,
        status=ResponseStatus.NO_ACTION,
        simulated=True,
        target=None,
        message="Security alert dispatched to telemetry feed.",
        error=None,
        timestamp=t3_end + timedelta(milliseconds=40),
    )

    events.append(
        SecurityEvent.create(
            flow_key=flow_3,
            window_start=t3_start,
            window_end=t3_end,
            detections=[det_3],
            risk=risk_3,
            policy=policy_3,
            response=resp_3,
            recorded_at=t3_end,
        )
    )

    return events


def main() -> None:
    store = SQLiteSecurityEventStore("sqlite:///aegis.db")
    events = generate_seed_events()
    for ev in events:
        store.save(ev)
    print(f"Successfully seeded {len(events)} security attack events into aegis.db")


if __name__ == "__main__":
    main()
