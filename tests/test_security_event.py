"""Tests for SecurityEvent modeling and SQLite persistence."""

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import sqlite3

import pytest

from app.models.detection import DetectionResult, DetectionSeverity
from app.models.flow import FlowKey
from app.models.packet import ParsedPacket, Protocol, TransportProtocol
from app.models.policy import ExecutionMode, PolicyAction, ResponseDecision, ResponseTarget
from app.models.response import ResponseResult, ResponseStatus
from app.models.risk import RiskLevel, RiskScore
from app.models.security_event import SecurityEvent, SecurityEventStatus
from app.storage.security_event_store import SQLiteSecurityEventStore


class NotJsonable:
    pass


def make_flow_key(src_ip="10.0.0.5", dst_ip="10.0.0.10", protocol="TCP", src_port=12345, dst_port=80):
    return FlowKey(src_ip=src_ip, dst_ip=dst_ip, protocol=protocol, src_port=src_port, dst_port=dst_port)


def make_detection(flow_key, window_start, window_end, *, rule_id="syn_flood", severity=DetectionSeverity.HIGH, evidence=None):
    return DetectionResult(
        rule_id=rule_id,
        rule_name="SYN Flood" if rule_id == "syn_flood" else "Port Scan",
        severity=severity,
        flow_key=flow_key,
        window_start=window_start,
        window_end=window_end,
        evidence=evidence if evidence is not None else {"syn_rate": 12.0, "response_target": {"ip": flow_key.src_ip, "port": flow_key.src_port, "role": "observed_source"}},
        explanation="detection explanation",
    )


def make_risk(flow_key, window_start, window_end, detections):
    return RiskScore(
        score=80,
        level=RiskLevel.CRITICAL,
        flow_key=flow_key,
        window_start=window_start,
        window_end=window_end,
        detections=list(detections),
        explanation="risk explanation",
    )


def make_policy(flow_key, window_start, window_end, detection_ids, *, target=None, action=PolicyAction.BLOCK_SOURCE, execution_mode=ExecutionMode.SIMULATE):
    return ResponseDecision(
        recommended_action=action,
        allowed=True,
        execution_mode=execution_mode,
        flow_key=flow_key,
        window_start=window_start,
        window_end=window_end,
        risk_score=80,
        risk_level=RiskLevel.CRITICAL,
        detection_ids=list(detection_ids),
        target=target,
        explanation="policy explanation",
    )


def make_response(*, action=PolicyAction.BLOCK_SOURCE, status=ResponseStatus.SIMULATED, target=None, timestamp=None):
    return ResponseResult(
        action=action,
        status=status,
        simulated=(status == ResponseStatus.SIMULATED),
        target=target,
        message="response message",
        error=None if status != ResponseStatus.REJECTED else "rejected",
        timestamp=timestamp or datetime(2024, 1, 1, 0, 0, 20, tzinfo=timezone.utc),
    )


def make_event(*, flow_key=None, window_start=None, window_end=None, detections=None, risk=None, policy=None, response=None, recorded_at=None):
    flow_key = flow_key or make_flow_key()
    window_start = window_start or datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    window_end = window_end or datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
    detections = detections if detections is not None else [make_detection(flow_key, window_start, window_end)]
    target = ResponseTarget(ip=flow_key.src_ip, port=flow_key.src_port, role="observed_source")
    risk = risk or make_risk(flow_key, window_start, window_end, detections)
    policy = policy or make_policy(flow_key, window_start, window_end, [d.rule_id for d in detections], target=target)
    response = response or make_response(target=target)
    recorded_at = recorded_at or datetime(2024, 1, 1, 0, 0, 30, tzinfo=timezone.utc)
    return SecurityEvent.create(
        flow_key=flow_key,
        window_start=window_start,
        window_end=window_end,
        detections=detections,
        risk=risk,
        policy=policy,
        response=response,
        recorded_at=recorded_at,
    )


class TestSecurityEventModel:
    def test_construction_and_immutability(self):
        event = make_event()
        assert event.lifecycle_status == SecurityEventStatus.SIMULATED
        with pytest.raises(FrozenInstanceError):
            event.event_id = "changed"

    def test_event_id_is_deterministic(self):
        first = make_event()
        second = make_event()
        assert first.event_id == second.event_id

    def test_different_identities_produce_different_event_ids(self):
        base = make_event()
        different_window = make_event(window_end=datetime(2024, 1, 1, 0, 0, 11, tzinfo=timezone.utc))
        different_flow = make_event(flow_key=make_flow_key(src_ip="10.0.0.6"))
        assert base.event_id != different_window.event_id
        assert base.event_id != different_flow.event_id

    def test_nested_models_preserved(self):
        event = make_event()
        assert event.detections[0].rule_id == "syn_flood"
        assert event.risk.level == RiskLevel.CRITICAL
        assert event.policy.recommended_action == PolicyAction.BLOCK_SOURCE
        assert event.response.status == ResponseStatus.SIMULATED

    def test_mismatched_detection_identity_rejected(self):
        flow_key = make_flow_key()
        start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
        bad_detection = make_detection(make_flow_key(src_ip="10.0.0.99"), start, end)
        risk = make_risk(flow_key, start, end, [bad_detection])
        target = ResponseTarget(ip=flow_key.src_ip, port=flow_key.src_port, role="observed_source")
        policy = make_policy(flow_key, start, end, [bad_detection.rule_id], target=target)
        response = make_response(target=target)
        with pytest.raises(ValueError, match="All detections must match"):
            SecurityEvent.create(
                flow_key=flow_key,
                window_start=start,
                window_end=end,
                detections=[bad_detection],
                risk=risk,
                policy=policy,
                response=response,
                recorded_at=datetime(2024, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
            )

    def test_mismatched_risk_identity_rejected(self):
        flow_key = make_flow_key()
        start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
        detections = [make_detection(flow_key, start, end)]
        bad_risk = make_risk(make_flow_key(src_ip="10.0.0.77"), start, end, detections)
        target = ResponseTarget(ip=flow_key.src_ip, port=flow_key.src_port, role="observed_source")
        policy = make_policy(flow_key, start, end, [d.rule_id for d in detections], target=target)
        response = make_response(target=target)
        with pytest.raises(ValueError, match="RiskScore must match"):
            SecurityEvent.create(
                flow_key=flow_key,
                window_start=start,
                window_end=end,
                detections=detections,
                risk=bad_risk,
                policy=policy,
                response=response,
                recorded_at=datetime(2024, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
            )

    def test_mismatched_policy_identity_rejected(self):
        flow_key = make_flow_key()
        start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
        detections = [make_detection(flow_key, start, end)]
        risk = make_risk(flow_key, start, end, detections)
        target = ResponseTarget(ip=flow_key.src_ip, port=flow_key.src_port, role="observed_source")
        bad_policy = make_policy(make_flow_key(src_ip="10.0.0.88"), start, end, [d.rule_id for d in detections], target=target)
        response = make_response(target=target)
        with pytest.raises(ValueError, match="ResponseDecision must match"):
            SecurityEvent.create(
                flow_key=flow_key,
                window_start=start,
                window_end=end,
                detections=detections,
                risk=risk,
                policy=bad_policy,
                response=response,
                recorded_at=datetime(2024, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
            )

    def test_mismatched_response_action_rejected(self):
        flow_key = make_flow_key()
        start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
        detections = [make_detection(flow_key, start, end)]
        risk = make_risk(flow_key, start, end, detections)
        target = ResponseTarget(ip=flow_key.src_ip, port=flow_key.src_port, role="observed_source")
        policy = make_policy(flow_key, start, end, [d.rule_id for d in detections], target=target)
        response = make_response(action=PolicyAction.ALERT_ONLY, status=ResponseStatus.NO_ACTION, target=target)
        with pytest.raises(ValueError, match="ResponseResult action must match"):
            SecurityEvent.create(
                flow_key=flow_key,
                window_start=start,
                window_end=end,
                detections=detections,
                risk=risk,
                policy=policy,
                response=response,
                recorded_at=datetime(2024, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
            )

    def test_mismatched_response_target_rejected(self):
        flow_key = make_flow_key()
        start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
        detections = [make_detection(flow_key, start, end)]
        risk = make_risk(flow_key, start, end, detections)
        policy_target = ResponseTarget(ip=flow_key.src_ip, port=flow_key.src_port, role="observed_source")
        response_target = ResponseTarget(ip="10.0.0.99", port=flow_key.src_port, role="observed_source")
        policy = make_policy(flow_key, start, end, [d.rule_id for d in detections], target=policy_target)
        response = make_response(target=response_target)
        with pytest.raises(ValueError, match="ResponseResult target must match"):
            SecurityEvent.create(
                flow_key=flow_key,
                window_start=start,
                window_end=end,
                detections=detections,
                risk=risk,
                policy=policy,
                response=response,
                recorded_at=datetime(2024, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
            )


class TestSecurityEventLifecycle:
    def test_no_action_maps_to_no_action(self):
        event = make_event(
            policy=make_policy(make_flow_key(), datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc), datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc), ["syn_flood"], target=None, action=PolicyAction.LOG_ONLY, execution_mode=ExecutionMode.NONE),
            response=make_response(action=PolicyAction.LOG_ONLY, status=ResponseStatus.NO_ACTION, target=None),
        )
        assert event.lifecycle_status == SecurityEventStatus.NO_ACTION

    def test_simulated_maps_to_simulated(self):
        event = make_event()
        assert event.lifecycle_status == SecurityEventStatus.SIMULATED

    def test_rejected_maps_to_rejected(self):
        flow_key = make_flow_key()
        target = ResponseTarget(ip=flow_key.src_ip, port=flow_key.src_port, role="observed_source")
        event = make_event(
            policy=make_policy(flow_key, datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc), datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc), ["syn_flood"], target=target, action=PolicyAction.BLOCK_SOURCE, execution_mode=ExecutionMode.EXECUTE),
            response=make_response(action=PolicyAction.BLOCK_SOURCE, status=ResponseStatus.REJECTED, target=target),
        )
        assert event.lifecycle_status == SecurityEventStatus.REJECTED

    def test_executed_is_unsupported(self):
        with pytest.raises(ValueError, match="unsupported"):
            make_event(response=make_response(status=ResponseStatus.EXECUTED))

    def test_failed_is_unsupported(self):
        with pytest.raises(ValueError, match="unsupported"):
            make_event(response=make_response(status=ResponseStatus.FAILED))


class TestSecurityEventSerialization:
    def test_full_round_trip(self):
        event = make_event()
        restored = SecurityEvent.from_serializable_dict(event.to_serializable_dict())
        assert restored == event

    def test_structured_evidence_round_trip(self):
        event = make_event(detections=[make_detection(make_flow_key(), datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc), datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc), evidence={"nested": {"numbers": [1, 2, 3], "ok": True}})])
        restored = SecurityEvent.from_serializable_dict(event.to_serializable_dict())
        assert restored.detections[0].evidence == {"nested": {"numbers": [1, 2, 3], "ok": True}}

    def test_timezone_preserved(self):
        event = make_event()
        serialized = event.to_serializable_dict()
        restored = SecurityEvent.from_serializable_dict(serialized)
        assert restored.window_start.tzinfo is not None
        assert restored.recorded_at.tzinfo is not None
        assert restored.window_start.utcoffset() == timezone.utc.utcoffset(restored.window_start)

    def test_unsupported_evidence_rejected(self):
        flow_key = make_flow_key()
        start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
        bad_detection = make_detection(flow_key, start, end, evidence={"bad": NotJsonable()})
        risk = make_risk(flow_key, start, end, [bad_detection])
        target = ResponseTarget(ip=flow_key.src_ip, port=flow_key.src_port, role="observed_source")
        policy = make_policy(flow_key, start, end, [bad_detection.rule_id], target=target)
        response = make_response(target=target)
        with pytest.raises(ValueError, match="unsupported non-JSON data"):
            SecurityEvent.create(
                flow_key=flow_key,
                window_start=start,
                window_end=end,
                detections=[bad_detection],
                risk=risk,
                policy=policy,
                response=response,
                recorded_at=datetime(2024, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
            )

    def test_raw_packet_object_rejected(self):
        flow_key = make_flow_key()
        start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
        packet = ParsedPacket(
            timestamp=datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
            src_mac="00:11:22:33:44:55",
            dst_mac="66:77:88:99:aa:bb",
            ethertype=0x0800,
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            transport_protocol=TransportProtocol.TCP,
            src_port=12345,
            dst_port=80,
            size=60,
        )
        bad_detection = make_detection(flow_key, start, end, evidence={"packet": packet})
        risk = make_risk(flow_key, start, end, [bad_detection])
        target = ResponseTarget(ip=flow_key.src_ip, port=flow_key.src_port, role="observed_source")
        policy = make_policy(flow_key, start, end, [bad_detection.rule_id], target=target)
        response = make_response(target=target)
        with pytest.raises(ValueError, match="unsupported non-JSON data"):
            SecurityEvent.create(
                flow_key=flow_key,
                window_start=start,
                window_end=end,
                detections=[bad_detection],
                risk=risk,
                policy=policy,
                response=response,
                recorded_at=datetime(2024, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
            )


class TestSQLiteSecurityEventStore:
    def test_save_get_and_list_recent(self, tmp_path):
        db_url = f"sqlite:///{tmp_path / 'events.db'}"
        store = SQLiteSecurityEventStore(db_url)
        older = make_event(recorded_at=datetime(2024, 1, 1, 0, 0, 30, tzinfo=timezone.utc))
        newer = make_event(
            flow_key=make_flow_key(src_ip="10.0.0.6"),
            recorded_at=datetime(2024, 1, 1, 0, 0, 40, tzinfo=timezone.utc),
        )

        assert store.save(older) is True
        assert store.save(newer) is True

        loaded = store.get(older.event_id)
        assert loaded == older

        recent = store.list_recent(limit=10)
        assert [event.event_id for event in recent] == [newer.event_id, older.event_id]

    def test_limit_validation(self, tmp_path):
        store = SQLiteSecurityEventStore(f"sqlite:///{tmp_path / 'events.db'}")
        with pytest.raises(ValueError, match="positive integer"):
            store.list_recent(limit=0)

    def test_exact_duplicate_save_is_idempotent(self, tmp_path):
        store = SQLiteSecurityEventStore(f"sqlite:///{tmp_path / 'events.db'}")
        event = make_event()
        assert store.save(event) is True
        assert store.save(event) is True
        assert store.get(event.event_id) == event

    def test_conflicting_duplicate_is_rejected(self, tmp_path):
        store = SQLiteSecurityEventStore(f"sqlite:///{tmp_path / 'events.db'}")
        first = make_event()
        second = make_event(recorded_at=datetime(2024, 1, 1, 0, 0, 31, tzinfo=timezone.utc))
        assert store.save(first) is True
        object.__setattr__(second, "event_id", first.event_id)
        with pytest.raises(ValueError, match="Conflicting SecurityEvent"):
            store.save(second)

    def test_database_survives_reopening(self, tmp_path):
        db_path = tmp_path / "events.db"
        db_url = f"sqlite:///{db_path}"
        first_store = SQLiteSecurityEventStore(db_url)
        event = make_event()
        assert first_store.save(event) is True

        reopened = SQLiteSecurityEventStore(db_url)
        assert reopened.get(event.event_id) == event

    def test_database_error_surfaces_clearly(self, tmp_path):
        store = SQLiteSecurityEventStore(f"sqlite:///{tmp_path / 'events.db'}")
        event = make_event()
        with store._connect() as conn:
            conn.execute("DROP TABLE security_events")
            conn.commit()
        with pytest.raises(RuntimeError, match="Failed to save SecurityEvent"):
            store.save(event)
