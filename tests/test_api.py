"""Read-only REST API tests for AEGIS security events."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.api.routes.shared import get_event_store
from app.detection.engine import DetectionEngine
from app.models.flow import FeatureObservation, FlowKey
from app.policy.engine import PolicyEngine
from app.response.engine import ResponseEngine
from app.scoring.risk_scorer import RiskScorer
from app.storage.security_event_store import SecurityEventStore
from app.models.security_event import SecurityEvent


class InMemoryApiStore(SecurityEventStore):
    def __init__(self, events=None, *, fail=False, malformed_on_get=False, malformed_on_list=False):
        self.events = list(events or [])
        self.fail = fail
        self.malformed_on_get = malformed_on_get
        self.malformed_on_list = malformed_on_list

    def save(self, event: SecurityEvent) -> bool:
        raise NotImplementedError("API tests are read-only")

    def get(self, event_id: str):
        if self.fail:
            raise RuntimeError("db unavailable")
        if self.malformed_on_get:
            raise ValueError("bad persisted record")
        for event in self.events:
            if event.event_id == event_id:
                return event
        return None

    def list_recent(self, limit: int = 100):
        if self.fail:
            raise RuntimeError("db unavailable")
        if self.malformed_on_list:
            raise ValueError("bad persisted record")
        return sorted(self.events, key=lambda e: (e.recorded_at, e.event_id), reverse=True)[:limit]


def make_event(*, recorded_at: datetime, risk_ports: int = 20, syn_rate: float = 10.0, incomplete_ratio: float = 1.0):
    flow_key = FlowKey(src_ip="10.0.0.5", dst_ip="10.0.0.10", protocol="TCP")
    window_start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    window_end = datetime(2024, 1, 1, 0, 0, 5, tzinfo=timezone.utc)
    observation = FeatureObservation(
        flow_key=flow_key,
        window_start=window_start,
        window_end=window_end,
        features={
            "unique_destination_ports": risk_ports,
            "syn_rate": syn_rate,
            "incomplete_connection_ratio": incomplete_ratio,
            "syn_count": int(round(syn_rate)),
            "connection_attempts": int(round(syn_rate)),
            "packet_count": int(round(syn_rate)),
        },
        finalized=True,
        sliding=False,
    )
    detections = DetectionEngine().evaluate(observation)
    risk = RiskScorer().score(detections)
    policy = PolicyEngine(safe_mode=True).decide(risk)
    response = ResponseEngine(safe_mode=True).handle(policy)
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


@pytest.fixture
def client():
    def _make(store: SecurityEventStore):
        app.dependency_overrides[get_event_store] = lambda: store
        return TestClient(app)

    yield _make
    app.dependency_overrides.clear()


class TestHealthEndpoint:
    def test_health_ok(self, client):
        response = client(InMemoryApiStore()).get("/health")
        assert response.status_code == 200
        assert response.json() == {
            "status": "ok",
            "app_name": "AEGIS",
            "app_version": "0.1.0",
            "database": "ok",
        }

    def test_health_storage_failure(self, client):
        response = client(InMemoryApiStore(fail=True)).get("/health")
        assert response.status_code == 503
        body = response.json()
        assert body["detail"]["code"] == "storage_unavailable"


class TestEventsEndpoint:
    def test_list_events_empty(self, client):
        response = client(InMemoryApiStore()).get("/events")
        assert response.status_code == 200
        assert response.json() == {"items": [], "count": 0, "limit": 50}

    def test_list_events_recent_ordering(self, client):
        older = make_event(recorded_at=datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc), risk_ports=20)
        newer = make_event(recorded_at=datetime(2024, 1, 1, 0, 0, 20, tzinfo=timezone.utc), risk_ports=21)
        response = client(InMemoryApiStore([older, newer])).get("/events?limit=2")
        assert response.status_code == 200
        items = response.json()["items"]
        assert [item["recorded_at"] for item in items] == [
            newer.recorded_at.isoformat(),
            older.recorded_at.isoformat(),
        ]

    def test_limit_validation(self, client):
        response = client(InMemoryApiStore()).get("/events?limit=0")
        assert response.status_code == 422

    def test_filter_by_risk_level(self, client):
        high = make_event(recorded_at=datetime(2024, 1, 1, 0, 0, 20, tzinfo=timezone.utc), risk_ports=20)
        critical = make_event(recorded_at=datetime(2024, 1, 1, 0, 0, 30, tzinfo=timezone.utc), risk_ports=21, syn_rate=11.0)
        response = client(InMemoryApiStore([high, critical])).get("/events?risk_level=critical")
        assert response.status_code == 200
        items = response.json()["items"]
        assert len(items) == 1
        assert items[0]["risk"]["level"] == "critical"

    def test_filter_by_lifecycle_status(self, client):
        event = make_event(recorded_at=datetime(2024, 1, 1, 0, 0, 20, tzinfo=timezone.utc), risk_ports=20)
        response = client(InMemoryApiStore([event])).get("/events?lifecycle_status=no_action")
        assert response.status_code == 200
        items = response.json()["items"]
        assert len(items) == 1
        assert items[0]["lifecycle_status"] == "no_action"

    def test_get_event(self, client):
        event = make_event(recorded_at=datetime(2024, 1, 1, 0, 0, 20, tzinfo=timezone.utc), risk_ports=21)
        response = client(InMemoryApiStore([event])).get(f"/events/{event.event_id}")
        assert response.status_code == 200
        assert response.json()["event_id"] == event.event_id

    def test_get_event_not_found(self, client):
        response = client(InMemoryApiStore()).get("/events/security-event:missing")
        assert response.status_code == 404
        body = response.json()
        assert body["detail"]["code"] == "event_not_found"

    def test_storage_failure(self, client):
        response = client(InMemoryApiStore(fail=True)).get("/events")
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == "storage_unavailable"

    def test_malformed_record_failure(self, client):
        response = client(InMemoryApiStore(malformed_on_list=True)).get("/events")
        assert response.status_code == 500
        assert response.json()["detail"]["code"] == "invalid_persisted_record"

    def test_json_serialization_exposes_no_raw_packets(self, client):
        event = make_event(recorded_at=datetime(2024, 1, 1, 0, 0, 20, tzinfo=timezone.utc), risk_ports=20)
        response = client(InMemoryApiStore([event])).get("/events")
        assert response.status_code == 200
        item = response.json()["items"][0]
        assert "event_id" in item
        assert "flow_key" in item
        assert "detections" in item
        assert "risk" in item
        assert "policy" in item
        assert "response" in item
        assert "raw_packet" not in str(item).lower()
        assert "payload" not in item

    def test_read_only_behavior(self, client):
        response = client(InMemoryApiStore()).post("/events", json={})
        assert response.status_code == 405
