"""Attack simulations run synthetic packets through the real pipeline."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.api.routes import simulations as simulation_routes
from app.api.routes.shared import get_event_store
from app.config.settings import settings
from app.models.policy import PolicyAction
from app.models.risk import RiskLevel
from app.models.response import ResponseStatus
from app.simulation.scenarios import SCENARIOS, is_simulated_source, run_scenario
from app.storage.security_event_store import SecurityEventStore


class MemoryStore(SecurityEventStore):
    def __init__(self):
        self.events = {}

    def save(self, event):
        existing = self.events.get(event.event_id)
        if existing is not None and existing != event:
            raise ValueError("Conflicting SecurityEvent already exists for this event_id")
        self.events[event.event_id] = event
        return True

    def get(self, event_id):
        return self.events.get(event_id)

    def list_recent(self, limit=100):
        return sorted(self.events.values(), key=lambda e: e.recorded_at, reverse=True)[:limit]


NOW = datetime(2026, 10, 7, 12, 0, 3, tzinfo=timezone.utc)


def run(scenario_id, **kwargs):
    store = MemoryStore()
    return run_scenario(scenario_id, store, now=NOW, source_ip=kwargs.pop("source_ip", None), **kwargs), store


class TestScenarios:
    def test_benign_traffic_stores_nothing(self):
        result, store = run("benign")
        assert result.packet_count == 5
        assert result.events == []
        assert store.events == {}

    def test_syn_flood_is_high_severity_medium_risk_alert(self):
        result, store = run("syn_flood")
        assert len(result.events) == 1
        event = result.events[0]
        assert [d.rule_id for d in event.detections] == ["syn_flood"]
        assert event.detections[0].severity.value == "high"
        assert event.risk.score == 55
        assert event.risk.level == RiskLevel.MEDIUM
        assert event.policy.recommended_action == PolicyAction.ALERT_ONLY
        assert event.response.status == ResponseStatus.NO_ACTION
        assert event.event_id in store.events

    def test_port_scan_is_high_severity_medium_risk(self):
        result, _ = run("port_scan")
        event = result.events[0]
        assert [d.rule_id for d in event.detections] == ["port_scan"]
        assert event.detections[0].evidence["features"]["unique_destination_ports"] == 32
        assert event.risk.score == 40
        assert event.risk.level == RiskLevel.MEDIUM

    def test_fast_scan_fires_both_rules_and_is_critical_but_never_blocks(self):
        result, _ = run("fast_scan")
        event = result.events[0]
        assert sorted(d.rule_id for d in event.detections) == ["port_scan", "syn_flood"]
        assert event.risk.score == 95
        assert event.risk.level == RiskLevel.CRITICAL
        # No rule attaches an observed source, so the policy refuses to block.
        assert event.policy.recommended_action == PolicyAction.ALERT_ONLY
        assert event.response.status == ResponseStatus.NO_ACTION

    def test_slow_scan_sits_on_the_threshold(self):
        result, _ = run("slow_scan")
        event = result.events[0]
        assert event.detections[0].severity.value == "medium"
        assert event.risk.score == 25
        assert event.risk.level == RiskLevel.LOW
        assert event.policy.recommended_action == PolicyAction.LOG_ONLY

    def test_sources_come_from_documentation_ranges(self):
        for scenario_id in SCENARIOS:
            result, _ = run(scenario_id)
            assert is_simulated_source(result.source_ip)

    def test_windows_have_closed_before_the_event_is_recorded(self):
        result, _ = run("syn_flood")
        event = result.events[0]
        assert event.window_end <= NOW


@pytest.fixture
def client():
    def factory(store):
        app.dependency_overrides[get_event_store] = lambda: store
        simulation_routes.reset_rate_limit()
        return TestClient(app)

    yield factory
    app.dependency_overrides.clear()


class TestSimulationApi:
    def test_lists_scenarios(self, client):
        response = client(MemoryStore()).get("/simulations")
        assert response.status_code == 200
        body = response.json()
        assert body["enabled"] is True
        assert {item["id"] for item in body["scenarios"]} == set(SCENARIOS)

    def test_runs_a_scenario_and_stores_the_engine_event(self, client):
        store = MemoryStore()
        response = client(store).post("/simulations", json={"scenario": "fast_scan"})
        assert response.status_code == 201
        body = response.json()
        assert body["stored"] == 1
        assert body["events"][0]["risk"]["score"] == 95
        assert body["events"][0]["event_id"] in store.events

    def test_benign_run_reports_nothing_stored(self, client):
        response = client(MemoryStore()).post("/simulations", json={"scenario": "benign"})
        assert response.status_code == 201
        assert response.json()["stored"] == 0

    def test_unknown_scenario(self, client):
        response = client(MemoryStore()).post("/simulations", json={"scenario": "icmp_storm"})
        assert response.status_code == 404
        assert response.json()["detail"]["code"] == "unknown_scenario"

    def test_disabled_by_setting(self, client, monkeypatch):
        monkeypatch.setattr(settings, "allow_simulations", False)
        response = client(MemoryStore()).post("/simulations", json={"scenario": "syn_flood"})
        assert response.status_code == 403
        assert response.json()["detail"]["code"] == "simulations_disabled"

    def test_rate_limited(self, client):
        api = client(MemoryStore())
        assert api.post("/simulations", json={"scenario": "benign"}).status_code == 201
        second = api.post("/simulations", json={"scenario": "benign"})
        assert second.status_code == 429

    def test_events_endpoint_stays_read_only(self, client):
        assert client(MemoryStore()).post("/events", json={}).status_code == 405
