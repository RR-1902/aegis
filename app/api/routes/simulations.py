"""Attack simulation endpoints.

These are the only write endpoints in the API. They never accept event data from the client:
the client names a scenario, and the server runs synthetic packets through the real pipeline,
which decides what, if anything, to store. Stored events remain immutable and are read back
through the read-only /events endpoints.
"""

from __future__ import annotations

import logging
import threading
import time

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.api.routes.shared import get_event_store
from app.config.settings import settings
from app.simulation.scenarios import SCENARIOS, run_scenario
from app.storage.security_event_store import SecurityEventStore

logger = logging.getLogger(__name__)
router = APIRouter(tags=["simulations"])

# One run per interval across the whole process keeps a public demo from being flooded.
MIN_INTERVAL_SECONDS = 1.0
_lock = threading.Lock()
_last_run = 0.0


class SimulationRequest(BaseModel):
    scenario: str


def _scenario_summary(scenario) -> dict:
    return {
        "id": scenario.id,
        "name": scenario.name,
        "summary": scenario.summary,
        "flow_key_strategy": scenario.flow_key_strategy,
        "target": scenario.target,
    }


@router.get("/simulations")
def list_simulations() -> dict:
    return {
        "enabled": settings.allow_simulations,
        "scenarios": [_scenario_summary(scenario) for scenario in SCENARIOS.values()],
    }


@router.post("/simulations", status_code=status.HTTP_201_CREATED)
def run_simulation(
    request: SimulationRequest,
    event_store: SecurityEventStore = Depends(get_event_store),
) -> dict:
    global _last_run

    if not settings.allow_simulations:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "simulations_disabled", "message": "Simulations are turned off on this server."},
        )
    if request.scenario not in SCENARIOS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "unknown_scenario", "message": f"There is no scenario called {request.scenario!r}."},
        )

    with _lock:
        now = time.monotonic()
        if now - _last_run < MIN_INTERVAL_SECONDS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={"code": "too_many_requests", "message": "Wait a second before running another simulation."},
            )
        _last_run = now
        try:
            result = run_scenario(request.scenario, event_store, safe_mode=settings.safe_mode)
        except RuntimeError as exc:
            logger.error("Simulation could not reach storage: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "storage_unavailable", "message": "Security event storage is unavailable."},
            ) from exc

    return {
        "scenario": _scenario_summary(result.scenario),
        "source_ip": result.source_ip,
        "packets": result.packet_count,
        "stored": len(result.events),
        "events": [event.to_serializable_dict() for event in result.events],
    }


def reset_rate_limit() -> None:
    """Test helper: forget the last run time."""
    global _last_run
    with _lock:
        _last_run = 0.0
