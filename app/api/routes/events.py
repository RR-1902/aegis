"""Read-only security event endpoints."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.routes.shared import get_event_store
from app.models.risk import RiskLevel
from app.models.security_event import SecurityEvent, SecurityEventStatus
from app.storage.security_event_store import SecurityEventStore

logger = logging.getLogger(__name__)
router = APIRouter(tags=["events"])


@dataclass(frozen=True)
class EventListQuery:
    limit: int
    risk_level: Optional[RiskLevel]
    lifecycle_status: Optional[SecurityEventStatus]


def _serialize_event(event: SecurityEvent) -> dict:
    return event.to_serializable_dict()


def _safe_storage_failure(exc: Exception) -> HTTPException:
    logger.error("Security event API storage failure: %s", exc)
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "code": "storage_unavailable",
            "message": "Security event storage is unavailable.",
        },
    )


def _safe_record_failure(exc: Exception) -> HTTPException:
    logger.error("Security event API encountered malformed persisted data: %s", exc)
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={
            "code": "invalid_persisted_record",
            "message": "A persisted security event record is invalid.",
        },
    )


def _filter_events(events: list[SecurityEvent], query: EventListQuery) -> list[SecurityEvent]:
    filtered = events
    if query.risk_level is not None:
        filtered = [event for event in filtered if event.risk.level == query.risk_level]
    if query.lifecycle_status is not None:
        filtered = [event for event in filtered if event.lifecycle_status == query.lifecycle_status]
    return filtered


@router.get("/events")
def list_events(
    limit: int = Query(default=50, ge=1, le=200),
    risk_level: Optional[RiskLevel] = Query(default=None),
    lifecycle_status: Optional[SecurityEventStatus] = Query(default=None),
    event_store: SecurityEventStore = Depends(get_event_store),
) -> dict:
    query = EventListQuery(limit=limit, risk_level=risk_level, lifecycle_status=lifecycle_status)
    try:
        events = event_store.list_recent(limit=query.limit)
        items = [_serialize_event(event) for event in _filter_events(events, query)]
    except RuntimeError as exc:
        raise _safe_storage_failure(exc) from exc
    except ValueError as exc:
        raise _safe_record_failure(exc) from exc

    return {
        "items": items,
        "count": len(items),
        "limit": query.limit,
    }


@router.get("/events/{event_id}")
def get_event(event_id: str, event_store: SecurityEventStore = Depends(get_event_store)) -> dict:
    try:
        event = event_store.get(event_id)
    except RuntimeError as exc:
        raise _safe_storage_failure(exc) from exc
    except ValueError as exc:
        raise _safe_record_failure(exc) from exc

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "event_not_found",
                "message": "SecurityEvent not found.",
            },
        )

    return _serialize_event(event)
