"""Health endpoint for the AEGIS REST API."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.routes.shared import get_event_store
from app.config.settings import settings
from app.storage.security_event_store import SecurityEventStore

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


@router.get("/health")
def get_health(event_store: SecurityEventStore = Depends(get_event_store)) -> dict:
    try:
        event_store.list_recent(limit=1)
    except Exception as exc:
        logger.error("Health check failed while reaching event store: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "storage_unavailable",
                "message": "Security event storage is unavailable.",
            },
        ) from exc

    return {
        "status": "ok",
        "app_name": settings.app_name,
        "app_version": settings.app_version,
        "database": "ok",
    }
