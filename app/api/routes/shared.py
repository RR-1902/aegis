"""Shared API dependencies."""

from __future__ import annotations

from app.config.settings import settings
from app.storage.security_event_store import SQLiteSecurityEventStore, SecurityEventStore


def get_event_store() -> SecurityEventStore:
    return SQLiteSecurityEventStore(settings.database_url)
