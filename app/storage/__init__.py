"""Persistence/storage interfaces for AEGIS."""

from app.storage.security_event_store import SecurityEventStore, SQLiteSecurityEventStore

__all__ = ["SecurityEventStore", "SQLiteSecurityEventStore"]
