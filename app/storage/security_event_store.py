"""Security event persistence abstractions and SQLite store for AEGIS."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import sqlite3
from typing import List, Optional

from app.models.security_event import SecurityEvent


class SecurityEventStore(ABC):
    """Minimal persistence interface for durable security events."""

    @abstractmethod
    def save(self, event: SecurityEvent) -> bool:
        """Persist one complete event idempotently."""
        raise NotImplementedError

    @abstractmethod
    def get(self, event_id: str) -> Optional[SecurityEvent]:
        """Return one event by deterministic ID, if present."""
        raise NotImplementedError

    @abstractmethod
    def list_recent(self, limit: int = 100) -> List[SecurityEvent]:
        """Return most recent events ordered by recorded_at descending."""
        raise NotImplementedError


@dataclass
class SQLiteSecurityEventStore(SecurityEventStore):
    """SQLite-backed durable store for immutable SecurityEvent records."""

    database_url: str

    def __post_init__(self) -> None:
        self._db_path = self._parse_sqlite_database_url(self.database_url)
        self._initialize_database()

    @staticmethod
    def _parse_sqlite_database_url(database_url: str) -> str:
        prefix = "sqlite:///"
        if not database_url.startswith(prefix):
            raise ValueError("SQLiteSecurityEventStore requires a sqlite:/// database_url")
        path = database_url[len(prefix):]
        if not path:
            raise ValueError("SQLite database_url must include a database path")
        return path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_database(self) -> None:
        db_path = Path(self._db_path)
        if db_path.parent and str(db_path.parent) not in ("", "."):
            db_path.parent.mkdir(parents=True, exist_ok=True)

        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    src_port INTEGER NULL,
                    dst_port INTEGER NULL,
                    window_start TEXT NOT NULL,
                    window_end TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    lifecycle_status TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    detections_json TEXT NOT NULL,
                    risk_json TEXT NOT NULL,
                    policy_json TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    event_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_security_events_recorded_at ON security_events(recorded_at DESC, event_id DESC)"
            )
            conn.commit()

    def save(self, event: SecurityEvent) -> bool:
        serialized = event.to_serializable_dict()
        event_json = json.dumps(serialized, sort_keys=True, separators=(",", ":"))
        detections_json = json.dumps(serialized["detections"], sort_keys=True, separators=(",", ":"))
        risk_json = json.dumps(serialized["risk"], sort_keys=True, separators=(",", ":"))
        policy_json = json.dumps(serialized["policy"], sort_keys=True, separators=(",", ":"))
        response_json = json.dumps(serialized["response"], sort_keys=True, separators=(",", ":"))

        try:
            with self._connect() as conn:
                existing = conn.execute(
                    "SELECT event_json FROM security_events WHERE event_id = ?",
                    (event.event_id,),
                ).fetchone()

                if existing is not None:
                    if existing["event_json"] == event_json:
                        return True
                    raise ValueError("Conflicting SecurityEvent already exists for this event_id")

                conn.execute(
                    """
                    INSERT INTO security_events (
                        event_id, src_ip, dst_ip, protocol, src_port, dst_port,
                        window_start, window_end, recorded_at, lifecycle_status,
                        risk_score, risk_level, detections_json, risk_json,
                        policy_json, response_json, event_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.flow_key.src_ip,
                        event.flow_key.dst_ip,
                        event.flow_key.protocol,
                        event.flow_key.src_port,
                        event.flow_key.dst_port,
                        serialized["window_start"],
                        serialized["window_end"],
                        serialized["recorded_at"],
                        event.lifecycle_status.value,
                        event.risk.score,
                        event.risk.level.value,
                        detections_json,
                        risk_json,
                        policy_json,
                        response_json,
                        event_json,
                    ),
                )
                conn.commit()
        except sqlite3.DatabaseError as exc:
            raise RuntimeError(f"Failed to save SecurityEvent: {exc}") from exc

        return True

    def get(self, event_id: str) -> Optional[SecurityEvent]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT event_json FROM security_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()

        if row is None:
            return None

        return SecurityEvent.from_serializable_dict(json.loads(row["event_json"]))

    def list_recent(self, limit: int = 100) -> List[SecurityEvent]:
        if not isinstance(limit, int) or limit <= 0:
            raise ValueError("limit must be a positive integer")

        with self._connect() as conn:
            rows = conn.execute(
                "SELECT event_json FROM security_events ORDER BY recorded_at DESC, event_id DESC LIMIT ?",
                (limit,),
            ).fetchall()

        return [SecurityEvent.from_serializable_dict(json.loads(row["event_json"])) for row in rows]
