"""SQLite persistence for completed investigations.

The prototype uses an idempotent schema initializer (CREATE TABLE IF NOT EXISTS)
instead of migrations. Database paths are supplied by application settings.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class InvestigationRepository:
    def __init__(self, database_path: Path, *, store_events: bool = True) -> None:
        self.database_path = database_path
        self.store_events = store_events

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    summary TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    result_json TEXT NOT NULL,
                    events_json TEXT
                )"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_investigations_created_at "
                "ON investigations(created_at DESC)"
            )

    def create(
        self,
        result: dict[str, Any],
        events: list[dict[str, Any]],
        source_type: str,
    ) -> dict[str, Any]:
        investigation_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        stored = {
            **result,
            "investigation_id": investigation_id,
            "created_at": created_at,
            "source_type": source_type,
            "event_count": len(events),
            "events_retained": self.store_events,
        }
        events_json = json.dumps(events, ensure_ascii=False) if self.store_events else None
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO investigations
                   (id, created_at, source_type, event_count, summary, severity,
                    confidence, result_json, events_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    investigation_id,
                    created_at,
                    source_type,
                    len(events),
                    result["summary"],
                    result["severity"],
                    result["confidence"],
                    json.dumps(stored, ensure_ascii=False),
                    events_json,
                ),
            )
        if self.store_events:
            stored["events"] = events
        return stored

    def list(
        self,
        *,
        offset: int = 0,
        limit: int = 20,
        search: str | None = None,
        severity: str | None = None,
        source_type: str | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        values: list[Any] = []
        if search:
            clauses.append("summary LIKE ?")
            values.append(f"%{search}%")
        if severity:
            clauses.append("severity = ?")
            values.append(severity.lower())
        if source_type:
            clauses.append("source_type = ?")
            values.append(source_type)
        if created_after:
            clauses.append("created_at >= ?")
            values.append(created_after)
        if created_before:
            clauses.append("created_at <= ?")
            values.append(created_before)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) FROM investigations {where}", values
            ).fetchone()[0]
            rows = connection.execute(
                f"""SELECT id, created_at, source_type, event_count, summary,
                           severity, confidence, result_json
                    FROM investigations {where}
                    ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?""",
                [*values, limit, offset],
            ).fetchall()
        return [self._summary(row) for row in rows], total

    def get(self, investigation_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json, events_json FROM investigations WHERE id = ?",
                (investigation_id,),
            ).fetchone()
        if row is None:
            return None
        result = json.loads(row["result_json"])
        if row["events_json"] is not None:
            result["events"] = json.loads(row["events_json"])
        return result

    def delete(self, investigation_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM investigations WHERE id = ?", (investigation_id,)
            )
            return cursor.rowcount > 0

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _summary(row: sqlite3.Row) -> dict[str, Any]:
        result = json.loads(row["result_json"])
        return {
            "investigation_id": row["id"],
            "created_at": row["created_at"],
            "source_type": row["source_type"],
            "event_count": row["event_count"],
            "summary": row["summary"],
            "severity": row["severity"],
            "confidence": row["confidence"],
            "finding_count": len(result["findings"]),
        }
