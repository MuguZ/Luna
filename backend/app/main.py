"""Luna local defensive security analysis API."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from agent.detections import DetectionConfig, analyze_events
from app.models import AnalysisRequest, InvestigationPage
from app.repository import InvestigationRepository

DEFAULT_DATABASE_PATH = Path(__file__).resolve().parents[1] / "data" / "sreema.sqlite3"
MAX_REQUEST_BYTES = 6 * 1024 * 1024


def _env_value(name: str, legacy_name: str, default: str) -> str:
    """Read Luna settings first while preserving existing SREEMA installations."""
    return os.getenv(name, os.getenv(legacy_name, default))


def _env_bool(name: str, legacy_name: str, default: bool) -> bool:
    value = _env_value(name, legacy_name, str(default))
    if value is None:
        return default
    return value.strip().casefold() in {"1", "true", "yes", "on"}


def health() -> dict[str, str]:
    """Basic liveness check; deliberately independent from database status."""
    return {"status": "ok", "service": "luna-api"}


def create_app(database_path: Path | None = None) -> FastAPI:
    configured_path = database_path or Path(_env_value("LUNA_DATABASE_PATH", "SREEMA_DATABASE_PATH", str(DEFAULT_DATABASE_PATH)))
    repository = InvestigationRepository(
        configured_path,
        store_events=_env_bool("LUNA_STORE_RAW_EVENTS", "SREEMA_STORE_RAW_EVENTS", True),
    )
    detection_config = DetectionConfig.from_environment()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        repository.initialize()
        yield

    app = FastAPI(
        title="Luna API",
        description="Luna — Threat Intelligence & Investigation Agent. Defensive security log investigation API.",
        version="0.3.0",
        lifespan=lifespan,
    )
    app.state.investigation_repository = repository
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type", "Authorization"],
    )

    @app.middleware("http")
    async def bound_request_size(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                too_large = int(content_length) > MAX_REQUEST_BYTES
            except ValueError:
                too_large = True
            if too_large:
                return Response(
                    content='{"detail":"Request body exceeds the 6 MB limit."}',
                    status_code=413,
                    media_type="application/json",
                )
        return await call_next(request)

    app.get("/health", tags=["health"])(health)

    @app.get("/detection-rules", tags=["detections"])
    def detection_rules() -> list[dict[str, Any]]:
        return detection_config.rules()

    @app.post("/investigations/analyze", tags=["investigations"])
    async def investigate(payload: AnalysisRequest, request: Request) -> dict[str, Any]:
        events = payload.events
        try:
            raw_events = json.loads((await request.body()).decode("utf-8"))["events"]
        except (json.JSONDecodeError, KeyError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=422, detail="Request body must contain an events array.") from exc
        event_ids = [event.event_id for event in events]
        if len(event_ids) != len(set(event_ids)):
            raise HTTPException(status_code=422, detail="Duplicate event_id values are not allowed")
        result = analyze_events(events, detection_config)
        raw_by_id = {item["event_id"]: item for item in raw_events}
        for timeline_event in result["timeline"]:
            original = raw_by_id[timeline_event["event_id"]]
            timeline_event["timestamp"] = original["timestamp"]
            timeline_event["username"] = original.get("username")
            timeline_event["source_ip"] = original.get("source_ip")
            timeline_event["outcome"] = original.get("outcome")
            if not repository.store_events:
                timeline_event.pop("username", None)
                timeline_event.pop("source_ip", None)
                timeline_event.pop("outcome", None)
        try:
            return repository.create(result, raw_events, payload.source_type)
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=503,
                detail="Investigation analysis completed but could not be saved locally.",
            ) from exc

    @app.get("/investigations", response_model=InvestigationPage, tags=["investigations"])
    def list_investigations(
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=1000000),
        search: str | None = Query(default=None, max_length=200),
        severity: str | None = Query(default=None, pattern="^(unknown|low|medium|high|critical)$"),
        source_type: Literal["upload", "demo"] | None = None,
        created_after: datetime | None = None,
        created_before: datetime | None = None,
    ) -> dict[str, Any]:
        if created_after and (created_after.tzinfo is None or created_after.utcoffset() is None):
            raise HTTPException(status_code=422, detail="created_after must include a timezone")
        if created_before and (created_before.tzinfo is None or created_before.utcoffset() is None):
            raise HTTPException(status_code=422, detail="created_before must include a timezone")
        try:
            items, total = repository.list(
                offset=offset,
                limit=limit,
                search=search,
                severity=severity,
                source_type=source_type,
                created_after=created_after.astimezone(timezone.utc).isoformat() if created_after else None,
                created_before=created_before.astimezone(timezone.utc).isoformat() if created_before else None,
            )
            return {"items": items, "total": total, "limit": limit, "offset": offset}
        except sqlite3.Error as exc:
            raise HTTPException(status_code=503, detail="Investigation history is temporarily unavailable.") from exc

    @app.get("/investigations/{investigation_id}", tags=["investigations"])
    def get_investigation(investigation_id: UUID) -> dict[str, Any]:
        try:
            result = repository.get(str(investigation_id))
        except sqlite3.Error as exc:
            raise HTTPException(status_code=503, detail="Investigation details are temporarily unavailable.") from exc
        if result is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return result

    @app.delete("/investigations/{investigation_id}", status_code=204, tags=["investigations"])
    def delete_investigation(investigation_id: UUID) -> Response:
        try:
            deleted = repository.delete(str(investigation_id))
        except sqlite3.Error as exc:
            raise HTTPException(status_code=503, detail="Investigation could not be deleted.") from exc
        if not deleted:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return Response(status_code=204)

    return app


app = create_app()
