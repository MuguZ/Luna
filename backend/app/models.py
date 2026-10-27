"""Validated HTTP request and response models."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from agent.schemas import SecurityEvent


class AnalysisRequest(BaseModel):
    events: list[SecurityEvent] = Field(min_length=1, max_length=10000)
    source_type: Literal["upload", "demo"] = "upload"


class InvestigationSummary(BaseModel):
    investigation_id: UUID
    created_at: str
    source_type: Literal["upload", "demo"]
    event_count: int
    summary: str
    severity: str
    confidence: float
    finding_count: int


class InvestigationPage(BaseModel):
    items: list[InvestigationSummary]
    total: int
    limit: int
    offset: int
