
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SecurityEvent(BaseModel):
    """A validated, normalised security event."""

    model_config = ConfigDict(extra="allow")

    event_id: str = Field(min_length=1, max_length=200)
    timestamp: datetime
    event_type: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=200)

    username: str | None = Field(default=None, max_length=256)
    source_ip: str | None = Field(default=None, max_length=100)
    outcome: str | None = Field(default=None, max_length=100)
    resource: str | None = Field(default=None, max_length=1000)
    message: str | None = Field(default=None, max_length=10000)

    @field_validator("event_id", "event_type", "source", mode="before")
    @classmethod
    def validate_required_strings(cls, value):
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Field must be a non-empty string")
        return value

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamp must include a timezone")
        return value


class Finding(BaseModel):
    title: str
    rationale: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    evidence_event_ids: list[str] = Field(min_length=1)
    recommended_actions: list[str] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    event_id: str
    timestamp: str
    event_type: str
    source: str
    username: str | None = None
    source_ip: str | None = None
    outcome: str | None = None


def validate_events(events: list[dict]) -> list[SecurityEvent]:
    """Validate events and reject duplicate event IDs."""

    if not isinstance(events, list):
        raise ValueError("Events must be provided as a list")

    if len(events) > 10000:
        raise ValueError("A maximum of 10000 events is allowed")

    validated_events = [
        SecurityEvent.model_validate(event)
        for event in events
    ]

    event_ids = [event.event_id for event in validated_events]

    if len(event_ids) != len(set(event_ids)):
        raise ValueError("Duplicate event_id values are not allowed")

    return validated_events
