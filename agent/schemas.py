
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator


class SecurityEvent(BaseModel):
    """A validated, normalised security event."""

    model_config = ConfigDict(extra="allow")

    event_id: str = Field(min_length=1)
    timestamp: datetime
    event_type: str = Field(min_length=1)
    source: str = Field(min_length=1)

    username: str | None = None
    source_ip: str | None = None
    outcome: str | None = None
    resource: str | None = None
    message: str | None = None

    @field_validator(
        "event_id",
        "event_type",
        "source",
        mode="before",
    )
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


def validate_events(events: list[dict]) -> list[SecurityEvent]:
    """Validate events and reject duplicate event IDs."""

    if not isinstance(events, list):
        raise ValueError("Events must be provided as a list")

    validated_events = [
        SecurityEvent.model_validate(event)
        for event in events
    ]

    event_ids = [event.event_id for event in validated_events]

    if len(event_ids) != len(set(event_ids)):
        raise ValueError("Duplicate event_id values are not allowed")

    return validated_events
