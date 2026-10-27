from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from agent.schemas import SecurityEvent, validate_events


def valid_event(**overrides):
    event = {
        "event_id": "evt-001",
        "timestamp": datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc),
        "event_type": "authentication",
        "source": "synthetic",
        "username": "alice",
        "source_ip": "192.0.2.10",
        "outcome": "failure",
        "resource": "/login",
        "message": "Failed login attempt",
    }
    event.update(overrides)
    return event


def test_valid_security_event():
    event = SecurityEvent.model_validate(valid_event())

    assert event.event_id == "evt-001"
    assert event.event_type == "authentication"


def test_missing_event_id_is_rejected():
    event = valid_event()
    event.pop("event_id")

    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(event)


def test_timezone_less_timestamp_is_rejected():
    event = valid_event(
        timestamp=datetime(2026, 10, 27, 10, 0)
    )

    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(event)


def test_timezone_aware_timestamp_is_accepted():
    event = valid_event(
        timestamp=datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)
    )

    SecurityEvent.model_validate(event)


def test_duplicate_event_ids_are_rejected():
    events = [
        valid_event(event_id="evt-001"),
        valid_event(event_id="evt-001"),
    ]

    with pytest.raises((ValidationError, ValueError)):
        validate_events(events)


def test_distinct_event_ids_are_accepted():
    events = [
        valid_event(event_id="evt-001"),
        valid_event(event_id="evt-002"),
    ]

    result = validate_events(events)

    assert len(result) == 2
    assert result[0].event_id == "evt-001"
    assert result[1].event_id == "evt-002"
