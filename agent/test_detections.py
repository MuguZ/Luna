
from datetime import datetime, timedelta, timezone

import pytest

from agent.schemas import SecurityEvent
from agent.detections import (
    detect_repeated_failed_logins,
    detect_success_after_repeated_failures,
)


def make_event(
    event_id,
    minutes,
    outcome="failure",
    username="alice",
    source_ip="192.0.2.10",
    event_type="authentication",
):
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)
        + timedelta(minutes=minutes),
        event_type=event_type,
        source="synthetic",
        username=username,
        source_ip=source_ip,
        outcome=outcome,
        resource="/login",
        message=f"Login {outcome}",
    )


# Tests for repeated failed logins

def test_detect_repeated_failed_logins():
    events = [
        make_event("evt-1", 0),
        make_event("evt-2", 1),
        make_event("evt-3", 2),
    ]

    findings = detect_repeated_failed_logins(events)

    assert len(findings) == 1
    assert findings[0]["title"] == (
        "Repeated failed authentication attempts"
    )
    assert findings[0]["evidence_event_ids"] == [
        "evt-1", "evt-2", "evt-3"
    ]


def test_two_failures_do_not_trigger_detection():
    events = [
        make_event("evt-1", 0),
        make_event("evt-2", 1),
    ]

    assert detect_repeated_failed_logins(events) == []


def test_success_is_not_counted_as_failure():
    events = [
        make_event("evt-1", 0),
        make_event("evt-2", 1),
        make_event("evt-3", 2, outcome="success"),
    ]

    assert detect_repeated_failed_logins(events) == []


def test_failures_outside_window_do_not_trigger():
    events = [
        make_event("evt-1", 0),
        make_event("evt-2", 10),
        make_event("evt-3", 20),
    ]

    assert detect_repeated_failed_logins(events) == []


def test_separate_accounts_are_not_combined():
    events = [
        make_event("evt-1", 0, username="alice"),
        make_event("evt-2", 1, username="bob"),
        make_event("evt-3", 2, username="alice"),
    ]

    assert detect_repeated_failed_logins(events) == []


def test_invalid_threshold_is_rejected():
    with pytest.raises(ValueError):
        detect_repeated_failed_logins([], threshold=0)


# Tests for successful login after repeated failures

def test_success_after_three_failed_logins():
    events = [
        make_event("evt-1", 0),
        make_event("evt-2", 1),
        make_event("evt-3", 2),
        make_event("evt-4", 3, outcome="success"),
    ]

    findings = detect_success_after_repeated_failures(events)

    assert len(findings) == 1
    assert findings[0]["title"] == (
        "Successful authentication after repeated failures"
    )
    assert findings[0]["evidence_event_ids"] == [
        "evt-1", "evt-2", "evt-3", "evt-4"
    ]


def test_success_without_enough_failures():
    events = [
        make_event("evt-1", 0),
        make_event("evt-2", 1, outcome="success"),
    ]

    assert detect_success_after_repeated_failures(events) == []


def test_success_outside_window_is_not_flagged():
    events = [
        make_event("evt-1", 0),
        make_event("evt-2", 1),
        make_event("evt-3", 2),
        make_event("evt-4", 10, outcome="success"),
    ]

    assert detect_success_after_repeated_failures(events) == []


def test_different_accounts_are_not_combined():
    events = [
        make_event("evt-1", 0, username="alice"),
        make_event("evt-2", 1, username="bob"),
        make_event("evt-3", 2, username="alice"),
        make_event("evt-4", 3, outcome="success", username="bob"),
    ]

    assert detect_success_after_repeated_failures(events) == []

