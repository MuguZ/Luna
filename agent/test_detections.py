
from datetime import datetime, timezone, timedelta

from agent.schemas import SecurityEvent
from agent.detections import detect_repeated_failed_logins


def make_event(event_id, minutes, outcome="failure", username="alice",
               source_ip="192.0.2.10"):
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)
        + timedelta(minutes=minutes),
        event_type="authentication",
        source="synthetic",
        username=username,
        source_ip=source_ip,
        outcome=outcome,
    )


def test_detects_three_failures():
    events = [
        make_event("evt-1", 0),
        make_event("evt-2", 1),
        make_event("evt-3", 2),
    ]

    findings = detect_repeated_failed_logins(events)

    assert len(findings) == 1
    assert findings[0]["evidence_event_ids"] == [
        "evt-1", "evt-2", "evt-3"
    ]


def test_two_failures_do_not_trigger():
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


def test_separate_accounts_are_not_combined():
    events = [
        make_event("evt-1", 0, username="alice"),
        make_event("evt-2", 1, username="bob"),
        make_event("evt-3", 2, username="alice"),
    ]

    assert detect_repeated_failed_logins(events) == []
