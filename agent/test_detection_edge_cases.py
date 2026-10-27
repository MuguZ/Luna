
from agent.schemas import validate_events
from agent.detections import (
    detect_repeated_failed_logins,
    detect_success_after_repeated_failures,
)


def make_event(event_id, timestamp, username, source_ip, outcome):
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": "authentication",
        "source": "test-system",
        "username": username,
        "source_ip": source_ip,
        "outcome": outcome,
    }


def test_different_ips_are_not_combined():
    events = [
        make_event("e1", "2026-10-27T10:00:00Z", "alice", "192.0.2.1", "failure"),
        make_event("e2", "2026-10-27T10:01:00Z", "alice", "192.0.2.2", "failure"),
        make_event("e3", "2026-10-27T10:02:00Z", "alice", "192.0.2.3", "failure"),
    ]

    findings = detect_repeated_failed_logins(validate_events(events))

    assert findings == []


def test_different_users_are_not_combined():
    events = [
        make_event("e1", "2026-10-27T10:00:00Z", "alice", "192.0.2.1", "failure"),
        make_event("e2", "2026-10-27T10:01:00Z", "bob", "192.0.2.1", "failure"),
        make_event("e3", "2026-10-27T10:02:00Z", "carol", "192.0.2.1", "failure"),
    ]

    findings = detect_repeated_failed_logins(validate_events(events))

    assert findings == []


def test_out_of_order_events_are_detected():
    events = [
        make_event("e3", "2026-10-27T10:02:00Z", "alice", "192.0.2.1", "failure"),
        make_event("e1", "2026-10-27T10:00:00Z", "alice", "192.0.2.1", "failure"),
        make_event("e2", "2026-10-27T10:01:00Z", "alice", "192.0.2.1", "failure"),
    ]

    findings = detect_repeated_failed_logins(validate_events(events))

    assert len(findings) >= 1


def test_failures_outside_window_do_not_trigger():
    events = [
        make_event("e1", "2026-10-27T10:00:00Z", "alice", "192.0.2.1", "failure"),
        make_event("e2", "2026-10-27T10:03:00Z", "alice", "192.0.2.1", "failure"),
        make_event("e3", "2026-10-27T10:06:00Z", "alice", "192.0.2.1", "failure"),
    ]

    findings = detect_repeated_failed_logins(
        validate_events(events),
        threshold=3,
        window_minutes=5,
    )

    assert findings == []
