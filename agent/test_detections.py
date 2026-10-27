
from datetime import datetime, timezone, timedelta
import pytest

from agent.schemas import SecurityEvent
from agent.detections import (
    DetectionConfig,
    analyze_events,
    detect_authentication_bursts,
    detect_multiple_account_targeting,
    detect_repeated_failed_logins,
    detect_success_after_repeated_failures,
)


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


def test_empty_input_has_unknown_severity_and_no_findings():
    result = analyze_events([])
    assert result["severity"] == "unknown"
    assert result["findings"] == []


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


def test_repeated_login_window_includes_exact_boundary_and_excludes_late_event():
    at_boundary = [make_event("evt-1", 0), make_event("evt-2", 2), make_event("evt-3", 5)]
    after_boundary = [make_event("evt-1", 0), make_event("evt-2", 2), make_event("evt-3", 5.01)]
    assert len(detect_repeated_failed_logins(at_boundary)) == 1
    assert detect_repeated_failed_logins(after_boundary) == []


def test_success_after_failures_detects_only_same_account_and_source():
    events = [
        make_event("fail-1", 0), make_event("fail-2", 1), make_event("fail-3", 2),
        make_event("login-ok", 3, outcome="success"),
    ]
    findings = detect_success_after_repeated_failures(events)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["evidence_event_ids"] == ["fail-1", "fail-2", "fail-3", "login-ok"]
    assert detect_success_after_repeated_failures([
        *events[:-1], make_event("login-ok", 3, outcome="success", source_ip="198.51.100.9")
    ]) == []


def test_authentication_burst_threshold_and_account_independence():
    events = [
        make_event("a", 0, username="alice"), make_event("b", 1, username="bob"),
        make_event("c", 2, username="carol"),
    ]
    assert detect_authentication_bursts(events, threshold=3)
    assert detect_authentication_bursts(events, threshold=4) == []
    assert detect_authentication_bursts([
        *events[:2], make_event("c", 2, source_ip="198.51.100.9")
    ], threshold=3) == []


def test_multiple_account_targeting_requires_distinct_accounts_and_source():
    events = [make_event(f"id-{i}", i, username=f"user-{i}") for i in range(4)]
    assert len(detect_multiple_account_targeting(events, threshold=4)) == 1
    same_user = [make_event(f"id-{i}", i, username="alice") for i in range(4)]
    assert detect_multiple_account_targeting(same_user, threshold=4) == []


def test_demo_shape_produces_one_medium_finding_with_four_failed_evidence_events():
    events = [make_event(f"fail-{i}", i) for i in range(4)]
    events.append(make_event("separate-success", 4, outcome="success", source_ip="192.0.2.11"))
    result = analyze_events(events)
    assert len(result["findings"]) == 1
    assert result["severity"] == "medium"
    assert len(result["findings"][0]["evidence_event_ids"]) == 4


def test_configured_rule_thresholds_are_reportable():
    rule = DetectionConfig(repeated_failures=4, repeated_window_minutes=7).rules()[0]
    assert rule["threshold"] == 4
    assert rule["window_minutes"] == 7


def test_detection_rejects_invalid_thresholds():
    events = [make_event("evt-1", 0)]
    with pytest.raises(ValueError):
        detect_repeated_failed_logins(events, threshold=0)
    with pytest.raises(ValueError):
        detect_multiple_account_targeting(events, threshold=1)


def test_event_type_and_outcome_matching_is_case_insensitive_and_order_independent():
    events = [
        make_event("third", 2, outcome="FAILURE"),
        make_event("first", 0, outcome="failure"),
        make_event("second", 1, outcome="Failure"),
    ]
    for event in events:
        event.event_type = "AUTHENTICATION"
    result = analyze_events(events)
    assert result["findings"][0]["evidence_event_ids"] == ["first", "second", "third"]
