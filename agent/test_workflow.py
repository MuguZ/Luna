
import json
from pathlib import Path

from agent.workflow import run_investigation


def make_event(event_id, minute, outcome, username="demo-user",
               source_ip="192.0.2.25"):
    return {
        "event_id": event_id,
        "timestamp": f"2026-10-27T10:{minute:02d}:00Z",
        "event_type": "authentication",
        "source": "test-system",
        "username": username,
        "source_ip": source_ip,
        "outcome": outcome,
    }


def get_sample_path():
    project_root = Path(__file__).resolve().parent.parent

    candidates = [
        project_root / "Sreema" / "sample_data" / "auth_events.json",
        project_root / "sample_data" / "auth_events.json",
    ]

    for path in candidates:
        if path.exists():
            return path

    raise FileNotFoundError(
        "Could not find sample_data/auth_events.json"
    )


def test_run_investigation_with_sample_events():
    sample_path = get_sample_path()
    events = json.loads(sample_path.read_text(encoding="utf-8"))

    report = run_investigation(events)

    required_fields = {
        "summary",
        "severity",
        "confidence",
        "findings",
        "timeline",
        "recommended_actions",
        "limitations",
    }

    assert required_fields.issubset(report.keys())
    assert len(report["timeline"]) == len(events)
    assert 0 <= report["confidence"] <= 1

    valid_ids = {event["event_id"] for event in events}

    for finding in report["findings"]:
        assert set(finding["evidence_event_ids"]).issubset(valid_ids)


def test_invalid_events_are_rejected():
    try:
        run_investigation([{"event_id": "missing-fields"}])
    except Exception:
        return

    assert False, "Invalid events should be rejected"


def test_normal_login_has_no_findings():
    events = [
        make_event("normal-001", 0, "success")
    ]

    report = run_investigation(events)

    assert report["findings"] == []
    assert len(report["timeline"]) == 1


def test_repeated_failed_logins_are_detected():
    events = [
        make_event("fail-001", 0, "failure"),
        make_event("fail-002", 1, "failure"),
        make_event("fail-003", 2, "failure"),
    ]

    report = run_investigation(events)

    assert len(report["findings"]) >= 1

    valid_ids = {event["event_id"] for event in events}

    for finding in report["findings"]:
        assert set(finding["evidence_event_ids"]).issubset(valid_ids)


def test_success_after_repeated_failures_is_detected():
    events = [
        make_event("fail-001", 0, "failure"),
        make_event("fail-002", 1, "failure"),
        make_event("fail-003", 2, "failure"),
        make_event("success-004", 3, "success"),
    ]

    report = run_investigation(events)

    assert len(report["findings"]) >= 2
    assert len(report["timeline"]) == 4


def test_unrelated_accounts_are_not_combined():
    events = [
        make_event("fail-001", 0, "failure", username="user-a"),
        make_event("fail-002", 1, "failure", username="user-b"),
        make_event("fail-003", 2, "failure", username="user-c"),
    ]

    report = run_investigation(events)

    assert report["findings"] == []


def test_timeline_is_chronological():
    events = [
        make_event("late-001", 3, "success"),
        make_event("early-001", 0, "success"),
        make_event("middle-001", 2, "success"),
    ]

    report = run_investigation(events)

    timestamps = [
        event["timestamp"] for event in report["timeline"]
    ]

    assert timestamps == sorted(timestamps)

