
from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def make_event(event_id: str, minute: int, outcome: str) -> dict:
    return {
        "event_id": event_id,
        "timestamp": f"2026-10-27T10:{minute:02d}:00Z",
        "event_type": "authentication",
        "source": "synthetic-test",
        "username": "demo-user",
        "source_ip": "192.0.2.25",
        "outcome": outcome,
        "message": "Synthetic test event",
    }


def test_investigate_returns_structured_report() -> None:
    events = [
        make_event("test-001", 0, "failure"),
        make_event("test-002", 1, "failure"),
        make_event("test-003", 2, "failure"),
        make_event("test-004", 3, "success"),
    ]

    response = client.post(
        "/investigate",
        json={"events": events, "context": None},
    )

    assert response.status_code == 200

    report = response.json()

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

    valid_ids = {event["event_id"] for event in events}
    for finding in report["findings"]:
        assert set(finding["evidence_event_ids"]).issubset(valid_ids)


def test_investigate_rejects_invalid_event() -> None:
    response = client.post(
        "/investigate",
        json={"events": [{"event_id": "incomplete"}]},
    )

    assert response.status_code == 422
