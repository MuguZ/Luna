"""HTTP-level API tests; the local Python 3.14 venv has a known TestClient hang."""

import sys

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.version_info >= (3, 14),
        reason="Installed Python 3.14 AnyIO/Starlette TestClient stalls before dispatch; CI uses Python 3.12.",
    ),
]


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "test-investigations.sqlite3")
    with TestClient(app) as test_client:
        yield test_client


def event(event_id: str, timestamp: str, *, username="alice", source_ip="192.0.2.10", outcome="failure"):
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": "authentication",
        "source": "synthetic",
        "username": username,
        "source_ip": source_ip,
        "outcome": outcome,
    }


def test_health_http_contract(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "luna-api"}


def test_detection_rules_endpoint_reports_configured_rules(client):
    response = client.get("/detection-rules")
    assert response.status_code == 200
    assert {rule["id"] for rule in response.json()} == {
        "repeated-failures", "success-after-failures", "authentication-burst", "multiple-account-targeting"
    }


def test_analysis_is_persisted_retrievable_and_evidence_is_preserved(client):
    events = [event(f"login-{index}", f"2026-10-27T10:0{index}:00Z") for index in range(4)]
    events.append(event("separate-success", "2026-10-27T10:04:00Z", outcome="success", source_ip="192.0.2.11"))
    response = client.post("/investigations/analyze", json={"events": events, "source_type": "demo"})
    assert response.status_code == 200
    analysis = response.json()
    assert analysis["investigation_id"]
    assert analysis["source_type"] == "demo"
    assert analysis["severity"] == "medium"
    assert len(analysis["findings"]) == 1
    assert len(analysis["findings"][0]["evidence_event_ids"]) == 4
    assert analysis["events"][0]["timestamp"] == "2026-10-27T10:00:00Z"

    loaded = client.get(f"/investigations/{analysis['investigation_id']}")
    assert loaded.status_code == 200
    assert loaded.json()["events"] == events

    page = client.get("/investigations", params={"source_type": "demo", "limit": 1})
    assert page.status_code == 200
    assert page.json()["total"] == 1
    assert page.json()["items"][0]["investigation_id"] == analysis["investigation_id"]


@pytest.mark.parametrize(
    "events",
    [
        [],
        [{"event_id": "missing-source", "timestamp": "2026-10-27T10:00:00Z", "event_type": "authentication"}],
        [{"event_id": "naive", "timestamp": "2026-10-27T10:00:00", "event_type": "authentication", "source": "test"}],
        [{"event_id": "bad-optional", "timestamp": "2026-10-27T10:00:00Z", "event_type": "authentication", "source": "test", "username": 123}],
        [event("duplicate", "2026-10-27T10:00:00Z"), event("duplicate", "2026-10-27T10:01:00Z")],
    ],
)
def test_invalid_event_batches_return_422(client, events):
    response = client.post("/investigations/analyze", json={"events": events})
    assert response.status_code == 422


def test_invalid_json_and_oversized_request_return_client_errors(client):
    malformed = client.post(
        "/investigations/analyze",
        content='{"events":[',
        headers={"Content-Type": "application/json"},
    )
    assert malformed.status_code == 422
    oversized = client.post(
        "/investigations/analyze",
        content=b"{}",
        headers={"Content-Type": "application/json", "Content-Length": str(7 * 1024 * 1024)},
    )
    assert oversized.status_code == 413


def test_delete_removes_investigation_and_missing_ids_return_404(client):
    response = client.post("/investigations/analyze", json={"events": [event("one", "2026-10-27T10:00:00Z")]})
    investigation_id = response.json()["investigation_id"]
    assert client.delete(f"/investigations/{investigation_id}").status_code == 204
    assert client.get(f"/investigations/{investigation_id}").status_code == 404
    assert client.delete(f"/investigations/{investigation_id}").status_code == 404
    assert client.get("/investigations/not-a-uuid").status_code == 422
