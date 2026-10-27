from app.repository import InvestigationRepository


def test_repository_persists_lists_filters_and_deletes(tmp_path):
    repo = InvestigationRepository(tmp_path / "history.sqlite3")
    repo.initialize()
    events = [{"event_id": "evt-1", "timestamp": "2026-10-27T10:00:00Z"}]
    result = {"summary": "synthetic check", "severity": "medium", "confidence": 0.8, "findings": []}
    saved = repo.create(result, events, "demo")
    assert repo.get(saved["investigation_id"])["events"] == events
    assert repo.list(limit=10, source_type="demo")[1] == 1
    assert repo.list(limit=10, source_type="upload")[1] == 0
    assert repo.delete(saved["investigation_id"])
    assert repo.get(saved["investigation_id"]) is None


def test_repository_can_disable_raw_event_retention(tmp_path):
    repo = InvestigationRepository(tmp_path / "metadata.sqlite3", store_events=False)
    repo.initialize()
    saved = repo.create(
        {"summary": "metadata only", "severity": "unknown", "confidence": 0, "findings": []},
        [{"event_id": "evt-1", "message": "synthetic"}],
        "upload",
    )
    loaded = repo.get(saved["investigation_id"])
    assert loaded["events_retained"] is False
    assert "events" not in loaded
    assert loaded["event_count"] == 1


def test_repository_searches_and_paginates_bounded_results(tmp_path):
    repo = InvestigationRepository(tmp_path / "paged.sqlite3")
    repo.initialize()
    for index in range(3):
        repo.create(
            {"summary": f"synthetic result {index}", "severity": "low", "confidence": 0.8, "findings": []},
            [{"event_id": f"evt-{index}"}],
            "demo",
        )
    items, total = repo.list(limit=2, offset=0, search="result 1")
    assert total == 1
    assert len(items) == 1
    assert "result 1" in items[0]["summary"]
