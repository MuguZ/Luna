# Backend

FastAPI handles event validation, deterministic detections, and the SQLite investigation repository. See the root [README](../README.md) for full setup, configuration, API, and data-retention guidance.

From `backend/` on Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
PYTHONPATH=.. uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Tests:

```bash
PYTHONPATH=.. python -m pytest -q tests ../agent
```

The default database remains `backend/data/sreema.sqlite3` to preserve existing history. Set `LUNA_DATABASE_PATH` to choose another file; the previous `SREEMA_DATABASE_PATH` variable remains supported as a fallback.
