# Luna — Threat Intelligence & Investigation Agent

Luna is a local-first defensive security investigation prototype. It accepts supplied JSON event logs, validates them, runs deterministic authentication rules, and stores reviewable investigation records in SQLite. It does not use an LLM, external threat-intelligence provider, live monitoring, or active response actions.

## Features implemented

- Dark React, TypeScript, and Vite security operations dashboard.
- Browser-side JSON upload validation (array or `{ "events": [...] }`), 5 MB file cap, 10,000-event cap, and clear validation errors.
- FastAPI analysis with timezone-aware Pydantic validation, duplicate-ID rejection, evidence integrity checks, and bounded request size.
- Four deterministic authentication detections with configurable thresholds, finding severity, confidence labels, evidence IDs, and recommendations.
- SQLite investigation persistence, paginated/filterable history, detail review, deletion, and JSON report export.
- Optional raw event retention control. By default, submitted event JSON is retained locally with the analysis until the investigation is deleted.
- CI for backend tests and the frontend TypeScript/production build.

## Architecture

```text
frontend/       React UI, upload validation, history and investigation review
backend/app/    FastAPI routes, request models, SQLite repository
agent/          shared event/finding schemas and deterministic detections
sample_data/    synthetic sample event file only
docs/           architecture and data-handling notes
```

The API and frontend run independently on localhost. SQLite is the only persistence dependency; no database server or API key is required. Investigation history is local to the backend process/database path and has no multi-user access control.

## Requirements

- Python 3.12 (CI-supported; Python 3.11+ should also work).
- Node.js 22 LTS and npm.
- Git.

## Install and run

### Backend — Linux/macOS

From the repository root:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
PYTHONPATH=.. uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

PowerShell:

```powershell
cd backend
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
$env:PYTHONPATH = ".."
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Health: `http://127.0.0.1:8000/health` · API docs: `http://127.0.0.1:8000/docs`.

### Frontend

In a second terminal:

```bash
cd frontend
npm ci
npm run dev
```

Open `http://127.0.0.1:5173`. The frontend uses `VITE_API_BASE_URL` when set; otherwise it calls `http://127.0.0.1:8000`.

## Environment variables

Backend variables are read when the application starts. The matching legacy `SREEMA_RULE_*` variables remain supported as fallbacks for all detection settings; when both names are set, the `LUNA_*` value takes precedence:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LUNA_DATABASE_PATH` | `backend/data/sreema.sqlite3` | Local SQLite file path. Relative paths use the backend process working directory. `SREEMA_DATABASE_PATH` remains a supported fallback. |
| `LUNA_STORE_RAW_EVENTS` | `true` | Retain submitted source event objects for later review. Set `false` to omit raw event JSON; summary, findings, and event references remain stored. `SREEMA_STORE_RAW_EVENTS` remains a supported fallback. |
| `LUNA_RULE_REPEATED_THRESHOLD` | `3` | Failures for same account/source rule threshold. |
| `LUNA_RULE_REPEATED_WINDOW_MINUTES` | `5` | Window for repeated failures. |
| `LUNA_RULE_SUCCESS_THRESHOLD` | `3` | Prior failures for success-after-failures rule. |
| `LUNA_RULE_SUCCESS_WINDOW_MINUTES` | `10` | Sequence window. |
| `LUNA_RULE_BURST_THRESHOLD` | `10` | Failures from one source for burst rule. |
| `LUNA_RULE_BURST_WINDOW_MINUTES` | `5` | Burst window. |
| `LUNA_RULE_MULTIPLE_ACCOUNT_THRESHOLD` | `5` | Distinct usernames for multi-account rule (minimum 2). |
| `LUNA_RULE_MULTIPLE_ACCOUNT_WINDOW_MINUTES` | `5` | Multi-account targeting window. |

For the frontend, create `frontend/.env.local` with `VITE_API_BASE_URL=http://127.0.0.1:8000` only if using a different API address. Do not commit local env files or secrets.

## JSON event schema

The upload may be a JSON array, or an object containing an `events` array. Each event requires:

- `event_id`: unique non-empty string (maximum 200 characters per ID)
- `timestamp`: valid ISO 8601 date/time with timezone, such as `2026-10-27T10:00:00Z`
- `event_type`: non-empty string
- `source`: non-empty string

Optional known fields are `username`, `source_ip`, `outcome`, `resource`, and `message`; when supplied, they must be strings or `null`. Unknown fields are retained as supplied. Missing values are not invented. Event IDs must be unique in each batch.

Example file (`sample_data/auth_events.json`):

```json
[
  {
    "event_id": "evt-001",
    "timestamp": "2026-10-27T09:14:00Z",
    "event_type": "authentication",
    "source": "linux-auth-synthetic",
    "username": "demo-user",
    "source_ip": "192.0.2.25",
    "outcome": "failure",
    "resource": "ssh",
    "message": "Synthetic example: authentication failed"
  }
]
```

The UI rejects files above 5 MB and batches above 10,000 events. The backend independently validates all data and rejects request bodies above 6 MB.

## API endpoints

| Method | Path | Behavior |
| --- | --- | --- |
| `GET` | `/health` | Liveness response; does not report database readiness. |
| `GET` | `/detection-rules` | Actual rule descriptions and configured thresholds. |
| `POST` | `/investigations/analyze` | Validates/analyzes `{"events": [...], "source_type": "upload"}` and persists a completed record. Source type may be `demo`. Returns stable UUID, result, and retained event evidence when enabled. |
| `GET` | `/investigations` | Bounded listing (`limit` 1–100, `offset` <= 1,000,000) with optional `search`, `severity`, `source_type`, `created_after`, and `created_before` filters. Date-time filters must include timezone. |
| `GET` | `/investigations/{uuid}` | Returns the stored analysis and raw events when retained; 404 when absent. |
| `DELETE` | `/investigations/{uuid}` | Deletes analysis and retained evidence; 204 on success, 404 when absent. |

Invalid request/event data returns HTTP 422, oversized declared request bodies return 413, and storage failures return 503. CORS is restricted to the two local Vite origins.

## Detection rules

The implemented rule set is intentionally limited to authentication signals:

1. Repeated failed authentication for the same username and source IP: default 3 failures in 5 minutes (medium, fixed confidence label 0.80).
2. Successful login after repeated failures for the same pair: default 3 prior failures in 10 minutes (high, 0.90).
3. Authentication failure burst from one source IP across accounts: default 10 failures in 5 minutes (high, 0.85).
4. Failures from one source IP against multiple distinct usernames: default 5 usernames in 5 minutes (medium, 0.82).

Time windows are inclusive at the boundary; input timestamps must be timezone-aware and event order is chronological. Event type and outcome matching is case-insensitive. Usernames and IP values are not rewritten because their identity semantics are source-dependent. Confidence numbers are fixed rule-strength labels, not calibrated probabilities. Findings are indicators, not proof of compromise; no malware, attribution, or other attack class is claimed.

## Persistence and data handling

The default DB path remains `backend/data/sreema.sqlite3` to preserve existing investigation history; Luna continues to use this file unless `LUNA_DATABASE_PATH` or its legacy `SREEMA_DATABASE_PATH` alias selects another path. SQLite tables are initialized idempotently at backend startup. No migration tool is used at this prototype stage. Database files, logs, local backups, Python environments, and frontend build/dependency directories are ignored by Git.

Raw logs can contain sensitive account names, addresses, and messages. Upload only logs you are authorized to inspect. The browser sends the validated event batch only to the configured Luna API. By default, that backend stores original event JSON alongside its findings and timeline on the local machine until deletion. This is disclosed in the investigation modal. Set `LUNA_STORE_RAW_EVENTS=false` before starting the backend to avoid storing raw events; analysis timeline and findings are still retained. Use the history Delete control to remove an investigation and its stored event data. There is no authentication or user isolation, so do not expose this prototype API to an untrusted network.

## Tests and CI

```bash
cd backend
source .venv/bin/activate
PYTHONPATH=.. python -m pytest -q tests ../agent
```

```bash
cd frontend
npm ci
npm run build
```

GitHub Actions runs backend tests (including HTTP-level integration tests) on Python 3.12 and the frontend production build on Node 22 for pushes to `main`/feature branches and pull requests targeting `main`.

## Limitations and roadmap

- Local single-user prototype without authentication, authorization, or audit identity.
- SQLite schema initialization is idempotent; production migrations and backup/retention policy are future work.
- Rules are deterministic, authentication-focused heuristics. They do not query external threat intelligence or take response actions.
- Manual browser verification and deployment hardening are required before operational use.
