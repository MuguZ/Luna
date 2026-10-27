# SREEMA Architecture

## Runtime flow

1. React reads and validates a user-selected JSON file using the browser File API.
2. FastAPI validates the submitted request again with Pydantic and rejects invalid/duplicate events.
3. `agent/detections.py` runs deterministic rules over timezone-aware event models and returns typed findings with evidence IDs.
4. `backend/app/repository.py` stores the response and, by default, the original event objects in a local SQLite database.
5. The frontend reloads paginated investigation history from the backend and requests a stored record when the user opens its details.

## Module boundaries

- `frontend/src/`: dashboard, upload flow, API client, local history filtering, result review.
- `backend/app/main.py`: HTTP routes and application configuration.
- `backend/app/models.py`: request and history response schemas.
- `backend/app/repository.py`: SQLite persistence and filtering.
- `agent/schemas.py`: validated event, finding, and timeline structures.
- `agent/detections.py`: four deterministic authentication rules.

SQLite schema creation uses `CREATE TABLE IF NOT EXISTS` at application startup. There is no migration tool yet. The repository is intended for a local, single-user prototype; it has no authentication, tenant separation, external integrations, or active response actions.

## Evidence and normalisation

The original submitted event objects are retained verbatim as JSON by default. The analysis timeline is sorted chronologically but carries source timestamp strings. Event type and authentication outcome comparisons use case-insensitive matching; usernames and IP addresses are left as supplied because normalization may change their identity semantics. Every detection evidence ID is checked against the submitted event set.

Raw-event retention can be disabled with `SREEMA_STORE_RAW_EVENTS=false`. The persisted finding/result metadata remains available, but user and source address timeline fields are omitted when raw retention is off.
