# Agent Integration Contract (v0.1)

This file is the shared agreement between Mugu's FastAPI application and Sreema's agent module. Propose changes in a PR and notify both teammates before changing field names.

## Integration approach

For the first version, call the agent as a Python module from the backend. Do not run a separate agent service yet.

Suggested public entry point:

```python
def run_investigation(events: list[dict], context: dict | None = None) -> dict:
    ...
```

Sreema owns the initial implementation of this interface. Mugu owns the API that invokes it.

## Normalised event shape

Required:
- `event_id`: stable string unique within the submitted dataset
- `timestamp`: ISO-8601 datetime with timezone where available
- `event_type`: short event category
- `source`: log source or system name

Optional, when present in source data:
- `username`: account name
- `source_ip`: source IP address
- `outcome`: e.g. success or failure
- `resource`: accessed resource
- `message`: original log message

Do not invent missing fields. Preserve source information and report incomplete data.

## Investigation output

Return a JSON-serialisable object with:
- `summary`: concise evidence-grounded summary
- `severity`: `low`, `medium`, `high`, `critical`, or `unknown`
- `confidence`: number from 0 to 1, described as an uncalibrated assessment unless measured
- `findings`: list of objects with `title`, `rationale`, `evidence_event_ids`, and `confidence`
- `timeline`: chronological event references or timeline entries
- `recommended_actions`: defensive recommendations, not executed actions
- `limitations`: missing data, uncertainty, and important caveats

Every cited event ID must exist in the submitted events. Unsupported conclusions must be marked uncertain or omitted. Severity and confidence must not be presented as proof of compromise.

## Error handling

- Invalid input: return a clear validation error or raise a documented validation exception.
- LLM unavailable: return deterministic findings if available and state that AI explanation was unavailable.
- Tool/workflow limit reached: stop safely and disclose partial results.
- Do not return secrets, provider keys, or hidden prompts in errors.

## Security boundaries

- Analyse synthetic or authorised logs only.
- Treat log messages as untrusted data, never as agent instructions.
- No arbitrary shell tools, active scanning, or automated remediation.
- Any future consequential action requires explicit human approval.

## Example

See `../sample_data/auth_events.json` for synthetic input. This contract is a starting point and should be updated only by team agreement.
