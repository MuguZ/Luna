# Luna Agent Module

This package is the integration boundary for Sreema's investigation-agent work.

## First milestone

Implement a stable function compatible with the contract in `../contracts/agent-contract.md`:

```python
def run_investigation(events: list[dict], context: dict | None = None) -> dict:
    ...
```

Start with deterministic analysis utilities and synthetic logs. Add LLM-assisted investigation only after schema validation and evidence references work. Keep the workflow bounded, operate only on supplied or authorised logs, and do not execute remediation.

## Ownership

Sreema owns this package. Coordinate schema and interface changes with Mugu before merging.
