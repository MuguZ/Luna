# SREEMA Architecture (Initial)

## Components

1. **React frontend (Mugu):** upload logs, view investigations, review event timelines and findings.
2. **FastAPI application (Mugu):** API validation, file ingestion, persistence, and invokes the agent module.
3. **Agent module (Sreema):** bounded investigation workflow, approved analysis tools, evidence correlation, and validated output.
4. **PostgreSQL (later milestone):** persistent investigations, alerts, and audit records.
5. **LLM provider (optional):** used for evidence-grounded explanation; deterministic detections must remain useful without it.

## First vertical slice

1. Load a synthetic JSON event file.
2. Validate and normalise the events.
3. Apply deterministic detection rules.
4. Run an investigation with the agent module.
5. Validate its result against the shared output contract.
6. Display the findings in the frontend.

## Principles

- Evidence first: every finding should trace to event IDs.
- Deterministic detection and LLM explanation remain separate.
- Bounded workflows with explicit tool-call and runtime limits.
- Read-only analysis of supplied logs.
- Human review before any future response action.
- Cross-platform local development on CachyOS and Windows.
