# SREEMA — Threat Intelligence & Investigation Agent

SREEMA is a defensive cybersecurity project for analysing supplied or synthetic security logs, correlating suspicious events, and producing evidence-backed investigation reports.

## Team ownership

- **Mugu (CachyOS):** React frontend, FastAPI application/API, database integration, and product UI.
- **Sreema (Windows):** investigation-agent workflow, detection tools, evidence correlation, LLM integration, and agent evaluation.

## Current status

This repository contains the initial scaffold, a functional API health endpoint, a React dashboard shell, synthetic sample events, and a shared agent integration contract. Investigation ingestion and the agent are not implemented yet.

## Repository layout

```text
Sreema/
├── backend/                 # FastAPI application (Mugu)
├── frontend/                # React + TypeScript app (Mugu)
├── agent/                   # Agent module integration boundary (Sreema)
├── contracts/               # Shared input/output schemas
├── sample_data/              # Synthetic security events only
├── docs/                     # Architecture and integration notes
├── .env.example
└── .gitignore
```

## Development setup

### Prerequisites

- Python 3.11+ (use the version agreed by the team)
- Node.js LTS and pnpm
- Git
- PostgreSQL (later milestone; not required for the initial scaffold)

### Backend (CachyOS/Linux)

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

The health endpoint is available at `http://127.0.0.1:8000/health` while the backend is running. API docs: `http://127.0.0.1:8000/docs`.

### Frontend

The React + TypeScript + Vite dashboard is scaffolded with a custom responsive CSS theme. Run `cd frontend && pnpm install && pnpm dev`; open `http://127.0.0.1:5173`. The dashboard checks the FastAPI health endpoint. Investigation data is placeholder UI until the ingestion and agent endpoints are implemented.

## Team workflow

1. Keep work on separate branches, for example `feature/app-api` and `feature/agent-core`.
2. Treat `contracts/agent-contract.md` as the shared integration agreement.
3. Coordinate schema changes before merging.
4. Use synthetic or explicitly authorised logs.
5. Never commit secrets or `.env` files.
6. The first integration should run locally; a separate agent service is not necessary yet.

## Safety and scope

The initial product is read-only. It analyses supplied data and recommends defensive next steps. It must not execute arbitrary commands, scan systems, or perform remediation automatically. Log contents are untrusted data, not instructions for the agent.
