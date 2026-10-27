
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ValidationError


app = FastAPI(
    title="SREEMA API",
    description="Defensive security log investigation API",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


class InvestigationRequest(BaseModel):
    events: list[dict]
    context: dict | None = None


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    """Basic liveness check."""
    return {"status": "ok", "service": "sreema-api"}


@app.post("/investigate", tags=["investigation"])
def investigate(request: InvestigationRequest) -> dict:
    """Run the deterministic SREEMA investigation agent."""
    try:
        from agent import run_investigation

        return run_investigation(
            events=request.events,
            context=request.context,
        )
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail="Invalid security event data.",
        ) from exc
