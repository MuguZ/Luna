from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="SREEMA API",
    description="Defensive security log investigation API",
    version="0.1.0",
)

# Development-only frontend origin. Tighten this for deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    """Basic liveness check."""
    return {"status": "ok", "service": "sreema-api"}
