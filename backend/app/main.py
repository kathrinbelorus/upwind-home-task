"""HTTP layer: routing and authentication only. Analysis lives in analyzer.py."""

import hmac

from fastapi import Depends, FastAPI, Header, HTTPException, status

from app.analyzer import analyze_email
from app.config import get_settings
from app.models import AnalysisResult, EmailIn

settings = get_settings()

app = FastAPI(
    title="Mail Scorer API",
    version="0.1.0",
    description="Scores how likely an email is to be malicious and explains why.",
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.enable_docs else None,
)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Reject requests that don't carry the shared secret.
    compare_digest takes the same time whether or not the key is close, so the
    key can't be guessed character by character from response times."""
    expected = settings.api_key.get_secret_value().encode()
    if not x_api_key or not hmac.compare_digest(x_api_key.encode(), expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisResult, dependencies=[Depends(require_api_key)])
def analyze(email: EmailIn) -> AnalysisResult:
    return analyze_email(email)
