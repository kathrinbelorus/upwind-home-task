"""Request and response schemas.

Everything in EmailIn comes from an email, which means it is attacker-controlled.
Strict limits keep oversized or malformed input out before any analysis runs.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_BODY_CHARS = 500_000
MAX_ATTACHMENTS = 100

Verdict = Literal["Safe", "Suspicious", "Malicious"]


class Attachment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str = Field(max_length=512)
    mime_type: str = Field(default="", max_length=255)
    size: int = Field(default=0, ge=0)


class EmailIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sender: str = Field(max_length=1024, description='Raw "From" header, e.g. "Name <a@b.com>"')
    reply_to: str | None = Field(default=None, max_length=1024)
    subject: str = Field(default="", max_length=2048)
    authentication_results: str | None = Field(
        default=None,
        max_length=8192,
        description="The Authentication-Results header added by Gmail (mx.google.com)",
    )
    body_text: str = Field(default="", max_length=MAX_BODY_CHARS)
    body_html: str = Field(default="", max_length=MAX_BODY_CHARS)
    attachments: list[Attachment] = Field(default_factory=list, max_length=MAX_ATTACHMENTS)


class Finding(BaseModel):
    check: str = Field(description="Which check produced this finding")
    title: str
    detail: str
    points: int = Field(ge=0, le=100)


class AiAssessment(BaseModel):
    risk: Literal["low", "medium", "high"]
    summary: str = Field(max_length=300)


class AnalysisResult(BaseModel):
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    findings: list[Finding]
    ai: AiAssessment | None = Field(default=None, description="Gemini's opinion, if available")
