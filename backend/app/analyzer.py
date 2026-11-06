"""Runs all checks and turns their findings into a score and a verdict."""

import logging

from app import ai
from app.checks import ALL_CHECKS
from app.models import AnalysisResult, EmailIn, Finding, Verdict
from app.parsing import parse_email

logger = logging.getLogger(__name__)

SUSPICIOUS_THRESHOLD = 30
MALICIOUS_THRESHOLD = 70


def verdict_for(score: int) -> Verdict:
    if score >= MALICIOUS_THRESHOLD:
        return "Malicious"
    if score >= SUSPICIOUS_THRESHOLD:
        return "Suspicious"
    return "Safe"


def analyze_email(email: EmailIn) -> AnalysisResult:
    parsed = parse_email(email)

    findings: list[Finding] = []
    for check in ALL_CHECKS:
        try:
            findings.extend(check.run(parsed))
        except Exception:
            # One broken check must not take down the whole analysis.
            # Log only the check name, never email content.
            logger.exception("Check %s failed", check.NAME)

    opinion = ai.assess(parsed)
    if opinion and ai.POINTS[opinion.risk]:
        findings.append(
            Finding(
                check="ai",
                title=f"AI rated this email {opinion.risk} risk",
                detail="Gemini's reading of the text points to phishing or a scam.",
                points=ai.POINTS[opinion.risk],
            )
        )

    findings.sort(key=lambda f: f.points, reverse=True)
    score = min(100, sum(f.points for f in findings))
    return AnalysisResult(score=score, verdict=verdict_for(score), findings=findings, ai=opinion)
