"""Social-engineering language: pressure and requests for sensitive data.
Phrases cover English and Hebrew."""

from app.models import Finding
from app.parsing import ParsedEmail

NAME = "content"
MAX_EXAMPLES = 3

URGENCY_PHRASES = [
    "urgent", "immediately", "action required", "within 24 hours", "within 48 hours",
    "account will be suspended", "account has been suspended", "account will be closed",
    "final notice", "last warning", "expires today", "unusual activity",
    "suspicious activity", "unauthorized login",
    "דחוף", "באופן מיידי", "פעולה נדרשת", "תוך 24 שעות", "החשבון שלך ייחסם",
    "החשבון שלך נחסם", "הודעה אחרונה", "פעילות חשודה",
]

CREDENTIAL_PHRASES = [
    "verify your account", "confirm your account", "confirm your password",
    "enter your password", "update your payment", "confirm your identity",
    "verify your identity", "credit card number", "social security number",
    "login to your account", "log in to your account", "update your billing",
    "אמת את החשבון", "אימות חשבון", "הזן את הסיסמה", "פרטי כרטיס האשראי",
    "עדכן את פרטי התשלום",
]


def _matches(text: str, phrases: list[str]) -> list[str]:
    return [p for p in phrases if p in text]


def run(email: ParsedEmail) -> list[Finding]:
    findings = []

    urgency = _matches(email.text, URGENCY_PHRASES)
    if urgency:
        findings.append(Finding(
            check=NAME,
            title="Pressure or urgency language",
            detail="Phrases meant to rush you: " + ", ".join(f'"{p}"' for p in urgency[:MAX_EXAMPLES]),
            points=15,
        ))

    credentials = _matches(email.text, CREDENTIAL_PHRASES)
    if credentials:
        findings.append(Finding(
            check=NAME,
            title="Asks for credentials or payment details",
            detail="Phrases asking for sensitive data: "
            + ", ".join(f'"{p}"' for p in credentials[:MAX_EXAMPLES]),
            points=20,
        ))

    return findings
