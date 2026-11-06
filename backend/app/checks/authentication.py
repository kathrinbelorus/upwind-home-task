"""SPF / DKIM / DMARC results from Gmail's Authentication-Results header.

Only the header added by Gmail itself (authserv-id "mx.google.com") is trusted.
Any other Authentication-Results header could have been written by the sender.
"""

import re

from app.models import Finding
from app.parsing import ParsedEmail

NAME = "authentication"
TRUSTED_AUTHSERV_ID = "mx.google.com"

_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)=([a-z]+)")

# (mechanism, result) -> points
_PENALTIES = {
    ("dmarc", "fail"): 30,
    ("spf", "fail"): 20,
    ("spf", "softfail"): 10,
    ("spf", "permerror"): 10,
    ("dkim", "fail"): 20,
    ("dkim", "permerror"): 10,
}

_EXPLANATIONS = {
    "spf": "the sending server is not authorized to send mail for this domain",
    "dkim": "the message signature is invalid, so it may have been altered or forged",
    "dmarc": "the message failed the domain owner's anti-spoofing policy",
}


def run(email: ParsedEmail) -> list[Finding]:
    header = email.authentication_results.lower()

    if not header:
        return [
            Finding(
                check=NAME,
                title="No authentication results",
                detail="Gmail's SPF/DKIM/DMARC results were not available for this message.",
                points=10,
            )
        ]

    if not header.startswith(TRUSTED_AUTHSERV_ID):
        return [
            Finding(
                check=NAME,
                title="Untrusted authentication results",
                detail="The authentication header was not added by Gmail, so it was ignored.",
                points=10,
            )
        ]

    # A mechanism can appear more than once (e.g. several DKIM signatures).
    # It counts as passing if any instance passed.
    results: dict[str, set[str]] = {}
    for mechanism, result in _RESULT_RE.findall(header):
        results.setdefault(mechanism, set()).add(result)

    findings = []
    for mechanism, outcomes in results.items():
        if "pass" in outcomes:
            continue
        for outcome in outcomes:
            points = _PENALTIES.get((mechanism, outcome))
            if points:
                findings.append(
                    Finding(
                        check=NAME,
                        title=f"{mechanism.upper()} {outcome}",
                        detail=f"{mechanism.upper()} check failed: {_EXPLANATIONS[mechanism]}.",
                        points=points,
                    )
                )
                break
    return findings
