"""Sender impersonation: display-name tricks and mismatched Reply-To."""

import re

from app.models import Finding
from app.parsing import ParsedEmail
from app.utils import base_domain, clean_for_display, defang

NAME = "sender"

# Frequently impersonated brands -> their legitimate registrable domains.
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "office.com", "outlook.com", "live.com"},
    "office 365": {"microsoft.com", "office.com"},
    "outlook": {"microsoft.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"apple.com", "icloud.com"},
    "google": {"google.com", "youtube.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazonses.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com", "facebookmail.com"},
    "linkedin": {"linkedin.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "docusign": {"docusign.com", "docusign.net"},
}

_BRAND_LABELS = {
    "paypal": "PayPal", "icloud": "iCloud", "linkedin": "LinkedIn", "dhl": "DHL",
    "fedex": "FedEx", "docusign": "DocuSign", "office 365": "Office 365",
}

_EMAIL_IN_TEXT_RE =re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")


def run(email: ParsedEmail) -> list[Finding]:
    if not email.domain:
        return [
            Finding(
                check=NAME,
                title="Malformed sender address",
                detail="The sender address is missing or could not be parsed.",
                points=20,
            )
        ]

    findings = []
    sender_base = base_domain(email.domain)
    name = email.display_name.lower()
    shown_domain = defang(email.domain)

    # "support@paypal.com <attacker@evil.com>": the display name shows another address.
    for shown in _EMAIL_IN_TEXT_RE.findall(name):
        if base_domain(shown) != sender_base:
            findings.append(
                Finding(
                    check=NAME,
                    title="Display name shows a different address",
                    detail=(
                        f'The name shows an address at "{defang(shown)}", '
                        f'but the email was sent from "{shown_domain}".'
                    ),
                    points=25,
                )
            )
            break

    # "PayPal Security <alerts@paypa1-secure.ru>": brand name from a foreign domain.
    for brand, official_domains in BRANDS.items():
        if re.search(rf"\b{re.escape(brand)}\b", name) and sender_base not in official_domains:
            label = _BRAND_LABELS.get(brand, brand.title())
            findings.append(
                Finding(
                    check=NAME,
                    title=f"Possible {label} impersonation",
                    detail=(
                        f'The sender name "{clean_for_display(email.display_name)}" '
                        f'suggests {label}, but the email came from "{shown_domain}".'
                    ),
                    points=30,
                )
            )
            break

    if email.reply_to_domain and base_domain(email.reply_to_domain) != sender_base:
        findings.append(
            Finding(
                check=NAME,
                title="Replies go to a different domain",
                detail=(
                    f'Replies will be sent to "{defang(email.reply_to_domain)}", '
                    f'not to the sender\'s domain "{shown_domain}".'
                ),
                points=15,
            )
        )

    return findings
