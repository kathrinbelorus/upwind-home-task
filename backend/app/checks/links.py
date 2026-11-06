"""Suspicious links. Links are analyzed statically and are never fetched:
visiting them could trigger an exploit, confirm to the attacker that the email
was opened, or turn the backend into a proxy (SSRF)."""

import re

from app.models import Finding
from app.parsing import Link, ParsedEmail
from app.utils import base_domain, defang, is_ip

NAME = "links"
MAX_EXAMPLES = 3

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}
DANGEROUS_SCHEMES = ("javascript:", "data:", "vbscript:", "file:")

# Link text that looks like a URL or domain, e.g. "www.paypal.com/login".
_TEXT_DOMAIN_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?$"
)


def _text_domain(link: Link) -> str | None:
    match = _TEXT_DOMAIN_RE.match(link.text.strip().lower())
    return match.group(1) if match else None


def _finding(title: str, detail: str, points: int, examples: list[str]) -> Finding:
    shown = ", ".join(examples[:MAX_EXAMPLES])
    more = f" (+{len(examples) - MAX_EXAMPLES} more)" if len(examples) > MAX_EXAMPLES else ""
    return Finding(check=NAME, title=title, detail=f"{detail} {shown}{more}", points=points)


def run(email: ParsedEmail) -> list[Finding]:
    mismatched, ip_links, shortened, punycode, bad_scheme = [], [], [], [], []

    for link in email.links:
        if link.url.lower().startswith(DANGEROUS_SCHEMES):
            bad_scheme.append(link.url.split(":", 1)[0] + ":")
            continue
        if not link.host:
            continue

        shown = _text_domain(link)
        if shown and base_domain(shown) != base_domain(link.host):
            mismatched.append(f'"{defang(shown)}" -> {defang(link.host)}')
        if is_ip(link.host):
            ip_links.append(defang(link.host))
        if link.host.removeprefix("www.") in SHORTENERS:
            shortened.append(defang(link.host))
        if any(label.startswith("xn--") for label in link.host.split(".")):
            punycode.append(defang(link.host))

    findings = []
    if mismatched:
        findings.append(_finding(
            "Link text hides the real destination",
            "The visible link text shows one site but the link goes to another:",
            30, mismatched,
        ))
    if punycode:
        findings.append(_finding(
            "Look-alike domain",
            "Links use encoded international characters that can imitate real domains:",
            20, punycode,
        ))
    if ip_links:
        findings.append(_finding(
            "Link to a raw IP address",
            "Legitimate services rarely link to an IP address instead of a domain:",
            20, ip_links,
        ))
    if bad_scheme:
        findings.append(_finding(
            "Script link",
            "Links that run code instead of opening a page:",
            25, sorted(set(bad_scheme)),
        ))
    if shortened:
        findings.append(_finding(
            "Shortened link",
            "Link shorteners hide where the link really goes:",
            10, sorted(set(shortened)),
        ))
    return findings
