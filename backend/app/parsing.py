"""Turns the raw request into a normalized structure the checks can share.

Parsing happens once here, so every check works on the same data and none of
them has to deal with raw HTML or header formats.
"""

from dataclasses import dataclass
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

from app.models import Attachment, EmailIn

MAX_LINKS = 500


@dataclass(frozen=True)
class Link:
    text: str
    url: str
    host: str  # lowercase hostname, "" if the URL has none (e.g. mailto:)


@dataclass(frozen=True)
class ParsedEmail:
    display_name: str
    address: str
    domain: str
    reply_to_domain: str
    subject: str
    text: str  # subject + visible body text, lowercased
    links: list[Link]
    attachments: list[Attachment]
    authentication_results: str


class _HtmlExtractor(HTMLParser):
    """Collects <a href> links and visible text. Uses the stdlib parser, which
    only tokenizes: nothing in the HTML is executed or fetched."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.text_parts: list[str] = []
        self._href: str | None = None
        self._link_text: list[str] = []
        self._skip_depth = 0  # inside <script>/<style>

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip_depth += 1
        elif tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._link_text = []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "a" and self._href is not None:
            if len(self.links) < MAX_LINKS:
                self.links.append(("".join(self._link_text).strip(), self._href.strip()))
            self._href = None

    def handle_data(self, data):
        if self._skip_depth:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._link_text.append(data)


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:  # malformed URL, e.g. broken IPv6 brackets
        return ""


def _domain_of(address: str) -> str:
    return address.rpartition("@")[2].lower() if "@" in address else ""


def parse_email(email: EmailIn) -> ParsedEmail:
    display_name, address = parseaddr(email.sender)
    _, reply_to_address = parseaddr(email.reply_to or "")

    extractor = _HtmlExtractor()
    if email.body_html:
        extractor.feed(email.body_html)
        extractor.close()

    body = email.body_text or " ".join(extractor.text_parts)
    links = [Link(text=t, url=u, host=_host_of(u)) for t, u in extractor.links]

    return ParsedEmail(
        display_name=display_name.strip(),
        address=address.lower(),
        domain=_domain_of(address),
        reply_to_domain=_domain_of(reply_to_address),
        subject=email.subject,
        text=" ".join(f"{email.subject} {body}".lower().split()),
        links=links,
        attachments=email.attachments,
        authentication_results=(email.authentication_results or "").strip(),
    )
