"""Small helpers for domains and for safely displaying untrusted text."""

import ipaddress
import re
import unicodedata

# Common two-part public suffixes. A full Public Suffix List would be more
# accurate; this keeps the MVP dependency-free and offline.
_MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "co.il", "org.il", "ac.il", "gov.il", "net.il",
    "com.au", "net.au", "co.jp", "com.br", "co.in", "co.za", "com.mx",
}


def base_domain(host: str) -> str:
    """Return the registrable domain: 'login.mail.paypal.com' -> 'paypal.com'."""
    labels = host.strip(".").lower().split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def defang(value: str) -> str:
    """Make a domain/URL non-clickable for display: 'evil.com' -> 'evil[.]com'."""
    return value.replace(".", "[.]")


def clean_for_display(value: str, max_len: int = 80) -> str:
    """Strip control/format characters (e.g. right-to-left override) and truncate."""
    cleaned = "".join(ch for ch in value if unicodedata.category(ch)[0] != "C")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned if len(cleaned) <= max_len else cleaned[: max_len - 1] + "…"
