"""
URL normalization and domain validation utilities.

Centralized here (rather than duplicated in target validation and the
crawler's URL manager) so "two URLs that differ only in port/case/query
order are the same URL" is decided in exactly one place. Target management
(Milestone 3) uses this for base_url normalization and duplicate-target
detection; the crawler (Milestone 4) will reuse it for crawl-time URL
deduplication.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_DEFAULT_PORTS = {"http": 80, "https": 443}


class InvalidUrlError(ValueError):
    """Raised when a URL cannot be parsed or is missing required parts."""


def normalize_url(raw_url: str, *, sort_query: bool = True, strip_fragment: bool = True) -> str:
    """Canonicalize a URL for storage, comparison, and deduplication.

    Applies:
    - lowercased scheme and host
    - removal of the default port for the scheme (":80" on http, ":443" on https)
    - fragment removal (unless strip_fragment=False)
    - alphabetical sorting of query parameters (unless sort_query=False),
      so "?b=2&a=1" and "?a=1&b=2" normalize identically
    - an empty path collapsed to "/"

    This is intentionally conservative: it does not attempt dot-segment
    (".."), trailing-slash-on-directory, or scheme-specific canonicalization
    beyond the above — those are handled by the crawler's URL manager
    (Milestone 4), which has more context (redirect chains, response
    Content-Type) to do so safely.
    """
    raw_url = raw_url.strip()
    parsed = urlparse(raw_url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise InvalidUrlError(f"Unsupported or missing URL scheme: {raw_url!r}")
    if not parsed.hostname:
        raise InvalidUrlError(f"URL has no host: {raw_url!r}")

    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    port = parsed.port

    netloc = f"{host}:{port}" if port and port != _DEFAULT_PORTS.get(scheme) else host

    path = parsed.path or "/"

    query = parsed.query
    if sort_query and query:
        pairs = sorted(parse_qsl(query, keep_blank_values=True))
        query = urlencode(pairs)

    fragment = "" if strip_fragment else parsed.fragment

    return urlunparse((scheme, netloc, path, "", query, fragment))


def extract_domain(url: str) -> str:
    """Return the lowercased hostname of a URL, after normalization."""
    normalized = normalize_url(url)
    hostname = urlparse(normalized).hostname
    if not hostname:
        raise InvalidUrlError(f"URL has no host: {url!r}")
    return hostname.lower()


def is_valid_domain(domain: str) -> bool:
    """Validate a bare domain/hostname (no scheme, no path, no port).

    Accepts IP literals (useful for lab environments scanning an app by IP)
    as well as standard DNS labels.
    """
    domain = domain.strip().lower().rstrip(".")
    if not domain or " " in domain:
        return False
    if "://" in domain or "/" in domain:
        return False

    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        pass

    labels = domain.split(".")
    if not labels:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not all(ch.isalnum() or ch == "-" for ch in label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True
