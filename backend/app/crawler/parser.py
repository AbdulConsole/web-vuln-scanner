"""
HTML parsing for attack-surface discovery (Section 7).

Produces structured DiscoveredForm/DiscoveredParameter objects rather than
handing raw HTML to the caller — detectors (Milestone 6/7) work against
this structured surface, not against re-parsed pages.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urljoin, urlparse

from bs4 import BeautifulSoup

from app.crawler.models import DiscoveredForm, DiscoveredParameter
from app.models.enums import HttpMethod, ParameterSource

_SKIPPABLE_HREF_PREFIXES = ("mailto:", "tel:", "javascript:", "data:", "#")


def _is_skippable_href(href: str) -> bool:
    href = href.strip().lower()
    return href == "" or href.startswith(_SKIPPABLE_HREF_PREFIXES)


def extract_links(html: str, base_url: str) -> list[str]:
    """Resolve every followable <a href> / <link href> on the page to an
    absolute URL. Non-navigational schemes (mailto, javascript, etc.) and
    fragment-only links are skipped."""
    soup = BeautifulSoup(html, "lxml")
    links: list[str] = []
    seen: set[str] = set()

    for tag in soup.find_all(["a", "link"], href=True):
        href = tag["href"]
        if _is_skippable_href(href):
            continue
        absolute = urljoin(base_url, href.strip())
        if absolute not in seen:
            seen.add(absolute)
            links.append(absolute)

    return links


def extract_forms(html: str, base_url: str) -> list[DiscoveredForm]:
    """Extract <form> elements as structured DiscoveredForm records.

    Per HTML spec, a form with no explicit method attribute defaults to
    GET — this is intentionally not defaulted to POST, even though POST is
    the more common case for state-changing forms, to match actual browser
    behaviour and avoid mischaracterizing a form's real method.
    """
    soup = BeautifulSoup(html, "lxml")
    forms: list[DiscoveredForm] = []

    for form_tag in soup.find_all("form"):
        action = (form_tag.get("action") or "").strip() or base_url
        action_url = urljoin(base_url, action)

        method_str = (form_tag.get("method") or "GET").strip().upper()
        try:
            method = HttpMethod(method_str)
        except ValueError:
            method = HttpMethod.GET

        inputs: list[dict] = []
        for field_tag in form_tag.find_all(["input", "textarea", "select"]):
            name = field_tag.get("name")
            if not name:
                continue
            if field_tag.name == "input":
                field_type = field_tag.get("type", "text")
            else:
                field_type = field_tag.name
            inputs.append(
                {
                    "name": name,
                    "type": field_type,
                    "value": field_tag.get("value", ""),
                }
            )

        forms.append(DiscoveredForm(action=action_url, method=method, inputs=inputs))

    return forms


def extract_query_parameters(url: str) -> list[DiscoveredParameter]:
    """Extract query-string parameters from a URL as DiscoveredParameter
    records, deduplicated by name (first occurrence wins)."""
    parsed = urlparse(url)
    seen_names: set[str] = set()
    parameters: list[DiscoveredParameter] = []

    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        if name in seen_names:
            continue
        seen_names.add(name)
        parameters.append(
            DiscoveredParameter(name=name, source=ParameterSource.QUERY, sample_value=value)
        )

    return parameters


def extract_form_parameters(form: DiscoveredForm) -> list[DiscoveredParameter]:
    """Convert a form's input fields into DiscoveredParameter records,
    tagged with the correct source depending on the form's HTTP method."""
    source = ParameterSource.FORM if form.method != HttpMethod.GET else ParameterSource.QUERY
    seen_names: set[str] = set()
    parameters: list[DiscoveredParameter] = []

    for field in form.inputs:
        name = field.get("name")
        if not name or name in seen_names:
            continue
        seen_names.add(name)
        parameters.append(
            DiscoveredParameter(name=name, source=source, sample_value=field.get("value"))
        )

    return parameters
