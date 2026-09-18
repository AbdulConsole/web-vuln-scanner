"""
robots.txt handling as a configurable policy (Section 7).

When respect_robots_txt is True (the default), the crawler fetches and
parses the target's robots.txt once at crawl start and consults it before
visiting each URL. When False, everything is allowed — this is an explicit
opt-out for authorized testing where the operator has already confirmed
scanning is permitted regardless of the robots.txt policy.

Uses the standard library's RobotFileParser rather than reimplementing
robots.txt parsing, but fetches the file ourselves via the crawler's own
HTTP client (rather than RobotFileParser.read(), which does a blocking
urllib.request call) so it participates in the same scope/timeout/retry
handling as every other request the scanner makes.
"""
from __future__ import annotations

from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import httpx

from app.core.logging import get_logger

logger = get_logger(__name__)


class RobotsPolicy:
    def __init__(self, respect_robots_txt: bool = True):
        self.respect_robots_txt = respect_robots_txt
        self._parser: RobotFileParser | None = None

    async def load(self, base_url: str, http_client: httpx.AsyncClient) -> None:
        """Fetch and parse robots.txt for base_url's host. Safe to call even
        when respect_robots_txt is False (it's a no-op in that case)."""
        if not self.respect_robots_txt:
            return

        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        parser = RobotFileParser()
        parser.set_url(robots_url)
        try:
            response = await http_client.get(robots_url, timeout=5.0)
            if response.status_code == 200:
                parser.parse(response.text.splitlines())
            else:
                # No robots.txt (404) or an error status -> treat as "allow
                # all", matching de facto crawler convention.
                parser.parse([])
        except httpx.HTTPError as exc:
            logger.warning(
                "Failed to fetch robots.txt; defaulting to allow-all for this host",
                extra={"context": {"robots_url": robots_url, "error": str(exc)}},
            )
            parser.parse([])

        self._parser = parser

    def is_allowed(self, url: str, user_agent: str) -> bool:
        if not self.respect_robots_txt or self._parser is None:
            return True
        return self._parser.can_fetch(user_agent, url)
