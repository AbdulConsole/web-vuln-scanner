"""
Scope and network-safety enforcement.

This module is the scanner's single security boundary: every outbound HTTP
request the scanner ever makes (crawler, detectors, verification requests)
must be checked here first — including redirect targets, not just the
initial URL. Centralizing this in one small, heavily-tested module is a
deliberate design choice: scope bugs scattered across detectors would be
very hard to audit.

Two independent checks are performed:

1. Domain scope: the request's hostname must match the target's configured
   base domain or one of its explicitly allowed additional domains.
2. Network safety: the resolved IP address must not fall within a blocked
   range (loopback, link-local, RFC1918 private ranges, cloud metadata
   endpoint) unless the deployment has explicitly enabled lab mode.
"""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlparse

from app.core.config import get_settings
from app.core.exceptions import ScopeViolationError, UnsafeTargetError
from app.core.logging import get_logger

logger = get_logger(__name__)


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


@dataclass(frozen=True)
class ScopePolicy:
    """The authorized scope for a single target.

    base_domain: the primary domain of the target (e.g. "example.com").
    allowed_domains: any additional domains explicitly authorized for this
        target (e.g. staging subdomains). Subdomains of an allowed domain
        are permitted; unrelated domains are not.
    """

    base_domain: str
    allowed_domains: tuple[str, ...] = field(default_factory=tuple)

    def _all_domains(self) -> Iterable[str]:
        yield _normalize_host(self.base_domain)
        for d in self.allowed_domains:
            yield _normalize_host(d)

    def is_host_in_scope(self, host: str) -> bool:
        host = _normalize_host(host)
        for domain in self._all_domains():
            if host == domain or host.endswith("." + domain):
                return True
        return False


class ScopeGuard:
    """Validates outbound requests against a target's ScopePolicy and
    against network-level SSRF protections before any request is sent."""

    def __init__(self, policy: ScopePolicy):
        self._policy = policy
        self._settings = get_settings()
        self._blocked_networks = [
            ipaddress.ip_network(net, strict=False)
            for net in self._settings.BLOCKED_IP_NETWORKS
        ]

    def check_domain_scope(self, url: str) -> None:
        parsed = urlparse(url)
        if not parsed.hostname:
            raise ScopeViolationError(f"URL has no resolvable host: {url}")
        if not self._policy.is_host_in_scope(parsed.hostname):
            raise ScopeViolationError(
                f"Host '{parsed.hostname}' is outside the authorized scope "
                f"for this target."
            )

    def check_network_safety(self, url: str) -> None:
        """Resolve the URL's host and reject it if it lands in a blocked
        network range, unless lab mode is explicitly enabled."""
        if self._settings.ALLOW_PRIVATE_NETWORK_TARGETS:
            return

        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            raise ScopeViolationError(f"URL has no resolvable host: {url}")

        try:
            # If host is already a literal IP, this succeeds directly.
            addresses = {ipaddress.ip_address(host)}
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None)
            except socket.gaierror as exc:
                raise ScopeViolationError(
                    f"Could not resolve host '{host}': {exc}"
                ) from exc
            addresses = {ipaddress.ip_address(info[4][0]) for info in infos}

        for addr in addresses:
            for network in self._blocked_networks:
                if addr in network:
                    logger.warning(
                        "Blocked unsafe target resolution",
                        extra={
                            "context": {
                                "host": host,
                                "resolved_ip": str(addr),
                                "blocked_network": str(network),
                            }
                        },
                    )
                    raise UnsafeTargetError(
                        f"Host '{host}' resolves to '{addr}', which falls "
                        f"within the restricted network range {network}. "
                        f"Enable ALLOW_PRIVATE_NETWORK_TARGETS for lab use."
                    )

    def validate(self, url: str) -> None:
        """Full validation: call this before every outbound request."""
        self.check_domain_scope(url)
        self.check_network_safety(url)
