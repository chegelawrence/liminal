"""Scope validation for bug bounty targets."""

from __future__ import annotations

import ipaddress
import logging
from fnmatch import fnmatch
from typing import Optional
from urllib.parse import urlparse

import tldextract

logger = logging.getLogger(__name__)


class OutOfScopeError(ValueError):
    """Raised when a target is not within the defined scope."""

    def __init__(self, target: str, reason: str = "") -> None:
        self.target = target
        self.reason = reason
        msg = f"Target '{target}' is out of scope"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)


class ScopeValidator:
    """Validates targets against program scope rules.

    Supports wildcard domains (*.example.com), exact domain matching,
    and IP CIDR range matching.  Out-of-scope rules always take precedence
    over in-scope rules.
    """

    def __init__(
        self,
        in_scope: list[str],
        out_of_scope: list[str],
        ip_ranges: list[str] | None = None,
    ) -> None:
        self.in_scope = [s.lower().strip() for s in in_scope]
        self.out_of_scope = [s.lower().strip() for s in out_of_scope]
        self.ip_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

        for cidr in ip_ranges or []:
            try:
                self.ip_networks.append(ipaddress.ip_network(cidr.strip(), strict=False))
            except ValueError:
                logger.warning("Invalid CIDR range in config: %s", cidr)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_in_scope(self, target: str) -> bool:
        """Return True if *target* is within the programme scope.

        Out-of-scope rules are checked first and always win.
        """
        normalized = self._normalize(target)
        if normalized is None:
            return False

        if self._matches_any(normalized, self.out_of_scope):
            return False

        if self._matches_any(normalized, self.in_scope):
            return True

        # Try IP matching for raw IPs
        ip = self._extract_ip(target)
        if ip is not None:
            if self._ip_is_out_of_scope(ip):
                return False
            if self._ip_in_ranges(ip):
                return True

        return False

    def assert_in_scope(self, target: str) -> None:
        """Raise OutOfScopeError if *target* is not in scope."""
        if not self.is_in_scope(target):
            raise OutOfScopeError(target)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalize(self, target: str) -> Optional[str]:
        """Extract a comparable host/domain from *target*."""
        target = target.strip().lower()

        # If it looks like a URL, extract the host
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            host = parsed.hostname or ""
        else:
            host = target

        # Strip port if present (and not an IPv6 literal)
        if ":" in host and not host.startswith("["):
            host = host.split(":")[0]

        return host if host else None

    def _extract_ip(self, target: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """Try to parse *target* as an IP address."""
        host = self._normalize(target) or ""
        # Strip surrounding brackets for IPv6
        host = host.strip("[]")
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            return None

    def _matches_any(self, host: str, patterns: list[str]) -> bool:
        """Return True if *host* matches any pattern in *patterns*.

        Supports:
        - Exact match: ``api.example.com``
        - Wildcard prefix: ``*.example.com``
        - Pure wildcard: ``*`` (matches everything)
        """
        for pattern in patterns:
            if self._match_pattern(host, pattern):
                return True
        return False

    @staticmethod
    def _match_pattern(host: str, pattern: str) -> bool:
        """Test a single pattern against a host."""
        # Exact match
        if host == pattern:
            return True

        # Wildcard pattern – use fnmatch which handles *.example.com correctly
        if "*" in pattern:
            if fnmatch(host, pattern):
                return True
            # Also match the apex domain itself for *.example.com → example.com
            # Only when the pattern is strictly *.something
            if pattern.startswith("*."):
                apex = pattern[2:]
                if host == apex:
                    return True

        return False

    def _ip_in_ranges(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Return True if *ip* falls within any configured IP range."""
        for network in self.ip_networks:
            try:
                if ip in network:
                    return True
            except TypeError:
                # IPv4 address vs IPv6 network mismatch
                continue
        return False

    def _ip_is_out_of_scope(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Check if an IP matches any out-of-scope pattern (exact IP strings)."""
        ip_str = str(ip)
        for entry in self.out_of_scope:
            if ip_str == entry.strip():
                return True
        return False

    # ------------------------------------------------------------------
    # Convenience helpers used by pipelines
    # ------------------------------------------------------------------

    def filter_in_scope(self, targets: list[str]) -> list[str]:
        """Return only the targets that are in scope."""
        result: list[str] = []
        for t in targets:
            if self.is_in_scope(t):
                result.append(t)
            else:
                logger.debug("Filtered out-of-scope target: %s", t)
        return result
