"""CORS misconfiguration scanner.

Tests for Access-Control-Allow-Origin misconfigurations that allow
unauthorised cross-origin access to sensitive data.

Only scans HTTPS URLs — HTTP CORS misconfigurations have no practical
security impact since the data is already transmitted in plaintext.

False-positive reduction:
- Re-verify critical and high findings before returning.
- Wildcard CORS without credentials is informational only (spec disallows
  cookies with wildcard ACAO).
- Check multiple API paths per host to find the highest-severity issue.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional
from urllib.parse import urlparse

import httpx

from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import ScopeValidator

logger = logging.getLogger(__name__)

# API paths to test per host — ordered by interest level
_API_PATHS = [
    "/api/v1/",
    "/api/v2/",
    "/api/",
    "/graphql",
    "/user",
    "/profile",
    "/account",
    "/me",
    "/",
]

# Origins to inject — ordered to escalate from most to least impactful
_TEST_ORIGINS = [
    ("reflected", "https://evil.com"),
    ("null", "null"),
    ("prefix", None),    # dynamically set per-target: https://TARGET.evil.com
    ("suffix", None),    # dynamically set per-target: https://evil.TARGET.com
    ("wildcard", "*"),
]


class CORSFinding:
    """A CORS misconfiguration finding."""

    def __init__(
        self,
        url: str,
        origin_tested: str,
        acao_header: str,
        acac_header: bool,
        severity: str,
        confidence: str,
        bypass_type: str,      # "reflected" | "null" | "wildcard" | "prefix" | "suffix"
        exploitability: str,
    ) -> None:
        self.url = url
        self.origin_tested = origin_tested
        self.acao_header = acao_header
        self.acac_header = acac_header
        self.severity = severity
        self.confidence = confidence
        self.bypass_type = bypass_type
        self.exploitability = exploitability

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "origin_tested": self.origin_tested,
            "acao_header": self.acao_header,
            "acac_header": self.acac_header,
            "severity": self.severity,
            "confidence": self.confidence,
            "bypass_type": self.bypass_type,
            "exploitability": self.exploitability,
        }


class CORSScanner:
    """Detects CORS misconfigurations.

    Tests these bypass techniques in order:
    1. Reflected origin: Origin: https://evil.com → ACAO: https://evil.com
    2. Null origin: Origin: null → ACAO: null
    3. Prefix bypass: Origin: https://TARGET.evil.com → ACAO: https://TARGET.evil.com
    4. Suffix bypass: Origin: https://evil.TARGET.com → ACAO: https://evil.TARGET.com
    5. Wildcard: Origin: * (mainly informational)

    Severity:
    - CRITICAL: Reflected/null + credentials: true → account takeover
    - HIGH: Reflected/null, no credentials → data theft if sensitive endpoint
    - MEDIUM: Wildcard (no credentials possible with wildcard per spec)
    - LOW: Prefix/suffix bypass only

    Only scans HTTPS URLs (HTTP CORS is meaningless for security).
    Tests API endpoints first (paths containing /api/, /v1/, /v2/, /graphql).
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        rate_limiter: Optional[RateLimiter] = None,
        concurrent: int = 10,
        timeout: float = 8.0,
        api_paths: Optional[list[str]] = None,
        verify_findings: bool = True,
    ) -> None:
        self.scope = scope_validator
        self.rate_limiter = rate_limiter
        self.concurrent = concurrent
        self.timeout = timeout
        self.api_paths = api_paths or _API_PATHS
        self.verify_findings = verify_findings
        self._semaphore = asyncio.Semaphore(concurrent)

    async def scan_hosts(self, live_hosts: list[str]) -> list[CORSFinding]:
        """Scan a list of live hosts for CORS misconfigurations.

        For each host, test up to 5 paths: root /, /api/, /api/v1/,
        /graphql, /user or /profile if discovered.

        Args:
            live_hosts: List of live host URLs.

        Returns:
            List of CORS findings, de-duplicated per host.
        """
        # Only HTTPS targets
        https_hosts = [
            h for h in live_hosts
            if h.startswith("https://") and self.scope.is_in_scope(h)
        ]

        logger.info(
            "CORS scanner: testing %d HTTPS hosts", len(https_hosts)
        )

        tasks = [
            asyncio.create_task(self._scan_host(host))
            for host in https_hosts
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[CORSFinding] = []
        for r in results:
            if isinstance(r, Exception):
                logger.debug("CORS host scan exception: %s", r)
                continue
            if r:
                findings.extend(r)

        logger.info("CORS scanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _scan_host(self, host_url: str) -> list[CORSFinding]:
        async with self._semaphore:
            parsed = urlparse(host_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            target_domain = parsed.netloc

            # Build test URLs: API paths first (more likely to be sensitive)
            test_paths = self.api_paths[:5]
            findings: list[CORSFinding] = []
            seen_bypass_types: set[str] = set()

            for path in test_paths:
                url = f"{base}{path}"
                if not self.scope.is_in_scope(url):
                    continue

                # Build origin variants for this target
                origins: list[tuple[str, str]] = []
                for bypass_type, origin_val in _TEST_ORIGINS:
                    if bypass_type == "prefix":
                        origin = f"https://{target_domain}.evil.com"
                    elif bypass_type == "suffix":
                        origin = f"https://evil.{target_domain}"
                    else:
                        origin = origin_val  # type: ignore[assignment]
                    origins.append((bypass_type, origin))

                for bypass_type, origin in origins:
                    if bypass_type in seen_bypass_types:
                        continue  # already found this bypass type on a different path

                    finding = await self._test_origin(url, origin, bypass_type)
                    if finding:
                        if self.verify_findings and finding.severity in ("critical", "high"):
                            confirmed = await self._verify(url, origin, bypass_type)
                            if not confirmed:
                                continue
                        findings.append(finding)
                        seen_bypass_types.add(bypass_type)
                        # If we found critical/high, no need to continue lower-priority checks
                        if finding.severity in ("critical", "high"):
                            break

                if findings and any(f.severity in ("critical", "high") for f in findings):
                    break  # Stop testing paths once a high/critical finding is confirmed

            return findings

    async def _test_origin(
        self,
        url: str,
        origin: str,
        bypass_type: str,
    ) -> Optional[CORSFinding]:
        """Send a preflight-style request and evaluate the response headers."""
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                resp = await client.get(
                    url,
                    headers={
                        "Origin": origin,
                        "Accept": "application/json, */*",
                    },
                )
                acao = resp.headers.get("access-control-allow-origin", "")
                acac_raw = resp.headers.get("access-control-allow-credentials", "").lower()
                acac = acac_raw == "true"
        except Exception as exc:
            logger.debug("CORS test failed for %s: %s", url, exc)
            return None

        if not acao:
            return None

        # Evaluate the ACAO response
        severity, exploitability = self._classify(acao, acac, bypass_type, origin)
        if severity is None:
            return None

        return CORSFinding(
            url=url,
            origin_tested=origin,
            acao_header=acao,
            acac_header=acac,
            severity=severity,
            confidence="confirmed",
            bypass_type=bypass_type,
            exploitability=exploitability,
        )

    async def _verify(self, url: str, origin: str, bypass_type: str) -> bool:
        """Re-test to confirm the finding is reproducible."""
        finding = await self._test_origin(url, origin, bypass_type)
        return finding is not None

    @staticmethod
    def _classify(
        acao: str,
        acac: bool,
        bypass_type: str,
        origin: str,
    ) -> tuple[Optional[str], str]:
        """Classify severity and exploitability of a CORS response.

        Returns:
            (severity, exploitability_description) or (None, "") if not vulnerable.
        """
        acao_stripped = acao.strip()

        # Wildcard ACAO — low severity because credentials are impossible with wildcard
        if acao_stripped == "*":
            return (
                "medium",
                "Wildcard ACAO allows any origin to read responses. "
                "Credentials (cookies/auth headers) cannot be sent with wildcard ACAO per spec, "
                "so impact is limited to unauthenticated data.",
            )

        # Null origin reflection — can be triggered from sandboxed iframes
        if bypass_type == "null" and acao_stripped == "null":
            if acac:
                return (
                    "critical",
                    "Null origin reflected with Access-Control-Allow-Credentials: true. "
                    "Attacker can send requests from a sandboxed iframe with cookies, "
                    "enabling full cross-origin account takeover.",
                )
            return (
                "high",
                "Null origin reflected without credentials flag. "
                "Attacker can exfiltrate unauthenticated response data from a sandboxed iframe.",
            )

        # Exact origin reflection
        if bypass_type == "reflected" and acao_stripped == origin:
            if acac:
                return (
                    "critical",
                    "Arbitrary origin reflected with Access-Control-Allow-Credentials: true. "
                    "Attacker can read authenticated responses from any origin, "
                    "enabling cross-origin account takeover and data exfiltration.",
                )
            return (
                "high",
                "Arbitrary origin reflected without credentials flag. "
                "Attacker can read unauthenticated response data cross-origin.",
            )

        # Prefix bypass (e.g. https://TARGET.evil.com was reflected)
        if bypass_type == "prefix" and acao_stripped == origin:
            return (
                "low",
                "Prefix subdomain bypass: origin ending in target domain was reflected. "
                "Attacker controlling a subdomain of the attacker domain can read responses.",
            )

        # Suffix bypass (e.g. https://evil.TARGET.com was reflected)
        if bypass_type == "suffix" and acao_stripped == origin:
            return (
                "low",
                "Suffix subdomain bypass: origin that starts with attacker host was reflected. "
                "Requires attacker-controlled subdomain of the target domain to exploit.",
            )

        return (None, "")
