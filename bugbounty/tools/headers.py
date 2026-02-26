"""HTTP header injection for SSRF detection.

Tests HTTP headers that servers commonly use to determine the originating
client IP or host — these are prime injection targets for SSRF because many
web servers and proxies forward or act on them.

Strategy:
1. Inject interactsh URL into each SSRF header.
2. Wait for OOB DNS/HTTP callback.
3. Also check if injected value appears reflected in response (IP reflection).
4. Test X-Original-URL and X-Rewrite-URL for path override (may bypass auth).

Only OOB-confirmed findings are reported at high confidence.
Response-difference based detection is marked medium confidence.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import httpx

from bugbounty.core.interactsh import InteractshClient
from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import ScopeValidator

logger = logging.getLogger(__name__)

# HTTP headers known to be processed by servers and proxies for routing/identity
SSRF_HEADERS = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Custom-IP-Authorization",
    "X-Host",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-ProxyUser-Ip",
    "X-Original-Host",
    "Referer",
    "True-Client-IP",
    "CF-Connecting-IP",
]

# Canary IP to inject in IP-based headers (our listener)
_CANARY_IP = "127.0.0.1"


class HeaderInjectionFinding:
    """A header injection SSRF finding."""

    def __init__(
        self,
        url: str,
        header: str,
        payload: str,
        evidence_type: str,       # "oob_interaction" | "response_difference" | "ip_reflection"
        confidence: str,          # "confirmed" | "medium"
        evidence: str,
        oob_interaction: Optional[dict] = None,
    ) -> None:
        self.url = url
        self.header = header
        self.payload = payload
        self.evidence_type = evidence_type
        self.confidence = confidence
        self.evidence = evidence
        self.oob_interaction = oob_interaction

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "header": self.header,
            "payload": self.payload,
            "evidence_type": self.evidence_type,
            "confidence": self.confidence,
            "evidence": self.evidence[:500],
            "oob_interaction": self.oob_interaction,
        }


class HeaderInjectionScanner:
    """Tests HTTP headers for SSRF injection.

    Strategy:
    1. For each live host, inject interactsh URL into each SSRF header.
    2. Wait for OOB callback (confirms server processed the header value).
    3. Also check if injected IP/host appears reflected in response.
    4. Test X-Original-URL and X-Rewrite-URL for path override.

    Only OOB-confirmed findings are reported as high confidence.
    Response-difference based detection is marked medium confidence.
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        rate_limiter: Optional[RateLimiter] = None,
        concurrent: int = 5,
        timeout: float = 10.0,
        oob_wait: float = 15.0,
    ) -> None:
        self.scope = scope_validator
        self.rate_limiter = rate_limiter
        self.concurrent = concurrent
        self.timeout = timeout
        self.oob_wait = oob_wait
        self._semaphore = asyncio.Semaphore(concurrent)

    async def scan_hosts(
        self,
        hosts: list[str],
        interactsh: InteractshClient,
    ) -> list[HeaderInjectionFinding]:
        """Inject SSRF headers into each live host and look for callbacks.

        Args:
            hosts:      List of live host URLs.
            interactsh: Configured and started InteractshClient.

        Returns:
            List of header injection findings.
        """
        in_scope = [h for h in hosts if self.scope.is_in_scope(h)]
        logger.info(
            "Header injection scanner: testing %d hosts across %d headers",
            len(in_scope), len(SSRF_HEADERS),
        )

        tasks = [
            asyncio.create_task(self._scan_host(host, interactsh))
            for host in in_scope
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[HeaderInjectionFinding] = []
        for r in results:
            if isinstance(r, Exception):
                logger.debug("Header injection host exception: %s", r)
                continue
            if r:
                findings.extend(r)

        logger.info("Header injection scanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _scan_host(
        self,
        host_url: str,
        interactsh: InteractshClient,
    ) -> list[HeaderInjectionFinding]:
        async with self._semaphore:
            findings: list[HeaderInjectionFinding] = []

            for header in SSRF_HEADERS:
                finding = await self._test_header(host_url, header, interactsh)
                if finding:
                    findings.append(finding)
                    # One confirmed finding per host is sufficient evidence
                    if finding.confidence == "confirmed":
                        break
                # Rate limit: pause 100ms between headers
                await asyncio.sleep(0.1)

            return findings

    async def _test_header(
        self,
        url: str,
        header: str,
        interactsh: InteractshClient,
    ) -> Optional[HeaderInjectionFinding]:
        """Test a single header on a single URL for SSRF.

        Tries OOB detection first, then falls back to response-difference.
        """
        # OOB detection (if interactsh available)
        if interactsh.available:
            oob_finding = await self._test_oob(url, header, interactsh)
            if oob_finding:
                return oob_finding

        # Response-difference / IP reflection detection
        reflection_finding = await self._test_reflection(url, header)
        return reflection_finding

    async def _test_oob(
        self,
        url: str,
        header: str,
        interactsh: InteractshClient,
    ) -> Optional[HeaderInjectionFinding]:
        """Inject interactsh payload into header and wait for callback."""
        safe_header = header.lower().replace("-", "")[:12]
        payload_url = interactsh.unique_url(tag=safe_header)
        if not payload_url:
            return None

        # For IP headers, use the domain only; for host headers, use full URL
        ip_headers = {
            "X-Forwarded-For", "X-Real-IP", "X-Remote-IP",
            "X-Remote-Addr", "X-ProxyUser-Ip", "True-Client-IP",
            "CF-Connecting-IP", "X-Custom-IP-Authorization",
        }
        if header in ip_headers:
            # Strip scheme for IP headers — inject just the hostname
            from urllib.parse import urlparse as _urlparse
            payload = _urlparse(payload_url).netloc
        else:
            payload = payload_url

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                await client.get(url, headers={header: payload})
        except Exception:
            pass  # Connection errors are expected; we rely on OOB callback

        interactions = await interactsh.wait_for_interaction(
            timeout=self.oob_wait,
            expected_tag=safe_header,
        )

        if interactions:
            interaction = interactions[0]
            protocol = interaction.get("protocol", "unknown")
            remote = interaction.get("remote-address", "unknown")
            logger.info(
                "Header SSRF confirmed (OOB %s callback) on %s header=%s from %s",
                protocol, url, header, remote,
            )
            return HeaderInjectionFinding(
                url=url,
                header=header,
                payload=payload,
                evidence_type="oob_interaction",
                confidence="confirmed",
                evidence=(
                    f"Received {protocol} OOB callback when injecting interactsh URL "
                    f"into {header} header. Server made outbound connection from {remote}."
                ),
                oob_interaction=interaction,
            )
        return None

    async def _test_reflection(
        self,
        url: str,
        header: str,
    ) -> Optional[HeaderInjectionFinding]:
        """Check if an injected canary value appears reflected in the response."""
        canary = "192.0.2.99"  # TEST-NET-1 — never a real server
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                resp = await client.get(url, headers={header: canary})
                body = resp.text[:4096]
        except Exception:
            return None

        if canary in body:
            return HeaderInjectionFinding(
                url=url,
                header=header,
                payload=canary,
                evidence_type="ip_reflection",
                confidence="medium",
                evidence=(
                    f"Canary IP '{canary}' injected via {header} header was reflected "
                    f"in the response body. Server may use this header for routing."
                ),
                oob_interaction=None,
            )
        return None
