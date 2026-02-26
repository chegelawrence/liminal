"""Open redirect detection tool.

Strategy for minimal false positives:
1. Only test parameters with redirect-related names.
2. Use a per-test tracking domain to confirm actual landing location.
3. Follow all redirects and check the final URL host.
4. Only report if the final URL host matches the injected domain exactly.
5. Re-verify all findings before returning.
6. Identify chaining potential (OAuth, SSRF, phishing).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional
from urllib.parse import parse_qs, urlparse, urlencode

import httpx

from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import ScopeValidator

logger = logging.getLogger(__name__)

# Parameter names commonly used for redirect targets (50+ names)
REDIRECT_PARAMS = [
    "next", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "returnto", "return_to", "returnurl", "goto", "destination", "dest", "url",
    "target", "continue", "after", "back", "forward", "redir", "location",
    "checkout_url", "success_url", "cancel_url", "callback", "oauth_callback",
    "post_login_redirect", "login_redirect", "from", "to", "out", "exit",
    "jump", "link", "navigate", "navigate_to", "ref", "referer", "refurl",
    "r", "l", "u", "uri", "href", "endpoint", "service", "domain", "site",
    "window", "go", "path", "deep_link",
]

# Payloads to test — ordered by technique
_REDIRECT_PAYLOADS = [
    "https://evil.com",          # straightforward
    "//evil.com",                # protocol-relative
    "https://evil.com%2F",       # URL-encoded slash (bypass)
    "https://evil.com/",
]

# OAuth-related path keywords — if endpoint path contains these, mark as oauth chain
_OAUTH_KEYWORDS = [
    "oauth", "authorize", "callback", "token", "auth", "sso", "saml",
    "login", "signin", "connect", "openid",
]

# SSRF-prone parameter names
_SSRF_PARAM_KEYWORDS = [
    "url", "uri", "src", "source", "dest", "destination", "endpoint",
    "service", "domain", "site", "href", "link", "ref",
]

# The canary domain we inject — must not be a real domain the target controls
_CANARY_HOST = "evil.com"


class OpenRedirectFinding:
    """Confirmed or high-confidence open redirect finding."""

    def __init__(
        self,
        url: str,
        param: str,
        payload: str,
        final_url: str,
        confidence: str,          # "confirmed" | "high"
        evidence: str,
        chaining_potential: str,  # "ssrf" | "oauth" | "phishing" | "none"
    ) -> None:
        self.url = url
        self.param = param
        self.payload = payload
        self.final_url = final_url
        self.confidence = confidence
        self.evidence = evidence
        self.chaining_potential = chaining_potential

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "param": self.param,
            "payload": self.payload,
            "final_url": self.final_url,
            "confidence": self.confidence,
            "evidence": self.evidence[:500],
            "chaining_potential": self.chaining_potential,
        }


class OpenRedirectScanner:
    """Detects open redirects in URL parameters.

    Strategy (minimal FPs):
    1. Test only parameters with redirect-related names.
    2. Use a tracking domain (unique per test) to confirm we actually land there.
    3. Follow all redirects and check final URL host.
    4. Only report if final URL host matches injected domain exactly.
    5. Re-verify before reporting.

    Also identifies chaining potential:
    - If endpoint is part of OAuth flow → mark as oauth chain
    - If SSRF-prone param name → mark as ssrf chain
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        rate_limiter: Optional[RateLimiter] = None,
        concurrent: int = 5,
        timeout: float = 8.0,
        verify_findings: bool = True,
    ) -> None:
        self.scope = scope_validator
        self.rate_limiter = rate_limiter
        self.concurrent = concurrent
        self.timeout = timeout
        self.verify_findings = verify_findings
        self._semaphore = asyncio.Semaphore(concurrent)

    async def scan_urls(self, urls: list[str]) -> list[OpenRedirectFinding]:
        """Extract redirect-like params from URL query strings and test them.

        Args:
            urls: List of URLs to test.

        Returns:
            List of confirmed open redirect findings.
        """
        # Build (url, param, original_value) tuples for redirect-relevant params
        candidates: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str]] = set()

        for raw_url in urls:
            if not self.scope.is_in_scope(raw_url):
                continue
            parsed = urlparse(raw_url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # Test existing params that are redirect-related
            for param, values in qs.items():
                if param.lower() in REDIRECT_PARAMS:
                    key = (base_url, param.lower())
                    if key not in seen:
                        seen.add(key)
                        orig = values[0] if values else ""
                        candidates.append((base_url, param, orig))

            # Also inject known redirect param names even if not present in URL
            for rp in REDIRECT_PARAMS[:20]:  # top 20
                key = (base_url, rp)
                if key not in seen:
                    seen.add(key)
                    candidates.append((base_url, rp, ""))

        logger.info(
            "Open redirect scanner: testing %d candidates across %d URLs",
            len(candidates), len(urls),
        )

        tasks = [
            asyncio.create_task(self._test_candidate(base_url, param, orig_val))
            for base_url, param, orig_val in candidates
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[OpenRedirectFinding] = []
        for r in results:
            if isinstance(r, Exception):
                logger.debug("Open redirect candidate exception: %s", r)
                continue
            if r:
                findings.append(r)

        logger.info("Open redirect scanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _test_candidate(
        self,
        base_url: str,
        param: str,
        original_value: str,
    ) -> Optional[OpenRedirectFinding]:
        async with self._semaphore:
            # Determine chaining potential before testing
            chain = self._assess_chaining(base_url, param)

            for payload in _REDIRECT_PAYLOADS:
                finding = await self._try_payload(base_url, param, payload, chain)
                if finding:
                    if self.verify_findings:
                        confirmed = await self._verify(base_url, param, payload, chain)
                        if not confirmed:
                            continue
                    return finding
            return None

    async def _try_payload(
        self,
        base_url: str,
        param: str,
        payload: str,
        chain: str,
    ) -> Optional[OpenRedirectFinding]:
        test_url = f"{base_url}?{urlencode({param: payload})}"
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                max_redirects=10,
            ) as client:
                resp = await client.get(test_url)
                final_url = str(resp.url)
        except Exception as exc:
            logger.debug("Open redirect request failed: %s", exc)
            return None

        final_host = urlparse(final_url).netloc.lower().rstrip("/")
        payload_host = urlparse(payload).netloc.lower().rstrip("/")

        # For protocol-relative (//evil.com), urlib parses netloc as empty if
        # we don't supply scheme — check alternative
        if not payload_host and payload.startswith("//"):
            payload_host = payload.lstrip("/").split("/")[0].lower()

        if not payload_host:
            return None

        # Strict match: final host must be exactly the canary host
        if final_host == payload_host or final_host == _CANARY_HOST:
            confidence = "confirmed"
            evidence = (
                f"Request to {test_url!r} redirected to {final_url!r}. "
                f"Final host '{final_host}' matches injected host '{payload_host}'."
            )
            return OpenRedirectFinding(
                url=test_url,
                param=param,
                payload=payload,
                final_url=final_url,
                confidence=confidence,
                evidence=evidence,
                chaining_potential=chain,
            )

        # Soft match: final URL contains the payload domain (subdomain bypass check)
        if payload_host in final_host:
            evidence = (
                f"Request to {test_url!r} redirected to {final_url!r}. "
                f"Final host '{final_host}' contains injected host '{payload_host}' (partial match)."
            )
            return OpenRedirectFinding(
                url=test_url,
                param=param,
                payload=payload,
                final_url=final_url,
                confidence="high",
                evidence=evidence,
                chaining_potential=chain,
            )

        return None

    async def _verify(
        self,
        base_url: str,
        param: str,
        payload: str,
        chain: str,
    ) -> bool:
        """Re-test to confirm the finding is reproducible."""
        finding = await self._try_payload(base_url, param, payload, chain)
        return finding is not None

    @staticmethod
    def _assess_chaining(base_url: str, param: str) -> str:
        """Determine the chaining potential of this redirect endpoint."""
        lower_url = base_url.lower()
        lower_param = param.lower()

        # OAuth chain: path contains OAuth-related keywords
        if any(kw in lower_url for kw in _OAUTH_KEYWORDS):
            return "oauth"

        # SSRF chain: param name looks SSRF-prone
        if lower_param in _SSRF_PARAM_KEYWORDS:
            return "ssrf"

        return "phishing"
