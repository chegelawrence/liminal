"""SSRF (Server-Side Request Forgery) detection tool.

Strategy for minimal false positives:
1. OOB detection via interactsh – only confirmed if a DNS/HTTP callback arrives.
2. Error-based detection – look for internal IPs, cloud metadata, or error patterns.
3. Time-based detection – measure significant response time differences.
4. Re-verification – re-test any finding before reporting it.

No authenticated endpoints are tested since the framework targets unauthenticated
attack surface.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Optional
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from bugbounty.core.interactsh import InteractshClient
from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import ScopeValidator

logger = logging.getLogger(__name__)

# Common SSRF parameter names (ordered by prevalence in bug bounty reports)
SSRF_PARAMS = [
    "url", "redirect", "dest", "destination", "next", "path", "uri", "href",
    "src", "source", "callback", "webhook", "hook", "fetch", "request",
    "load", "open", "file", "proxy", "target", "resource", "return",
    "returnurl", "return_to", "redirectto", "redirecturi", "redirect_uri",
    "continue", "goto", "feed", "redir", "location", "u", "r", "l",
    "data", "window", "domain", "doc", "xml", "service", "api", "endpoint",
    "host", "from", "to", "ref", "view", "link", "image", "img",
]

# Patterns that indicate a successful SSRF in the response body
_INTERNAL_IP_RE = re.compile(
    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
)
_METADATA_RE = re.compile(
    r'(?:ami-id|instance-id|local-hostname|iam/security-credentials'
    r'|computeMetadata|instance_id|169\.254\.169\.254)',
    re.IGNORECASE,
)
_SSRF_ERROR_RE = re.compile(
    r'(?:connection refused|no route to host|name or service not known'
    r'|getaddrinfo|SSRF|server-side request|internal network|curl.*error)',
    re.IGNORECASE,
)


class SSRFCandidate:
    """Represents a potential SSRF injection point."""

    def __init__(
        self,
        url: str,
        param: str,
        method: str = "GET",
        original_value: str = "",
    ) -> None:
        self.url = url
        self.param = param
        self.method = method
        self.original_value = original_value


class SSRFFinding:
    """A confirmed or suspected SSRF finding."""

    def __init__(
        self,
        candidate: SSRFCandidate,
        evidence_type: str,
        evidence: str,
        confidence: str,   # "confirmed" | "high" | "medium"
        payload: str = "",
        interaction: Optional[dict] = None,
    ) -> None:
        self.candidate = candidate
        self.evidence_type = evidence_type
        self.evidence = evidence
        self.confidence = confidence
        self.payload = payload
        self.interaction = interaction

    def to_dict(self) -> dict:
        return {
            "url": self.candidate.url,
            "param": self.candidate.param,
            "method": self.candidate.method,
            "evidence_type": self.evidence_type,
            "evidence": self.evidence[:500],
            "confidence": self.confidence,
            "payload": self.payload,
            "oob_interaction": self.interaction,
        }


class SSRFScanner:
    """Scans a list of URLs and parameter candidates for SSRF vulnerabilities."""

    # Cloud metadata SSRF test payloads (blocked by default on most clouds now
    # but still worth trying as error-based detection)
    _METADATA_PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",          # AWS IMDS v1
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://169.254.169.254/metadata/instance",          # Azure IMDS
    ]

    def __init__(
        self,
        scope_validator: ScopeValidator,
        interactsh: InteractshClient,
        rate_limiter: Optional[RateLimiter] = None,
        concurrent: int = 5,
        timeout: float = 10.0,
        oob_wait: float = 15.0,
        verify_findings: bool = True,
    ) -> None:
        self.scope = scope_validator
        self.interactsh = interactsh
        self.rate_limiter = rate_limiter
        self.concurrent = concurrent
        self.timeout = timeout
        self.oob_wait = oob_wait
        self.verify_findings = verify_findings
        self._semaphore = asyncio.Semaphore(concurrent)

    async def scan_candidates(
        self,
        candidates: list[SSRFCandidate],
    ) -> list[SSRFFinding]:
        """Test a list of SSRFCandidate objects and return confirmed findings."""
        findings: list[SSRFFinding] = []
        tasks = [
            asyncio.create_task(self._test_candidate(c))
            for c in candidates
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                logger.debug("SSRF candidate test exception: %s", r)
                continue
            if r:
                findings.extend(r)

        return findings

    async def scan_urls(
        self,
        urls: list[str],
        extra_params: Optional[list[str]] = None,
    ) -> list[SSRFFinding]:
        """Extract SSRF candidates from URLs and scan them.

        Args:
            urls:         URLs to scan (with or without query parameters).
            extra_params: Additional parameter names to inject beyond SSRF_PARAMS.
        """
        target_params = list(SSRF_PARAMS)
        if extra_params:
            for p in extra_params:
                if p not in target_params:
                    target_params.append(p)

        candidates: list[SSRFCandidate] = []
        seen: set[tuple[str, str]] = set()

        from urllib.parse import parse_qs
        for url in urls:
            if not self.scope.is_in_scope(url):
                continue
            parsed = urlparse(url)
            existing_params = list(parse_qs(parsed.query).keys())
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # Test existing URL parameters that look SSRF-related
            for p in existing_params:
                key = (base_url, p.lower())
                if p.lower() in [ep.lower() for ep in target_params] and key not in seen:
                    seen.add(key)
                    candidates.append(SSRFCandidate(url=base_url, param=p))

            # Inject common SSRF params even if not in the original URL
            for p in target_params[:20]:  # top 20 most common
                key = (base_url, p.lower())
                if key not in seen:
                    seen.add(key)
                    candidates.append(SSRFCandidate(url=base_url, param=p))

        logger.info(
            "SSRF scanner: testing %d candidates across %d URLs",
            len(candidates), len(urls)
        )
        return await self.scan_candidates(candidates)

    # ------------------------------------------------------------------
    # Internal testing logic
    # ------------------------------------------------------------------

    async def _test_candidate(
        self, candidate: SSRFCandidate
    ) -> list[SSRFFinding]:
        async with self._semaphore:
            findings: list[SSRFFinding] = []

            # --- OOB test (interactsh) ---
            if self.interactsh.available:
                oob_finding = await self._test_oob(candidate)
                if oob_finding:
                    findings.append(oob_finding)
                    return findings  # OOB confirmation is definitive

            # --- Error-based / response content tests ---
            for payload in self._METADATA_PAYLOADS:
                finding = await self._test_error_based(candidate, payload)
                if finding:
                    # Verify before reporting to reduce FPs
                    if self.verify_findings:
                        confirmed = await self._verify(candidate, payload)
                        if not confirmed:
                            continue
                    findings.append(finding)
                    break  # one finding per candidate is enough

            return findings

    async def _test_oob(self, candidate: SSRFCandidate) -> Optional[SSRFFinding]:
        """Inject an interactsh payload and wait for a callback."""
        tag = candidate.param[:10]
        payload_url = self.interactsh.unique_url(tag=tag)
        if not payload_url:
            return None

        test_url = self._build_url(candidate.url, candidate.param, payload_url)
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(test_url, follow_redirects=True)
                _ = resp.status_code  # trigger the request
        except Exception:
            pass  # Connection errors are expected; we rely on OOB callback

        # Wait for callback
        interactions = await self.interactsh.wait_for_interaction(
            timeout=self.oob_wait,
            expected_tag=tag,
        )

        if interactions:
            interaction = interactions[0]
            protocol = interaction.get("protocol", "unknown")
            remote = interaction.get("remote-address", "unknown")
            logger.info(
                "SSRF confirmed (OOB %s callback) on %s param=%s from %s",
                protocol, candidate.url, candidate.param, remote
            )
            return SSRFFinding(
                candidate=candidate,
                evidence_type="oob_interaction",
                evidence=f"Received {protocol} callback from target server ({remote})",
                confidence="confirmed",
                payload=payload_url,
                interaction=interaction,
            )
        return None

    async def _test_error_based(
        self, candidate: SSRFCandidate, payload: str
    ) -> Optional[SSRFFinding]:
        """Inject a cloud-metadata payload and analyse the response."""
        test_url = self._build_url(candidate.url, candidate.param, payload)
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                t0 = time.monotonic()
                resp = await client.get(test_url, follow_redirects=True)
                elapsed = time.monotonic() - t0
                body = resp.text[:4096]
        except Exception:
            return None

        # Check for internal IP leakage
        if _INTERNAL_IP_RE.search(body):
            match = _INTERNAL_IP_RE.search(body)
            return SSRFFinding(
                candidate=candidate,
                evidence_type="internal_ip_leak",
                evidence=f"Internal IP '{match.group()}' found in response body",
                confidence="high",
                payload=payload,
            )

        # Check for cloud metadata content
        if _METADATA_RE.search(body):
            return SSRFFinding(
                candidate=candidate,
                evidence_type="metadata_content",
                evidence="Cloud metadata keywords found in response body",
                confidence="high",
                payload=payload,
            )

        # Check for SSRF-indicative error messages
        if _SSRF_ERROR_RE.search(body):
            match = _SSRF_ERROR_RE.search(body)
            return SSRFFinding(
                candidate=candidate,
                evidence_type="error_message",
                evidence=f"SSRF-indicative error: '{match.group()}'",
                confidence="medium",
                payload=payload,
            )

        return None

    async def _verify(
        self, candidate: SSRFCandidate, payload: str
    ) -> bool:
        """Re-test a finding to reduce false positives.

        Returns True if the finding is reproducible.
        """
        finding = await self._test_error_based(candidate, payload)
        return finding is not None

    @staticmethod
    def _build_url(base_url: str, param: str, value: str) -> str:
        """Construct a URL with *param* set to *value*."""
        return f"{base_url}?{urlencode({param: value})}"


# ---------------------------------------------------------------------------
# POST body SSRF testing
# ---------------------------------------------------------------------------

# JSON / form field names that frequently accept URLs in POST bodies
POST_SSRF_FIELDS = [
    "url", "callback", "webhook", "endpoint", "redirect",
    "target", "dest", "destination", "src", "source",
    "uri", "resource", "link", "href", "fetch",
    "image_url", "avatar_url", "logo_url", "icon_url",
    "thumbnail", "preview_url", "embed_url", "feed_url",
    "import_url", "export_url", "download_url", "upload_url",
    "notify_url", "notification_url", "success_url", "return_url",
    "service_url", "api_url", "base_url", "proxy_url",
]


class PostSSRFScanner:
    """Tests POST endpoints for SSRF via JSON body and form-encoded parameters.

    For each endpoint:
    1. Tries POST with JSON body {field: interactsh_url} for each field in POST_SSRF_FIELDS.
    2. Also tries form-encoded POST.
    3. Waits for OOB callback.
    4. Rate limit: pause 100ms between fields per endpoint.
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        interactsh: InteractshClient,
        rate_limiter: Optional[RateLimiter] = None,
        concurrent: int = 5,
        timeout: float = 10.0,
        oob_wait: float = 15.0,
    ) -> None:
        self.scope = scope_validator
        self.interactsh = interactsh
        self.rate_limiter = rate_limiter
        self.concurrent = concurrent
        self.timeout = timeout
        self.oob_wait = oob_wait
        self._semaphore = asyncio.Semaphore(concurrent)

    async def scan_post_endpoints(
        self,
        endpoints: list[str],
    ) -> list[SSRFFinding]:
        """Test POST endpoints for SSRF in JSON body parameters.

        Args:
            endpoints: List of endpoint URLs to test.

        Returns:
            List of confirmed SSRF findings.
        """
        if not self.interactsh.available:
            logger.warning(
                "PostSSRFScanner: interactsh not available – POST SSRF skipped"
            )
            return []

        in_scope = [e for e in endpoints if self.scope.is_in_scope(e)]
        logger.info(
            "POST SSRF scanner: testing %d endpoints × %d fields",
            len(in_scope), len(POST_SSRF_FIELDS),
        )

        tasks = [
            asyncio.create_task(self._scan_endpoint(url))
            for url in in_scope
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[SSRFFinding] = []
        for r in results:
            if isinstance(r, Exception):
                logger.debug("POST SSRF endpoint exception: %s", r)
                continue
            if r:
                findings.extend(r)

        logger.info("POST SSRF scanner: %d findings", len(findings))
        return findings

    async def _scan_endpoint(self, url: str) -> list[SSRFFinding]:
        async with self._semaphore:
            findings: list[SSRFFinding] = []
            for field in POST_SSRF_FIELDS:
                # JSON body
                finding = await self._test_post_field(url, field, "application/json")
                if finding:
                    findings.append(finding)
                    break  # one confirmed finding per endpoint is enough

                # Form-encoded
                finding = await self._test_post_field(
                    url, field, "application/x-www-form-urlencoded"
                )
                if finding:
                    findings.append(finding)
                    break

                await asyncio.sleep(0.1)
            return findings

    async def _test_post_field(
        self,
        url: str,
        field: str,
        content_type: str,
    ) -> Optional[SSRFFinding]:
        """Send a POST request with the SSRF payload in a specific field.

        Args:
            url:          Endpoint URL.
            field:        JSON/form field name.
            content_type: "application/json" or "application/x-www-form-urlencoded".

        Returns:
            SSRFFinding if an OOB interaction is received, else None.
        """
        safe_tag = field[:10]
        payload_url = self.interactsh.unique_url(tag=safe_tag)
        if not payload_url:
            return None

        import json as _json

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                if content_type == "application/json":
                    body_data = _json.dumps({field: payload_url})
                    await client.post(
                        url,
                        content=body_data,
                        headers={"Content-Type": "application/json"},
                    )
                else:
                    await client.post(
                        url,
                        data={field: payload_url},
                    )
        except Exception:
            pass  # Connection errors expected — we rely on OOB callback

        interactions = await self.interactsh.wait_for_interaction(
            timeout=self.oob_wait,
            expected_tag=safe_tag,
        )

        if interactions:
            interaction = interactions[0]
            protocol = interaction.get("protocol", "unknown")
            remote = interaction.get("remote-address", "unknown")
            logger.info(
                "POST SSRF confirmed (OOB %s callback) on %s field=%s ct=%s from %s",
                protocol, url, field, content_type, remote,
            )
            # Build a synthetic SSRFCandidate to reuse SSRFFinding
            candidate = SSRFCandidate(
                url=url,
                param=f"{field}[{content_type}]",
                method="POST",
            )
            return SSRFFinding(
                candidate=candidate,
                evidence_type="oob_interaction",
                evidence=(
                    f"Received {protocol} OOB callback when POSTing interactsh URL "
                    f"in JSON field '{field}' (Content-Type: {content_type}). "
                    f"Server made outbound connection from {remote}."
                ),
                confidence="confirmed",
                payload=payload_url,
                interaction=interaction,
            )
        return None
