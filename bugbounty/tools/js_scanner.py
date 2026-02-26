"""JavaScript file secret and endpoint scanner.

Scans JavaScript files for:
1. Hardcoded secrets (API keys, tokens, credentials).
2. Hidden API endpoint paths.

Secrets are truncated before storing to avoid logging actual sensitive values
(first 8 chars + "..." is retained for identification purposes).

Returns both findings and newly discovered endpoint paths — these feed back
into the SSRF and XSS scanners.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional
from urllib.parse import urlparse

import httpx

from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import ScopeValidator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------

SECRET_PATTERNS: dict[str, str] = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
    "stripe_secret": r"sk_live_[0-9a-zA-Z]{24}",
    "stripe_publishable": r"pk_live_[0-9a-zA-Z]{24}",
    "github_token": r"ghp_[a-zA-Z0-9]{36}",
    "slack_token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "jwt_token": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "basic_auth": r"(?i)(?:authorization|auth).*?['\"]Basic [a-zA-Z0-9+/=]{10,}['\"]",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "bearer_token": r"(?i)bearer [a-zA-Z0-9\-_]{20,}",
    "sendgrid_key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "twilio_sid": r"AC[a-z0-9]{32}",
    "mailgun_key": r"key-[a-z0-9]{32}",
    "password_in_url": r"(?i)['\"](?:password|passwd|pwd)['\"]:\s*['\"][^'\"]{6,}['\"]",
    "generic_secret": (
        r"(?i)(?:secret|token|api_key|apikey|access_key)['\"]?"
        r"\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]"
    ),
}

# Compile all patterns once at module load
_COMPILED_SECRETS: dict[str, re.Pattern] = {
    name: re.compile(pattern)
    for name, pattern in SECRET_PATTERNS.items()
}

# ---------------------------------------------------------------------------
# Endpoint extraction patterns
# ---------------------------------------------------------------------------

ENDPOINT_PATTERNS: list[str] = [
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(\s*['"](\/[^'"]{3,})['"]\s*[,\)]""",
    r"""['"](\/api\/[a-zA-Z0-9_\/\-]{2,})['"]\s*""",
    r"""url\s*[:=]\s*['"](\/[a-zA-Z0-9_\/\-\.]{3,})['"]\s*""",
    r"""path\s*[:=]\s*['"](\/[a-zA-Z0-9_\/\-\.]{3,})['"]\s*""",
]

_COMPILED_ENDPOINTS: list[re.Pattern] = [
    re.compile(p) for p in ENDPOINT_PATTERNS
]

# Severity mapping for secret types
_SECRET_SEVERITY: dict[str, str] = {
    "aws_access_key": "critical",
    "aws_secret_key": "critical",
    "private_key": "critical",
    "stripe_secret": "critical",
    "github_token": "high",
    "slack_token": "high",
    "sendgrid_key": "high",
    "mailgun_key": "high",
    "twilio_sid": "medium",
    "google_api_key": "medium",
    "bearer_token": "medium",
    "jwt_token": "medium",
    "basic_auth": "medium",
    "stripe_publishable": "low",
    "password_in_url": "high",
    "generic_secret": "medium",
}


class JSFinding:
    """A finding from a JavaScript file scan."""

    def __init__(
        self,
        js_url: str,
        finding_type: str,   # "secret" | "endpoint"
        secret_type: str,    # e.g. "aws_access_key" or "" for endpoints
        match: str,          # truncated match for secrets; full path for endpoints
        severity: str,
        confidence: str,
    ) -> None:
        self.js_url = js_url
        self.finding_type = finding_type
        self.secret_type = secret_type
        self.match = match
        self.severity = severity
        self.confidence = confidence

    def to_dict(self) -> dict:
        return {
            "js_url": self.js_url,
            "finding_type": self.finding_type,
            "secret_type": self.secret_type,
            "match": self.match,
            "severity": self.severity,
            "confidence": self.confidence,
        }


class JSScanner:
    """Scans JavaScript files for secrets and hidden API endpoints.

    1. Fetches each JS URL.
    2. Applies secret regex patterns.
    3. Extracts API endpoint paths.
    4. Deduplicates and returns findings + new endpoints.

    Secret matches are truncated before storing (first 8 chars + "...").
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        rate_limiter: Optional[RateLimiter] = None,
        max_js_files: int = 100,
        timeout: float = 10.0,
    ) -> None:
        self.scope = scope_validator
        self.rate_limiter = rate_limiter
        self.max_js_files = max_js_files
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(10)

    async def scan_js_files(
        self,
        js_urls: list[str],
    ) -> tuple[list[JSFinding], list[str]]:
        """Scan JS files for secrets and endpoint paths.

        Args:
            js_urls: List of JavaScript file URLs to scan.

        Returns:
            (findings, discovered_endpoint_paths)
        """
        # Filter to in-scope JS files only
        in_scope = [
            u for u in js_urls
            if self.scope.is_in_scope(u)
            and u.lower().endswith(".js")
        ]

        # Cap the number of JS files to prevent runaway scanning
        capped = in_scope[: self.max_js_files]
        logger.info(
            "JS scanner: scanning %d JS files (capped from %d)",
            len(capped), len(in_scope),
        )

        tasks = [
            asyncio.create_task(self._scan_file(url))
            for url in capped
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings: list[JSFinding] = []
        all_endpoints: set[str] = set()

        for r in results:
            if isinstance(r, Exception):
                logger.debug("JS scan exception: %s", r)
                continue
            if r:
                findings, endpoints = r
                all_findings.extend(findings)
                all_endpoints.update(endpoints)

        # Deduplicate findings by (js_url, secret_type, match)
        seen: set[tuple[str, str, str]] = set()
        unique_findings: list[JSFinding] = []
        for f in all_findings:
            key = (f.js_url, f.secret_type, f.match)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        endpoint_list = sorted(all_endpoints)
        logger.info(
            "JS scanner: %d findings, %d new endpoints",
            len(unique_findings), len(endpoint_list),
        )
        return unique_findings, endpoint_list

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _scan_file(
        self,
        js_url: str,
    ) -> Optional[tuple[list[JSFinding], list[str]]]:
        async with self._semaphore:
            content = await self._fetch(js_url)
            if content is None:
                return None

            findings: list[JSFinding] = []
            endpoints: list[str] = []

            # --- Secret detection ---
            for secret_type, pattern in _COMPILED_SECRETS.items():
                for match in pattern.finditer(content):
                    raw_match = match.group(0)
                    truncated = self._truncate_secret(raw_match)
                    severity = _SECRET_SEVERITY.get(secret_type, "medium")
                    findings.append(
                        JSFinding(
                            js_url=js_url,
                            finding_type="secret",
                            secret_type=secret_type,
                            match=truncated,
                            severity=severity,
                            confidence="high",
                        )
                    )

            # --- Endpoint extraction ---
            seen_endpoints: set[str] = set()
            for ep_pattern in _COMPILED_ENDPOINTS:
                for match in ep_pattern.finditer(content):
                    path = match.group(1)
                    # Normalise and filter noise
                    path = path.strip()
                    if len(path) < 3 or path in seen_endpoints:
                        continue
                    # Skip common static paths
                    if any(
                        path.endswith(ext)
                        for ext in (".js", ".css", ".png", ".jpg", ".svg", ".ico")
                    ):
                        continue
                    seen_endpoints.add(path)
                    endpoints.append(path)
                    findings.append(
                        JSFinding(
                            js_url=js_url,
                            finding_type="endpoint",
                            secret_type="",
                            match=path,
                            severity="info",
                            confidence="medium",
                        )
                    )

            return findings, endpoints

    async def _fetch(self, url: str) -> Optional[str]:
        """Fetch a JS file and return its content."""
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                resp = await client.get(
                    url,
                    headers={"Accept": "application/javascript, */*"},
                )
                if resp.status_code == 200:
                    # Limit content size to 5MB
                    return resp.text[:5_000_000]
        except Exception as exc:
            logger.debug("JS fetch failed for %s: %s", url, exc)
        return None

    @staticmethod
    def _truncate_secret(raw: str) -> str:
        """Truncate a secret match to avoid logging the full value.

        Keeps the first 8 characters to assist identification, then appends "..."
        """
        raw = raw.strip()
        if len(raw) > 8:
            return raw[:8] + "..."
        return raw
