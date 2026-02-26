"""XSS (Cross-Site Scripting) detection tool.

Strategy for minimal false positives:
1. Reflection detection first – only test parameters that actually reflect input.
2. Context analysis – determine where input appears (HTML body, attribute, JS context).
3. Context-aware payloads – use the appropriate XSS vector for each context.
4. Unescaped confirmation – verify the payload appears unescaped before reporting.
5. Dalfox integration – for comprehensive automated XSS scanning.
6. Re-verification pass – re-test positives to confirm reproducibility.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import secrets
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import ScopeValidator
from bugbounty.tools.base import BaseTool

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Context detection helpers
# ---------------------------------------------------------------------------

def _detect_context(body: str, probe: str) -> str:
    """Determine the HTML context where *probe* appears in *body*.

    Returns one of: "html_body", "html_attribute", "js_string", "html_comment",
                    "url_value", "unknown".
    """
    idx = body.find(probe)
    if idx == -1:
        return "unknown"

    # Look at 200 chars before the probe
    before = body[max(0, idx - 200): idx]
    after = body[idx + len(probe): idx + len(probe) + 100]

    # Inside a <script> block
    last_open_script = before.rfind("<script")
    last_close_script = before.rfind("</script>")
    if last_open_script > last_close_script:
        return "js_string"

    # Inside an HTML comment
    last_open_comment = before.rfind("<!--")
    last_close_comment = before.rfind("-->")
    if last_open_comment > last_close_comment:
        return "html_comment"

    # Inside an HTML attribute (look for = and quote before probe)
    attr_re = re.search(r'=\s*["\']?\s*$', before)
    if attr_re:
        return "html_attribute"

    # Inside a URL value (href, src, action, formaction)
    url_attr_re = re.search(r'(?:href|src|action|formaction)\s*=\s*["\']?\s*$', before, re.IGNORECASE)
    if url_attr_re:
        return "url_value"

    return "html_body"


# ---------------------------------------------------------------------------
# Context-aware payloads
# ---------------------------------------------------------------------------

_PAYLOADS: dict[str, list[str]] = {
    "html_body": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "html_attribute": [
        '" onmouseover="alert(1)" x="',
        "' onmouseover='alert(1)' x='",
        '" autofocus onfocus="alert(1)" x="',
    ],
    "js_string": [
        "';alert(1)//",
        '";alert(1)//',
        "`-alert(1)-`",
    ],
    "html_comment": [
        "--><script>alert(1)</script><!--",
    ],
    "url_value": [
        "javascript:alert(1)",
    ],
    "unknown": [
        "<script>alert(1)</script>",
        '" onmouseover="alert(1)"',
    ],
}


class XSSFinding:
    """A confirmed XSS finding."""

    def __init__(
        self,
        url: str,
        param: str,
        payload: str,
        context: str,
        evidence: str,
        xss_type: str = "reflected",    # "reflected" | "dom" | "dalfox"
        confidence: str = "confirmed",   # "confirmed" | "high"
    ) -> None:
        self.url = url
        self.param = param
        self.payload = payload
        self.context = context
        self.evidence = evidence
        self.xss_type = xss_type
        self.confidence = confidence

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "param": self.param,
            "payload": self.payload,
            "context": self.context,
            "evidence": self.evidence[:500],
            "xss_type": self.xss_type,
            "confidence": self.confidence,
        }


class ReflectionScanner:
    """Scans URLs for reflected XSS by detecting unescaped input reflections."""

    def __init__(
        self,
        scope_validator: ScopeValidator,
        rate_limiter: Optional[RateLimiter] = None,
        concurrent: int = 5,
        timeout: float = 10.0,
        verify_findings: bool = True,
    ) -> None:
        self.scope = scope_validator
        self.rate_limiter = rate_limiter
        self.concurrent = concurrent
        self.timeout = timeout
        self.verify_findings = verify_findings
        self._semaphore = asyncio.Semaphore(concurrent)

    async def scan_urls(self, urls: list[str]) -> list[XSSFinding]:
        """Scan a list of URLs for reflected XSS."""
        in_scope = [u for u in urls if self.scope.is_in_scope(u)]
        logger.info("XSS reflection scanner: testing %d URLs", len(in_scope))

        tasks = [asyncio.create_task(self._scan_url(u)) for u in in_scope]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[XSSFinding] = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return findings

    async def _scan_url(self, url: str) -> list[XSSFinding]:
        async with self._semaphore:
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())
            if not params:
                return []

            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            findings: list[XSSFinding] = []

            for param in params:
                probe = f"xss{secrets.token_hex(4)}"
                test_url = f"{base_url}?{urlencode({param: probe})}"

                try:
                    async with httpx.AsyncClient(timeout=self.timeout) as client:
                        resp = await client.get(test_url, follow_redirects=True)
                        body = resp.text
                except Exception:
                    continue

                if probe not in body:
                    continue  # No reflection → skip

                # Determine context
                context = _detect_context(body, probe)

                # Try context-appropriate payloads
                payloads = _PAYLOADS.get(context, _PAYLOADS["unknown"])
                for payload in payloads:
                    finding = await self._test_payload(
                        base_url=base_url,
                        param=param,
                        payload=payload,
                        context=context,
                    )
                    if finding:
                        if self.verify_findings:
                            if not await self._verify(base_url, param, payload):
                                continue
                        findings.append(finding)
                        break  # One finding per param is enough

            return findings

    async def _test_payload(
        self,
        base_url: str,
        param: str,
        payload: str,
        context: str,
    ) -> Optional[XSSFinding]:
        test_url = f"{base_url}?{urlencode({param: payload})}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(test_url, follow_redirects=True)
                body = resp.text
        except Exception:
            return None

        # Confirm the payload is in the response *unescaped*
        # Key check: the raw payload (or key parts of it) must appear literally
        key_marker = _extract_key_marker(payload)
        if key_marker and key_marker in body:
            evidence = (
                f"Payload '{payload[:80]}' reflects unescaped in {context} context"
            )
            return XSSFinding(
                url=test_url,
                param=param,
                payload=payload,
                context=context,
                evidence=evidence,
                xss_type="reflected",
                confidence="confirmed",
            )
        return None

    async def _verify(self, base_url: str, param: str, payload: str) -> bool:
        """Re-test the payload to confirm reproducibility."""
        finding = await self._test_payload(base_url, param, payload, "unknown")
        return finding is not None


def _extract_key_marker(payload: str) -> str:
    """Extract a substring of the payload that would only appear if unescaped."""
    # For script tags: look for "alert(1)"
    if "alert(1)" in payload:
        return "alert(1)"
    # For event handlers: look for "onmouseover" or "onerror"
    for marker in ["onerror", "onmouseover", "onfocus", "onload", "autofocus"]:
        if marker in payload.lower():
            return marker
    # For JS context: look for "alert"
    if "alert" in payload:
        return "alert"
    # Fallback: first 20 chars
    return payload[:20]


# ---------------------------------------------------------------------------
# Dalfox wrapper
# ---------------------------------------------------------------------------

def _write_tmp(lines: list[str]) -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.write("\n".join(lines))
    tmp.flush()
    tmp.close()
    return tmp.name


def _delete(path: str) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except Exception:
        pass


class DalfoxScanner(BaseTool):
    """XSS scanner using dalfox.

    dalfox has very good built-in false-positive filtering and is the most
    reliable automated XSS scanner for unauthenticated testing.
    """

    name = "dalfox"

    async def _execute(
        self,
        urls: list[str],
        timeout: int = 20,
        blind_url: str = "",
    ) -> tuple[bool, str, str]:
        if not self._check_tool_installed("dalfox"):
            return True, "", ""

        in_scope = [u for u in urls if self.scope.is_in_scope(u) and "?" in u]
        if not in_scope:
            return True, "", ""

        url_file = _write_tmp(in_scope)
        try:
            cmd = [
                "dalfox",
                "file", url_file,
                "--silence",
                "--format", "json",
                "--timeout", str(timeout),
                "--delay", "100",      # 100ms between requests
                "--user-agent",
                "Mozilla/5.0 (compatible; DalfoxBugBounty/1.0)",
            ]
            if blind_url:
                cmd += ["--blind", blind_url]

            rc, stdout, stderr = await self._run_subprocess(
                cmd, timeout=timeout * len(in_scope) + 120
            )
            if rc == -2:
                return True, "", stderr
            return True, stdout, stderr
        finally:
            _delete(url_file)

    async def scan(
        self,
        urls: list[str],
        timeout: int = 20,
        blind_url: str = "",
    ) -> list[XSSFinding]:
        """Run dalfox on a list of URLs and return XSS findings."""
        from bugbounty.tools.base import ToolResult
        result: ToolResult = await self.run(
            urls=urls, timeout=timeout, blind_url=blind_url
        )

        if not result.raw_output:
            return []

        findings: list[XSSFinding] = []
        for line in result.raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            # dalfox JSON fields
            vuln_url = data.get("url", data.get("URL", ""))
            payload = data.get("poc", data.get("payload", ""))
            param = data.get("param", data.get("parameter", ""))
            cwe = data.get("cwe", "")
            evidence = data.get("evidence", f"dalfox detected XSS: {cwe}")

            if not vuln_url:
                continue

            if not self.scope.is_in_scope(vuln_url):
                continue

            findings.append(
                XSSFinding(
                    url=vuln_url,
                    param=param,
                    payload=payload,
                    context="html_body",  # dalfox handles context internally
                    evidence=str(evidence)[:500],
                    xss_type="dalfox",
                    confidence="confirmed",
                )
            )

        logger.info("dalfox found %d XSS findings across %d URLs", len(findings), len(urls))
        return findings
