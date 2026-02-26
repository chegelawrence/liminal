"""URL discovery tool wrappers: gau, katana, waybackurls."""

from __future__ import annotations

import json
import logging
from urllib.parse import urlparse

import httpx

from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import ScopeValidator
from bugbounty.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)


def _filter_urls(urls: list[str], scope: ScopeValidator) -> list[str]:
    """Return only URLs that are in scope."""
    result: list[str] = []
    for u in urls:
        if scope.is_in_scope(u):
            result.append(u)
    return result


class GauTool(BaseTool):
    """Fetch historical URLs using getallurls (gau)."""

    name = "gau"

    async def _execute(
        self,
        domain: str,
        providers: list[str] | None = None,
        timeout: int = 300,
    ) -> tuple[bool, str, str]:
        if not self._check_tool_installed("gau"):
            return True, "", ""

        self.scope.assert_in_scope(domain)

        cmd = ["gau"]
        if providers:
            cmd += ["--providers", ",".join(providers)]
        cmd.append(domain)

        rc, stdout, stderr = await self._run_subprocess(cmd, timeout=timeout)
        if rc == -2:
            return True, "", stderr
        return rc == 0 or bool(stdout), stdout, stderr

    async def fetch_urls(
        self,
        domain: str,
        providers: list[str] | None = None,
        timeout: int = 300,
    ) -> list[str]:
        """Return list of URLs discovered from archive sources."""
        result: ToolResult = await self.run(
            domain=domain, providers=providers, timeout=timeout
        )

        if not result.raw_output:
            return []

        urls = [line.strip() for line in result.raw_output.splitlines() if line.strip()]
        in_scope = _filter_urls(urls, self.scope)
        logger.info("gau found %d in-scope URLs for %s", len(in_scope), domain)
        return in_scope


class KatanaTool(BaseTool):
    """Active web crawler using projectdiscovery/katana."""

    name = "katana"

    async def _execute(
        self,
        url: str,
        depth: int = 3,
        timeout: int = 300,
        headless: bool = False,
    ) -> tuple[bool, str, str]:
        if not self._check_tool_installed("katana"):
            return True, "", ""

        self.scope.assert_in_scope(url)

        cmd = [
            "katana",
            "-u", url,
            "-d", str(depth),
            "-json",
            "-silent",
            "-timeout", str(timeout // 60 or 5),  # katana uses minutes for -timeout
        ]
        if headless:
            cmd.append("-headless")

        rc, stdout, stderr = await self._run_subprocess(cmd, timeout=timeout)
        if rc == -2:
            return True, "", stderr
        return rc == 0 or bool(stdout), stdout, stderr

    async def crawl(
        self,
        url: str,
        depth: int = 3,
        timeout: int = 300,
        headless: bool = False,
    ) -> list[dict]:
        """Crawl a URL and return discovered endpoints."""
        result: ToolResult = await self.run(
            url=url, depth=depth, timeout=timeout, headless=headless
        )

        if not result.raw_output:
            return []

        endpoints: list[dict] = []
        for line in result.raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                endpoint_url = data.get("endpoint", data.get("url", ""))
                if not endpoint_url:
                    continue
                if not self.scope.is_in_scope(endpoint_url):
                    continue
                endpoints.append(
                    {
                        "url": endpoint_url,
                        "method": data.get("method", "GET"),
                        "status_code": data.get("status_code", None),
                        "source": "katana",
                        "raw": data,
                    }
                )
            except json.JSONDecodeError:
                # Plain URL output
                if line.startswith("http") and self.scope.is_in_scope(line):
                    endpoints.append({"url": line, "method": "GET", "source": "katana"})

        logger.info("katana crawled %d endpoints from %s", len(endpoints), url)
        return endpoints


class WaybackTool(BaseTool):
    """Fetch URLs from the Wayback Machine (waybackurls or CDX API fallback)."""

    name = "waybackurls"

    async def _execute(self, domain: str, timeout: int = 180) -> tuple[bool, str, str]:
        # Try the waybackurls binary first
        if self._check_tool_installed("waybackurls"):
            self.scope.assert_in_scope(domain)
            rc, stdout, stderr = await self._run_subprocess(
                ["waybackurls", domain], timeout=timeout
            )
            if rc != -2:
                return rc == 0 or bool(stdout), stdout, stderr

        # Fallback: query the CDX API directly via httpx
        logger.info("waybackurls not installed, falling back to CDX API")
        self.scope.assert_in_scope(domain)
        try:
            cdx_url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=50000"
            )
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(cdx_url)
                resp.raise_for_status()
                return True, resp.text, ""
        except Exception as exc:
            return False, "", str(exc)

    async def fetch_urls(self, domain: str, timeout: int = 180) -> list[str]:
        """Return list of URLs from the Wayback Machine."""
        result: ToolResult = await self.run(domain=domain, timeout=timeout)

        if not result.raw_output:
            return []

        urls = [line.strip() for line in result.raw_output.splitlines() if line.strip()]
        in_scope = _filter_urls(urls, self.scope)
        logger.info("wayback found %d in-scope URLs for %s", len(in_scope), domain)
        return in_scope
