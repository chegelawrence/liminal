"""Parameter discovery tools.

Extracts parameters from URLs already in the database and optionally uses
arjun for hidden parameter enumeration.
"""

from __future__ import annotations

import json
import logging
import re
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse

from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import ScopeValidator
from bugbounty.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)

# Regex to find params inside JS files (e.g., fetch('/api?foo=bar'))
_JS_PARAM_RE = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_\-]{0,50})=', re.MULTILINE)


def _delete(path: str) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except Exception:
        pass


class ParamExtractor:
    """Extracts parameters from a collection of URLs without running any external tool.

    This is used as a first pass before arjun to avoid redundant work.
    """

    # Parameters commonly associated with SSRF
    SSRF_PARAMS: frozenset[str] = frozenset({
        "url", "redirect", "dest", "destination", "next", "path", "uri",
        "href", "src", "source", "from", "to", "callback", "webhook", "hook",
        "fetch", "request", "load", "open", "file", "image", "img", "link",
        "proxy", "target", "resource", "host", "site", "page", "return",
        "returnurl", "returnto", "return_to", "redirect_to", "redirectto",
        "redirecturi", "redirect_uri", "continue", "goto", "out", "view",
        "ref", "refurl", "u", "url2", "url1", "feed", "redir", "location",
        "r", "l", "data", "window", "domain", "doc", "document", "root",
        "xml", "oauth", "auth", "service", "api", "endpoint",
    })

    # Parameters commonly associated with XSS
    XSS_PARAMS: frozenset[str] = frozenset({
        "q", "s", "search", "query", "keyword", "keywords", "name", "title",
        "message", "comment", "text", "input", "content", "body", "value",
        "description", "desc", "note", "html", "output", "term", "filter",
        "tag", "tags", "username", "user", "email", "first_name", "last_name",
        "firstname", "lastname", "fullname", "full_name", "display_name",
        "displayname", "msg", "error", "success", "info", "warning",
        "label", "placeholder", "hint", "caption", "subject",
    })

    def extract_from_urls(self, urls: list[str]) -> dict[str, list[str]]:
        """Extract all query parameters from a list of URLs.

        Returns:
            Dict mapping base URL (without query) → list of param names.
        """
        result: dict[str, list[str]] = {}
        for url in urls:
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                if params:
                    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    existing = result.setdefault(base, [])
                    for p in params:
                        if p not in existing:
                            existing.append(p)
            except Exception:
                continue
        return result

    def classify_params(self, params: list[str]) -> dict[str, list[str]]:
        """Classify parameter names by likely vulnerability class.

        Returns:
            Dict with "ssrf", "xss", "other" keys.
        """
        lower = {p.lower(): p for p in params}
        ssrf: list[str] = []
        xss: list[str] = []
        other: list[str] = []
        for lp, orig in lower.items():
            if lp in self.SSRF_PARAMS:
                ssrf.append(orig)
            elif lp in self.XSS_PARAMS:
                xss.append(orig)
            else:
                other.append(orig)
        return {"ssrf": ssrf, "xss": xss, "other": other}

    def build_test_url(self, base_url: str, param: str, value: str) -> str:
        """Construct a test URL with a single parameter set to *value*."""
        return f"{base_url}?{urlencode({param: value})}"


class ArjunTool(BaseTool):
    """Hidden parameter discovery using arjun.

    arjun (https://github.com/s0md3v/Arjun) finds hidden GET/POST parameters
    that are not present in known URLs by brute-forcing from a wordlist.
    """

    name = "arjun"

    async def _execute(
        self,
        url: str,
        method: str = "GET",
        threads: int = 5,
        timeout: int = 30,
    ) -> tuple[bool, str, str]:
        if not self._check_tool_installed("arjun"):
            return True, "", ""

        if not self.scope.is_in_scope(url):
            self.logger.warning("arjun: %s is out of scope", url)
            return True, "", ""

        output_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        output_file.close()

        cmd = [
            "arjun",
            "-u", url,
            "-m", method.upper(),
            "-t", str(threads),
            "--rate-limit", "5",
            "-oJ", output_file.name,
            "--passive",  # use passive sources too
        ]

        try:
            rc, stdout, stderr = await self._run_subprocess(
                cmd, timeout=timeout + 30
            )
            if rc == -2:
                return True, "", stderr
            return rc == 0 or bool(stdout), stdout, stderr
        finally:
            _delete(output_file.name)

    async def discover(
        self,
        url: str,
        method: str = "GET",
        threads: int = 5,
        timeout: int = 30,
    ) -> list[str]:
        """Run arjun and return a list of discovered parameter names."""
        result: ToolResult = await self.run(
            url=url, method=method, threads=threads, timeout=timeout
        )

        if not result.raw_output:
            return []

        # arjun outputs JSON with discovered params
        for line in result.raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    params = data.get("params", [])
                    if params:
                        self.logger.info(
                            "arjun found %d params on %s: %s",
                            len(params), url, params
                        )
                        return [str(p) for p in params]
            except json.JSONDecodeError:
                continue
        return []
