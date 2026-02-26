"""Web fuzzing tool wrappers: ffuf, dalfox."""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import ScopeValidator
from bugbounty.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)


def _delete(path: str) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except Exception:
        pass


class FfufTool(BaseTool):
    """Directory and file fuzzer using ffuf."""

    name = "ffuf"

    async def _execute(
        self,
        url: str,
        wordlist: str,
        rate: int = 100,
        threads: int = 40,
        timeout: int = 10,
    ) -> tuple[bool, str, str]:
        if not self._check_tool_installed("ffuf"):
            return True, "", ""

        self.scope.assert_in_scope(url)

        if not Path(wordlist).exists():
            logger.warning("ffuf wordlist not found: %s", wordlist)
            return True, "", f"Wordlist not found: {wordlist}"

        out_file = tempfile.mktemp(suffix=".json")
        try:
            fuzz_url = url.rstrip("/") + "/FUZZ"
            cmd = [
                "ffuf",
                "-u", fuzz_url,
                "-w", wordlist,
                "-o", out_file,
                "-of", "json",
                "-rate", str(rate),
                "-t", str(threads),
                "-timeout", str(timeout),
                "-mc", "200,201,204,301,302,307,401,403",
                "-s",  # silent
            ]
            rc, stdout, stderr = await self._run_subprocess(
                cmd, timeout=timeout * 200 + 120
            )
            if rc == -2:
                return True, "", stderr

            output_path = Path(out_file)
            if output_path.exists():
                content = output_path.read_text(errors="replace")
                return True, content, stderr
            return rc == 0, stdout, stderr
        finally:
            _delete(out_file)

    async def fuzz_directories(
        self,
        url: str,
        wordlist: str,
        rate: int = 100,
        threads: int = 40,
        timeout: int = 10,
    ) -> list[dict]:
        """Fuzz directories/files and return list of discovered paths."""
        result: ToolResult = await self.run(
            url=url, wordlist=wordlist, rate=rate, threads=threads, timeout=timeout
        )

        if not result.raw_output:
            return []

        discovered: list[dict] = []
        try:
            data = json.loads(result.raw_output)
            results = data.get("results", [])
            for item in results:
                discovered.append(
                    {
                        "url": item.get("url", ""),
                        "status": item.get("status", 0),
                        "length": item.get("length", 0),
                        "words": item.get("words", 0),
                        "lines": item.get("lines", 0),
                        "input": item.get("input", {}).get("FUZZ", ""),
                        "redirectlocation": item.get("redirectlocation", ""),
                    }
                )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("Failed to parse ffuf output: %s", exc)

        logger.info("ffuf found %d paths on %s", len(discovered), url)
        return discovered


class DalfoxTool(BaseTool):
    """XSS scanner using dalfox."""

    name = "dalfox"

    async def _execute(self, url: str, timeout: int = 60) -> tuple[bool, str, str]:
        if not self._check_tool_installed("dalfox"):
            return True, "", ""

        self.scope.assert_in_scope(url)

        cmd = [
            "dalfox",
            "url",
            url,
            "--silence",
            "--format", "json",
        ]
        rc, stdout, stderr = await self._run_subprocess(cmd, timeout=timeout)
        if rc == -2:
            return True, "", stderr
        return rc == 0 or bool(stdout), stdout, stderr

    def _url_has_params(self, url: str) -> bool:
        """Return True if the URL contains query parameters."""
        parsed = urlparse(url)
        return bool(parsed.query)

    async def scan_xss(self, url: str, timeout: int = 60) -> list[dict]:
        """Scan a URL for XSS vulnerabilities.

        Only runs when the URL contains query parameters (no point fuzzing
        a parameter-free URL with dalfox).
        """
        if not self._url_has_params(url):
            logger.debug("dalfox: skipping %s – no query parameters", url)
            return []

        result: ToolResult = await self.run(url=url, timeout=timeout)
        if not result.raw_output:
            return []

        findings: list[dict] = []
        # Dalfox can output JSONL (one JSON object per line)
        for line in result.raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                # Dalfox finding has type, evidence, poc_code etc.
                findings.append(
                    {
                        "url": url,
                        "type": data.get("type", "XSS"),
                        "evidence": data.get("evidence", ""),
                        "poc": data.get("poc_code", ""),
                        "param": data.get("param", ""),
                        "raw": data,
                    }
                )
            except json.JSONDecodeError:
                # Plain text output from dalfox
                if "[V]" in line or "[POC]" in line:
                    findings.append({"url": url, "type": "XSS", "evidence": line, "raw": {}})

        logger.info("dalfox found %d XSS findings on %s", len(findings), url)
        return findings
