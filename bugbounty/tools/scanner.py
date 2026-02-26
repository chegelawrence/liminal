"""Vulnerability scanner tool wrappers: nuclei."""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import ScopeValidator
from bugbounty.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)


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


class NucleiTool(BaseTool):
    """Vulnerability scanner using projectdiscovery/nuclei."""

    name = "nuclei"

    async def _execute(
        self,
        targets: list[str],
        severity: list[str] | None = None,
        tags: list[str] | None = None,
        exclude_tags: list[str] | None = None,
        rate_limit: int = 50,
        timeout: int = 30,
    ) -> tuple[bool, str, str]:
        if not self._check_tool_installed("nuclei"):
            return True, "", ""

        # Scope-validate every target before scanning
        in_scope = [t for t in targets if self.scope.is_in_scope(t)]
        if not in_scope:
            logger.info("nuclei: no in-scope targets to scan")
            return True, "", ""

        targets_file = _write_tmp(in_scope)
        try:
            cmd = [
                "nuclei",
                "-l", targets_file,
                "-json",
                "-silent",
                "-rate-limit", str(rate_limit),
                "-timeout", str(timeout),
            ]

            if severity:
                cmd += ["-severity", ",".join(severity)]
            if tags:
                cmd += ["-tags", ",".join(tags)]
            if exclude_tags:
                cmd += ["-etags", ",".join(exclude_tags)]

            # Use a long timeout: nuclei can take a while on many templates
            rc, stdout, stderr = await self._run_subprocess(
                cmd, timeout=timeout * len(in_scope) + 600
            )
            if rc == -2:
                return True, "", stderr
            return rc == 0 or bool(stdout), stdout, stderr
        finally:
            _delete(targets_file)

    async def scan(
        self,
        targets: list[str],
        severity: list[str] | None = None,
        tags: list[str] | None = None,
        exclude_tags: list[str] | None = None,
        rate_limit: int = 50,
        timeout: int = 30,
    ) -> list[dict]:
        """Run nuclei and return a list of finding dicts.

        Each dict contains:
            template_id, name, severity, host, matched-at, description,
            tags, cvss-score, cve-id, and the full raw dict.
        """
        result: ToolResult = await self.run(
            targets=targets,
            severity=severity,
            tags=tags,
            exclude_tags=exclude_tags,
            rate_limit=rate_limit,
            timeout=timeout,
        )

        if not result.raw_output:
            return []

        findings: list[dict] = []
        for line in result.raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data: dict = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extract fields, handle both v2 and v3 nuclei output formats
            info = data.get("info", {})
            classification = info.get("classification", {})

            host = data.get("host", data.get("matched-at", ""))
            matched_at = data.get("matched-at", host)

            # Final scope check on matched host
            if not self.scope.is_in_scope(host) and not self.scope.is_in_scope(matched_at):
                continue

            severity_val = info.get("severity", data.get("severity", "info")).lower()

            cvss_score: float | None = None
            raw_cvss = classification.get("cvss-score")
            if raw_cvss is not None:
                try:
                    cvss_score = float(raw_cvss)
                except (TypeError, ValueError):
                    pass

            cve_ids = classification.get("cve-id", [])
            cve_id: str | None = cve_ids[0] if cve_ids else None

            findings.append(
                {
                    "template_id": data.get("template-id", data.get("templateID", "")),
                    "name": info.get("name", data.get("template-id", "Unknown")),
                    "severity": severity_val,
                    "host": host,
                    "matched_at": matched_at,
                    "description": info.get("description", ""),
                    "tags": info.get("tags", []) if isinstance(info.get("tags"), list) else
                             [t.strip() for t in str(info.get("tags", "")).split(",") if t.strip()],
                    "cvss_score": cvss_score,
                    "cve_id": cve_id,
                    "raw": data,
                }
            )

        logger.info("nuclei found %d findings across %d targets", len(findings), len(targets))
        return findings
