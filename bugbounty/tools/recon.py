"""Recon tool wrappers: subfinder, amass, dnsx, httpx, naabu."""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Optional

from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import ScopeValidator
from bugbounty.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)


def _write_tmp(lines: list[str]) -> str:
    """Write *lines* to a NamedTemporaryFile and return its path."""
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


class SubfinderTool(BaseTool):
    """Enumerate subdomains using projectdiscovery/subfinder."""

    name = "subfinder"

    async def _execute(self, domain: str, timeout: int = 120) -> tuple[bool, str, str]:
        if not self._check_tool_installed("subfinder"):
            return True, "", ""  # Graceful skip

        self.scope.assert_in_scope(domain)
        cmd = ["subfinder", "-d", domain, "-silent", "-json", "-all"]
        rc, stdout, stderr = await self._run_subprocess(cmd, timeout=timeout)
        if rc == -2:
            return True, "", stderr  # tool missing, treated as soft skip
        success = rc == 0 or (rc != 0 and stdout)
        return success, stdout, stderr

    async def enumerate(self, domain: str, timeout: int = 120) -> list[dict]:
        """Return list of dicts with 'host' and 'source' keys."""
        result: ToolResult = await self.run(domain=domain, timeout=timeout)
        if not result.raw_output:
            return []

        subdomains: list[dict] = []
        for line in result.raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "").lower().strip()
                if host and self.scope.is_in_scope(host):
                    subdomains.append(
                        {"host": host, "source": data.get("source", "subfinder")}
                    )
            except json.JSONDecodeError:
                # Some lines may be plain hostnames in older subfinder versions
                host = line.lower()
                if host and self.scope.is_in_scope(host):
                    subdomains.append({"host": host, "source": "subfinder"})

        logger.info("subfinder found %d subdomains for %s", len(subdomains), domain)
        return subdomains


class AmaasTool(BaseTool):
    """Enumerate subdomains using OWASP Amass."""

    name = "amass"

    async def _execute(
        self, domain: str, mode: str = "passive", timeout: int = 300
    ) -> tuple[bool, str, str]:
        if not self._check_tool_installed("amass"):
            return True, "", ""

        self.scope.assert_in_scope(domain)

        out_file = tempfile.mktemp(suffix=".json")
        try:
            cmd = ["amass", "enum"]
            if mode == "passive":
                cmd.append("-passive")
            cmd += ["-d", domain, "-json", out_file]

            rc, stdout, stderr = await self._run_subprocess(cmd, timeout=timeout)
            if rc == -2:
                return True, "", stderr

            # Read the output file if it exists
            output_path = Path(out_file)
            if output_path.exists():
                content = output_path.read_text(errors="replace")
                return True, content, stderr
            return rc == 0, stdout, stderr
        finally:
            _delete(out_file)

    async def enumerate(self, domain: str, mode: str = "passive", timeout: int = 300) -> list[dict]:
        """Return list of dicts with 'host' and 'source' keys."""
        result = await self.run(domain=domain, mode=mode, timeout=timeout)
        if not result.raw_output:
            return []

        subdomains: list[dict] = []
        for line in result.raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                # Amass JSON has 'name' field
                host = data.get("name", data.get("host", "")).lower().strip()
                if host and self.scope.is_in_scope(host):
                    subdomains.append({"host": host, "source": "amass"})
            except json.JSONDecodeError:
                host = line.lower()
                if host and self.scope.is_in_scope(host):
                    subdomains.append({"host": host, "source": "amass"})

        logger.info("amass found %d subdomains for %s", len(subdomains), domain)
        return subdomains


class DnsxTool(BaseTool):
    """Resolve subdomains using projectdiscovery/dnsx."""

    name = "dnsx"

    async def _execute(
        self,
        subdomains: list[str],
        resolvers: list[str] | None = None,
        timeout: int = 120,
    ) -> tuple[bool, str, str]:
        if not self._check_tool_installed("dnsx"):
            return True, "", ""

        in_scope = self.scope.filter_in_scope(subdomains)
        if not in_scope:
            return True, "", ""

        input_file = _write_tmp(in_scope)
        try:
            cmd = ["dnsx", "-l", input_file, "-json", "-silent", "-a", "-aaaa", "-cname"]
            if resolvers:
                cmd += ["-r", ",".join(resolvers)]

            rc, stdout, stderr = await self._run_subprocess(cmd, timeout=timeout)
            if rc == -2:
                return True, "", stderr
            return rc == 0 or bool(stdout), stdout, stderr
        finally:
            _delete(input_file)

    async def resolve(
        self,
        subdomains: list[str],
        resolvers: list[str] | None = None,
        timeout: int = 120,
    ) -> list[dict]:
        """Return list of dicts for resolved subdomains."""
        result = await self.run(subdomains=subdomains, resolvers=resolvers, timeout=timeout)
        if not result.raw_output:
            return []

        resolved: list[dict] = []
        for line in result.raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "").lower().strip()
                if host:
                    resolved.append(
                        {
                            "host": host,
                            "a": data.get("a", []),
                            "aaaa": data.get("aaaa", []),
                            "cname": data.get("cname", []),
                            "status_code": data.get("status_code", ""),
                        }
                    )
            except json.JSONDecodeError:
                host = line.lower()
                if host:
                    resolved.append({"host": host, "a": [], "aaaa": [], "cname": []})

        logger.info("dnsx resolved %d/%d subdomains", len(resolved), len(subdomains))
        return resolved


class HttpxTool(BaseTool):
    """Probe live HTTP/HTTPS hosts using projectdiscovery/httpx."""

    name = "httpx"

    async def _execute(
        self,
        hosts: list[str],
        timeout: int = 10,
        follow_redirects: bool = True,
    ) -> tuple[bool, str, str]:
        if not self._check_tool_installed("httpx"):
            return True, "", ""

        in_scope = self.scope.filter_in_scope(hosts)
        if not in_scope:
            return True, "", ""

        input_file = _write_tmp(in_scope)
        try:
            cmd = [
                "httpx",
                "-l", input_file,
                "-json",
                "-silent",
                "-title",
                "-tech-detect",
                "-status-code",
                "-content-length",
                "-server",
                "-timeout", str(timeout),
            ]
            if follow_redirects:
                cmd.append("-follow-redirects")

            rc, stdout, stderr = await self._run_subprocess(cmd, timeout=timeout * 10 + 60)
            if rc == -2:
                return True, "", stderr
            return rc == 0 or bool(stdout), stdout, stderr
        finally:
            _delete(input_file)

    async def probe(
        self,
        hosts: list[str],
        timeout: int = 10,
        follow_redirects: bool = True,
    ) -> list[dict]:
        """Return list of dicts for live hosts with metadata."""
        result = await self.run(hosts=hosts, timeout=timeout, follow_redirects=follow_redirects)
        if not result.raw_output:
            return []

        live: list[dict] = []
        for line in result.raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("url", "").strip()
                if not url:
                    continue

                # Validate scope on the resolved URL
                if not self.scope.is_in_scope(url):
                    continue

                # Technologies may be a list of dicts or list of strings
                raw_tech = data.get("tech", data.get("technologies", []))
                technologies: list[str] = []
                for t in raw_tech:
                    if isinstance(t, dict):
                        technologies.append(t.get("name", str(t)))
                    elif isinstance(t, str):
                        technologies.append(t)

                live.append(
                    {
                        "url": url,
                        "subdomain": data.get("input", url),
                        "status_code": data.get("status-code", data.get("status_code", 0)),
                        "title": data.get("title", ""),
                        "technologies": technologies,
                        "content_length": data.get("content-length", data.get("content_length")),
                        "server": data.get("webserver", data.get("server", "")),
                    }
                )
            except json.JSONDecodeError:
                continue

        logger.info("httpx found %d live hosts", len(live))
        return live


class NaabuTool(BaseTool):
    """Port scanner using projectdiscovery/naabu."""

    name = "naabu"

    async def _execute(
        self,
        hosts: list[str],
        top_ports: int = 1000,
        timeout: int = 300,
    ) -> tuple[bool, str, str]:
        if not self._check_tool_installed("naabu"):
            return True, "", ""

        in_scope = self.scope.filter_in_scope(hosts)
        if not in_scope:
            return True, "", ""

        input_file = _write_tmp(in_scope)
        try:
            cmd = [
                "naabu",
                "-l", input_file,
                "-top-ports", str(top_ports),
                "-json",
                "-silent",
            ]
            rc, stdout, stderr = await self._run_subprocess(cmd, timeout=timeout)
            if rc == -2:
                return True, "", stderr
            return rc == 0 or bool(stdout), stdout, stderr
        finally:
            _delete(input_file)

    async def scan(
        self,
        hosts: list[str],
        top_ports: int = 1000,
        timeout: int = 300,
    ) -> list[dict]:
        """Return list of dicts with 'host', 'port', 'protocol'."""
        result = await self.run(hosts=hosts, top_ports=top_ports, timeout=timeout)
        if not result.raw_output:
            return []

        ports: list[dict] = []
        for line in result.raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("ip", data.get("host", ""))
                port = data.get("port", 0)
                protocol = data.get("protocol", "tcp")
                if host and port:
                    ports.append(
                        {
                            "host": host,
                            "port": int(port),
                            "protocol": protocol,
                            "service": data.get("service", {}).get("name", ""),
                        }
                    )
            except (json.JSONDecodeError, ValueError):
                continue

        logger.info("naabu found %d open ports across %d hosts", len(ports), len(hosts))
        return ports
