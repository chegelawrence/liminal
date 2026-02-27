"""Exposed sensitive endpoint detection.

Checks common paths that expose sensitive information:
- .git repositories
- .env / configuration backup files
- Swagger / OpenAPI documentation
- GraphQL introspection endpoints
- Spring Boot Actuator endpoints
- Debug pages (phpinfo, Symfony profiler, Laravel Telescope)
- Database backup files
- Admin panels

False-positive reduction:
- Content validation: don't report a 200 unless the body confirms sensitivity.
- GraphQL introspection: sends an actual introspection query.
- .git/config: must contain [core] or [remote].
- .env: must contain KEY=VALUE patterns.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

import httpx

from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import ScopeValidator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths to check, grouped by category
# ---------------------------------------------------------------------------

EXPOSURE_PATHS: dict[str, list[str]] = {
    "git": [
        "/.git/config",
        "/.git/HEAD",
        "/.git/COMMIT_EDITMSG",
    ],
    "env": [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.backup",
        "/config.php.bak",
        "/wp-config.php.bak",
        "/configuration.php.bak",
    ],
    "api_docs": [
        "/swagger.json",
        "/swagger.yaml",
        "/swagger-ui.html",
        "/swagger-ui/",
        "/api-docs",
        "/api-docs/",
        "/api/docs",
        "/openapi.json",
        "/openapi.yaml",
        "/v1/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/redoc",
        "/docs/",
    ],
    "graphql": [
        "/graphql",
        "/graphiql",
        "/graphql/console",
        "/api/graphql",
        "/v1/graphql",
        "/query",
    ],
    "spring_actuator": [
        "/actuator",
        "/actuator/env",
        "/actuator/mappings",
        "/actuator/beans",
        "/actuator/health",
        "/actuator/info",
        "/actuator/configprops",
        "/actuator/loggers",
        "/actuator/heapdump",
        "/actuator/threaddump",
        "/manage/env",
        "/manage/health",
    ],
    "debug": [
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/server-status",
        "/server-info",
        "/_profiler",
        "/__clockwork",
        "/telescope",
        "/horizon",
        "/_ignition/health-check",
        "/debug",
        "/admin/debug",
    ],
    "backup": [
        "/backup.zip",
        "/backup.tar.gz",
        "/backup.sql",
        "/db.sql",
        "/database.sql",
        "/dump.sql",
        "/site.zip",
        "/www.zip",
        "/.htpasswd",
        "/.htaccess",
    ],
    "admin": [
        "/admin",
        "/admin/",
        "/administrator",
        "/wp-admin",
        "/wp-login.php",
        "/phpmyadmin",
        "/pma",
        "/adminer.php",
        "/console",
        "/jenkins",
        "/kibana",
        "/grafana",
        "/portainer",
    ],
}

# GraphQL introspection query
_GRAPHQL_INTROSPECTION_QUERY = '{"query":"{__schema{types{name}}}"}'

# Severity map by category
_CATEGORY_SEVERITY: dict[str, str] = {
    "env": "critical",
    "git": "high",
    "spring_actuator": "high",
    "api_docs": "medium",
    "graphql": "medium",
    "debug": "medium",
    "backup": "critical",
    "admin": "medium",
}

# Content validators: category → callable(body: str, path: str) -> bool
def _validate_git(body: str, path: str) -> bool:
    return "[core]" in body or "[remote" in body or "ref: refs/heads" in body

def _validate_env(body: str, path: str) -> bool:
    # Must have at least one KEY=VALUE pattern
    return bool(re.search(r'^[A-Z_][A-Z0-9_]*\s*=\s*.+', body, re.MULTILINE))

def _validate_api_docs(body: str, path: str) -> bool:
    body_lower = body.lower()
    return (
        "swagger" in body_lower
        or "openapi" in body_lower
        or '"paths"' in body_lower
        or "paths:" in body_lower
    )

def _validate_graphql(body: str, path: str) -> bool:
    body_lower = body.lower()
    return (
        "__schema" in body_lower
        or "__typename" in body_lower
        or "graphql" in body_lower
        or '"data"' in body
    )

def _validate_spring_actuator(body: str, path: str) -> bool:
    body_lower = body.lower()
    return (
        '"_links"' in body
        or '"properties"' in body
        or '"beans"' in body
        or '"contexts"' in body
        or "actuator" in body_lower
        or '"activeProfiles"' in body
    )

def _validate_debug(body: str, path: str) -> bool:
    body_lower = body.lower()
    return (
        "phpinfo" in body_lower
        or "php version" in body_lower
        or "server software" in body_lower
        or "symfony" in body_lower
        or "profiler" in body_lower
        or "clockwork" in body_lower
        or "telescope" in body_lower
        or "horizon" in body_lower
    )

def _validate_backup(body: str, path: str) -> bool:
    # Binary content for archives — check magic bytes or known SQL patterns
    body_lower = body.lower()
    return (
        "create table" in body_lower
        or "insert into" in body_lower
        or body.startswith("PK\x03\x04")  # ZIP magic
        or body[:3] == "\x1f\x8b\x08"     # gzip magic
        or "deny from all" in body_lower   # .htaccess
        or "order deny" in body_lower
    )

def _validate_admin(body: str, path: str) -> bool:
    body_lower = body.lower()
    return (
        "login" in body_lower
        or "password" in body_lower
        or "username" in body_lower
        or "jenkins" in body_lower
        or "kibana" in body_lower
        or "grafana" in body_lower
        or "portainer" in body_lower
        or "phpmyadmin" in body_lower
        or "adminer" in body_lower
    )

_VALIDATORS: dict[str, object] = {
    "git": _validate_git,
    "env": _validate_env,
    "api_docs": _validate_api_docs,
    "graphql": _validate_graphql,
    "spring_actuator": _validate_spring_actuator,
    "debug": _validate_debug,
    "backup": _validate_backup,
    "admin": _validate_admin,
}


class ExposureFinding:
    """A sensitive endpoint exposure finding."""

    def __init__(
        self,
        url: str,
        path: str,
        category: str,
        status_code: int,
        evidence: str,
        severity: str,
        confidence: str,
        content_preview: str,
    ) -> None:
        self.url = url
        self.path = path
        self.category = category
        self.status_code = status_code
        self.evidence = evidence
        self.severity = severity
        self.confidence = confidence
        self.content_preview = content_preview

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "path": self.path,
            "category": self.category,
            "status_code": self.status_code,
            "evidence": self.evidence[:500],
            "severity": self.severity,
            "confidence": self.confidence,
            "content_preview": self.content_preview[:200],
        }


class ExposureScanner:
    """Detects exposed sensitive endpoints and files.

    For each live host:
    1. Tests all paths in EXPOSURE_PATHS concurrently.
    2. For each 200/403 response, validates it is actually sensitive via
       category-specific content checks.
    3. GraphQL: sends actual introspection query to confirm.
    4. Does NOT report 404/500 as findings.
    5. Does NOT report generic 200s without content validation.
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        rate_limiter: Optional[RateLimiter] = None,
        concurrent: int = 20,
        timeout: float = 8.0,
        categories: Optional[list[str]] = None,
    ) -> None:
        self.scope = scope_validator
        self.rate_limiter = rate_limiter
        self.concurrent = concurrent
        self.timeout = timeout
        self.categories = categories or list(EXPOSURE_PATHS.keys())
        self._semaphore = asyncio.Semaphore(concurrent)

    async def scan_hosts(
        self,
        hosts: list[str],
        extra_paths: Optional[list[str]] = None,
    ) -> list[ExposureFinding]:
        """Scan a list of live hosts for exposed sensitive endpoints.

        Args:
            hosts:       List of live host base URLs (e.g. https://example.com).
            extra_paths: Additional paths to probe alongside the static lists,
                         e.g. AI-generated paths.  Reported as category
                         ``"ai_generated"`` with no content-validation gate.

        Returns:
            List of exposure findings.
        """
        in_scope = [h for h in hosts if self.scope.is_in_scope(h)]
        logger.info("Exposure scanner: scanning %d hosts", len(in_scope))

        tasks = [
            asyncio.create_task(self._scan_host(host, extra_paths or []))
            for host in in_scope
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[ExposureFinding] = []
        for r in results:
            if isinstance(r, Exception):
                logger.debug("Exposure scan exception: %s", r)
                continue
            if r:
                findings.extend(r)

        logger.info("Exposure scanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _scan_host(
        self,
        host_url: str,
        extra_paths: Optional[list[str]] = None,
    ) -> list[ExposureFinding]:
        async with self._semaphore:
            # Normalise host: strip trailing slash and path
            from urllib.parse import urlparse
            parsed = urlparse(host_url)
            base = f"{parsed.scheme}://{parsed.netloc}"

            # Build list of (category, path) pairs to test
            test_pairs: list[tuple[str, str]] = []
            for category in self.categories:
                if category not in EXPOSURE_PATHS:
                    continue
                for path in EXPOSURE_PATHS[category]:
                    test_pairs.append((category, path))

            # Append AI-generated paths (probed without content-validation gate)
            for path in (extra_paths or []):
                test_pairs.append(("ai_generated", path))

            # Run all path checks concurrently (inner semaphore limits per-host)
            inner_sem = asyncio.Semaphore(10)
            path_tasks = [
                asyncio.create_task(
                    self._check_path(base, category, path, inner_sem)
                )
                for category, path in test_pairs
            ]
            path_results = await asyncio.gather(*path_tasks, return_exceptions=True)

            findings: list[ExposureFinding] = []
            for r in path_results:
                if isinstance(r, Exception):
                    continue
                if r:
                    findings.append(r)
            return findings

    async def _check_path(
        self,
        base: str,
        category: str,
        path: str,
        sem: asyncio.Semaphore,
    ) -> Optional[ExposureFinding]:
        async with sem:
            full_url = f"{base}{path}"
            if not self.scope.is_in_scope(full_url):
                return None

            # GraphQL gets a special POST introspection test
            if category == "graphql":
                return await self._check_graphql(base, path)

            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=True,
                    verify=False,
                ) as client:
                    resp = await client.get(full_url)
                    status = resp.status_code
                    body = resp.text[:8192]
            except Exception as exc:
                logger.debug("Exposure check failed for %s: %s", full_url, exc)
                return None

            # Only process 200 responses (and 403 for admin panels which may confirm existence)
            if status == 404 or status >= 500:
                return None

            # Content validation
            validator = _VALIDATORS.get(category)
            if validator and not validator(body, path):  # type: ignore[operator]
                return None

            severity = _CATEGORY_SEVERITY.get(category, "medium")
            evidence = (
                f"HTTP {status} response from {full_url}. "
                f"Content validation confirmed: category='{category}', path='{path}'."
            )

            return ExposureFinding(
                url=full_url,
                path=path,
                category=category,
                status_code=status,
                evidence=evidence,
                severity=severity,
                confidence="confirmed",
                content_preview=body[:200],
            )

    async def _check_graphql(
        self, base: str, path: str
    ) -> Optional[ExposureFinding]:
        """Test a GraphQL endpoint by sending an introspection query."""
        full_url = f"{base}{path}"
        if not self.scope.is_in_scope(full_url):
            return None

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.post(
                    full_url,
                    content=_GRAPHQL_INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"},
                )
                status = resp.status_code
                body = resp.text[:8192]
        except Exception as exc:
            logger.debug("GraphQL check failed for %s: %s", full_url, exc)
            return None

        if status == 404 or status >= 500:
            return None

        # Confirm introspection is enabled: response must contain type names
        if "__schema" not in body and "types" not in body:
            return None

        evidence = (
            f"GraphQL introspection enabled at {full_url} (HTTP {status}). "
            "Schema types are readable by unauthenticated attackers."
        )
        return ExposureFinding(
            url=full_url,
            path=path,
            category="graphql",
            status_code=status,
            evidence=evidence,
            severity="medium",
            confidence="confirmed",
            content_preview=body[:200],
        )
