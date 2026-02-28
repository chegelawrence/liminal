"""PostgreSQL persistence layer using asyncpg."""

from __future__ import annotations

import logging
from typing import Optional

import asyncpg

from bugbounty.db.models import (
    AnomalyPattern,
    DiscoveredURL,
    Finding,
    LiveHost,
    OpenPort,
    ScanRun,
    Subdomain,
)

logger = logging.getLogger(__name__)

_SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS scan_runs (
        id TEXT PRIMARY KEY,
        target_domain TEXT NOT NULL,
        program_name TEXT NOT NULL,
        started_at TIMESTAMPTZ NOT NULL,
        completed_at TIMESTAMPTZ,
        status TEXT NOT NULL DEFAULT 'running'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS subdomains (
        id TEXT PRIMARY KEY,
        scan_run_id TEXT NOT NULL,
        subdomain TEXT NOT NULL,
        source TEXT NOT NULL,
        discovered_at TIMESTAMPTZ NOT NULL,
        UNIQUE(scan_run_id, subdomain)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS live_hosts (
        id TEXT PRIMARY KEY,
        scan_run_id TEXT NOT NULL,
        url TEXT NOT NULL,
        subdomain TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        title TEXT,
        technologies JSONB NOT NULL DEFAULT '[]',
        content_length INTEGER,
        server TEXT,
        probed_at TIMESTAMPTZ NOT NULL,
        UNIQUE(scan_run_id, url)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS open_ports (
        id TEXT PRIMARY KEY,
        scan_run_id TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        service TEXT,
        discovered_at TIMESTAMPTZ NOT NULL,
        UNIQUE(scan_run_id, host, port, protocol)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS discovered_urls (
        id TEXT PRIMARY KEY,
        scan_run_id TEXT NOT NULL,
        url TEXT NOT NULL,
        source TEXT NOT NULL,
        status_code INTEGER,
        discovered_at TIMESTAMPTZ NOT NULL,
        UNIQUE(scan_run_id, url)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS anomaly_patterns (
        id TEXT PRIMARY KEY,
        created_at TIMESTAMPTZ NOT NULL,
        tech_stack TEXT[] NOT NULL DEFAULT '{}',
        probe_type TEXT NOT NULL,
        vulnerability_class TEXT NOT NULL,
        severity TEXT NOT NULL,
        confirmation_method JSONB NOT NULL DEFAULT '{}',
        response_signature TEXT NOT NULL,
        confirmed_count INT NOT NULL DEFAULT 1,
        fp_count INT NOT NULL DEFAULT 0,
        last_seen TIMESTAMPTZ NOT NULL,
        UNIQUE(vulnerability_class, probe_type, response_signature)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        scan_run_id TEXT NOT NULL,
        template_id TEXT NOT NULL,
        name TEXT NOT NULL,
        severity TEXT NOT NULL,
        host TEXT NOT NULL,
        matched_at TEXT NOT NULL,
        description TEXT NOT NULL,
        tags JSONB NOT NULL DEFAULT '[]',
        cvss_score DOUBLE PRECISION,
        cve_id TEXT,
        raw_output JSONB NOT NULL DEFAULT '{}',
        is_false_positive BOOLEAN NOT NULL DEFAULT FALSE,
        ai_analysis TEXT,
        poc_steps TEXT,
        impact_statement TEXT,
        remediation TEXT,
        references JSONB NOT NULL DEFAULT '[]',
        report_title TEXT,
        formatted_description TEXT,
        discovered_at TIMESTAMPTZ NOT NULL,
        UNIQUE(scan_run_id, template_id, host, matched_at)
    )
    """,
]


class DataStore:
    """Async PostgreSQL data store for all scan artefacts."""

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self._pool: Optional[asyncpg.Pool] = None

    async def initialize(self) -> None:
        """Create the connection pool and all tables if they do not exist."""
        self._pool = await asyncpg.create_pool(
            self.dsn,
            min_size=1,
            max_size=5,
        )
        async with self._pool.acquire() as conn:
            for stmt in _SCHEMA_STATEMENTS:
                await conn.execute(stmt)
        logger.info("Database initialized: %s", self.dsn.split("@")[-1])

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._pool = None

    def _pool_conn(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("DataStore not initialized – call await store.initialize() first")
        return self._pool

    # ------------------------------------------------------------------
    # ScanRun
    # ------------------------------------------------------------------

    async def save_scan_run(self, run: ScanRun) -> None:
        async with self._pool_conn().acquire() as conn:
            await conn.execute(
                """
                INSERT INTO scan_runs (id, target_domain, program_name, started_at, completed_at, status)
                VALUES ($1, $2, $3, $4, $5, $6)
                """,
                run.id,
                run.target_domain,
                run.program_name,
                run.started_at,
                run.completed_at,
                run.status,
            )

    async def update_scan_run(self, run: ScanRun) -> None:
        async with self._pool_conn().acquire() as conn:
            await conn.execute(
                """
                UPDATE scan_runs
                   SET target_domain = $1,
                       program_name  = $2,
                       started_at    = $3,
                       completed_at  = $4,
                       status        = $5
                 WHERE id = $6
                """,
                run.target_domain,
                run.program_name,
                run.started_at,
                run.completed_at,
                run.status,
                run.id,
            )

    async def get_scan_run(self, scan_run_id: str) -> Optional[ScanRun]:
        async with self._pool_conn().acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM scan_runs WHERE id = $1", scan_run_id
            )
        if row is None:
            return None
        return ScanRun(
            id=row["id"],
            target_domain=row["target_domain"],
            program_name=row["program_name"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            status=row["status"],
        )

    async def list_scan_runs(self) -> list[ScanRun]:
        async with self._pool_conn().acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM scan_runs ORDER BY started_at DESC"
            )
        return [
            ScanRun(
                id=r["id"],
                target_domain=r["target_domain"],
                program_name=r["program_name"],
                started_at=r["started_at"],
                completed_at=r["completed_at"],
                status=r["status"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Subdomains
    # ------------------------------------------------------------------

    async def save_subdomain(self, sub: Subdomain) -> bool:
        """Insert subdomain; return False if it already exists (duplicate)."""
        async with self._pool_conn().acquire() as conn:
            status = await conn.execute(
                """
                INSERT INTO subdomains (id, scan_run_id, subdomain, source, discovered_at)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT DO NOTHING
                """,
                sub.id, sub.scan_run_id, sub.subdomain, sub.source, sub.discovered_at,
            )
        return int(status.split()[-1]) > 0

    async def save_subdomains(self, subs: list[Subdomain]) -> int:
        """Bulk-insert subdomains; return count of newly inserted records."""
        new_count = 0
        for sub in subs:
            if await self.save_subdomain(sub):
                new_count += 1
        return new_count

    async def get_subdomains(self, scan_run_id: str) -> list[Subdomain]:
        async with self._pool_conn().acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM subdomains WHERE scan_run_id = $1", scan_run_id
            )
        return [
            Subdomain(
                id=r["id"],
                scan_run_id=r["scan_run_id"],
                subdomain=r["subdomain"],
                source=r["source"],
                discovered_at=r["discovered_at"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Live hosts
    # ------------------------------------------------------------------

    async def save_live_host(self, host: LiveHost) -> bool:
        async with self._pool_conn().acquire() as conn:
            status = await conn.execute(
                """
                INSERT INTO live_hosts
                    (id, scan_run_id, url, subdomain, status_code, title,
                     technologies, content_length, server, probed_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT DO NOTHING
                """,
                host.id,
                host.scan_run_id,
                host.url,
                host.subdomain,
                host.status_code,
                host.title,
                host.technologies,
                host.content_length,
                host.server,
                host.probed_at,
            )
        return int(status.split()[-1]) > 0

    async def get_live_hosts(self, scan_run_id: str) -> list[LiveHost]:
        async with self._pool_conn().acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM live_hosts WHERE scan_run_id = $1", scan_run_id
            )
        return [
            LiveHost(
                id=r["id"],
                scan_run_id=r["scan_run_id"],
                url=r["url"],
                subdomain=r["subdomain"],
                status_code=r["status_code"],
                title=r["title"],
                technologies=list(r["technologies"]),
                content_length=r["content_length"],
                server=r["server"],
                probed_at=r["probed_at"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Open ports
    # ------------------------------------------------------------------

    async def save_open_port(self, port: OpenPort) -> None:
        async with self._pool_conn().acquire() as conn:
            await conn.execute(
                """
                INSERT INTO open_ports
                    (id, scan_run_id, host, port, protocol, service, discovered_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT DO NOTHING
                """,
                port.id,
                port.scan_run_id,
                port.host,
                port.port,
                port.protocol,
                port.service,
                port.discovered_at,
            )

    async def get_open_ports(self, scan_run_id: str) -> list[OpenPort]:
        async with self._pool_conn().acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM open_ports WHERE scan_run_id = $1", scan_run_id
            )
        return [
            OpenPort(
                id=r["id"],
                scan_run_id=r["scan_run_id"],
                host=r["host"],
                port=r["port"],
                protocol=r["protocol"],
                service=r["service"],
                discovered_at=r["discovered_at"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Discovered URLs
    # ------------------------------------------------------------------

    async def save_url(self, url: DiscoveredURL) -> bool:
        async with self._pool_conn().acquire() as conn:
            status = await conn.execute(
                """
                INSERT INTO discovered_urls
                    (id, scan_run_id, url, source, status_code, discovered_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT DO NOTHING
                """,
                url.id,
                url.scan_run_id,
                url.url,
                url.source,
                url.status_code,
                url.discovered_at,
            )
        return int(status.split()[-1]) > 0

    async def get_urls(self, scan_run_id: str) -> list[DiscoveredURL]:
        async with self._pool_conn().acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM discovered_urls WHERE scan_run_id = $1", scan_run_id
            )
        return [
            DiscoveredURL(
                id=r["id"],
                scan_run_id=r["scan_run_id"],
                url=r["url"],
                source=r["source"],
                status_code=r["status_code"],
                discovered_at=r["discovered_at"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    async def save_finding(self, finding: Finding) -> bool:
        async with self._pool_conn().acquire() as conn:
            status = await conn.execute(
                """
                INSERT INTO findings
                    (id, scan_run_id, template_id, name, severity, host,
                     matched_at, description, tags, cvss_score, cve_id,
                     raw_output, is_false_positive, ai_analysis, poc_steps,
                     impact_statement, remediation, references,
                     report_title, formatted_description, discovered_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                        $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
                ON CONFLICT DO NOTHING
                """,
                finding.id,
                finding.scan_run_id,
                finding.template_id,
                finding.name,
                finding.severity,
                finding.host,
                finding.matched_at,
                finding.description,
                finding.tags,
                finding.cvss_score,
                finding.cve_id,
                finding.raw_output,
                finding.is_false_positive,
                finding.ai_analysis,
                finding.poc_steps,
                finding.impact_statement,
                finding.remediation,
                finding.references,
                finding.report_title,
                finding.formatted_description,
                finding.discovered_at,
            )
        return int(status.split()[-1]) > 0

    async def get_findings(self, scan_run_id: str) -> list[Finding]:
        async with self._pool_conn().acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM findings WHERE scan_run_id = $1", scan_run_id
            )
        return [self._row_to_finding(r) for r in rows]

    async def update_finding(self, finding: Finding) -> None:
        async with self._pool_conn().acquire() as conn:
            await conn.execute(
                """
                UPDATE findings
                   SET template_id          = $1,
                       name                 = $2,
                       severity             = $3,
                       host                 = $4,
                       matched_at           = $5,
                       description          = $6,
                       tags                 = $7,
                       cvss_score           = $8,
                       cve_id               = $9,
                       raw_output           = $10,
                       is_false_positive    = $11,
                       ai_analysis          = $12,
                       poc_steps            = $13,
                       impact_statement     = $14,
                       remediation          = $15,
                       references           = $16,
                       report_title         = $17,
                       formatted_description = $18
                 WHERE id = $19
                """,
                finding.template_id,
                finding.name,
                finding.severity,
                finding.host,
                finding.matched_at,
                finding.description,
                finding.tags,
                finding.cvss_score,
                finding.cve_id,
                finding.raw_output,
                finding.is_false_positive,
                finding.ai_analysis,
                finding.poc_steps,
                finding.impact_statement,
                finding.remediation,
                finding.references,
                finding.report_title,
                finding.formatted_description,
                finding.id,
            )

    @staticmethod
    def _row_to_finding(r: asyncpg.Record) -> Finding:
        return Finding(
            id=r["id"],
            scan_run_id=r["scan_run_id"],
            template_id=r["template_id"],
            name=r["name"],
            severity=r["severity"],
            host=r["host"],
            matched_at=r["matched_at"],
            description=r["description"],
            tags=list(r["tags"]),
            cvss_score=r["cvss_score"],
            cve_id=r["cve_id"],
            raw_output=dict(r["raw_output"]),
            is_false_positive=r["is_false_positive"],
            ai_analysis=r["ai_analysis"],
            poc_steps=r["poc_steps"],
            impact_statement=r["impact_statement"],
            remediation=r["remediation"],
            references=list(r["references"]),
            report_title=r["report_title"],
            formatted_description=r["formatted_description"],
            discovered_at=r["discovered_at"],
        )

    # ------------------------------------------------------------------
    # Anomaly patterns (cross-scan learning)
    # ------------------------------------------------------------------

    async def save_pattern(self, pattern: AnomalyPattern) -> bool:
        """Upsert an anomaly pattern; increment confirmed_count on conflict.

        Returns True if a new row was inserted, False if an existing row
        was updated.
        """
        import json as _json
        async with self._pool_conn().acquire() as conn:
            status = await conn.execute(
                """
                INSERT INTO anomaly_patterns
                    (id, created_at, tech_stack, probe_type, vulnerability_class,
                     severity, confirmation_method, response_signature,
                     confirmed_count, fp_count, last_seen)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                ON CONFLICT (vulnerability_class, probe_type, response_signature)
                DO UPDATE SET
                    confirmed_count = anomaly_patterns.confirmed_count + 1,
                    last_seen       = EXCLUDED.last_seen
                """,
                pattern.id,
                pattern.created_at,
                pattern.tech_stack,
                pattern.probe_type,
                pattern.vulnerability_class,
                pattern.severity,
                _json.dumps(pattern.confirmation_method),
                pattern.response_signature,
                pattern.confirmed_count,
                pattern.fp_count,
                pattern.last_seen,
            )
        return int(status.split()[-1]) > 0

    async def get_patterns_by_tech(
        self, tech_stack: list[str]
    ) -> list[AnomalyPattern]:
        """Return patterns whose tech_stack overlaps with the given list.

        Results are ordered by confirmed_count DESC, fp_count ASC, capped at 50.
        """
        import json as _json
        async with self._pool_conn().acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT *
                  FROM anomaly_patterns
                 WHERE tech_stack && $1::text[]
                 ORDER BY confirmed_count DESC, fp_count ASC
                 LIMIT 50
                """,
                tech_stack,
            )
        return [
            AnomalyPattern(
                id=r["id"],
                created_at=r["created_at"],
                tech_stack=list(r["tech_stack"]),
                probe_type=r["probe_type"],
                vulnerability_class=r["vulnerability_class"],
                severity=r["severity"],
                confirmation_method=_json.loads(r["confirmation_method"])
                if isinstance(r["confirmation_method"], str)
                else dict(r["confirmation_method"]),
                response_signature=r["response_signature"],
                confirmed_count=r["confirmed_count"],
                fp_count=r["fp_count"],
                last_seen=r["last_seen"],
            )
            for r in rows
        ]

    async def increment_fp(self, pattern_id: str) -> None:
        """Increment the false-positive counter for a pattern."""
        async with self._pool_conn().acquire() as conn:
            await conn.execute(
                """
                UPDATE anomaly_patterns
                   SET fp_count = fp_count + 1
                 WHERE id = $1
                """,
                pattern_id,
            )
