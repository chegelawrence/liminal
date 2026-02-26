"""SQLite persistence layer using aiosqlite."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiosqlite

from bugbounty.db.models import (
    DiscoveredURL,
    Finding,
    LiveHost,
    OpenPort,
    ScanRun,
    Subdomain,
)

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    target_domain TEXT NOT NULL,
    program_name TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS subdomains (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    source TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    UNIQUE(scan_run_id, subdomain)
);

CREATE TABLE IF NOT EXISTS live_hosts (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT NOT NULL,
    url TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    title TEXT,
    technologies TEXT NOT NULL DEFAULT '[]',
    content_length INTEGER,
    server TEXT,
    probed_at TEXT NOT NULL,
    UNIQUE(scan_run_id, url)
);

CREATE TABLE IF NOT EXISTS open_ports (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    service TEXT,
    discovered_at TEXT NOT NULL,
    UNIQUE(scan_run_id, host, port, protocol)
);

CREATE TABLE IF NOT EXISTS discovered_urls (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT NOT NULL,
    url TEXT NOT NULL,
    source TEXT NOT NULL,
    status_code INTEGER,
    discovered_at TEXT NOT NULL,
    UNIQUE(scan_run_id, url)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    host TEXT NOT NULL,
    matched_at TEXT NOT NULL,
    description TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]',
    cvss_score REAL,
    cve_id TEXT,
    raw_output TEXT NOT NULL DEFAULT '{}',
    is_false_positive INTEGER NOT NULL DEFAULT 0,
    ai_analysis TEXT,
    poc_steps TEXT,
    impact_statement TEXT,
    remediation TEXT,
    references TEXT NOT NULL DEFAULT '[]',
    report_title TEXT,
    formatted_description TEXT,
    discovered_at TEXT NOT NULL,
    UNIQUE(scan_run_id, template_id, host, matched_at)
);
"""


def _dt(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None
    return datetime.fromisoformat(value)


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat()


class DataStore:
    """Async SQLite data store for all scan artefacts."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._db: Optional[aiosqlite.Connection] = None

    async def initialize(self) -> None:
        """Create the database file and all tables if they do not exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(_SCHEMA)
        await self._db.commit()
        logger.info("Database initialized at %s", self.db_path)

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    def _conn(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("DataStore not initialized – call await store.initialize() first")
        return self._db

    # ------------------------------------------------------------------
    # ScanRun
    # ------------------------------------------------------------------

    async def save_scan_run(self, run: ScanRun) -> None:
        await self._conn().execute(
            """
            INSERT INTO scan_runs (id, target_domain, program_name, started_at, completed_at, status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                run.id,
                run.target_domain,
                run.program_name,
                _iso(run.started_at),
                _iso(run.completed_at),
                run.status,
            ),
        )
        await self._conn().commit()

    async def update_scan_run(self, run: ScanRun) -> None:
        await self._conn().execute(
            """
            UPDATE scan_runs
               SET target_domain = ?,
                   program_name = ?,
                   started_at = ?,
                   completed_at = ?,
                   status = ?
             WHERE id = ?
            """,
            (
                run.target_domain,
                run.program_name,
                _iso(run.started_at),
                _iso(run.completed_at),
                run.status,
                run.id,
            ),
        )
        await self._conn().commit()

    async def get_scan_run(self, scan_run_id: str) -> Optional[ScanRun]:
        async with self._conn().execute(
            "SELECT * FROM scan_runs WHERE id = ?", (scan_run_id,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        return ScanRun(
            id=row["id"],
            target_domain=row["target_domain"],
            program_name=row["program_name"],
            started_at=datetime.fromisoformat(row["started_at"]),
            completed_at=_dt(row["completed_at"]),
            status=row["status"],
        )

    async def list_scan_runs(self) -> list[ScanRun]:
        async with self._conn().execute(
            "SELECT * FROM scan_runs ORDER BY started_at DESC"
        ) as cursor:
            rows = await cursor.fetchall()
        return [
            ScanRun(
                id=r["id"],
                target_domain=r["target_domain"],
                program_name=r["program_name"],
                started_at=datetime.fromisoformat(r["started_at"]),
                completed_at=_dt(r["completed_at"]),
                status=r["status"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Subdomains
    # ------------------------------------------------------------------

    async def save_subdomain(self, sub: Subdomain) -> bool:
        """Insert subdomain; return False if it already exists (duplicate)."""
        try:
            await self._conn().execute(
                """
                INSERT INTO subdomains (id, scan_run_id, subdomain, source, discovered_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (sub.id, sub.scan_run_id, sub.subdomain, sub.source, _iso(sub.discovered_at)),
            )
            await self._conn().commit()
            return True
        except aiosqlite.IntegrityError:
            return False

    async def save_subdomains(self, subs: list[Subdomain]) -> int:
        """Bulk-insert subdomains; return count of newly inserted records."""
        new_count = 0
        for sub in subs:
            if await self.save_subdomain(sub):
                new_count += 1
        return new_count

    async def get_subdomains(self, scan_run_id: str) -> list[Subdomain]:
        async with self._conn().execute(
            "SELECT * FROM subdomains WHERE scan_run_id = ?", (scan_run_id,)
        ) as cursor:
            rows = await cursor.fetchall()
        return [
            Subdomain(
                id=r["id"],
                scan_run_id=r["scan_run_id"],
                subdomain=r["subdomain"],
                source=r["source"],
                discovered_at=datetime.fromisoformat(r["discovered_at"]),
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Live hosts
    # ------------------------------------------------------------------

    async def save_live_host(self, host: LiveHost) -> bool:
        try:
            await self._conn().execute(
                """
                INSERT INTO live_hosts
                    (id, scan_run_id, url, subdomain, status_code, title,
                     technologies, content_length, server, probed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    host.id,
                    host.scan_run_id,
                    host.url,
                    host.subdomain,
                    host.status_code,
                    host.title,
                    json.dumps(host.technologies),
                    host.content_length,
                    host.server,
                    _iso(host.probed_at),
                ),
            )
            await self._conn().commit()
            return True
        except aiosqlite.IntegrityError:
            return False

    async def get_live_hosts(self, scan_run_id: str) -> list[LiveHost]:
        async with self._conn().execute(
            "SELECT * FROM live_hosts WHERE scan_run_id = ?", (scan_run_id,)
        ) as cursor:
            rows = await cursor.fetchall()
        return [
            LiveHost(
                id=r["id"],
                scan_run_id=r["scan_run_id"],
                url=r["url"],
                subdomain=r["subdomain"],
                status_code=r["status_code"],
                title=r["title"],
                technologies=json.loads(r["technologies"]),
                content_length=r["content_length"],
                server=r["server"],
                probed_at=datetime.fromisoformat(r["probed_at"]),
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Open ports
    # ------------------------------------------------------------------

    async def save_open_port(self, port: OpenPort) -> None:
        try:
            await self._conn().execute(
                """
                INSERT INTO open_ports
                    (id, scan_run_id, host, port, protocol, service, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    port.id,
                    port.scan_run_id,
                    port.host,
                    port.port,
                    port.protocol,
                    port.service,
                    _iso(port.discovered_at),
                ),
            )
            await self._conn().commit()
        except aiosqlite.IntegrityError:
            pass  # Already exists

    async def get_open_ports(self, scan_run_id: str) -> list[OpenPort]:
        async with self._conn().execute(
            "SELECT * FROM open_ports WHERE scan_run_id = ?", (scan_run_id,)
        ) as cursor:
            rows = await cursor.fetchall()
        return [
            OpenPort(
                id=r["id"],
                scan_run_id=r["scan_run_id"],
                host=r["host"],
                port=r["port"],
                protocol=r["protocol"],
                service=r["service"],
                discovered_at=datetime.fromisoformat(r["discovered_at"]),
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Discovered URLs
    # ------------------------------------------------------------------

    async def save_url(self, url: DiscoveredURL) -> bool:
        try:
            await self._conn().execute(
                """
                INSERT INTO discovered_urls
                    (id, scan_run_id, url, source, status_code, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    url.id,
                    url.scan_run_id,
                    url.url,
                    url.source,
                    url.status_code,
                    _iso(url.discovered_at),
                ),
            )
            await self._conn().commit()
            return True
        except aiosqlite.IntegrityError:
            return False

    async def get_urls(self, scan_run_id: str) -> list[DiscoveredURL]:
        async with self._conn().execute(
            "SELECT * FROM discovered_urls WHERE scan_run_id = ?", (scan_run_id,)
        ) as cursor:
            rows = await cursor.fetchall()
        return [
            DiscoveredURL(
                id=r["id"],
                scan_run_id=r["scan_run_id"],
                url=r["url"],
                source=r["source"],
                status_code=r["status_code"],
                discovered_at=datetime.fromisoformat(r["discovered_at"]),
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    async def save_finding(self, finding: Finding) -> bool:
        try:
            await self._conn().execute(
                """
                INSERT INTO findings
                    (id, scan_run_id, template_id, name, severity, host,
                     matched_at, description, tags, cvss_score, cve_id,
                     raw_output, is_false_positive, ai_analysis, poc_steps,
                     impact_statement, remediation, references,
                     report_title, formatted_description, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.id,
                    finding.scan_run_id,
                    finding.template_id,
                    finding.name,
                    finding.severity,
                    finding.host,
                    finding.matched_at,
                    finding.description,
                    json.dumps(finding.tags),
                    finding.cvss_score,
                    finding.cve_id,
                    json.dumps(finding.raw_output),
                    int(finding.is_false_positive),
                    finding.ai_analysis,
                    finding.poc_steps,
                    finding.impact_statement,
                    finding.remediation,
                    json.dumps(finding.references),
                    finding.report_title,
                    finding.formatted_description,
                    _iso(finding.discovered_at),
                ),
            )
            await self._conn().commit()
            return True
        except aiosqlite.IntegrityError:
            return False

    async def get_findings(self, scan_run_id: str) -> list[Finding]:
        async with self._conn().execute(
            "SELECT * FROM findings WHERE scan_run_id = ?", (scan_run_id,)
        ) as cursor:
            rows = await cursor.fetchall()
        return [self._row_to_finding(r) for r in rows]

    async def update_finding(self, finding: Finding) -> None:
        await self._conn().execute(
            """
            UPDATE findings
               SET template_id = ?,
                   name = ?,
                   severity = ?,
                   host = ?,
                   matched_at = ?,
                   description = ?,
                   tags = ?,
                   cvss_score = ?,
                   cve_id = ?,
                   raw_output = ?,
                   is_false_positive = ?,
                   ai_analysis = ?,
                   poc_steps = ?,
                   impact_statement = ?,
                   remediation = ?,
                   references = ?,
                   report_title = ?,
                   formatted_description = ?
             WHERE id = ?
            """,
            (
                finding.template_id,
                finding.name,
                finding.severity,
                finding.host,
                finding.matched_at,
                finding.description,
                json.dumps(finding.tags),
                finding.cvss_score,
                finding.cve_id,
                json.dumps(finding.raw_output),
                int(finding.is_false_positive),
                finding.ai_analysis,
                finding.poc_steps,
                finding.impact_statement,
                finding.remediation,
                json.dumps(finding.references),
                finding.report_title,
                finding.formatted_description,
                finding.id,
            ),
        )
        await self._conn().commit()

    @staticmethod
    def _row_to_finding(r: aiosqlite.Row) -> Finding:
        return Finding(
            id=r["id"],
            scan_run_id=r["scan_run_id"],
            template_id=r["template_id"],
            name=r["name"],
            severity=r["severity"],
            host=r["host"],
            matched_at=r["matched_at"],
            description=r["description"],
            tags=json.loads(r["tags"]),
            cvss_score=r["cvss_score"],
            cve_id=r["cve_id"],
            raw_output=json.loads(r["raw_output"]),
            is_false_positive=bool(r["is_false_positive"]),
            ai_analysis=r["ai_analysis"],
            poc_steps=r["poc_steps"],
            impact_statement=r["impact_statement"],
            remediation=r["remediation"],
            references=json.loads(r["references"]),
            report_title=r["report_title"],
            formatted_description=r["formatted_description"],
            discovered_at=datetime.fromisoformat(r["discovered_at"]),
        )
