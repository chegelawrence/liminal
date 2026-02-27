"""Recon pipeline: enumerate subdomains, probe live hosts, discover URLs."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from pydantic import BaseModel

from bugbounty.core.config import AppConfig
from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import OutOfScopeError, ScopeValidator
from bugbounty.db.models import DiscoveredURL, LiveHost, OpenPort, Subdomain
from bugbounty.db.store import DataStore
from bugbounty.tools.discovery import GauTool, KatanaTool, WaybackTool
from bugbounty.tools.recon import AmaasTool, DnsxTool, HttpxTool, NaabuTool, SubfinderTool

logger = logging.getLogger(__name__)


class ReconResult(BaseModel):
    """Counts returned by the ReconPipeline."""

    subdomains_found: int = 0
    live_hosts_found: int = 0
    ports_found: int = 0
    urls_found: int = 0


class ReconPipeline:
    """Orchestrates the full reconnaissance phase.

    Steps:
    1. Enumerate subdomains (subfinder + amass in parallel).
    2. Resolve subdomains with dnsx.
    3. Probe live HTTP/HTTPS hosts with httpx.
    4. Port-scan live hosts with naabu.
    5. Discover historical URLs (gau + waybackurls in parallel).
    6. Crawl live hosts with katana.
    7. Persist all artefacts to the database.
    """

    def __init__(
        self,
        config: AppConfig,
        store: DataStore,
        scope: ScopeValidator,
    ) -> None:
        self.config = config
        self.store = store
        self.scope = scope

        rate_limiter = RateLimiter(config.rate_limits.concurrent_requests)
        tool_kwargs = {"scope_validator": scope, "rate_limiter": rate_limiter}

        self.subfinder = SubfinderTool(**tool_kwargs)
        self.amass = AmaasTool(**tool_kwargs)
        self.dnsx = DnsxTool(**tool_kwargs)
        self.httpx = HttpxTool(**tool_kwargs)
        self.naabu = NaabuTool(**tool_kwargs)
        self.gau = GauTool(**tool_kwargs)
        self.katana = KatanaTool(**tool_kwargs)
        self.wayback = WaybackTool(**tool_kwargs)

    async def run(
        self,
        scan_run_id: str,
        domain: str,
        progress_callback=None,
    ) -> ReconResult:
        """Execute the full recon pipeline for *domain*.

        Args:
            scan_run_id:       ID of the current ScanRun record.
            domain:            Primary target domain.
            progress_callback: Optional async callable(step: str, count: int)
                               invoked after each phase completes.

        Returns:
            ReconResult with discovery counts.
        """
        result = ReconResult()

        try:
            self.scope.assert_in_scope(domain)
        except OutOfScopeError:
            logger.error("Domain %s is out of scope – aborting recon", domain)
            return result

        async def notify(step: str, count: int = 0) -> None:
            if progress_callback:
                await progress_callback(step, count)

        # ---------------------------------------------------------------
        # Phase 1: Subdomain enumeration (parallel)
        # ---------------------------------------------------------------
        await notify("subdomain_enum_start")
        logger.info("[recon] Phase 1: Subdomain enumeration for %s", domain)

        async def _empty_list() -> list:
            return []

        subfinder_task = asyncio.create_task(
            self.subfinder.enumerate(
                domain, timeout=self.config.tools.subfinder.timeout
            )
            if self.config.tools.subfinder.enabled
            else _empty_list()
        )
        amass_task = asyncio.create_task(
            self.amass.enumerate(
                domain,
                mode=self.config.tools.amass.mode,
                timeout=self.config.tools.amass.timeout,
            )
            if self.config.tools.amass.enabled
            else _empty_list()
        )

        subfinder_results, amass_results = await asyncio.gather(
            subfinder_task, amass_task, return_exceptions=True
        )

        all_subs: dict[str, str] = {}  # host -> source

        for tool_name, tool_results in [
            ("subfinder", subfinder_results),
            ("amass", amass_results),
        ]:
            if isinstance(tool_results, Exception):
                logger.warning("[recon] %s failed: %s", tool_name, tool_results)
                continue
            for item in tool_results:
                host = item.get("host", "").lower()
                if host and host not in all_subs:
                    all_subs[host] = item.get("source", tool_name)

        logger.info("[recon] Total unique subdomains pre-resolve: %d", len(all_subs))

        # ---------------------------------------------------------------
        # Phase 2: DNS resolution
        # ---------------------------------------------------------------
        await notify("dns_resolve_start")
        logger.info("[recon] Phase 2: Resolving %d subdomains", len(all_subs))

        resolved_hosts: list[str] = []
        if all_subs and self.config.tools.dnsx.enabled:
            resolved_data = await self.dnsx.resolve(
                list(all_subs.keys()),
                resolvers=self.config.tools.dnsx.resolvers,
            )
            resolved_hosts = [r["host"] for r in resolved_data]
        else:
            resolved_hosts = list(all_subs.keys())

        # Persist subdomains
        now = datetime.now(timezone.utc)
        subdomain_models = [
            Subdomain(
                id=str(uuid.uuid4()),
                scan_run_id=scan_run_id,
                subdomain=host,
                source=all_subs.get(host, "unknown"),
                discovered_at=now,
            )
            for host in resolved_hosts
        ]
        result.subdomains_found = await self.store.save_subdomains(subdomain_models)
        await notify("subdomain_enum_done", result.subdomains_found)
        logger.info("[recon] Saved %d new subdomains", result.subdomains_found)

        # ---------------------------------------------------------------
        # Phase 3: Live host probing
        # ---------------------------------------------------------------
        await notify("httpx_probe_start")
        logger.info("[recon] Phase 3: Probing %d hosts with httpx", len(resolved_hosts))

        live_host_data: list[dict] = []
        if resolved_hosts and self.config.tools.httpx.enabled:
            live_host_data = await self.httpx.probe(
                resolved_hosts,
                timeout=self.config.tools.httpx.timeout,
                follow_redirects=self.config.tools.httpx.follow_redirects,
            )

        live_host_models: list[LiveHost] = []
        for h in live_host_data:
            model = LiveHost(
                id=str(uuid.uuid4()),
                scan_run_id=scan_run_id,
                url=h["url"],
                subdomain=h.get("subdomain", h["url"]),
                status_code=h.get("status_code", 0),
                title=h.get("title", ""),
                technologies=h.get("technologies", []),
                content_length=h.get("content_length"),
                server=h.get("server", ""),
                probed_at=now,
            )
            if await self.store.save_live_host(model):
                live_host_models.append(model)

        result.live_hosts_found = len(live_host_models)
        await notify("httpx_probe_done", result.live_hosts_found)
        logger.info("[recon] Found %d live hosts", result.live_hosts_found)

        # ---------------------------------------------------------------
        # Phase 4: Port scanning
        # ---------------------------------------------------------------
        await notify("port_scan_start")
        logger.info("[recon] Phase 4: Port scanning %d hosts", len(resolved_hosts))

        if resolved_hosts and self.config.tools.naabu.enabled:
            naabu_cfg = self.config.tools.naabu
            port_data = await self.naabu.scan(
                resolved_hosts,
                ports=naabu_cfg.ports if naabu_cfg.ports else None,
                top_ports=naabu_cfg.top_ports,
                timeout=naabu_cfg.timeout,
            )
            for p in port_data:
                port_model = OpenPort(
                    id=str(uuid.uuid4()),
                    scan_run_id=scan_run_id,
                    host=p["host"],
                    port=p["port"],
                    protocol=p.get("protocol", "tcp"),
                    service=p.get("service", ""),
                    discovered_at=now,
                )
                await self.store.save_open_port(port_model)
                result.ports_found += 1

        await notify("port_scan_done", result.ports_found)
        logger.info("[recon] Found %d open ports", result.ports_found)

        # ---------------------------------------------------------------
        # Phase 5: URL discovery (gau + wayback in parallel)
        # ---------------------------------------------------------------
        await notify("url_discovery_start")
        logger.info("[recon] Phase 5: URL discovery for %s", domain)

        url_tasks = []
        if self.config.tools.gau.enabled:
            url_tasks.append(
                asyncio.create_task(
                    self.gau.fetch_urls(domain, providers=self.config.tools.gau.providers)
                )
            )
        url_tasks.append(asyncio.create_task(self.wayback.fetch_urls(domain)))

        url_results = await asyncio.gather(*url_tasks, return_exceptions=True)

        all_urls: set[str] = set()
        for r in url_results:
            if isinstance(r, Exception):
                logger.warning("[recon] URL discovery tool failed: %s", r)
                continue
            all_urls.update(r)

        # ---------------------------------------------------------------
        # Phase 6: Active crawling with katana
        # ---------------------------------------------------------------
        if live_host_models and self.config.tools.katana.enabled:
            logger.info(
                "[recon] Phase 6: Crawling %d live hosts with katana",
                len(live_host_models),
            )
            crawl_tasks = [
                asyncio.create_task(
                    self.katana.crawl(
                        h.url,
                        depth=self.config.tools.katana.depth,
                        timeout=self.config.tools.katana.timeout,
                        headless=self.config.tools.katana.headless,
                    )
                )
                for h in live_host_models[:10]  # Limit to top 10 to avoid abuse
            ]
            crawl_results = await asyncio.gather(*crawl_tasks, return_exceptions=True)
            for r in crawl_results:
                if isinstance(r, Exception):
                    continue
                for endpoint in r:
                    all_urls.add(endpoint["url"])

        # Persist URLs
        for url in all_urls:
            url_model = DiscoveredURL(
                id=str(uuid.uuid4()),
                scan_run_id=scan_run_id,
                url=url,
                source="gau/wayback/katana",
                discovered_at=now,
            )
            if await self.store.save_url(url_model):
                result.urls_found += 1

        await notify("url_discovery_done", result.urls_found)
        logger.info("[recon] Saved %d unique URLs", result.urls_found)

        return result
