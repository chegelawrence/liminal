"""SSRF and XSS focused vulnerability scanning pipeline.

Phases:
1. Nuclei – run XSS and SSRF templates only.
2. Parameter discovery – extract params from known URLs + optional arjun.
3. SSRF scanning – OOB + error-based detection on SSRF-prone params.
4. XSS scanning – reflection detection + dalfox on parameterised URLs.
5. Persist all deduplicated findings to the database.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel

from bugbounty.core.config import AppConfig
from bugbounty.core.interactsh import InteractshClient
from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import ScopeValidator
from bugbounty.db.models import Finding
from bugbounty.db.store import DataStore
from bugbounty.tools.params import ArjunTool, ParamExtractor
from bugbounty.tools.scanner import NucleiTool
from bugbounty.tools.ssrf import SSRFCandidate, SSRFScanner
from bugbounty.tools.xss import DalfoxScanner, ReflectionScanner

logger = logging.getLogger(__name__)

# Nuclei tags to focus on (XSS and SSRF only)
_NUCLEI_FOCUS_TAGS = ["xss", "ssrf"]
_NUCLEI_EXCLUDE_TAGS = ["dos", "fuzz", "intrusive", "tech"]


class ScanResult(BaseModel):
    """Counts returned by the ScanPipeline."""
    findings_total: int = 0
    findings_by_severity: dict[str, int] = {}
    ssrf_findings: int = 0
    xss_findings: int = 0
    nuclei_findings: int = 0


class ScanPipeline:
    """SSRF + XSS focused vulnerability scanning pipeline.

    Focuses exclusively on unauthenticated attack surface.
    Minimises false positives by:
    - Using OOB (interactsh) for SSRF confirmation.
    - Using unescaped reflection detection for XSS.
    - Re-verifying every finding before persisting.
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

        # Tools
        self.nuclei = NucleiTool(**tool_kwargs)
        self.arjun = ArjunTool(**tool_kwargs)
        self.param_extractor = ParamExtractor()

        # SSRF scanner (interactsh client initialised in run())
        self._ssrf_scanner: Optional[SSRFScanner] = None
        self._interactsh: Optional[InteractshClient] = None

        # XSS scanners
        ssrf_cfg = config.vuln.ssrf
        xss_cfg = config.vuln.xss
        self._xss_reflection = ReflectionScanner(
            scope_validator=scope,
            rate_limiter=rate_limiter,
            concurrent=xss_cfg.concurrent,
            timeout=xss_cfg.timeout,
            verify_findings=xss_cfg.verify_findings,
        )
        self._dalfox = DalfoxScanner(**tool_kwargs)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self,
        scan_run_id: str,
        progress_callback=None,
    ) -> ScanResult:
        """Execute the full SSRF/XSS scan for an existing scan run.

        Args:
            scan_run_id:       ID of the scan run (must have completed recon).
            progress_callback: Optional async callable(step: str, count: int).

        Returns:
            ScanResult with finding counts.
        """
        result = ScanResult()
        now = datetime.now(timezone.utc)

        async def notify(step: str, count: int = 0) -> None:
            if progress_callback:
                await progress_callback(step, count)

        # Load live hosts from DB
        live_hosts = await self.store.get_live_hosts(scan_run_id)
        if not live_hosts:
            logger.warning("[scan] No live hosts for scan run %s", scan_run_id)
            return result

        target_urls = [h.url for h in live_hosts if self.scope.is_in_scope(h.url)]
        logger.info("[scan] Scanning %d in-scope live hosts", len(target_urls))

        # Load discovered URLs for param extraction
        discovered_urls_db = await self.store.get_urls(scan_run_id)
        all_urls = [u.url for u in discovered_urls_db if self.scope.is_in_scope(u.url)]
        # Also include live host URLs with their paths
        all_urls.extend(target_urls)
        all_urls = list(dict.fromkeys(all_urls))  # deduplicate while preserving order

        all_findings: list[dict] = []

        # ---------------------------------------------------------------
        # Phase 1: Nuclei (XSS + SSRF templates only)
        # ---------------------------------------------------------------
        await notify("nuclei_start")
        nuclei_cfg = self.config.tools.nuclei
        if target_urls and nuclei_cfg.enabled:
            logger.info("[scan] Nuclei (XSS+SSRF templates) on %d targets", len(target_urls))
            nuclei_results = await self.nuclei.scan(
                targets=target_urls,
                severity=nuclei_cfg.severity,
                tags=_NUCLEI_FOCUS_TAGS,
                exclude_tags=_NUCLEI_EXCLUDE_TAGS,
                rate_limit=nuclei_cfg.rate_limit,
                timeout=nuclei_cfg.timeout,
            )
            for r in nuclei_results:
                r["source"] = "nuclei"
            all_findings.extend(nuclei_results)
            result.nuclei_findings = len(nuclei_results)
            await notify("nuclei_done", len(nuclei_results))
            logger.info("[scan] Nuclei: %d findings", len(nuclei_results))

        # ---------------------------------------------------------------
        # Phase 2: Parameter discovery
        # ---------------------------------------------------------------
        await notify("params_start")
        # Extract params from known URLs
        param_map = self.param_extractor.extract_from_urls(all_urls)
        logger.info(
            "[scan] Extracted params from %d base URLs", len(param_map)
        )

        # Optional: arjun on high-value targets (API, admin, search endpoints)
        arjun_cfg = self.config.vuln.arjun
        if arjun_cfg.enabled:
            high_value = self._select_high_value_targets(target_urls)
            for url in high_value[:5]:  # cap at 5 to avoid excessive scanning
                try:
                    new_params = await self.arjun.discover(
                        url=url,
                        threads=arjun_cfg.threads,
                        timeout=arjun_cfg.timeout,
                    )
                    if new_params:
                        parsed = urlparse(url)
                        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        existing = param_map.setdefault(base, [])
                        for p in new_params:
                            if p not in existing:
                                existing.append(p)
                except Exception as exc:
                    logger.warning("[scan] arjun failed on %s: %s", url, exc)

        await notify("params_done", sum(len(v) for v in param_map.values()))

        # ---------------------------------------------------------------
        # Phase 3: SSRF scanning
        # ---------------------------------------------------------------
        await notify("ssrf_start")
        ssrf_cfg = self.config.vuln.ssrf

        if ssrf_cfg.enabled:
            # Start interactsh client for OOB detection
            self._interactsh = InteractshClient(
                server=ssrf_cfg.interactsh_server,
                poll_interval=3.0,
            )
            oob_available = await self._interactsh.start()
            if not oob_available:
                logger.warning(
                    "[scan] interactsh not available – SSRF will use error-based detection only"
                )

            self._ssrf_scanner = SSRFScanner(
                scope_validator=self.scope,
                interactsh=self._interactsh,
                concurrent=ssrf_cfg.concurrent,
                timeout=ssrf_cfg.timeout,
                oob_wait=ssrf_cfg.oob_wait_seconds,
                verify_findings=ssrf_cfg.verify_findings,
            )

            try:
                # Build SSRF candidates from URLs with known params
                ssrf_candidates = self._build_ssrf_candidates(param_map)
                logger.info("[scan] SSRF: testing %d candidates", len(ssrf_candidates))

                ssrf_findings = await self._ssrf_scanner.scan_candidates(ssrf_candidates)
                logger.info("[scan] SSRF: %d findings", len(ssrf_findings))

                for sf in ssrf_findings:
                    all_findings.append(self._ssrf_to_finding_dict(sf))

                result.ssrf_findings = len(ssrf_findings)
                await notify("ssrf_done", len(ssrf_findings))
            finally:
                await self._interactsh.stop()

        # ---------------------------------------------------------------
        # Phase 4: XSS scanning
        # ---------------------------------------------------------------
        await notify("xss_start")
        xss_cfg = self.config.vuln.xss

        if xss_cfg.enabled:
            # URLs with query parameters
            urls_with_params = [
                u for u in all_urls
                if "?" in u and self.scope.is_in_scope(u)
            ]
            logger.info("[scan] XSS: %d URLs with query params", len(urls_with_params))

            xss_results: list = []

            # 4a. Reflection-based XSS scanner
            if xss_cfg.reflection_scanner_enabled and urls_with_params:
                try:
                    reflected = await self._xss_reflection.scan_urls(
                        urls_with_params[:100]  # cap at 100
                    )
                    xss_results.extend(reflected)
                    logger.info("[scan] Reflection XSS: %d findings", len(reflected))
                except Exception as exc:
                    logger.warning("[scan] Reflection XSS scanner error: %s", exc)

            # 4b. Dalfox – comprehensive XSS scanner with FP filtering
            if xss_cfg.dalfox_enabled and urls_with_params:
                try:
                    dalfox_results = await self._dalfox.scan(
                        urls=urls_with_params[:200],  # cap at 200
                        timeout=20,
                        blind_url=xss_cfg.blind_xss_url,
                    )
                    xss_results.extend(dalfox_results)
                    logger.info("[scan] Dalfox XSS: %d findings", len(dalfox_results))
                except Exception as exc:
                    logger.warning("[scan] Dalfox error: %s", exc)

            for xf in xss_results:
                all_findings.append(self._xss_to_finding_dict(xf))

            result.xss_findings = len(xss_results)
            await notify("xss_done", len(xss_results))

        # ---------------------------------------------------------------
        # Persist all findings
        # ---------------------------------------------------------------
        severity_counts: dict[str, int] = {}
        for finding_dict in all_findings:
            severity = finding_dict.get("severity", "info").lower()
            finding = Finding(
                id=str(uuid.uuid4()),
                scan_run_id=scan_run_id,
                template_id=finding_dict.get("template_id", "unknown"),
                name=finding_dict.get("name", "Unknown"),
                severity=severity,
                host=finding_dict.get("host", ""),
                matched_at=finding_dict.get("matched_at", ""),
                description=finding_dict.get("description", ""),
                tags=finding_dict.get("tags", []),
                cvss_score=finding_dict.get("cvss_score"),
                cve_id=finding_dict.get("cve_id"),
                raw_output=finding_dict.get("raw", {}),
                discovered_at=now,
            )
            if await self.store.save_finding(finding):
                result.findings_total += 1
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

        result.findings_by_severity = severity_counts
        logger.info(
            "[scan] Saved %d findings: %s", result.findings_total, severity_counts
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_ssrf_candidates(
        self, param_map: dict[str, list[str]]
    ) -> list[SSRFCandidate]:
        """Build SSRF candidates from the extracted parameter map."""
        from bugbounty.tools.params import ParamExtractor
        extractor = ParamExtractor()
        candidates: list[SSRFCandidate] = []
        seen: set[tuple[str, str]] = set()

        for base_url, params in param_map.items():
            if not self.scope.is_in_scope(base_url):
                continue
            classified = extractor.classify_params(params)
            # SSRF candidates first
            for p in classified["ssrf"]:
                key = (base_url, p.lower())
                if key not in seen:
                    seen.add(key)
                    candidates.append(SSRFCandidate(url=base_url, param=p))
            # Also test "other" params from interesting endpoints
            parsed = urlparse(base_url)
            path_lower = parsed.path.lower()
            is_interesting = any(
                kw in path_lower for kw in [
                    "api", "proxy", "fetch", "request", "load", "open", "download",
                    "redirect", "export", "import", "webhook", "notify",
                ]
            )
            if is_interesting:
                for p in classified["other"][:5]:  # top 5 other params from interesting endpoints
                    key = (base_url, p.lower())
                    if key not in seen:
                        seen.add(key)
                        candidates.append(SSRFCandidate(url=base_url, param=p))

        # Also test top SSRF param names against all base URLs (even without known params)
        from bugbounty.tools.ssrf import SSRF_PARAMS
        base_urls_set = set(param_map.keys())
        for base_url in list(base_urls_set)[:50]:  # cap at 50 hosts
            if not self.scope.is_in_scope(base_url):
                continue
            for p in SSRF_PARAMS[:15]:  # top 15 most common SSRF params
                key = (base_url, p.lower())
                if key not in seen:
                    seen.add(key)
                    candidates.append(SSRFCandidate(url=base_url, param=p))

        return candidates

    def _select_high_value_targets(self, urls: list[str]) -> list[str]:
        """Select URLs most likely to have interesting hidden parameters."""
        scored: list[tuple[int, str]] = []
        for url in urls:
            score = 0
            lower = url.lower()
            for kw in ["api", "search", "query", "find", "filter", "proxy", "fetch",
                       "admin", "dashboard", "export", "import", "webhook"]:
                if kw in lower:
                    score += 2
            scored.append((score, url))
        scored.sort(reverse=True)
        return [u for _, u in scored if _ > 0]

    @staticmethod
    def _ssrf_to_finding_dict(sf) -> dict:
        from bugbounty.tools.ssrf import SSRFFinding
        severity_map = {
            "confirmed": "high",
            "high": "high",
            "medium": "medium",
        }
        return {
            "template_id": f"ssrf-{sf.evidence_type}",
            "name": "Server-Side Request Forgery (SSRF)",
            "severity": severity_map.get(sf.confidence, "medium"),
            "host": sf.candidate.url,
            "matched_at": sf.candidate.url,
            "description": (
                f"SSRF detected via parameter '{sf.candidate.param}'. "
                f"Evidence type: {sf.evidence_type}. {sf.evidence}"
            ),
            "tags": ["ssrf", "oob" if sf.evidence_type == "oob_interaction" else sf.evidence_type],
            "cvss_score": 8.6 if sf.confidence == "confirmed" else 6.5,
            "cve_id": None,
            "raw": sf.to_dict(),
            "source": "ssrf-scanner",
            "evidence_type": sf.evidence_type,
            "confidence": sf.confidence,
        }

    @staticmethod
    def _xss_to_finding_dict(xf) -> dict:
        from bugbounty.tools.xss import XSSFinding
        return {
            "template_id": f"xss-{xf.xss_type}",
            "name": "Cross-Site Scripting (XSS)",
            "severity": "high",
            "host": xf.url,
            "matched_at": xf.url,
            "description": (
                f"XSS via parameter '{xf.param}' in {xf.context} context. "
                f"Payload: {xf.payload[:100]}. {xf.evidence}"
            ),
            "tags": ["xss", xf.xss_type, xf.context],
            "cvss_score": 6.1,
            "cve_id": None,
            "raw": xf.to_dict(),
            "source": f"xss-{xf.xss_type}",
            "confidence": xf.confidence,
        }
