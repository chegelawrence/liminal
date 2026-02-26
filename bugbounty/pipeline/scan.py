"""Comprehensive vulnerability scanning pipeline.

Phases:
0. Nuclei – XSS and SSRF templates.
1. Subdomain takeover check.
2. Exposed endpoint detection.
3. CORS misconfiguration scan.
4. JavaScript secret scanning (feeds new endpoints into later phases).
5. Parameter discovery (arjun on high-value targets).
6. SSRF scanning – GET parameters.
7. SSRF scanning – POST/JSON body.
8. HTTP header injection SSRF.
9. Open redirect detection.
10. XSS scanning (reflection + dalfox).
11. Persist all findings.
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
from bugbounty.tools.ssrf import SSRFCandidate, SSRFScanner, PostSSRFScanner
from bugbounty.tools.xss import DalfoxScanner, ReflectionScanner

# New scanners — graceful degradation if any import fails
try:
    from bugbounty.tools.cors import CORSScanner, CORSFinding
    _CORS_AVAILABLE = True
except ImportError as _e:
    logger_bootstrap = logging.getLogger(__name__)
    logger_bootstrap.warning("CORSScanner unavailable: %s", _e)
    _CORS_AVAILABLE = False

try:
    from bugbounty.tools.redirect import OpenRedirectScanner, OpenRedirectFinding
    _REDIRECT_AVAILABLE = True
except ImportError as _e:
    logger_bootstrap = logging.getLogger(__name__)
    logger_bootstrap.warning("OpenRedirectScanner unavailable: %s", _e)
    _REDIRECT_AVAILABLE = False

try:
    from bugbounty.tools.takeover import TakeoverScanner, TakeoverFinding
    _TAKEOVER_AVAILABLE = True
except ImportError as _e:
    logger_bootstrap = logging.getLogger(__name__)
    logger_bootstrap.warning("TakeoverScanner unavailable: %s", _e)
    _TAKEOVER_AVAILABLE = False

try:
    from bugbounty.tools.exposure import ExposureScanner, ExposureFinding
    _EXPOSURE_AVAILABLE = True
except ImportError as _e:
    logger_bootstrap = logging.getLogger(__name__)
    logger_bootstrap.warning("ExposureScanner unavailable: %s", _e)
    _EXPOSURE_AVAILABLE = False

try:
    from bugbounty.tools.js_scanner import JSScanner, JSFinding
    _JS_AVAILABLE = True
except ImportError as _e:
    logger_bootstrap = logging.getLogger(__name__)
    logger_bootstrap.warning("JSScanner unavailable: %s", _e)
    _JS_AVAILABLE = False

try:
    from bugbounty.tools.headers import HeaderInjectionScanner, HeaderInjectionFinding
    _HEADER_AVAILABLE = True
except ImportError as _e:
    logger_bootstrap = logging.getLogger(__name__)
    logger_bootstrap.warning("HeaderInjectionScanner unavailable: %s", _e)
    _HEADER_AVAILABLE = False

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
    cors_findings: int = 0
    redirect_findings: int = 0
    takeover_findings: int = 0
    exposure_findings: int = 0
    js_secrets: int = 0
    header_ssrf_findings: int = 0


class ScanPipeline:
    """Comprehensive vulnerability scanning pipeline.

    Focuses exclusively on unauthenticated attack surface.
    Minimises false positives via OOB confirmation, content validation,
    and re-verification passes.
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

        # Core tools
        self.nuclei = NucleiTool(**tool_kwargs)
        self.arjun = ArjunTool(**tool_kwargs)
        self.param_extractor = ParamExtractor()

        # SSRF + POST SSRF (interactsh initialised in run())
        self._ssrf_scanner: Optional[SSRFScanner] = None
        self._post_ssrf_scanner: Optional[PostSSRFScanner] = None
        self._interactsh: Optional[InteractshClient] = None

        # XSS scanners
        xss_cfg = config.vuln.xss
        self._xss_reflection = ReflectionScanner(
            scope_validator=scope,
            rate_limiter=rate_limiter,
            concurrent=xss_cfg.concurrent,
            timeout=xss_cfg.timeout,
            verify_findings=xss_cfg.verify_findings,
        )
        self._dalfox = DalfoxScanner(**tool_kwargs)

        # New scanners (conditionally initialised)
        cors_cfg = config.vuln.cors
        self._cors: Optional[CORSScanner] = (
            CORSScanner(
                scope_validator=scope,
                rate_limiter=rate_limiter,
                concurrent=cors_cfg.concurrent,
                timeout=cors_cfg.timeout,
                api_paths=cors_cfg.api_paths,
            )
            if _CORS_AVAILABLE and cors_cfg.enabled
            else None
        )

        redirect_cfg = config.vuln.open_redirect
        self._redirect: Optional[OpenRedirectScanner] = (
            OpenRedirectScanner(
                scope_validator=scope,
                rate_limiter=rate_limiter,
                concurrent=redirect_cfg.concurrent,
                timeout=redirect_cfg.timeout,
                verify_findings=redirect_cfg.verify_findings,
            )
            if _REDIRECT_AVAILABLE and redirect_cfg.enabled
            else None
        )

        takeover_cfg = config.vuln.takeover
        self._takeover: Optional[TakeoverScanner] = (
            TakeoverScanner(
                scope_validator=scope,
                rate_limiter=rate_limiter,
                concurrent=takeover_cfg.concurrent,
                timeout=takeover_cfg.timeout,
            )
            if _TAKEOVER_AVAILABLE and takeover_cfg.enabled
            else None
        )

        exposure_cfg = config.vuln.exposure
        self._exposure: Optional[ExposureScanner] = (
            ExposureScanner(
                scope_validator=scope,
                rate_limiter=rate_limiter,
                concurrent=exposure_cfg.concurrent,
                timeout=exposure_cfg.timeout,
                categories=exposure_cfg.categories,
            )
            if _EXPOSURE_AVAILABLE and exposure_cfg.enabled
            else None
        )

        js_cfg = config.vuln.js_scanner
        self._js: Optional[JSScanner] = (
            JSScanner(
                scope_validator=scope,
                rate_limiter=rate_limiter,
                max_js_files=js_cfg.max_js_files,
                timeout=js_cfg.timeout,
            )
            if _JS_AVAILABLE and js_cfg.enabled
            else None
        )

        header_cfg = config.vuln.header_injection
        self._header: Optional[HeaderInjectionScanner] = (
            HeaderInjectionScanner(
                scope_validator=scope,
                rate_limiter=rate_limiter,
                concurrent=header_cfg.concurrent,
                timeout=header_cfg.timeout,
            )
            if _HEADER_AVAILABLE and header_cfg.enabled
            else None
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self,
        scan_run_id: str,
        progress_callback=None,
    ) -> ScanResult:
        """Execute the full vulnerability scan for an existing scan run.

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

        # Load discovered URLs for param extraction and JS scanning
        discovered_urls_db = await self.store.get_urls(scan_run_id)
        all_urls = [u.url for u in discovered_urls_db if self.scope.is_in_scope(u.url)]
        all_urls.extend(target_urls)
        all_urls = list(dict.fromkeys(all_urls))  # deduplicate preserving order

        all_findings: list[dict] = []

        # ---------------------------------------------------------------
        # Phase 0: Nuclei (XSS + SSRF templates)
        # ---------------------------------------------------------------
        await notify("nuclei_start")
        nuclei_cfg = self.config.tools.nuclei
        if target_urls and nuclei_cfg.enabled:
            logger.info("[scan] Nuclei (XSS+SSRF templates) on %d targets", len(target_urls))
            try:
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
            except Exception as exc:
                logger.warning("[scan] Nuclei error: %s", exc)

        # ---------------------------------------------------------------
        # Phase 1: Subdomain takeover check
        # ---------------------------------------------------------------
        await notify("takeover_start")
        if self._takeover and target_urls:
            logger.info("[scan] Subdomain takeover check on %d hosts", len(target_urls))
            try:
                # Extract subdomains from live host URLs
                subdomains = list({
                    urlparse(u).netloc
                    for u in target_urls
                    if urlparse(u).netloc
                })
                takeover_findings = await self._takeover.scan_subdomains(subdomains)
                for tf in takeover_findings:
                    all_findings.append(self._takeover_to_finding_dict(tf))
                result.takeover_findings = len(takeover_findings)
                await notify("takeover_done", len(takeover_findings))
                logger.info("[scan] Takeover: %d findings", len(takeover_findings))
            except Exception as exc:
                logger.warning("[scan] Takeover scanner error: %s", exc)

        # ---------------------------------------------------------------
        # Phase 2: Exposed endpoint detection
        # ---------------------------------------------------------------
        await notify("exposure_start")
        if self._exposure and target_urls:
            logger.info("[scan] Exposure scan on %d hosts", len(target_urls))
            try:
                exposure_findings = await self._exposure.scan_hosts(target_urls)
                for ef in exposure_findings:
                    all_findings.append(self._exposure_to_finding_dict(ef))
                result.exposure_findings = len(exposure_findings)
                await notify("exposure_done", len(exposure_findings))
                logger.info("[scan] Exposure: %d findings", len(exposure_findings))
            except Exception as exc:
                logger.warning("[scan] Exposure scanner error: %s", exc)

        # ---------------------------------------------------------------
        # Phase 3: CORS misconfiguration scan
        # ---------------------------------------------------------------
        await notify("cors_start")
        if self._cors and target_urls:
            logger.info("[scan] CORS scan on %d hosts", len(target_urls))
            try:
                cors_findings = await self._cors.scan_hosts(target_urls)
                for cf in cors_findings:
                    all_findings.append(self._cors_to_finding_dict(cf))
                result.cors_findings = len(cors_findings)
                await notify("cors_done", len(cors_findings))
                logger.info("[scan] CORS: %d findings", len(cors_findings))
            except Exception as exc:
                logger.warning("[scan] CORS scanner error: %s", exc)

        # ---------------------------------------------------------------
        # Phase 4: JavaScript secret scanning
        # ---------------------------------------------------------------
        await notify("js_start")
        js_discovered_endpoints: list[str] = []
        if self._js and all_urls:
            js_urls = [u for u in all_urls if u.lower().endswith(".js")]
            logger.info("[scan] JS scan on %d JS files", len(js_urls))
            try:
                js_findings, js_endpoints = await self._js.scan_js_files(js_urls)
                for jf in js_findings:
                    if jf.finding_type == "secret":
                        all_findings.append(self._js_to_finding_dict(jf))
                # Feed discovered endpoints into later phases
                js_discovered_endpoints = js_endpoints
                result.js_secrets = sum(
                    1 for jf in js_findings if jf.finding_type == "secret"
                )
                await notify("js_done", result.js_secrets)
                logger.info(
                    "[scan] JS: %d secrets, %d new endpoints",
                    result.js_secrets, len(js_endpoints),
                )
            except Exception as exc:
                logger.warning("[scan] JS scanner error: %s", exc)

        # Augment URL list with JS-discovered endpoints
        if js_discovered_endpoints:
            for ep_path in js_discovered_endpoints:
                for base_url in target_urls:
                    parsed = urlparse(base_url)
                    candidate_url = f"{parsed.scheme}://{parsed.netloc}{ep_path}"
                    if candidate_url not in all_urls and self.scope.is_in_scope(candidate_url):
                        all_urls.append(candidate_url)

        # ---------------------------------------------------------------
        # Phase 5: Parameter discovery
        # ---------------------------------------------------------------
        await notify("params_start")
        param_map = self.param_extractor.extract_from_urls(all_urls)
        logger.info(
            "[scan] Extracted params from %d base URLs", len(param_map)
        )

        arjun_cfg = self.config.vuln.arjun
        if arjun_cfg.enabled:
            high_value = self._select_high_value_targets(target_urls)
            for url in high_value[:5]:
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
        # Phase 6 + 7 + 8: SSRF scanning (GET, POST, Headers) — shared interactsh
        # ---------------------------------------------------------------
        await notify("ssrf_start")
        ssrf_cfg = self.config.vuln.ssrf

        if ssrf_cfg.enabled:
            self._interactsh = InteractshClient(
                server=ssrf_cfg.interactsh_server,
                poll_interval=3.0,
            )
            oob_available = await self._interactsh.start()
            if not oob_available:
                logger.warning(
                    "[scan] interactsh not available – OOB detection disabled"
                )

            self._ssrf_scanner = SSRFScanner(
                scope_validator=self.scope,
                interactsh=self._interactsh,
                concurrent=ssrf_cfg.concurrent,
                timeout=ssrf_cfg.timeout,
                oob_wait=ssrf_cfg.oob_wait_seconds,
                verify_findings=ssrf_cfg.verify_findings,
            )

            if self.config.vuln.post_ssrf:
                self._post_ssrf_scanner = PostSSRFScanner(
                    scope_validator=self.scope,
                    interactsh=self._interactsh,
                    concurrent=ssrf_cfg.concurrent,
                    timeout=ssrf_cfg.timeout,
                    oob_wait=ssrf_cfg.oob_wait_seconds,
                )

            try:
                # Phase 6: SSRF GET parameters
                ssrf_candidates = self._build_ssrf_candidates(param_map)
                logger.info("[scan] SSRF GET: testing %d candidates", len(ssrf_candidates))
                ssrf_findings = await self._ssrf_scanner.scan_candidates(ssrf_candidates)
                logger.info("[scan] SSRF GET: %d findings", len(ssrf_findings))
                for sf in ssrf_findings:
                    all_findings.append(self._ssrf_to_finding_dict(sf))
                result.ssrf_findings += len(ssrf_findings)
                await notify("ssrf_get_done", len(ssrf_findings))

                # Phase 7: SSRF POST/JSON body
                if self._post_ssrf_scanner:
                    logger.info(
                        "[scan] SSRF POST: testing %d endpoints", len(target_urls)
                    )
                    try:
                        post_ssrf_findings = await self._post_ssrf_scanner.scan_post_endpoints(
                            target_urls[:50]  # cap at 50 hosts
                        )
                        logger.info("[scan] SSRF POST: %d findings", len(post_ssrf_findings))
                        for sf in post_ssrf_findings:
                            all_findings.append(self._ssrf_to_finding_dict(sf))
                        result.ssrf_findings += len(post_ssrf_findings)
                        await notify("ssrf_post_done", len(post_ssrf_findings))
                    except Exception as exc:
                        logger.warning("[scan] POST SSRF scanner error: %s", exc)

                # Phase 8: HTTP header injection SSRF
                if self._header:
                    logger.info(
                        "[scan] Header injection: testing %d hosts", len(target_urls)
                    )
                    try:
                        header_findings = await self._header.scan_hosts(
                            target_urls,
                            self._interactsh,
                        )
                        logger.info(
                            "[scan] Header injection: %d findings", len(header_findings)
                        )
                        for hf in header_findings:
                            all_findings.append(self._header_to_finding_dict(hf))
                        result.header_ssrf_findings = len(header_findings)
                        await notify("header_ssrf_done", len(header_findings))
                    except Exception as exc:
                        logger.warning("[scan] Header injection scanner error: %s", exc)

            finally:
                await self._interactsh.stop()

        # ---------------------------------------------------------------
        # Phase 9: Open redirect detection
        # ---------------------------------------------------------------
        await notify("redirect_start")
        if self._redirect and all_urls:
            urls_for_redirect = [u for u in all_urls if self.scope.is_in_scope(u)]
            logger.info(
                "[scan] Open redirect: testing %d URLs", len(urls_for_redirect)
            )
            try:
                redirect_findings = await self._redirect.scan_urls(
                    urls_for_redirect[:200]
                )
                logger.info("[scan] Open redirect: %d findings", len(redirect_findings))
                for rf in redirect_findings:
                    all_findings.append(self._redirect_to_finding_dict(rf))
                result.redirect_findings = len(redirect_findings)
                await notify("redirect_done", len(redirect_findings))
            except Exception as exc:
                logger.warning("[scan] Open redirect scanner error: %s", exc)

        # ---------------------------------------------------------------
        # Phase 10: XSS scanning (reflection + dalfox)
        # ---------------------------------------------------------------
        await notify("xss_start")
        xss_cfg = self.config.vuln.xss

        if xss_cfg.enabled:
            urls_with_params = [
                u for u in all_urls
                if "?" in u and self.scope.is_in_scope(u)
            ]
            logger.info("[scan] XSS: %d URLs with query params", len(urls_with_params))
            xss_results: list = []

            # Reflection-based XSS
            if xss_cfg.reflection_scanner_enabled and urls_with_params:
                try:
                    reflected = await self._xss_reflection.scan_urls(
                        urls_with_params[:100]
                    )
                    xss_results.extend(reflected)
                    logger.info("[scan] Reflection XSS: %d findings", len(reflected))
                except Exception as exc:
                    logger.warning("[scan] Reflection XSS scanner error: %s", exc)

            # Dalfox
            if xss_cfg.dalfox_enabled and urls_with_params:
                try:
                    dalfox_results = await self._dalfox.scan(
                        urls=urls_with_params[:200],
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
        # Phase 11: Persist all findings
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
            for p in classified["ssrf"]:
                key = (base_url, p.lower())
                if key not in seen:
                    seen.add(key)
                    candidates.append(SSRFCandidate(url=base_url, param=p))
            parsed = urlparse(base_url)
            path_lower = parsed.path.lower()
            is_interesting = any(
                kw in path_lower for kw in [
                    "api", "proxy", "fetch", "request", "load", "open", "download",
                    "redirect", "export", "import", "webhook", "notify",
                ]
            )
            if is_interesting:
                for p in classified["other"][:5]:
                    key = (base_url, p.lower())
                    if key not in seen:
                        seen.add(key)
                        candidates.append(SSRFCandidate(url=base_url, param=p))

        from bugbounty.tools.ssrf import SSRF_PARAMS
        base_urls_set = set(param_map.keys())
        for base_url in list(base_urls_set)[:50]:
            if not self.scope.is_in_scope(base_url):
                continue
            for p in SSRF_PARAMS[:15]:
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

    # ------------------------------------------------------------------
    # Finding dict converters
    # ------------------------------------------------------------------

    @staticmethod
    def _ssrf_to_finding_dict(sf) -> dict:
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

    @staticmethod
    def _cors_to_finding_dict(cf) -> dict:
        severity_to_cvss = {
            "critical": 8.8,
            "high": 6.5,
            "medium": 5.4,
            "low": 3.1,
        }
        return {
            "template_id": f"cors-{cf.bypass_type}",
            "name": f"CORS Misconfiguration ({cf.bypass_type})",
            "severity": cf.severity,
            "host": cf.url,
            "matched_at": cf.url,
            "description": (
                f"CORS misconfiguration detected. Bypass type: {cf.bypass_type}. "
                f"Origin tested: {cf.origin_tested}. "
                f"Access-Control-Allow-Origin: {cf.acao_header}. "
                f"Access-Control-Allow-Credentials: {cf.acac_header}. "
                f"Exploitability: {cf.exploitability}"
            ),
            "tags": ["cors", "misconfiguration", cf.bypass_type, "CWE-942"],
            "cvss_score": severity_to_cvss.get(cf.severity, 5.4),
            "cve_id": None,
            "raw": cf.to_dict(),
            "source": "cors-scanner",
            "confidence": cf.confidence,
            "bypass_type": cf.bypass_type,
        }

    @staticmethod
    def _redirect_to_finding_dict(rf) -> dict:
        # Raise CVSS for OAuth chains
        cvss = 8.0 if rf.chaining_potential in ("oauth", "ssrf") else 6.1
        severity = "high" if rf.chaining_potential in ("oauth", "ssrf") else "medium"
        return {
            "template_id": "open-redirect",
            "name": "Open Redirect",
            "severity": severity,
            "host": rf.url,
            "matched_at": rf.url,
            "description": (
                f"Open redirect via parameter '{rf.param}'. "
                f"Payload '{rf.payload}' redirected to '{rf.final_url}'. "
                f"Chaining potential: {rf.chaining_potential}. "
                f"Evidence: {rf.evidence}"
            ),
            "tags": ["redirect", "open-redirect", "CWE-601", rf.chaining_potential],
            "cvss_score": cvss,
            "cve_id": None,
            "raw": rf.to_dict(),
            "source": "redirect-scanner",
            "confidence": rf.confidence,
            "chaining_potential": rf.chaining_potential,
        }

    @staticmethod
    def _takeover_to_finding_dict(tf) -> dict:
        return {
            "template_id": f"subdomain-takeover-{tf.service}",
            "name": f"Subdomain Takeover ({tf.service})",
            "severity": tf.severity,
            "host": tf.subdomain,
            "matched_at": tf.subdomain,
            "description": (
                f"Subdomain '{tf.subdomain}' has a dangling CNAME to '{tf.cname}' "
                f"(service: {tf.service}). "
                f"The subdomain appears unclaimed and may be registerable by an attacker. "
                f"Evidence: {tf.evidence}"
            ),
            "tags": ["subdomain-takeover", "takeover", tf.service, "CWE-284"],
            "cvss_score": 8.1,
            "cve_id": None,
            "raw": tf.to_dict(),
            "source": "takeover-scanner",
            "confidence": tf.confidence,
        }

    @staticmethod
    def _exposure_to_finding_dict(ef) -> dict:
        # CVSS scores by category
        cvss_map = {
            "env": 9.1,
            "git": 8.5,
            "spring_actuator": 7.5 if "heapdump" in ef.path else 5.3,
            "api_docs": 5.3,
            "graphql": 5.3,
            "debug": 5.3,
            "backup": 9.1,
            "admin": 6.5,
        }
        category_names = {
            "env": "Exposed Environment File",
            "git": "Exposed Git Repository",
            "spring_actuator": "Exposed Spring Boot Actuator",
            "api_docs": "Exposed API Documentation",
            "graphql": "GraphQL Introspection Enabled",
            "debug": "Debug Endpoint Exposed",
            "backup": "Exposed Backup File",
            "admin": "Exposed Admin Panel",
        }
        name = category_names.get(ef.category, f"Exposed Sensitive Path ({ef.category})")
        cvss = cvss_map.get(ef.category, 5.3)
        if ef.category == "spring_actuator" and "heapdump" in ef.path:
            cvss = 7.5
        cwe_map = {
            "git": "CWE-538",
            "env": "CWE-312",
            "spring_actuator": "CWE-215",
            "api_docs": "CWE-200",
            "graphql": "CWE-200",
            "debug": "CWE-215",
            "backup": "CWE-312",
            "admin": "CWE-200",
        }
        cwe = cwe_map.get(ef.category, "CWE-200")
        return {
            "template_id": f"exposure-{ef.category}-{ef.path.strip('/').replace('/', '-')}",
            "name": name,
            "severity": ef.severity,
            "host": ef.url,
            "matched_at": ef.url,
            "description": (
                f"{name} detected at '{ef.url}' (HTTP {ef.status_code}). "
                f"Category: {ef.category}. Evidence: {ef.evidence} "
                f"Content preview: {ef.content_preview[:100]}"
            ),
            "tags": ["exposure", "disclosure", ef.category, cwe],
            "cvss_score": cvss,
            "cve_id": None,
            "raw": ef.to_dict(),
            "source": "exposure-scanner",
            "confidence": ef.confidence,
        }

    @staticmethod
    def _js_to_finding_dict(jf) -> dict:
        severity_to_cvss = {
            "critical": 9.0,
            "high": 7.5,
            "medium": 5.3,
            "low": 3.1,
            "info": 0.0,
        }
        return {
            "template_id": f"js-secret-{jf.secret_type}",
            "name": f"Hardcoded Secret in JavaScript ({jf.secret_type})",
            "severity": jf.severity,
            "host": jf.js_url,
            "matched_at": jf.js_url,
            "description": (
                f"A hardcoded secret of type '{jf.secret_type}' was detected in the "
                f"JavaScript file at '{jf.js_url}'. "
                f"Truncated match: {jf.match}. "
                "Hardcoded secrets in client-accessible JavaScript files allow any user "
                "to extract and abuse them."
            ),
            "tags": ["secret", "exposure", "js", jf.secret_type, "CWE-312"],
            "cvss_score": severity_to_cvss.get(jf.severity, 5.3),
            "cve_id": None,
            "raw": jf.to_dict(),
            "source": "js-scanner",
            "confidence": jf.confidence,
        }

    @staticmethod
    def _header_to_finding_dict(hf) -> dict:
        confidence_severity = {
            "confirmed": "high",
            "medium": "medium",
        }
        return {
            "template_id": f"header-ssrf-{hf.header.lower().replace('-', '_')}",
            "name": f"HTTP Header Injection SSRF ({hf.header})",
            "severity": confidence_severity.get(hf.confidence, "medium"),
            "host": hf.url,
            "matched_at": hf.url,
            "description": (
                f"SSRF via HTTP header injection detected. "
                f"Header: '{hf.header}'. Payload: '{hf.payload}'. "
                f"Evidence type: {hf.evidence_type}. "
                f"Evidence: {hf.evidence}"
            ),
            "tags": ["ssrf", "header-injection", "CWE-918", hf.header.lower()],
            "cvss_score": 8.6 if hf.confidence == "confirmed" else 5.3,
            "cve_id": None,
            "raw": hf.to_dict(),
            "source": "header-injection-scanner",
            "confidence": hf.confidence,
            "evidence_type": hf.evidence_type,
        }
