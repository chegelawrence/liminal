"""Adaptive anomaly-based HTTP probe and divergence scorer.

This module implements Gate 1 of the three-gate vulnerability detection pipeline:
  - Sends ~20 targeted HTTP variations per host
  - Scores divergence from the baseline GET response
  - Only high-divergence cases (score >= threshold) are passed to the LLM

No vulnerability classifications are made here. The prober only detects
HTTP-level behavioural anomalies.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlunparse

import httpx

logger = logging.getLogger(__name__)

# Internal IP patterns for divergence scoring
_INTERNAL_IP_RE = re.compile(
    r'(?:10\.\d+\.\d+\.\d+'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+'
    r'|192\.168\.\d+\.\d+'
    r'|169\.254\.169\.254)'
)

# Server-side error / information-disclosure keywords
_ERROR_KEYWORDS = (
    "exception", "traceback", "stack trace", "stack_trace",
    "ORA-", "SQLSTATE", "mysql_fetch", "pg_query", "syntax error",
    "java.lang.", "at com.", "at org.", "NullPointerException",
    "RuntimeException", "PHP Fatal error", "Warning: ", "Notice: ",
)

# Credential-leak patterns
_CRED_RE = re.compile(
    r'(?:password\s*=|api_key\s*=|secret\s*=|Bearer\s+[A-Za-z0-9\-._~+/]+=*)',
    re.IGNORECASE,
)

# Debug / trace response headers that signal internal exposure
_DEBUG_HEADERS: frozenset[str] = frozenset({
    "x-debug",
    "x-internal",
    "x-debug-token",
    "x-powered-by-debug",
    "x-request-id",
    "x-trace-id",
    "x-amzn-trace-id",
    "x-b3-traceid",
    "server-timing",
    "x-cache-debug",
})


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ResponseSummary:
    """Normalised summary of a single HTTP response."""

    status_code: int
    body: str           # truncated to 4 000 chars
    headers: dict[str, str]
    elapsed_ms: float
    content_type: str


@dataclass
class AnomalyProbe:
    """One HTTP probe variation sent against a target URL."""

    name: str           # e.g. "x-forwarded-for-127", "trace-method"
    probe_type: str     # "method" | "header" | "path" | "param"
    method: str         # HTTP method overriding the baseline GET
    extra_headers: dict[str, str] = field(default_factory=dict)
    path_suffix: str = ""           # appended to the URL path as-is
    extra_params: dict[str, str] = field(default_factory=dict)
    body_override: Optional[str] = None   # None → no body


@dataclass
class AnomalyResult:
    """A probe result whose divergence score exceeded the configured threshold."""

    url: str
    probe: AnomalyProbe
    baseline: ResponseSummary
    probe_response: ResponseSummary
    divergence_score: int
    divergence_reasons: list[str]


# ---------------------------------------------------------------------------
# Probe list
# ---------------------------------------------------------------------------

def _build_probes() -> list[AnomalyProbe]:
    """Return the standard set of ~20 HTTP anomaly probes."""
    probes: list[AnomalyProbe] = []

    # ── Method confusion (5) ──────────────────────────────────────────
    probes.append(AnomalyProbe(
        name="trace-method",
        probe_type="method",
        method="TRACE",
    ))
    probes.append(AnomalyProbe(
        name="put-empty",
        probe_type="method",
        method="PUT",
        body_override="",
    ))
    probes.append(AnomalyProbe(
        name="delete-method",
        probe_type="method",
        method="DELETE",
    ))
    probes.append(AnomalyProbe(
        name="patch-method",
        probe_type="method",
        method="PATCH",
    ))
    probes.append(AnomalyProbe(
        name="method-override-delete",
        probe_type="method",
        method="GET",
        extra_headers={"X-HTTP-Method-Override": "DELETE"},
    ))

    # ── Header injection (8) ──────────────────────────────────────────
    probes.append(AnomalyProbe(
        name="x-forwarded-for-127",
        probe_type="header",
        method="GET",
        extra_headers={"X-Forwarded-For": "127.0.0.1"},
    ))
    probes.append(AnomalyProbe(
        name="x-forwarded-for-imds",
        probe_type="header",
        method="GET",
        extra_headers={"X-Forwarded-For": "169.254.169.254"},
    ))
    probes.append(AnomalyProbe(
        name="x-forwarded-host-evil",
        probe_type="header",
        method="GET",
        extra_headers={"X-Forwarded-Host": "evil.com"},
    ))
    probes.append(AnomalyProbe(
        name="x-original-url-admin",
        probe_type="header",
        method="GET",
        extra_headers={"X-Original-URL": "/admin"},
    ))
    probes.append(AnomalyProbe(
        name="x-rewrite-url-admin",
        probe_type="header",
        method="GET",
        extra_headers={"X-Rewrite-URL": "/admin"},
    ))
    probes.append(AnomalyProbe(
        name="xxe-content-type",
        probe_type="header",
        method="POST",
        extra_headers={"Content-Type": "application/xml"},
        body_override=(
            '<?xml version="1.0"?>'
            '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<x>&xxe;</x>'
        ),
    ))
    probes.append(AnomalyProbe(
        name="accept-xml",
        probe_type="header",
        method="GET",
        extra_headers={"Accept": "application/xml"},
    ))
    probes.append(AnomalyProbe(
        name="accept-html",
        probe_type="header",
        method="GET",
        extra_headers={"Accept": "text/html"},
    ))

    # ── Parameter / path injection (7) ───────────────────────────────
    probes.append(AnomalyProbe(
        name="debug-param",
        probe_type="param",
        method="GET",
        extra_params={"debug": "true"},
    ))
    probes.append(AnomalyProbe(
        name="format-xml-param",
        probe_type="param",
        method="GET",
        extra_params={"format": "xml"},
    ))
    probes.append(AnomalyProbe(
        name="jsonp-callback",
        probe_type="param",
        method="GET",
        extra_params={"callback": "x"},
    ))
    probes.append(AnomalyProbe(
        name="admin-param",
        probe_type="param",
        method="GET",
        extra_params={"admin": "true"},
    ))
    probes.append(AnomalyProbe(
        name="path-traversal",
        probe_type="path",
        method="GET",
        path_suffix="%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",
    ))
    probes.append(AnomalyProbe(
        name="null-byte",
        probe_type="path",
        method="GET",
        path_suffix="%00.html",
    ))
    probes.append(AnomalyProbe(
        name="overflow-param",
        probe_type="param",
        method="GET",
        extra_params={"x": "A" * 2000},
    ))

    return probes


# Module-level probe list — built once at import time
_PROBE_LIST: list[AnomalyProbe] = _build_probes()


# ---------------------------------------------------------------------------
# AnomalyProber
# ---------------------------------------------------------------------------

class AnomalyProber:
    """Sends HTTP probe variations and scores divergence from the baseline.

    Only anomalies with ``divergence_score >= score_threshold`` are returned.
    The prober intentionally does NOT classify vulnerability types — that is
    the responsibility of the downstream LLM agent.
    """

    def __init__(
        self,
        scope,
        rate_limiter,
        concurrent: int = 5,
        timeout: float = 10.0,
        score_threshold: int = 5,
        max_hosts: int = 50,
    ) -> None:
        self.scope = scope
        self.rate_limiter = rate_limiter
        self.concurrent = concurrent
        self.timeout = timeout
        self.score_threshold = score_threshold
        self.max_hosts = max_hosts
        self._semaphore = asyncio.Semaphore(concurrent)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    async def probe_hosts(self, urls: list[str]) -> list[AnomalyResult]:
        """Probe multiple hosts; return only high-divergence anomalies.

        Deduplicates to one representative URL per eTLD+1 and caps at
        ``max_hosts`` to keep cost predictable.
        """
        seen_etld: set[str] = set()
        deduped: list[str] = []
        for url in urls:
            try:
                etld = self._etld1(urlparse(url).netloc)
                if etld not in seen_etld:
                    seen_etld.add(etld)
                    deduped.append(url)
            except Exception:
                if url not in deduped:
                    deduped.append(url)

        capped = deduped[: self.max_hosts]
        logger.info(
            "[anomaly] Probing %d hosts (deduped from %d, threshold=%d)",
            len(capped),
            len(urls),
            self.score_threshold,
        )

        results_nested = await asyncio.gather(
            *[self.probe_url(u) for u in capped],
            return_exceptions=True,
        )

        all_results: list[AnomalyResult] = []
        for item in results_nested:
            if isinstance(item, Exception):
                logger.debug("[anomaly] probe_hosts gather error: %s", item)
            elif isinstance(item, list):
                all_results.extend(item)

        logger.info("[anomaly] %d high-divergence anomalies found", len(all_results))
        return all_results

    async def probe_url(self, url: str) -> list[AnomalyResult]:
        """Baseline GET + all probe variants for a single URL.

        Returns only results with ``divergence_score >= score_threshold``.
        """
        async with self._semaphore:
            try:
                baseline = await self._request(url, "GET", {}, {}, None, self.timeout)
            except Exception as exc:
                logger.debug("[anomaly] Baseline failed for %s: %s", url, exc)
                return []

            inner_sem = asyncio.Semaphore(5)

            async def _run_probe(probe: AnomalyProbe) -> Optional[AnomalyResult]:
                async with inner_sem:
                    try:
                        probe_url = self._apply_path_suffix(url, probe.path_suffix)
                        resp = await self._request(
                            probe_url,
                            probe.method,
                            probe.extra_headers,
                            probe.extra_params,
                            probe.body_override,
                            self.timeout,
                        )
                        score, reasons = self._compute_divergence(baseline, resp)
                        if score >= self.score_threshold:
                            return AnomalyResult(
                                url=url,
                                probe=probe,
                                baseline=baseline,
                                probe_response=resp,
                                divergence_score=score,
                                divergence_reasons=reasons,
                            )
                    except Exception as exc:
                        logger.debug(
                            "[anomaly] Probe '%s' failed on %s: %s",
                            probe.name, url, exc,
                        )
                return None

            raw = await asyncio.gather(
                *[_run_probe(p) for p in _PROBE_LIST],
                return_exceptions=True,
            )
            return [r for r in raw if isinstance(r, AnomalyResult)]

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    async def _request(
        self,
        url: str,
        method: str,
        headers: dict[str, str],
        params: dict[str, str],
        body: Optional[str],
        timeout: float,
    ) -> ResponseSummary:
        """Execute one HTTP request and return a normalised ResponseSummary."""
        async with httpx.AsyncClient(
            follow_redirects=False,
            verify=False,
            timeout=timeout,
        ) as client:
            kwargs: dict = {"headers": headers, "params": params}
            if body is not None:
                kwargs["content"] = body.encode("utf-8", errors="replace")

            resp = await client.request(method, url, **kwargs)
            elapsed_ms = (
                resp.elapsed.total_seconds() * 1000 if resp.elapsed else 0.0
            )
            return ResponseSummary(
                status_code=resp.status_code,
                body=resp.text[:4000] if resp.text else "",
                headers=dict(resp.headers),
                elapsed_ms=elapsed_ms,
                content_type=resp.headers.get("content-type", ""),
            )

    # ------------------------------------------------------------------
    # Divergence scoring
    # ------------------------------------------------------------------

    def _compute_divergence(
        self,
        baseline: ResponseSummary,
        probe_resp: ResponseSummary,
    ) -> tuple[int, list[str]]:
        """Score the response divergence; return (score, reasons)."""
        score = 0
        reasons: list[str] = []

        # Status code changes
        base_2xx = 200 <= baseline.status_code < 300
        probe_2xx = 200 <= probe_resp.status_code < 300
        if base_2xx != probe_2xx:
            score += 5
            reasons.append(
                f"Status flip: {baseline.status_code} → {probe_resp.status_code}"
            )
        elif baseline.status_code != probe_resp.status_code:
            score += 3
            reasons.append(
                f"Status changed: {baseline.status_code} → {probe_resp.status_code}"
            )

        # Error keywords
        body_lower = probe_resp.body.lower()
        for kw in _ERROR_KEYWORDS:
            if kw.lower() in body_lower:
                score += 4
                reasons.append(f"Error keyword in body: '{kw}'")
                break  # count at most once per probe

        # Internal IP disclosure
        if _INTERNAL_IP_RE.search(probe_resp.body):
            score += 4
            reasons.append("Internal IP in response body")

        # Credential pattern
        if _CRED_RE.search(probe_resp.body):
            score += 4
            reasons.append("Credential pattern in response body")

        # Body length delta
        base_len = len(baseline.body)
        probe_len = len(probe_resp.body)
        if base_len > 0:
            delta_ratio = abs(probe_len - base_len) / base_len
            if delta_ratio > 0.5:
                score += 3
                reasons.append(
                    f"Body length delta >50%: {base_len} → {probe_len} chars"
                )
            elif delta_ratio > 0.2:
                score += 1
                reasons.append(
                    f"Body length delta >20%: {base_len} → {probe_len} chars"
                )
        elif probe_len > 100:
            score += 3
            reasons.append(
                f"Non-empty probe response vs empty baseline: {probe_len} chars"
            )

        # Response time delta
        if baseline.elapsed_ms > 0:
            ratio = probe_resp.elapsed_ms / baseline.elapsed_ms
            if ratio > 5:
                score += 3
                reasons.append(
                    f"Elapsed >5× baseline: "
                    f"{probe_resp.elapsed_ms:.0f}ms vs {baseline.elapsed_ms:.0f}ms"
                )
            elif ratio > 2:
                score += 1
                reasons.append(
                    f"Elapsed >2× baseline: "
                    f"{probe_resp.elapsed_ms:.0f}ms vs {baseline.elapsed_ms:.0f}ms"
                )

        # Content-Type changed
        if baseline.content_type != probe_resp.content_type:
            score += 1
            reasons.append(
                f"Content-Type changed: "
                f"'{baseline.content_type}' → '{probe_resp.content_type}'"
            )

        # New debug/internal response headers
        probe_hdr_names = {h.lower() for h in probe_resp.headers}
        base_hdr_names = {h.lower() for h in baseline.headers}
        new_debug = (probe_hdr_names & _DEBUG_HEADERS) - base_hdr_names
        if new_debug:
            score += 2
            reasons.append(f"Debug headers appeared: {sorted(new_debug)}")

        return score, reasons

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _etld1(netloc: str) -> str:
        """Best-effort eTLD+1: strip port then keep last two labels."""
        host = netloc.split(":")[0]
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

    @staticmethod
    def _apply_path_suffix(url: str, suffix: str) -> str:
        """Append *suffix* to the URL path component."""
        if not suffix:
            return url
        parsed = urlparse(url)
        new_path = parsed.path.rstrip("/") + suffix
        return urlunparse(parsed._replace(path=new_path))
