"""Subdomain takeover detection tool.

Strategy:
1. Resolve CNAME chain for each subdomain using dnspython.
2. Check if any CNAME target matches a known cloud/SaaS service.
3. Fetch the subdomain HTTP response and check body for takeover fingerprints.
4. Report with service name, CNAME, and evidence.

Falls back to subprocess `dig` if dnspython is unavailable.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from typing import Optional

import httpx

from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import ScopeValidator

logger = logging.getLogger(__name__)

# Fingerprints: service name → list of response body strings indicating unclaimed
TAKEOVER_FINGERPRINTS: dict[str, list[str]] = {
    "github-pages": ["There isn't a GitHub Pages site here", "404"],
    "heroku": ["No such app", "herokucdn.com"],
    "shopify": ["Sorry, this shop is currently unavailable"],
    "tumblr": ["Whatever you were looking for doesn't live here"],
    "wordpress": ["Do you want to register"],
    "fastly": ["Fastly error: unknown domain"],
    "pantheon": ["404 error unknown site"],
    "azure": ["404 Web Site not found"],
    "amazonaws": ["NoSuchBucket", "The specified bucket does not exist"],
    "cargo": ["If you're moving your domain away from Cargo"],
    "statuspage": ["You are being redirected"],
    "surge": ["project not found"],
    "unbounce": ["The requested URL was not found"],
    "helpjuice": ["We could not find what you're looking for"],
    "helpscout": ["No settings were found for this company"],
    "ghost": ["The thing you were looking for is no longer here"],
    "feedpress": ["The feed has not been found"],
    "readme": ["Project doesnt exist"],
    "intercom": ["This page is reserved for artistic works"],
    "zendesk": ["Help Center Closed"],
    "netlify": ["Not Found - Request ID"],
}

# Mapping of CNAME target substrings to service names
_CNAME_SERVICE_MAP: dict[str, str] = {
    "github.io": "github-pages",
    "githubusercontent.com": "github-pages",
    "heroku.com": "heroku",
    "herokucdn.com": "heroku",
    "myshopify.com": "shopify",
    "tumblr.com": "tumblr",
    "wordpress.com": "wordpress",
    "fastly.net": "fastly",
    "pantheonsite.io": "pantheon",
    "azurewebsites.net": "azure",
    "cloudapp.azure.com": "azure",
    "trafficmanager.net": "azure",
    "amazonaws.com": "amazonaws",
    "s3.amazonaws.com": "amazonaws",
    "cargocollective.com": "cargo",
    "statuspage.io": "statuspage",
    "surge.sh": "surge",
    "unbounce.com": "unbounce",
    "helpjuice.com": "helpjuice",
    "helpscout.net": "helpscout",
    "ghost.io": "ghost",
    "feedpress.me": "feedpress",
    "readme.io": "readme",
    "intercom.io": "intercom",
    "zendesk.com": "zendesk",
    "netlify.app": "netlify",
    "netlify.com": "netlify",
}


class TakeoverFinding:
    """A confirmed or high-confidence subdomain takeover finding."""

    def __init__(
        self,
        subdomain: str,
        cname: str,
        service: str,
        evidence: str,
        confidence: str,
        severity: str,  # always "high" or "critical"
    ) -> None:
        self.subdomain = subdomain
        self.cname = cname
        self.service = service
        self.evidence = evidence
        self.confidence = confidence
        self.severity = severity

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "cname": self.cname,
            "service": self.service,
            "evidence": self.evidence[:500],
            "confidence": self.confidence,
            "severity": self.severity,
        }


class TakeoverScanner:
    """Checks subdomains for dangling CNAME records (takeover potential).

    For each subdomain:
    1. Resolve CNAME chain using dnspython (or dig fallback).
    2. Check if any CNAME target matches a known cloud service.
    3. Fetch the subdomain and check response body for takeover fingerprints.
    4. Report with service name and evidence.
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        rate_limiter: Optional[RateLimiter] = None,
        concurrent: int = 20,
        timeout: float = 10.0,
    ) -> None:
        self.scope = scope_validator
        self.rate_limiter = rate_limiter
        self.concurrent = concurrent
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(concurrent)
        self._dnspython_available = self._check_dnspython()

    async def scan_subdomains(self, subdomains: list[str]) -> list[TakeoverFinding]:
        """Check a list of subdomains for takeover potential.

        Args:
            subdomains: List of subdomains (bare hostnames or full URLs).

        Returns:
            List of takeover findings.
        """
        # Normalise to bare hostnames
        normalised: list[str] = []
        for s in subdomains:
            if s.startswith("http://") or s.startswith("https://"):
                from urllib.parse import urlparse
                normalised.append(urlparse(s).netloc)
            else:
                normalised.append(s)

        # Filter to in-scope
        in_scope = [
            sd for sd in normalised
            if self.scope.is_in_scope(f"https://{sd}")
            or self.scope.is_in_scope(f"http://{sd}")
        ]

        logger.info(
            "Takeover scanner: checking %d subdomains", len(in_scope)
        )

        tasks = [
            asyncio.create_task(self._check_subdomain(sd))
            for sd in in_scope
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[TakeoverFinding] = []
        for r in results:
            if isinstance(r, Exception):
                logger.debug("Takeover check exception: %s", r)
                continue
            if r:
                findings.append(r)

        logger.info("Takeover scanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _check_subdomain(self, subdomain: str) -> Optional[TakeoverFinding]:
        async with self._semaphore:
            # Step 1: Resolve CNAME chain
            cname_targets = await self._resolve_cname_chain(subdomain)
            if not cname_targets:
                return None

            # Step 2: Match CNAME targets to known services
            service_name: Optional[str] = None
            matched_cname: str = ""
            for cname in cname_targets:
                for cname_suffix, svc in _CNAME_SERVICE_MAP.items():
                    if cname_suffix in cname.lower():
                        service_name = svc
                        matched_cname = cname
                        break
                if service_name:
                    break

            if not service_name:
                return None

            # Step 3: Fetch the subdomain and check for takeover fingerprints
            fingerprints = TAKEOVER_FINGERPRINTS.get(service_name, [])
            body = await self._fetch_body(subdomain)
            if body is None:
                return None

            matched_fingerprint: Optional[str] = None
            for fp in fingerprints:
                if fp.lower() in body.lower():
                    matched_fingerprint = fp
                    break

            if not matched_fingerprint:
                return None

            evidence = (
                f"CNAME '{subdomain}' → '{matched_cname}' (service: {service_name}). "
                f"Response body contains fingerprint: '{matched_fingerprint[:100]}'"
            )
            logger.info(
                "Subdomain takeover found: %s → %s (%s)",
                subdomain, matched_cname, service_name,
            )
            return TakeoverFinding(
                subdomain=subdomain,
                cname=matched_cname,
                service=service_name,
                evidence=evidence,
                confidence="confirmed",
                severity="high",
            )

    async def _resolve_cname_chain(self, subdomain: str) -> list[str]:
        """Resolve the full CNAME chain for a subdomain.

        Returns:
            List of CNAME targets in the chain (empty if no CNAME).
        """
        if self._dnspython_available:
            return await asyncio.get_event_loop().run_in_executor(
                None, self._resolve_cname_dnspython, subdomain
            )
        return await self._resolve_cname_dig(subdomain)

    @staticmethod
    def _resolve_cname_dnspython(subdomain: str) -> list[str]:
        """Resolve CNAME chain synchronously using dnspython."""
        try:
            import dns.resolver
            import dns.exception

            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            chain: list[str] = []
            current = subdomain

            for _ in range(10):  # limit chain depth
                try:
                    answers = resolver.resolve(current, "CNAME")
                    for rdata in answers:
                        target = str(rdata.target).rstrip(".")
                        chain.append(target)
                        current = target
                        break
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                        dns.exception.DNSException):
                    break
            return chain
        except ImportError:
            return []
        except Exception as exc:
            logger.debug("dnspython CNAME resolution failed for %s: %s", subdomain, exc)
            return []

    async def _resolve_cname_dig(self, subdomain: str) -> list[str]:
        """Resolve CNAME chain using subprocess dig as fallback."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["dig", "+short", "CNAME", subdomain],
                    capture_output=True,
                    text=True,
                    timeout=10,
                ),
            )
            if result.returncode != 0 or not result.stdout.strip():
                return []
            targets = [
                line.strip().rstrip(".")
                for line in result.stdout.splitlines()
                if line.strip()
            ]
            return targets
        except FileNotFoundError:
            logger.debug("dig not found in PATH")
            return []
        except Exception as exc:
            logger.debug("dig CNAME lookup failed for %s: %s", subdomain, exc)
            return []

    async def _fetch_body(self, subdomain: str) -> Optional[str]:
        """Fetch the HTTP/HTTPS response body from a subdomain."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=True,
                    verify=False,
                ) as client:
                    resp = await client.get(url)
                    return resp.text[:8192]
            except Exception:
                continue
        return None

    @staticmethod
    def _check_dnspython() -> bool:
        """Return True if dnspython is importable."""
        try:
            import dns.resolver  # noqa: F401
            return True
        except ImportError:
            logger.debug("dnspython not available; falling back to dig")
            return False
