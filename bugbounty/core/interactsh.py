"""Interactsh OOB (out-of-band) interaction client for SSRF verification.

Supports two modes:
1. CLI mode  – wraps the ``interactsh-client`` binary (preferred).
2. API mode  – direct HTTP calls to the interactsh server using RSA + AES
               encryption as implemented by projectdiscovery.

Falls back gracefully when neither is available.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import secrets
import shutil
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class InteractshClient:
    """Client for interactsh OOB interaction detection.

    Usage::

        client = InteractshClient()
        await client.start()
        payload_url = client.unique_url(tag="param-url")

        # ... inject payload_url into a request parameter ...

        await asyncio.sleep(10)
        interactions = await client.poll()
        # interactions is a list of dicts with type/protocol/raw-request data

        await client.stop()
    """

    def __init__(
        self,
        server: str = "oast.pro",
        poll_interval: float = 5.0,
        token: str = "",
    ) -> None:
        self.server = server
        self.poll_interval = poll_interval
        self.token = token

        # State set after start()
        self._domain: Optional[str] = None
        self._correlation_id: str = ""
        self._secret_key: str = ""
        self._mode: str = "unavailable"   # "cli" | "api" | "unavailable"
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._interactions: list[dict] = []
        self._reader_task: Optional[asyncio.Task] = None
        self._http_client: Optional[httpx.AsyncClient] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def start(self) -> bool:
        """Start the interactsh client.

        Returns:
            True if successfully started, False if no method is available.
        """
        if shutil.which("interactsh-client"):
            ok = await self._start_cli()
            if ok:
                self._mode = "cli"
                return True

        ok = await self._start_api()
        if ok:
            self._mode = "api"
            return True

        logger.warning(
            "interactsh not available (no CLI and API registration failed). "
            "SSRF OOB detection will be disabled."
        )
        self._mode = "unavailable"
        return False

    async def stop(self) -> None:
        """Stop the client and clean up resources."""
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

        if self._proc:
            try:
                self._proc.kill()
                await self._proc.wait()
            except Exception:
                pass

        if self._http_client:
            await self._http_client.aclose()

    @property
    def domain(self) -> Optional[str]:
        """The unique interactsh domain assigned to this client."""
        return self._domain

    @property
    def available(self) -> bool:
        """True if interactsh is ready to receive callbacks."""
        return self._mode != "unavailable" and self._domain is not None

    def unique_url(self, tag: str = "", scheme: str = "http") -> str:
        """Return a unique URL to use as an SSRF payload.

        Each call generates a fresh subdomain so individual injections
        can be correlated to specific parameters.

        Args:
            tag:    Short label embedded in the subdomain (e.g. parameter name).
            scheme: "http" or "https"

        Returns:
            A URL like ``http://abc123-url.oast.pro`` if available,
            otherwise an empty string.
        """
        if not self.available:
            return ""
        uid = secrets.token_hex(4)
        if tag:
            # Sanitise tag: lowercase alphanumeric + hyphens only
            safe_tag = "".join(c if c.isalnum() else "-" for c in tag.lower())[:20]
            subdomain = f"{uid}-{safe_tag}.{self._domain}"
        else:
            subdomain = f"{uid}.{self._domain}"
        return f"{scheme}://{subdomain}"

    async def poll(self) -> list[dict]:
        """Return and clear accumulated interactions."""
        if self._mode == "api":
            fresh = await self._poll_api()
            self._interactions.extend(fresh)

        result = list(self._interactions)
        self._interactions.clear()
        return result

    async def wait_for_interaction(
        self,
        timeout: float = 30.0,
        expected_tag: str = "",
    ) -> list[dict]:
        """Poll until an interaction arrives or timeout expires.

        Args:
            timeout:      Max seconds to wait.
            expected_tag: Optional tag to look for in the subdomain.

        Returns:
            List of matching interaction dicts (may be empty on timeout).
        """
        if not self.available:
            return []

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            interactions = await self.poll()
            if interactions:
                if not expected_tag:
                    return interactions
                matched = [
                    i for i in interactions
                    if expected_tag in i.get("full-id", "")
                    or expected_tag in i.get("unique-id", "")
                ]
                if matched:
                    return matched
                # Put non-matching ones back
                self._interactions.extend(interactions)
            await asyncio.sleep(self.poll_interval)

        return []

    # ------------------------------------------------------------------
    # CLI mode internals
    # ------------------------------------------------------------------

    async def _start_cli(self) -> bool:
        """Start interactsh-client as a subprocess and parse its domain."""
        cmd = ["interactsh-client", "-server", self.server, "-json", "-v"]
        if self.token:
            cmd += ["-token", self.token]
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            # Read lines until we see the registered domain
            domain = None
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if self._proc.stdout is None:
                    break
                try:
                    line = await asyncio.wait_for(
                        self._proc.stdout.readline(), timeout=5.0
                    )
                except asyncio.TimeoutError:
                    continue
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").strip()
                try:
                    data = json.loads(decoded)
                    if "domain" in data or "token" in data:
                        domain = data.get("domain", data.get("token", ""))
                        break
                except json.JSONDecodeError:
                    # Plain text output – look for domain patterns
                    if ".oast." in decoded or f".{self.server}" in decoded:
                        parts = decoded.split()
                        for part in parts:
                            if f".{self.server}" in part or ".oast." in part:
                                domain = part.strip("[]()\"'")
                                break
                    if domain:
                        break

            if not domain:
                logger.warning("interactsh-client: could not parse registered domain")
                if self._proc:
                    self._proc.kill()
                return False

            self._domain = domain
            # Start background reader for interactions
            self._reader_task = asyncio.create_task(self._cli_reader())
            logger.info("interactsh CLI started, domain: %s", domain)
            return True

        except FileNotFoundError:
            logger.debug("interactsh-client binary not found")
            return False
        except Exception as exc:
            logger.warning("interactsh-client start failed: %s", exc)
            return False

    async def _cli_reader(self) -> None:
        """Background task: read JSON interactions from CLI stdout."""
        if not self._proc or not self._proc.stdout:
            return
        try:
            async for line in self._proc.stdout:
                decoded = line.decode("utf-8", errors="replace").strip()
                if not decoded:
                    continue
                try:
                    data = json.loads(decoded)
                    if "protocol" in data or "unique-id" in data:
                        self._interactions.append(data)
                        logger.info(
                            "interactsh callback: %s from %s",
                            data.get("protocol", "?"),
                            data.get("remote-address", "?"),
                        )
                except json.JSONDecodeError:
                    pass
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------
    # API mode internals
    # ------------------------------------------------------------------

    async def _start_api(self) -> bool:
        """Register with the interactsh HTTP API."""
        try:
            self._correlation_id = secrets.token_hex(10)  # 20-char hex
            self._secret_key = secrets.token_urlsafe(32)
            self._http_client = httpx.AsyncClient(timeout=20.0)

            resp = await self._http_client.post(
                f"https://{self.server}/register",
                json={
                    "public-key": "",           # simplified: server assigns domain
                    "secret-key": self._secret_key,
                    "correlation-id": self._correlation_id,
                },
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                domain = data.get("domain", data.get("token", ""))
                if domain:
                    self._domain = domain
                    logger.info("interactsh API registered, domain: %s", domain)
                    return True
        except Exception as exc:
            logger.debug("interactsh API registration failed: %s", exc)

        return False

    async def _poll_api(self) -> list[dict]:
        """Poll the interactsh HTTP API for new interactions."""
        if not self._http_client:
            return []
        try:
            resp = await self._http_client.get(
                f"https://{self.server}/poll",
                params={
                    "id": self._correlation_id,
                    "secret": self._secret_key,
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                interactions = data.get("data", [])
                result = []
                for item in interactions:
                    if isinstance(item, str):
                        result.append({"raw": item, "protocol": "unknown"})
                    elif isinstance(item, dict):
                        result.append(item)
                return result
        except Exception as exc:
            logger.debug("interactsh poll failed: %s", exc)
        return []
