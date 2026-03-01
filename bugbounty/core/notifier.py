"""Notification delivery for scan lifecycle events."""

from __future__ import annotations

import asyncio
import logging
import smtplib
from email.mime.text import MIMEText
from typing import Optional

import aiohttp

from bugbounty.core.config import NotificationsConfig

logger = logging.getLogger(__name__)


class Notifier:
    """Sends notifications to configured backends on scan lifecycle events.

    All delivery methods run in parallel and never raise — failures are
    logged but do not interrupt the scan.
    """

    def __init__(self, cfg: NotificationsConfig) -> None:
        self.cfg = cfg

    # ------------------------------------------------------------------
    # Public lifecycle methods
    # ------------------------------------------------------------------

    async def scan_started(self, domain: str, run_id: str) -> None:
        if not self.cfg.notify_on_start:
            return
        msg = f"*Scan started* — `{domain}`\nRun ID: `{run_id}`"
        await self._deliver(subject=f"[Liminal] Scan started: {domain}", body=msg)

    async def scan_complete(
        self,
        domain: str,
        run_id: str,
        duration_seconds: float,
        counts: dict[str, int],
        report_path: str,
    ) -> None:
        if not self.cfg.notify_on_complete:
            return
        minutes = int(duration_seconds // 60)
        seconds = int(duration_seconds % 60)
        duration_str = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"
        crit = counts.get("critical", 0)
        high = counts.get("high", 0)
        med = counts.get("medium", 0)
        low = counts.get("low", 0)
        msg = (
            f"*Scan complete* — `{domain}`\n"
            f"Duration: {duration_str}\n"
            f"Findings: Critical={crit}  High={high}  Medium={med}  Low={low}\n"
            f"Report: `{report_path}`"
        )
        await self._deliver(subject=f"[Liminal] Scan complete: {domain}", body=msg)

    async def scan_failed(self, domain: str, error: str) -> None:
        msg = f"*Scan FAILED* — `{domain}`\nError: {error}"
        await self._deliver(subject=f"[Liminal] Scan failed: {domain}", body=msg)

    async def critical_finding(
        self,
        domain: str,
        name: str,
        host: str,
        cvss: Optional[float] = None,
    ) -> None:
        if not self.cfg.notify_on_critical:
            return
        cvss_str = f"  CVSS: {cvss}" if cvss is not None else ""
        msg = (
            f"*CRITICAL FINDING* — `{domain}`\n"
            f"Vulnerability: *{name}*\n"
            f"Host: `{host}`{cvss_str}"
        )
        await self._deliver(
            subject=f"[Liminal] Critical finding on {domain}: {name}", body=msg
        )

    async def batch_complete(
        self,
        total: int,
        succeeded: int,
        failed: int,
        total_findings: int,
    ) -> None:
        msg = (
            f"*Batch scan complete*\n"
            f"Targets: {total}  Succeeded: {succeeded}  Failed: {failed}\n"
            f"Total findings: {total_findings}"
        )
        await self._deliver(subject="[Liminal] Batch scan complete", body=msg)

    # ------------------------------------------------------------------
    # Internal delivery
    # ------------------------------------------------------------------

    async def _deliver(self, subject: str, body: str) -> None:
        """Fire all configured backends in parallel; swallow all errors."""
        tasks = []
        cfg = self.cfg

        if cfg.slack_webhook:
            tasks.append(self._send_slack(body))
        if cfg.discord_webhook:
            tasks.append(self._send_discord(body))
        if cfg.webhook_url:
            tasks.append(self._send_generic_webhook(body))
        if cfg.email_to and cfg.smtp_host:
            tasks.append(self._send_email(subject, body))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.warning("Notification delivery error: %s", result)

    async def _send_slack(self, text: str) -> None:
        payload = {"text": text}
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.cfg.slack_webhook, json=payload, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status not in (200, 204):
                    body = await resp.text()
                    logger.warning("Slack webhook returned %s: %s", resp.status, body)

    async def _send_discord(self, text: str) -> None:
        payload = {"content": text}
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.cfg.discord_webhook, json=payload, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status not in (200, 204):
                    body = await resp.text()
                    logger.warning("Discord webhook returned %s: %s", resp.status, body)

    async def _send_generic_webhook(self, text: str) -> None:
        payload = {"message": text, "source": "liminal"}
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.cfg.webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status not in (200, 201, 204):
                    body = await resp.text()
                    logger.warning("Generic webhook returned %s: %s", resp.status, body)

    async def _send_email(self, subject: str, body: str) -> None:
        """Send email via SMTP with STARTTLS, offloaded to a thread executor."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._send_email_sync, subject, body)

    def _send_email_sync(self, subject: str, body: str) -> None:
        cfg = self.cfg
        msg = MIMEText(body, "plain")
        msg["Subject"] = subject
        msg["From"] = cfg.smtp_from or cfg.smtp_user
        msg["To"] = cfg.email_to

        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls()
            if cfg.smtp_user and cfg.smtp_password:
                smtp.login(cfg.smtp_user, cfg.smtp_password)
            smtp.sendmail(msg["From"], [cfg.email_to], msg.as_string())
