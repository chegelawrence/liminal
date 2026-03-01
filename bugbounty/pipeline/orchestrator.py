"""Main orchestrator: coordinates all pipeline phases end-to-end."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from bugbounty.agents.analyzer import AnalyzerAgent
from bugbounty.agents.planner import PlannerAgent
from bugbounty.agents.reporter import ReporterAgent
from bugbounty.core.config import AppConfig
from bugbounty.core.llm import create_provider
from bugbounty.core.notifier import Notifier
from bugbounty.core.rate_limiter import RateLimiter
from bugbounty.core.scope import ScopeValidator
from bugbounty.db.models import AnalysisResult, ScanRun
from bugbounty.db.store import DataStore
from bugbounty.pipeline.recon import ReconPipeline
from bugbounty.pipeline.scan import ScanPipeline
from bugbounty.reporting.generator import ReportGenerator

logger = logging.getLogger(__name__)


@dataclass
class OrchestratorResult:
    """Result returned by Orchestrator.run()."""

    report_dir: str
    finding_counts: dict[str, int] = field(default_factory=dict)


_SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "bold orange3",
    "medium": "bold yellow",
    "low": "bold blue",
    "info": "dim",
}

_BANNER = r"""
[bold cyan]
  ____              ____                  _         _    ___
 | __ ) _   _  __ | __ )  ___  _   _ _ __ | |_ _   _| |  / _ \
 |  _ \| | | |/ _` |  _ \ / _ \| | | | '_ \| __| | | | | | | |
 | |_) | |_| | (_| | |_) | (_) | |_| | | | | |_| |_| | | |_| |
 |____/ \__,_|\__, |____/ \___/ \__,_|_| |_|\__|\__, |_|\___/
              |___/                              |___/
[/bold cyan]
[dim]AI-Powered Bug Bounty Automation Framework[/dim]
"""


class Orchestrator:
    """Top-level coordinator for a full bug bounty scan.

    Manages database initialisation, agent invocations, pipeline execution,
    report generation, and Rich console output.
    """

    def __init__(self, config: AppConfig, notifier: Optional[Notifier] = None) -> None:
        self.config = config
        self.notifier = notifier

        # Resolve output directory (make absolute if relative)
        results_dir = Path(config.output.results_dir).expanduser()
        if not results_dir.is_absolute():
            results_dir = Path.cwd() / results_dir
        self.results_dir = results_dir

        self.store = DataStore(config.db_dsn)
        self.scope = ScopeValidator(
            in_scope=config.scope.in_scope,
            out_of_scope=config.scope.out_of_scope,
            ip_ranges=config.scope.ip_ranges,
        )
        self.rate_limiter = RateLimiter(config.rate_limits.concurrent_requests)

        provider = create_provider(
            name=config.ai.provider,
            anthropic_api_key=config.anthropic_api_key,
            openai_api_key=config.openai_api_key,
            groq_api_key=config.groq_api_key,
            claude_model=config.ai.claude_model,
            openai_model=config.ai.model,
            max_tokens=config.ai.max_tokens,
            temperature=config.ai.temperature,
        )
        self.planner = PlannerAgent(provider=provider)
        self.analyzer = AnalyzerAgent(provider=provider)
        self.reporter = ReporterAgent(provider=provider)

        self.recon_pipeline = ReconPipeline(config, self.store, self.scope)
        self.scan_pipeline = ScanPipeline(config, self.store, self.scope)
        self.report_generator = ReportGenerator(str(results_dir))

    async def run(
        self,
        console: Console,
        only_recon: bool = False,
        only_scan: bool = False,
        resume_scan_run_id: Optional[str] = None,
    ) -> OrchestratorResult:
        """Execute the full scan workflow.

        Args:
            console:            Rich Console for output.
            only_recon:         If True, skip scanning phase.
            only_scan:          If True, skip recon phase (requires prior recon).
            resume_scan_run_id: Resume an existing scan run ID.

        Returns:
            OrchestratorResult with report_dir and finding_counts.
        """
        # Ensure output directory exists
        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Display banner
        console.print(_BANNER)

        # Initialise database
        await self.store.initialize()

        domain = self.config.target.domain
        program_name = self.config.target.program_name
        _start_time = datetime.now(timezone.utc)

        # Create or resume scan run
        if resume_scan_run_id:
            scan_run = await self.store.get_scan_run(resume_scan_run_id)
            if scan_run is None:
                console.print(
                    f"[red]Scan run '{resume_scan_run_id}' not found.[/red]"
                )
                raise ValueError(f"Scan run not found: {resume_scan_run_id}")
            console.print(
                f"[yellow]Resuming scan run: {scan_run.id}[/yellow]"
            )
        else:
            scan_run = ScanRun(
                id=str(uuid.uuid4()),
                target_domain=domain,
                program_name=program_name,
                started_at=datetime.now(timezone.utc),
                status="running",
            )
            await self.store.save_scan_run(scan_run)

        if self.notifier:
            await self.notifier.scan_started(domain, scan_run.id)

        # Display scan info panel
        vuln_cfg = self.config.vuln
        enabled_scans: list[str] = []
        if vuln_cfg.ssrf.enabled:
            enabled_scans.append("SSRF-GET")
        if vuln_cfg.post_ssrf:
            enabled_scans.append("SSRF-POST")
        if vuln_cfg.header_injection.enabled:
            enabled_scans.append("Header-SSRF")
        if vuln_cfg.xss.enabled:
            enabled_scans.append("XSS")
        if vuln_cfg.cors.enabled:
            enabled_scans.append("CORS")
        if vuln_cfg.open_redirect.enabled:
            enabled_scans.append("Open-Redirect")
        if vuln_cfg.takeover.enabled:
            enabled_scans.append("Takeover")
        if vuln_cfg.exposure.enabled:
            enabled_scans.append("Exposure")
        if vuln_cfg.js_scanner.enabled:
            enabled_scans.append("JS-Secrets")

        info_table = Table.grid(padding=(0, 2))
        info_table.add_column(style="bold dim")
        info_table.add_column()
        info_table.add_row("Target:", f"[cyan]{domain}[/cyan]")
        info_table.add_row("Programme:", program_name)
        info_table.add_row("Platform:", self.config.target.platform)
        info_table.add_row("Scan ID:", scan_run.id)
        info_table.add_row("Model:", self.config.ai.model)
        info_table.add_row(
            "Vuln Coverage:",
            ", ".join(enabled_scans) if enabled_scans else "Default",
        )
        console.print(Panel(info_table, title="[bold]Scan Configuration[/bold]", expand=False))

        report_dir: Optional[Path] = None

        try:
            # ----------------------------------------------------------
            # Phase 0: AI Planner
            # ----------------------------------------------------------
            if not only_scan:
                with console.status("[bold green]AI Planner analysing scope...[/bold green]"):
                    try:
                        recon_plan = await self.planner.create_plan(
                            target=domain,
                            scope=self.config.scope,
                            program_info={
                                "program_name": program_name,
                                "platform": self.config.target.platform,
                            },
                        )
                        console.print(
                            Panel(
                                f"[bold]Recon Strategy[/bold]\n"
                                f"Technology focus: {', '.join(recon_plan.technology_focus) or 'General'}\n"
                                f"Scan types: {', '.join(recon_plan.recommended_scan_types)}\n"
                                f"Notes: {recon_plan.notes[:200]}",
                                title="[bold green]AI Planner[/bold green]",
                                expand=False,
                            )
                        )
                    except Exception as exc:
                        logger.warning("Planner agent failed: %s", exc)
                        console.print(f"[yellow]Planner skipped: {exc}[/yellow]")

            # ----------------------------------------------------------
            # Phase 1: Recon Pipeline
            # ----------------------------------------------------------
            if not only_scan:
                console.rule("[bold]Phase 1: Reconnaissance[/bold]")
                recon_result = await self._run_with_progress(
                    console,
                    "Reconnaissance",
                    self.recon_pipeline.run(
                        scan_run_id=scan_run.id,
                        domain=domain,
                    ),
                )
                console.print(
                    f"[green]Recon complete:[/green] "
                    f"{recon_result.subdomains_found} subdomains, "
                    f"{recon_result.live_hosts_found} live hosts, "
                    f"{recon_result.ports_found} ports, "
                    f"{recon_result.urls_found} URLs"
                )

            # ----------------------------------------------------------
            # Phase 2: Scan Pipeline
            # ----------------------------------------------------------
            if not only_recon:
                console.rule("[bold]Phase 2: Vulnerability Scanning[/bold]")
                scan_result = await self._run_with_progress(
                    console,
                    "Vulnerability Scanning",
                    self.scan_pipeline.run(scan_run_id=scan_run.id),
                )
                severity_str = ", ".join(
                    f"{v} {k}" for k, v in scan_result.findings_by_severity.items()
                )
                scan_detail_parts = [
                    f"[red]SSRF: {scan_result.ssrf_findings}[/red]",
                    f"[orange3]XSS: {scan_result.xss_findings}[/orange3]",
                    f"CORS: {scan_result.cors_findings}",
                    f"Redirect: {scan_result.redirect_findings}",
                    f"Takeover: {scan_result.takeover_findings}",
                    f"Exposure: {scan_result.exposure_findings}",
                    f"JS-Secrets: {scan_result.js_secrets}",
                    f"Header-SSRF: {scan_result.header_ssrf_findings}",
                    f"Nuclei: {scan_result.nuclei_findings}",
                ]
                console.print(
                    f"[green]Scan complete:[/green] "
                    f"{scan_result.findings_total} findings "
                    f"({', '.join(scan_detail_parts)}) "
                    f"({severity_str or 'none'})"
                )

            # ----------------------------------------------------------
            # Phase 3: AI Analysis
            # ----------------------------------------------------------
            console.rule("[bold]Phase 3: AI Analysis[/bold]")
            findings = await self.store.get_findings(scan_run.id)
            live_hosts = await self.store.get_live_hosts(scan_run.id)

            analysis: AnalysisResult
            if findings:
                with console.status("[bold green]AI Analyzer triaging findings...[/bold green]"):
                    try:
                        analysis = await self.analyzer.analyze_findings(findings, live_hosts)
                    except Exception as exc:
                        logger.warning("Analyzer agent failed: %s", exc)
                        console.print(f"[yellow]Analyzer fallback: {exc}[/yellow]")
                        # Fallback: treat all as true positives
                        analysis = AnalysisResult(
                            true_positives=findings,
                            executive_summary="Automated analysis only – AI triage unavailable.",
                            total_critical=sum(1 for f in findings if f.severity == "critical"),
                            total_high=sum(1 for f in findings if f.severity == "high"),
                            total_medium=sum(1 for f in findings if f.severity == "medium"),
                            total_low=sum(1 for f in findings if f.severity == "low"),
                        )
            else:
                analysis = AnalysisResult(
                    executive_summary="No security findings were discovered during this scan.",
                )
                console.print("[dim]No findings to analyse.[/dim]")

            # Update findings in DB
            for f in analysis.true_positives + analysis.false_positives:
                await self.store.update_finding(f)

            # Notify on critical true positives
            if self.notifier:
                for f in analysis.true_positives:
                    if f.severity == "critical":
                        await self.notifier.critical_finding(
                            domain=domain,
                            name=f.name or f.template_id or "Unknown",
                            host=f.host or "",
                            cvss=f.cvss_score if hasattr(f, "cvss_score") else None,
                        )

            # ----------------------------------------------------------
            # Phase 4: AI Report Writer
            # ----------------------------------------------------------
            console.rule("[bold]Phase 4: Report Generation[/bold]")
            report_content: dict = {}
            if analysis.true_positives:
                with console.status("[bold green]AI Reporter formatting findings...[/bold green]"):
                    try:
                        report_content = await self.reporter.generate_report_content(
                            scan_run=scan_run,
                            analysis=analysis,
                            live_hosts=live_hosts,
                        )
                    except Exception as exc:
                        logger.warning("Reporter agent failed: %s", exc)
                        console.print(f"[yellow]Reporter fallback: {exc}[/yellow]")
                        report_content = {
                            "executive_summary": analysis.executive_summary,
                            "formatted_findings": [],
                            "recommended_disclosures": [],
                            "remediation_roadmap": "",
                        }

                # Apply formatted content back to findings
                formatted_by_id = {
                    f.get("finding_id"): f
                    for f in report_content.get("formatted_findings", [])
                }
                for finding in analysis.true_positives:
                    formatted = formatted_by_id.get(finding.id, {})
                    if formatted:
                        finding.report_title = formatted.get("report_title", finding.report_title)
                        finding.impact_statement = formatted.get("impact_statement")
                        finding.remediation = formatted.get("remediation")
                        finding.references = formatted.get("references", [])
                        finding.formatted_description = formatted.get("formatted_description")
                        if formatted.get("poc_steps"):
                            finding.poc_steps = formatted["poc_steps"]
                        await self.store.update_finding(finding)

            # Generate report files
            report_paths = await self.report_generator.generate(
                scan_run=scan_run,
                analysis=analysis,
                report_content=report_content,
                live_hosts=live_hosts,
                formats=self.config.output.formats,
            )

            report_dir_path = self.results_dir / scan_run.id
            report_dir_path.mkdir(parents=True, exist_ok=True)

            # Display summary
            await self._display_summary(analysis, live_hosts, console)

            if report_paths:
                console.print("\n[bold green]Reports generated:[/bold green]")
                for fmt, path in report_paths.items():
                    console.print(f"  [dim]{fmt}:[/dim] {path}")

            # Mark scan as completed
            scan_run.completed_at = datetime.now(timezone.utc)
            scan_run.status = "completed"
            await self.store.update_scan_run(scan_run)

            console.print(
                f"\n[bold green]Scan completed![/bold green] "
                f"Scan ID: [cyan]{scan_run.id}[/cyan]"
            )

            finding_counts = {
                "critical": analysis.total_critical,
                "high": analysis.total_high,
                "medium": analysis.total_medium,
                "low": analysis.total_low,
            }
            duration = (datetime.now(timezone.utc) - _start_time).total_seconds()

            if self.notifier:
                await self.notifier.scan_complete(
                    domain=domain,
                    run_id=scan_run.id,
                    duration_seconds=duration,
                    counts=finding_counts,
                    report_path=str(report_dir_path),
                )

            return OrchestratorResult(
                report_dir=str(report_dir_path),
                finding_counts=finding_counts,
            )

        except Exception as exc:
            logger.exception("Scan failed with unexpected error")
            scan_run.status = "failed"
            scan_run.completed_at = datetime.now(timezone.utc)
            await self.store.update_scan_run(scan_run)
            console.print(f"[bold red]Scan failed:[/bold red] {exc}")
            if self.notifier:
                await self.notifier.scan_failed(domain=domain, error=str(exc))
            raise
        finally:
            await self.store.close()

    async def _run_with_progress(
        self,
        console: Console,
        label: str,
        coro,
    ):
        """Run *coro* with a spinner progress indicator."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(f"[cyan]{label}[/cyan]", total=None)
            result = await coro
            progress.remove_task(task)
        return result

    async def _display_summary(
        self,
        analysis: AnalysisResult,
        live_hosts,
        console: Console,
    ) -> None:
        """Display a Rich summary table of scan results."""
        console.rule("[bold]Scan Summary[/bold]")

        # Severity breakdown table
        sev_table = Table(
            title="Findings by Severity",
            show_header=True,
            header_style="bold dim",
        )
        sev_table.add_column("Severity", style="bold")
        sev_table.add_column("Count", justify="right")
        sev_table.add_column("False Positives", justify="right")

        severity_counts = {
            "critical": analysis.total_critical,
            "high": analysis.total_high,
            "medium": analysis.total_medium,
            "low": analysis.total_low,
        }
        fp_counts = {
            sev: sum(1 for f in analysis.false_positives if f.severity == sev)
            for sev in severity_counts
        }

        for sev, count in severity_counts.items():
            color = _SEVERITY_COLORS.get(sev, "white")
            sev_table.add_row(
                Text(sev.capitalize(), style=color),
                str(count),
                str(fp_counts.get(sev, 0)),
            )

        sev_table.add_row(
            "Total TP",
            str(len(analysis.true_positives)),
            "",
        )

        console.print(sev_table)

        # Vulnerability coverage breakdown table
        all_findings = analysis.true_positives + analysis.false_positives
        if all_findings:
            vuln_counts: dict[str, int] = {}
            for f in all_findings:
                src = f.template_id or ""
                if "ssrf" in src or "ssrf" in (f.name or "").lower():
                    key = "SSRF"
                elif "xss" in src or "xss" in (f.name or "").lower():
                    key = "XSS"
                elif "cors" in src or "cors" in (f.name or "").lower():
                    key = "CORS"
                elif "redirect" in src or "redirect" in (f.name or "").lower():
                    key = "Open Redirect"
                elif "takeover" in src or "takeover" in (f.name or "").lower():
                    key = "Subdomain Takeover"
                elif "exposure" in src or any(
                    kw in (f.name or "").lower()
                    for kw in ["exposed", "disclosure", "git", "actuator", "env", "debug"]
                ):
                    key = "Exposure"
                elif "secret" in src or "secret" in (f.name or "").lower():
                    key = "JS Secret"
                elif "header" in src:
                    key = "Header SSRF"
                elif "nuclei" in src:
                    key = "Nuclei"
                else:
                    key = "Other"
                vuln_counts[key] = vuln_counts.get(key, 0) + 1

            if vuln_counts:
                vuln_table = Table(
                    title="Findings by Vulnerability Type",
                    show_header=True,
                    header_style="bold dim",
                )
                vuln_table.add_column("Vulnerability Type", style="bold")
                vuln_table.add_column("Count", justify="right")
                for vtype, cnt in sorted(vuln_counts.items(), key=lambda x: -x[1]):
                    vuln_table.add_row(vtype, str(cnt))
                console.print(vuln_table)

        # Chains
        if analysis.high_impact_chains:
            console.print(
                f"\n[bold yellow]Vulnerability Chains Found: {len(analysis.high_impact_chains)}[/bold yellow]"
            )
            for chain in analysis.high_impact_chains[:3]:
                console.print(
                    f"  [orange3]{chain.get('chain_id', 'unknown')}[/orange3]: "
                    f"{chain.get('impact', '')}"
                )

        # Executive summary
        if analysis.executive_summary:
            console.print(
                Panel(
                    analysis.executive_summary[:800],
                    title="[bold]Executive Summary[/bold]",
                    expand=False,
                )
            )

        # Live hosts table (top 10)
        if live_hosts:
            host_table = Table(
                title=f"Live Hosts ({len(live_hosts)} total, showing top 10)",
                show_header=True,
                header_style="bold dim",
            )
            host_table.add_column("URL")
            host_table.add_column("Status", justify="right")
            host_table.add_column("Title")
            host_table.add_column("Technologies")

            for h in live_hosts[:10]:
                status_style = "green" if h.status_code == 200 else "yellow"
                host_table.add_row(
                    h.url[:50],
                    Text(str(h.status_code), style=status_style),
                    (h.title or "")[:30],
                    ", ".join(h.technologies[:3]),
                )
            console.print(host_table)
