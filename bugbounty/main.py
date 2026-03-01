"""CLI entry point for the Liminal Framework."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from bugbounty.core.config import AppConfig, TargetConfig, load_config
from bugbounty.core.notifier import Notifier
from bugbounty.db.store import DataStore
from bugbounty.pipeline.orchestrator import Orchestrator

console = Console()

_BANNER = r"""[bold cyan]
 _     ___  __  __ ___ _  _    _   _
| |   |_ _||  \/  |_ _| \| |  /_\ | |
| |_   | | | |\/| | | | .` | / _ \| |_
|___| |___|_|  |_|___|_|\_|/_/ \_\|___|
[/bold cyan][dim]  AI-Powered Security Reconnaissance Framework v0.1.0[/dim]
"""


def _configure_logging(verbose: bool, log_file: Optional[str] = None) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    handlers: list[logging.Handler] = []

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S")
    )
    handlers.append(console_handler)

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        handlers.append(file_handler)

    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, handlers=handlers)

    if not verbose:
        logging.getLogger("httpx").setLevel(logging.ERROR)
        logging.getLogger("anthropic").setLevel(logging.ERROR)


@click.group()
@click.version_option("0.1.0", prog_name="liminal")
def cli() -> None:
    """Liminal — AI-Powered Security Reconnaissance Framework.

    An AI-powered automation framework for bug bounty reconnaissance,
    vulnerability scanning, and professional report generation.
    """


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--config", "-c",
    required=True,
    type=click.Path(exists=True, dir_okay=False, readable=True),
    help="Path to config.yaml",
)
@click.option("--domain", "-d", default=None, help="Override target domain from config")
@click.option("--output", "-o", default=None, help="Output directory (overrides config)")
@click.option("--resume", "-r", default=None, help="Resume a previous scan run ID")
@click.option(
    "--only-recon",
    is_flag=True,
    default=False,
    help="Only run reconnaissance phase, skip vulnerability scanning",
)
@click.option(
    "--only-scan",
    is_flag=True,
    default=False,
    help="Only run vulnerability scanning (requires prior recon for the same target)",
)
@click.option("--verbose", "-v", is_flag=True, default=False, help="Enable verbose logging")
@click.option(
    "--log-file",
    default=None,
    help="Path to write log output (e.g. /var/log/liminal/scan.log)",
)
def scan(
    config: str,
    domain: Optional[str],
    output: Optional[str],
    resume: Optional[str],
    only_recon: bool,
    only_scan: bool,
    verbose: bool,
    log_file: Optional[str],
) -> None:
    """Run a full bug bounty scan against the configured target(s).

    The scan consists of:
    \b
    1. AI Planner     – creates a prioritised recon strategy
    2. Reconnaissance – subdomain enumeration, live host probing, URL discovery
    3. Vulnerability Scanning – nuclei, ffuf, dalfox
    4. AI Analysis    – false positive removal, PoC suggestions, chain detection
    5. Report Generation – HTML, Markdown, JSON

    When the config file contains a `targets:` list, all targets are scanned
    sequentially and a batch summary is printed at the end.
    """
    _configure_logging(verbose, log_file)

    if only_recon and only_scan:
        console.print("[red]Error:[/red] --only-recon and --only-scan are mutually exclusive.")
        sys.exit(1)

    try:
        app_config = load_config(config, domain_override=domain)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        sys.exit(1)

    if not app_config.anthropic_api_key:
        console.print(
            "[red]Error:[/red] ANTHROPIC_API_KEY is not set. "
            "Set it in your environment or .env file."
        )
        sys.exit(1)

    if not app_config.db_dsn:
        console.print(
            "[red]Error:[/red] DATABASE_URL is not set. "
            "Set it in your environment or .env file."
        )
        sys.exit(1)

    if output:
        app_config.output.results_dir = output

    # ----------------------------------------------------------------
    # Build target list
    # ----------------------------------------------------------------
    all_targets: list[TargetConfig] = []
    if domain:
        # Explicit --domain override: single target, ignore config lists
        all_targets = [TargetConfig(domain=domain)]
    else:
        if app_config.target.domain:
            all_targets.append(app_config.target)
        all_targets.extend(app_config.targets)

    if not all_targets:
        console.print("[red]Error:[/red] No target domain configured.")
        sys.exit(1)

    notifier = Notifier(app_config.notifications)

    # ----------------------------------------------------------------
    # Graceful shutdown flag (SIGTERM + KeyboardInterrupt)
    # ----------------------------------------------------------------
    shutdown_requested = False

    def _request_shutdown(signum, frame):  # noqa: ANN001
        nonlocal shutdown_requested
        shutdown_requested = True
        console.print("\n[yellow]Shutdown requested — will stop after current target.[/yellow]")

    signal.signal(signal.SIGTERM, _request_shutdown)

    # ----------------------------------------------------------------
    # Batch execution
    # ----------------------------------------------------------------
    batch_results: dict[str, dict] = {}
    is_batch = len(all_targets) > 1

    try:
        for target in all_targets:
            if shutdown_requested:
                break

            # Build per-target config: merge target-level scope into the
            # global scope if the target has its own in_scope/out_of_scope
            per_config = app_config.model_copy(deep=True)
            per_config.target = target
            if target.in_scope:
                per_config.scope.in_scope = list(target.in_scope)
            if target.out_of_scope:
                per_config.scope.out_of_scope = list(target.out_of_scope)

            domain_label = target.domain
            console.rule(f"[bold cyan]Target: {domain_label}[/bold cyan]")

            start_ts = time.monotonic()
            status = "failed"
            finding_counts: dict[str, int] = {}
            report_dir = ""

            max_retries = 2
            attempt = 0
            last_error: Optional[Exception] = None

            while attempt <= max_retries:
                try:
                    result = asyncio.run(
                        Orchestrator(per_config, notifier).run(
                            console=console,
                            only_recon=only_recon,
                            only_scan=only_scan,
                            resume_scan_run_id=resume if not is_batch else None,
                        )
                    )
                    status = "complete"
                    finding_counts = result.finding_counts
                    report_dir = result.report_dir
                    last_error = None
                    break
                except KeyboardInterrupt:
                    shutdown_requested = True
                    console.print("\n[yellow]Interrupted — stopping after this target.[/yellow]")
                    break
                except Exception as exc:
                    last_error = exc
                    attempt += 1
                    if attempt <= max_retries:
                        console.print(
                            f"[yellow]Scan failed ({exc}). "
                            f"Retrying in 60s (attempt {attempt}/{max_retries})...[/yellow]"
                        )
                        time.sleep(60)
                    else:
                        console.print(
                            f"[bold red]All {max_retries} retries exhausted for {domain_label}.[/bold red]"
                        )

            elapsed = time.monotonic() - start_ts
            batch_results[domain_label] = {
                "status": status,
                "duration_seconds": elapsed,
                "finding_counts": finding_counts,
                "report_dir": report_dir,
                "error": str(last_error) if last_error else None,
            }

            if report_dir:
                console.print(f"\n[bold green]Reports saved to:[/bold green] {report_dir}")

            if shutdown_requested:
                break

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")

    # ----------------------------------------------------------------
    # Batch summary
    # ----------------------------------------------------------------
    if is_batch and batch_results:
        _print_batch_summary(batch_results)

        succeeded = sum(1 for r in batch_results.values() if r["status"] == "complete")
        failed = len(batch_results) - succeeded
        total_findings = sum(
            sum(r["finding_counts"].values()) for r in batch_results.values()
        )

        try:
            asyncio.run(
                notifier.batch_complete(
                    total=len(batch_results),
                    succeeded=succeeded,
                    failed=failed,
                    total_findings=total_findings,
                )
            )
        except Exception as exc:
            logging.getLogger(__name__).warning("Batch complete notification failed: %s", exc)

        if failed:
            sys.exit(1)
    elif batch_results:
        only_result = next(iter(batch_results.values()))
        if only_result["status"] == "failed":
            sys.exit(1)


def _print_batch_summary(results: dict[str, dict]) -> None:
    """Print a Rich table summarising all batch scan results."""
    console.rule("[bold]Batch Summary[/bold]")

    table = Table(show_header=True, header_style="bold dim", show_lines=True)
    table.add_column("Target", style="cyan")
    table.add_column("Status")
    table.add_column("Duration", justify="right")
    table.add_column("Crit", justify="right")
    table.add_column("High", justify="right")
    table.add_column("Med", justify="right")
    table.add_column("Low", justify="right")

    for domain, info in results.items():
        elapsed = info["duration_seconds"]
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        duration_str = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"

        counts = info.get("finding_counts", {})
        status = info["status"]

        if status == "complete":
            status_text = Text(status, style="bold green")
        else:
            status_text = Text(status, style="bold red")

        def _count(key: str) -> str:
            v = counts.get(key, 0)
            return str(v) if v else "–"

        table.add_row(
            domain,
            status_text,
            duration_str,
            _count("critical"),
            _count("high"),
            _count("medium"),
            _count("low"),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("scan_run_id")
@click.option(
    "--format",
    "fmt",
    default="html",
    type=click.Choice(["html", "markdown", "json"], case_sensitive=False),
    help="Report format to generate",
)
@click.option("--config", "-c", required=True, help="Path to config.yaml (for output dir)")
def report(scan_run_id: str, fmt: str, config: str) -> None:
    """Generate or re-generate a report for a previous scan run.

    SCAN_RUN_ID is the UUID of a previously completed scan run.
    Use `liminal list-scans` to find available scan run IDs.
    """
    _configure_logging(verbose=False)

    try:
        app_config = load_config(config)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        sys.exit(1)

    results_dir = Path(app_config.output.results_dir).expanduser()
    if not results_dir.is_absolute():
        results_dir = Path.cwd() / results_dir

    async def _gen() -> None:
        store = DataStore(app_config.db_dsn)
        await store.initialize()

        scan_run = await store.get_scan_run(scan_run_id)
        if scan_run is None:
            console.print(f"[red]Scan run '{scan_run_id}' not found.[/red]")
            await store.close()
            sys.exit(1)

        from bugbounty.db.models import AnalysisResult
        from bugbounty.reporting.generator import ReportGenerator

        findings = await store.get_findings(scan_run_id)
        live_hosts = await store.get_live_hosts(scan_run_id)

        true_pos = [f for f in findings if not f.is_false_positive]
        false_pos = [f for f in findings if f.is_false_positive]

        counts = {sev: sum(1 for f in true_pos if f.severity == sev)
                  for sev in ("critical", "high", "medium", "low", "info")}

        analysis = AnalysisResult(
            true_positives=true_pos,
            false_positives=false_pos,
            executive_summary=(
                f"Re-generated report for scan {scan_run_id}. "
                f"Found {len(true_pos)} confirmed vulnerabilities."
            ),
            **{f"total_{k}": v for k, v in counts.items()},
        )

        generator = ReportGenerator(str(results_dir))
        paths = await generator.generate(
            scan_run=scan_run,
            analysis=analysis,
            report_content={
                "executive_summary": analysis.executive_summary,
                "formatted_findings": [],
                "recommended_disclosures": [f.id for f in true_pos],
                "remediation_roadmap": "",
            },
            live_hosts=live_hosts,
            formats=[fmt],
        )

        await store.close()

        for format_name, path in paths.items():
            console.print(f"[green]{format_name} report:[/green] {path}")

    asyncio.run(_gen())


# ---------------------------------------------------------------------------
# list-scans command
# ---------------------------------------------------------------------------

@cli.command("list-scans")
@click.option("--config", "-c", required=True, help="Path to config.yaml (for database location)")
def list_scans(config: str) -> None:
    """List all previous scan runs stored in the database."""
    _configure_logging(verbose=False)

    try:
        app_config = load_config(config)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        sys.exit(1)

    async def _list() -> None:
        store = DataStore(app_config.db_dsn)
        await store.initialize()
        runs = await store.list_scan_runs()
        await store.close()

        if not runs:
            console.print("[dim]No scan runs found.[/dim]")
            return

        table = Table(
            title="Scan Runs",
            show_header=True,
            header_style="bold dim",
        )
        table.add_column("ID", style="cyan")
        table.add_column("Target")
        table.add_column("Programme")
        table.add_column("Started")
        table.add_column("Status")

        status_colors = {
            "completed": "green",
            "running": "yellow",
            "failed": "red",
        }

        for run in runs:
            status_color = status_colors.get(run.status, "white")
            table.add_row(
                run.id[:8] + "…",
                run.target_domain,
                run.program_name,
                run.started_at.strftime("%Y-%m-%d %H:%M"),
                Text(run.status, style=status_color),
            )

        console.print(table)
        console.print(
            f"\n[dim]Use `liminal report <FULL_SCAN_ID> --config <config>` "
            f"to regenerate a report.[/dim]"
        )

    asyncio.run(_list())


# ---------------------------------------------------------------------------
# check-tools command
# ---------------------------------------------------------------------------

@cli.command("check-tools")
def check_tools() -> None:
    """Check which external security tools are installed and available."""
    console.print(_BANNER)

    import shutil

    # (tool_name, purpose, priority) – priority: "core" | "ssrf" | "xss" | "recon"
    tools = [
        # Recon
        ("subfinder",           "Subdomain enumeration",                "recon"),
        ("amass",               "Subdomain enumeration (passive/active)","recon"),
        ("dnsx",                "DNS resolution & validation",           "recon"),
        ("httpx",               "HTTP probing & tech detection",         "recon"),
        ("naabu",               "Port scanning",                         "recon"),
        ("gau",                 "URL discovery (archives)",              "recon"),
        ("katana",              "Web crawler",                           "recon"),
        ("waybackurls",         "Wayback Machine URL fetcher",           "recon"),
        # XSS
        ("dalfox",              "XSS scanner (primary)",                 "xss"),
        # SSRF
        ("interactsh-client",   "OOB interaction server (SSRF)",         "ssrf"),
        # Param discovery
        ("arjun",               "Hidden parameter discovery",            "params"),
        # General vuln scanning
        ("nuclei",              "Template-based vuln scanner",           "scanning"),
    ]

    priority_colors = {
        "recon": "cyan",
        "xss": "orange3",
        "ssrf": "red",
        "params": "yellow",
        "scanning": "magenta",
    }

    table = Table(title="Tool Availability", show_header=True, header_style="bold dim")
    table.add_column("Tool")
    table.add_column("Category")
    table.add_column("Purpose")
    table.add_column("Status")
    table.add_column("Path")

    for tool_name, purpose, priority in tools:
        path = shutil.which(tool_name)
        if path:
            status = Text("Installed", style="bold green")
        else:
            status = Text("Not found", style="bold red")
        color = priority_colors.get(priority, "white")
        table.add_row(
            tool_name,
            Text(priority.upper(), style=f"bold {color}"),
            purpose,
            status,
            path or "–",
        )

    console.print(table)

    key_table = Table(title="API Keys", show_header=True, header_style="bold dim")
    key_table.add_column("Provider")
    key_table.add_column("Status")
    for env_var, label in [("ANTHROPIC_API_KEY", "Claude (Anthropic)"), ("OPENAI_API_KEY", "OpenAI")]:
        val = os.environ.get(env_var, "")
        if val:
            key_table.add_row(label, Text("Configured", style="bold green"))
        else:
            key_table.add_row(label, Text("Not set", style="dim"))
    console.print(key_table)

    console.print(
        "\n[dim]Missing tools are skipped gracefully. "
        "Install projectdiscovery tools: go install github.com/projectdiscovery/<tool>/...@latest\n"
        "Install dalfox: go install github.com/hahwul/dalfox/v2@latest\n"
        "Install arjun: pip install arjun\n"
        "Install interactsh-client: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest[/dim]"
    )


if __name__ == "__main__":
    cli()
