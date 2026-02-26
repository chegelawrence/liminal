"""CLI entry point for the Bug Bounty AI Agent Framework."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from bugbounty.core.config import load_config
from bugbounty.db.store import DataStore
from bugbounty.pipeline.orchestrator import Orchestrator

console = Console()

_BANNER = r"""[bold cyan]
  ____              ____                  _         _    ___
 | __ ) _   _  __ | __ )  ___  _   _ _ __ | |_ _   _| |  / _ \
 |  _ \| | | |/ _` |  _ \ / _ \| | | | '_ \| __| | | | | | | |
 | |_) | |_| | (_| | |_) | (_) | |_| | | | | |_| |_| | | |_| |
 |____/ \__,_|\__, |____/ \___/ \__,_|_| |_|\__|\__, |_|\___/
              |___/                              |___/
[/bold cyan][dim]  AI-Powered Bug Bounty Automation Framework v0.1.0[/dim]
"""


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Keep httpx/anthropic quieter unless debug
    if not verbose:
        logging.getLogger("httpx").setLevel(logging.ERROR)
        logging.getLogger("anthropic").setLevel(logging.ERROR)


@click.group()
@click.version_option("0.1.0", prog_name="bugbounty")
def cli() -> None:
    """Bug Bounty AI Agent Framework.

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
def scan(
    config: str,
    domain: Optional[str],
    output: Optional[str],
    resume: Optional[str],
    only_recon: bool,
    only_scan: bool,
    verbose: bool,
) -> None:
    """Run a full bug bounty scan against the configured target.

    The scan consists of:
    \b
    1. AI Planner     – creates a prioritised recon strategy
    2. Reconnaissance – subdomain enumeration, live host probing, URL discovery
    3. Vulnerability Scanning – nuclei, ffuf, dalfox
    4. AI Analysis    – false positive removal, PoC suggestions, chain detection
    5. Report Generation – HTML, Markdown, JSON
    """
    _configure_logging(verbose)

    # Validate mutual exclusion
    if only_recon and only_scan:
        console.print("[red]Error:[/red] --only-recon and --only-scan are mutually exclusive.")
        sys.exit(1)

    # Load configuration
    try:
        app_config = load_config(config, domain_override=domain)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        sys.exit(1)

    # Check for API key
    if not app_config.anthropic_api_key:
        console.print(
            "[red]Error:[/red] ANTHROPIC_API_KEY is not set. "
            "Set it in your environment or .env file."
        )
        sys.exit(1)

    # Override output directory if provided
    if output:
        app_config.output.results_dir = output

    # Run
    try:
        report_path = asyncio.run(
            Orchestrator(app_config).run(
                console=console,
                only_recon=only_recon,
                only_scan=only_scan,
                resume_scan_run_id=resume,
            )
        )
        console.print(f"\n[bold green]Reports saved to:[/bold green] {report_path}")
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as exc:
        console.print(f"\n[bold red]Fatal error:[/bold red] {exc}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


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
    Use `bugbounty list-scans` to find available scan run IDs.
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

    db_path = str(results_dir / "scans.db")

    async def _gen() -> None:
        store = DataStore(db_path)
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

    results_dir = Path(app_config.output.results_dir).expanduser()
    if not results_dir.is_absolute():
        results_dir = Path.cwd() / results_dir

    db_path = str(results_dir / "scans.db")

    if not Path(db_path).exists():
        console.print("[yellow]No scan database found. Run a scan first.[/yellow]")
        return

    async def _list() -> None:
        store = DataStore(db_path)
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
            f"\n[dim]Use `bugbounty report <FULL_SCAN_ID> --config <config>` "
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

    # Check API keys
    import os
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
