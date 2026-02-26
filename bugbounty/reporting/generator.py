"""Report generation: HTML, Markdown, and JSON formats."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jinja2

from bugbounty.db.models import AnalysisResult, Finding, LiveHost, ScanRun

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    """Generates HTML, Markdown, and JSON reports from scan results."""

    def __init__(self, output_dir: str) -> None:
        self.output_dir = Path(output_dir)
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=jinja2.select_autoescape(["html"]),
        )
        # Add custom filters
        self.env.filters["severity_color"] = _severity_color
        self.env.filters["severity_badge"] = _severity_badge
        self.env.filters["format_dt"] = _format_dt

    async def generate(
        self,
        scan_run: ScanRun,
        analysis: AnalysisResult,
        report_content: dict[str, Any],
        live_hosts: list[LiveHost],
        formats: list[str],
    ) -> dict[str, Path]:
        """Generate reports in all requested formats.

        Args:
            scan_run:       Scan run metadata.
            analysis:       Triaged findings.
            report_content: Agent-formatted content dict.
            live_hosts:     Discovered live hosts.
            formats:        List of formats to generate (html, markdown, json).

        Returns:
            Dict mapping format name to the generated file Path.
        """
        # Create per-scan output directory
        report_dir = self.output_dir / scan_run.id
        report_dir.mkdir(parents=True, exist_ok=True)

        # Build template context
        context = self._build_context(scan_run, analysis, report_content, live_hosts)

        generated: dict[str, Path] = {}

        for fmt in formats:
            fmt = fmt.lower()
            try:
                if fmt == "html":
                    path = await self._render_html(context, report_dir)
                    generated["html"] = path
                elif fmt in ("markdown", "md"):
                    path = await self._render_markdown(context, report_dir)
                    generated["markdown"] = path
                elif fmt == "json":
                    path = await self._render_json(context, report_dir)
                    generated["json"] = path
                else:
                    logger.warning("Unknown report format: %s", fmt)
            except Exception as exc:
                logger.exception("Failed to generate %s report: %s", fmt, exc)

        return generated

    def _build_context(
        self,
        scan_run: ScanRun,
        analysis: AnalysisResult,
        report_content: dict[str, Any],
        live_hosts: list[LiveHost],
    ) -> dict[str, Any]:
        """Build the Jinja2 template rendering context."""
        # Merge formatted findings into the true positive objects
        formatted_by_id = {
            f.get("finding_id", ""): f
            for f in report_content.get("formatted_findings", [])
        }

        findings_for_template = []
        for f in analysis.true_positives:
            formatted = formatted_by_id.get(f.id, {})
            findings_for_template.append(
                {
                    "id": f.id,
                    "title": formatted.get("report_title") or f.report_title or f.name,
                    "severity": f.severity,
                    "cvss_score": formatted.get("cvss_score") or f.cvss_score,
                    "host": f.host,
                    "matched_at": f.matched_at,
                    "description": formatted.get("formatted_description") or f.description,
                    "impact": formatted.get("impact_statement") or f.impact_statement or "",
                    "poc_steps": _format_poc(formatted.get("poc_steps") or f.poc_steps or ""),
                    "remediation": formatted.get("remediation") or f.remediation or "",
                    "references": formatted.get("references") or f.references or [],
                    "tags": f.tags,
                    "cve_id": f.cve_id,
                    "discovered_at": f.discovered_at,
                    "template_id": f.template_id,
                }
            )

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings_for_template.sort(key=lambda x: severity_order.get(x["severity"], 9))

        return {
            "scan_run": scan_run,
            "generated_at": datetime.now(timezone.utc),
            "findings": findings_for_template,
            "false_positives": analysis.false_positives,
            "chains": analysis.high_impact_chains,
            "live_hosts": live_hosts,
            "executive_summary": report_content.get(
                "executive_summary", analysis.executive_summary
            ),
            "remediation_roadmap": report_content.get("remediation_roadmap", ""),
            "stats": {
                "total_findings": len(analysis.true_positives),
                "total_fp": len(analysis.false_positives),
                "critical": analysis.total_critical,
                "high": analysis.total_high,
                "medium": analysis.total_medium,
                "low": analysis.total_low,
                "info": analysis.total_info,
                "chains": len(analysis.high_impact_chains),
                "live_hosts": len(live_hosts),
            },
        }

    async def _render_html(self, context: dict, report_dir: Path) -> Path:
        template = self.env.get_template("report.html.j2")
        rendered = template.render(**context)
        out_path = report_dir / "report.html"
        out_path.write_text(rendered, encoding="utf-8")
        logger.info("HTML report written to %s", out_path)
        return out_path

    async def _render_markdown(self, context: dict, report_dir: Path) -> Path:
        # Disable autoescape for markdown rendering
        md_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=False,
        )
        md_env.filters["severity_color"] = _severity_color
        md_env.filters["severity_badge"] = _severity_badge
        md_env.filters["format_dt"] = _format_dt
        template = md_env.get_template("report.md.j2")
        rendered = template.render(**context)
        out_path = report_dir / "report.md"
        out_path.write_text(rendered, encoding="utf-8")
        logger.info("Markdown report written to %s", out_path)
        return out_path

    async def _render_json(self, context: dict, report_dir: Path) -> Path:
        out_path = report_dir / "report.json"

        # Build JSON-serialisable dict
        export = {
            "scan_run": {
                "id": context["scan_run"].id,
                "target_domain": context["scan_run"].target_domain,
                "program_name": context["scan_run"].program_name,
                "started_at": context["scan_run"].started_at.isoformat(),
                "completed_at": (
                    context["scan_run"].completed_at.isoformat()
                    if context["scan_run"].completed_at
                    else None
                ),
                "status": context["scan_run"].status,
            },
            "generated_at": context["generated_at"].isoformat(),
            "executive_summary": context["executive_summary"],
            "remediation_roadmap": context["remediation_roadmap"],
            "statistics": context["stats"],
            "findings": [
                {
                    **f,
                    "discovered_at": f["discovered_at"].isoformat()
                    if hasattr(f.get("discovered_at"), "isoformat")
                    else str(f.get("discovered_at", "")),
                    "poc_steps": f["poc_steps"] if isinstance(f["poc_steps"], list) else [f["poc_steps"]],
                }
                for f in context["findings"]
            ],
            "vulnerability_chains": context["chains"],
            "live_hosts": [
                {
                    "url": h.url,
                    "status_code": h.status_code,
                    "title": h.title,
                    "technologies": h.technologies,
                    "server": h.server,
                }
                for h in context["live_hosts"]
            ],
        }

        out_path.write_text(
            json.dumps(export, indent=2, default=str), encoding="utf-8"
        )
        logger.info("JSON report written to %s", out_path)
        return out_path


# ------------------------------------------------------------------
# Template filters
# ------------------------------------------------------------------

def _severity_color(severity: str) -> str:
    return {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#0d6efd",
        "info": "#6c757d",
    }.get(severity.lower(), "#6c757d")


def _severity_badge(severity: str) -> str:
    colors = {
        "critical": "danger",
        "high": "warning",
        "medium": "warning",
        "low": "info",
        "info": "secondary",
    }
    return colors.get(severity.lower(), "secondary")


def _format_dt(dt) -> str:
    if dt is None:
        return "N/A"
    if isinstance(dt, str):
        return dt
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _format_poc(poc_raw: str) -> list[str]:
    """Split PoC string into a list of step strings."""
    if not poc_raw:
        return []
    lines = poc_raw.strip().splitlines()
    steps: list[str] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Remove leading step numbers like "1." or "1)"
        import re
        line = re.sub(r"^\d+[\.\)]\s*", "", line)
        if line:
            steps.append(line)
    return steps
