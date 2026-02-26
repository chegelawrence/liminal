"""Reporter agent: formats findings into professional bug bounty reports."""

from __future__ import annotations

import json
import logging
from typing import Any

from bugbounty.agents.base import AgentTool, BaseAgent
from bugbounty.core.llm import LLMProvider
from bugbounty.db.models import AnalysisResult, Finding, LiveHost, ScanRun

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are an expert bug bounty report writer with extensive experience submitting
to HackerOne, Bugcrowd, Intigriti, and Synack.

Your reports are known for:
- Clear, professional language that security teams immediately understand
- Compelling impact statements that justify the severity rating
- Reproducible proof-of-concept steps that leave no room for ambiguity
- Actionable remediation advice tied to specific code patterns or configurations
- Accurate CVSS scoring with justification

You write reports that maximise bounty payouts by demonstrating clear business impact.
Always structure findings to tell a story: what it is, why it matters, how to reproduce it,
and how to fix it.

Use the available tools to format each finding and then return the complete report content
as structured JSON."""


class ReporterAgent(BaseAgent):
    """AI agent that formats security findings into polished bug bounty reports."""

    def __init__(self, provider: LLMProvider) -> None:
        super().__init__(provider)

    def get_tools(self) -> list[AgentTool]:
        return [
            {
                "name": "format_finding_for_report",
                "description": (
                    "Format a security finding into a complete bug bounty report entry. "
                    "Returns a structured dict with title, severity, description, impact, "
                    "proof-of-concept, and remediation."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string"},
                        "name": {"type": "string"},
                        "severity": {"type": "string"},
                        "host": {"type": "string"},
                        "matched_at": {"type": "string"},
                        "description": {"type": "string"},
                        "poc_steps": {
                            "type": "string",
                            "description": "Existing PoC steps from the analyzer",
                        },
                        "tags": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "cvss_score": {"type": "number"},
                    },
                    "required": ["finding_id", "name", "severity", "host", "description"],
                },
            },
            {
                "name": "assess_cvss_score",
                "description": (
                    "Calculate a CVSS 3.1 score for a finding based on its characteristics. "
                    "Returns the numeric score and vector string."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "vulnerability_type": {"type": "string"},
                        "severity": {"type": "string"},
                        "attack_vector": {
                            "type": "string",
                            "enum": ["network", "adjacent", "local", "physical"],
                        },
                        "requires_authentication": {"type": "boolean"},
                        "impact_confidentiality": {
                            "type": "string",
                            "enum": ["none", "low", "high"],
                        },
                        "impact_integrity": {
                            "type": "string",
                            "enum": ["none", "low", "high"],
                        },
                        "impact_availability": {
                            "type": "string",
                            "enum": ["none", "low", "high"],
                        },
                    },
                    "required": ["vulnerability_type", "severity"],
                },
            },
        ]

    async def process_tool_call(self, tool_name: str, tool_input: dict) -> str:
        if tool_name == "format_finding_for_report":
            return await self._format_finding(tool_input)
        if tool_name == "assess_cvss_score":
            return await self._assess_cvss(tool_input)
        return json.dumps({"error": f"Unknown tool: {tool_name}"})

    # ------------------------------------------------------------------
    # Tool implementations
    # ------------------------------------------------------------------

    async def _format_finding(self, inp: dict) -> str:
        finding_id = inp.get("finding_id", "")
        name = inp.get("name", "Unknown Vulnerability")
        severity = inp.get("severity", "info").capitalize()
        host = inp.get("host", "")
        matched_at = inp.get("matched_at", host)
        description = inp.get("description", "")
        poc_steps_raw = inp.get("poc_steps", "")
        tags = inp.get("tags", [])
        cvss_score = inp.get("cvss_score")

        # Build formatted title
        title = f"{severity}: {name} in {host}"

        # Build formatted description
        formatted_description = (
            f"A **{severity.lower()}** severity vulnerability was identified at "
            f"`{matched_at}`.\n\n"
            f"{description}\n\n"
            f"This vulnerability was detected by automated scanning and has been manually "
            f"triaged as a true positive."
        )

        # Impact statement based on severity
        impact_map: dict[str, str] = {
            "Critical": (
                "This vulnerability poses an immediate and severe risk. Successful exploitation "
                "could allow an attacker to fully compromise the affected system, exfiltrate "
                "sensitive data, or disrupt critical business operations. Immediate remediation "
                "is required."
            ),
            "High": (
                "Exploitation of this vulnerability could lead to significant unauthorised access, "
                "data exposure, or privilege escalation. This represents a material risk to the "
                "organisation's security posture and should be addressed as a priority."
            ),
            "Medium": (
                "This vulnerability may allow an attacker to gain partial access, leak sensitive "
                "information, or assist in mounting further attacks. While not immediately critical, "
                "it should be remediated within the normal patch cycle."
            ),
            "Low": (
                "While this vulnerability has limited direct impact, it may assist an attacker in "
                "reconnaissance or serve as a component in a vulnerability chain. Remediation is "
                "recommended during routine maintenance."
            ),
            "Info": (
                "This finding is informational and does not represent a direct security risk. "
                "It is provided for awareness to assist in hardening the attack surface."
            ),
        }
        impact = impact_map.get(severity, impact_map["Info"])

        # Format PoC steps
        if poc_steps_raw:
            poc_formatted = poc_steps_raw
        else:
            poc_formatted = (
                f"1. Navigate to the affected endpoint: `{matched_at}`\n"
                "2. Use Burp Suite to intercept the request.\n"
                "3. Observe the vulnerability as described above.\n"
                "4. Document the request and response for the report."
            )

        # Remediation guidance based on tags and name
        remediation = _get_remediation(name, tags, description)

        # References
        references: list[str] = []
        if any(t.lower() in ["xss", "cross-site-scripting"] for t in tags):
            references.append("https://owasp.org/www-community/attacks/xss/")
            references.append("https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html")
        if any(t.lower() in ["sqli", "sql-injection"] for t in tags):
            references.append("https://owasp.org/www-community/attacks/SQL_Injection")
        if any(t.lower() in ["ssrf"] for t in tags):
            references.append("https://owasp.org/www-community/attacks/Server_Side_Request_Forgery")
        references.append("https://owasp.org/www-project-top-ten/")

        return json.dumps(
            {
                "finding_id": finding_id,
                "report_title": title,
                "severity": severity,
                "cvss_score": cvss_score,
                "formatted_description": formatted_description,
                "impact_statement": impact,
                "poc_steps": poc_formatted,
                "remediation": remediation,
                "references": references,
            }
        )

    async def _assess_cvss(self, inp: dict) -> str:
        severity = inp.get("severity", "info").lower()
        attack_vector = inp.get("attack_vector", "network")
        requires_auth = inp.get("requires_authentication", False)
        conf = inp.get("impact_confidentiality", "none")
        integ = inp.get("impact_integrity", "none")
        avail = inp.get("impact_availability", "none")

        # Simplified CVSS 3.1 base score approximation
        av_score = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.20}.get(
            attack_vector, 0.85
        )
        ac_score = 0.77  # Low complexity (most scanner findings)
        pr_score = 0.85 if not requires_auth else 0.62
        ui_score = 0.85  # No user interaction required (conservative)

        exploitability = 8.22 * av_score * ac_score * pr_score * ui_score

        impact_scores = {"none": 0.0, "low": 0.22, "high": 0.56}
        iss = (
            1
            - (1 - impact_scores.get(conf, 0))
            * (1 - impact_scores.get(integ, 0))
            * (1 - impact_scores.get(avail, 0))
        )
        impact = 6.42 * iss

        # Use severity override if provided
        severity_defaults = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "info": 0.0,
        }

        if impact == 0:
            base_score = 0.0
        else:
            base_score = min(10.0, round(min(impact + exploitability, 10.0) * 0.6, 1))

        # If impact/exploitability calc gives something very different from named severity,
        # bias toward the named severity
        named = severity_defaults.get(severity, 5.0)
        final_score = round((base_score + named) / 2, 1)

        # Build vector string
        av_vec = {"network": "N", "adjacent": "A", "local": "L", "physical": "P"}.get(
            attack_vector, "N"
        )
        pr_vec = "N" if not requires_auth else "L"
        conf_vec = {"none": "N", "low": "L", "high": "H"}.get(conf, "N")
        integ_vec = {"none": "N", "low": "L", "high": "H"}.get(integ, "N")
        avail_vec = {"none": "N", "low": "L", "high": "H"}.get(avail, "N")
        vector = f"CVSS:3.1/AV:{av_vec}/AC:L/PR:{pr_vec}/UI:N/S:U/C:{conf_vec}/I:{integ_vec}/A:{avail_vec}"

        return json.dumps(
            {
                "score": final_score,
                "vector": vector,
                "severity": severity.capitalize(),
                "justification": (
                    f"Score of {final_score} based on network-accessible attack vector, "
                    f"low attack complexity, {'no' if not requires_auth else 'low'} privileges required, "
                    f"confidentiality impact: {conf}, integrity impact: {integ}, "
                    f"availability impact: {avail}."
                ),
            }
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate_report_content(
        self,
        scan_run: ScanRun,
        analysis: AnalysisResult,
        live_hosts: list[LiveHost],
    ) -> dict[str, Any]:
        """Generate complete report content for all true positive findings.

        Args:
            scan_run:   Metadata about the scan.
            analysis:   Triaged findings from the AnalyzerAgent.
            live_hosts: Discovered live hosts for context.

        Returns:
            Dict with executive_summary, formatted_findings,
            recommended_disclosures, remediation_roadmap.
        """
        if not analysis.true_positives:
            return {
                "executive_summary": analysis.executive_summary or "No vulnerabilities found.",
                "formatted_findings": [],
                "recommended_disclosures": [],
                "remediation_roadmap": "No remediation required for this scan.",
            }

        findings_for_agent = [
            {
                "finding_id": f.id,
                "name": f.name,
                "severity": f.severity,
                "host": f.host,
                "matched_at": f.matched_at,
                "description": f.description,
                "poc_steps": f.poc_steps or "",
                "tags": f.tags,
                "cvss_score": f.cvss_score,
            }
            for f in analysis.true_positives
        ]

        user_message = (
            f"Generate a complete bug bounty report for the following scan:\n\n"
            f"Programme: {scan_run.program_name}\n"
            f"Target: {scan_run.target_domain}\n"
            f"Scan Date: {scan_run.started_at.strftime('%Y-%m-%d')}\n\n"
            f"CONFIRMED VULNERABILITIES ({len(analysis.true_positives)}):\n"
            + "\n".join(
                f"  [{f['severity'].upper()}] {f['name']} @ {f['host']}"
                for f in findings_for_agent
            )
            + "\n\nVULNERABILITY CHAINS:\n"
            + "\n".join(
                f"  - {c.get('chain_id', '')}: {c.get('impact', '')}"
                for c in analysis.high_impact_chains
            )
            + "\n\nFull findings:\n"
            + json.dumps(findings_for_agent, indent=2)
            + "\n\nInstructions:\n"
            "1. Use format_finding_for_report for each finding to create polished report entries.\n"
            "2. Use assess_cvss_score for any finding missing a CVSS score.\n"
            "3. Return final JSON with:\n"
            "   - executive_summary: str\n"
            "   - formatted_findings: list of formatted finding dicts\n"
            "   - recommended_disclosures: list of finding IDs sorted by priority (highest first)\n"
            "   - remediation_roadmap: str summarising remediation priorities and timelines\n"
        )

        final_text = await self.run_agentic_loop(
            system_prompt=_SYSTEM_PROMPT,
            user_message=user_message,
            max_iterations=min(len(analysis.true_positives) * 2 + 5, 25),
        )

        # Parse agent output
        try:
            json_start = final_text.find("{")
            json_end = final_text.rfind("}") + 1
            if json_start != -1:
                report_dict = json.loads(final_text[json_start:json_end])
            else:
                report_dict = {}
        except (json.JSONDecodeError, ValueError):
            logger.warning("Could not parse reporter JSON – using defaults")
            report_dict = {}

        # Build default formatted findings if agent didn't return them
        formatted_findings = report_dict.get("formatted_findings", [])
        if not formatted_findings:
            formatted_findings = [
                {
                    "finding_id": f.id,
                    "report_title": f"{f.severity.capitalize()}: {f.name} in {f.host}",
                    "severity": f.severity.capitalize(),
                    "cvss_score": f.cvss_score,
                    "formatted_description": f.description,
                    "impact_statement": f"This {f.severity} severity vulnerability requires attention.",
                    "poc_steps": f.poc_steps or "Manual verification required.",
                    "remediation": "Refer to OWASP guidelines for remediation advice.",
                    "references": ["https://owasp.org/www-project-top-ten/"],
                }
                for f in analysis.true_positives
            ]

        # Sort disclosures by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            analysis.true_positives,
            key=lambda f: (severity_order.get(f.severity, 9), f.name),
        )
        recommended_disclosures = report_dict.get(
            "recommended_disclosures",
            [f.id for f in sorted_findings],
        )

        executive_summary = report_dict.get(
            "executive_summary",
            analysis.executive_summary,
        )

        remediation_roadmap = report_dict.get(
            "remediation_roadmap",
            _build_default_roadmap(analysis),
        )

        return {
            "executive_summary": executive_summary,
            "formatted_findings": formatted_findings,
            "recommended_disclosures": recommended_disclosures,
            "remediation_roadmap": remediation_roadmap,
        }


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _get_remediation(name: str, tags: list[str], description: str) -> str:
    """Return targeted remediation advice based on vulnerability characteristics."""
    name_lower = name.lower()
    tags_lower = [t.lower() for t in tags]
    combined = name_lower + " " + " ".join(tags_lower)

    if "xss" in combined or "cross-site-scripting" in combined:
        return (
            "Implement Content Security Policy (CSP) headers. Encode all user-supplied "
            "data before rendering in HTML using a context-aware encoding library "
            "(e.g. OWASP Java Encoder, DOMPurify). Validate and sanitize input on "
            "the server side. Use the `HttpOnly` and `Secure` cookie flags."
        )
    if "sqli" in combined or "sql injection" in combined:
        return (
            "Use parameterised queries or prepared statements for all database interactions. "
            "Never concatenate user input directly into SQL strings. Implement an ORM where "
            "possible. Apply the principle of least privilege to database accounts. "
            "Enable Web Application Firewall (WAF) rules for SQL injection patterns."
        )
    if "ssrf" in combined:
        return (
            "Validate and whitelist allowed URL schemes and destinations. Block requests to "
            "private IP ranges (RFC 1918) and link-local addresses (169.254.0.0/16). "
            "Use a dedicated egress proxy with allow-listing. Disable unnecessary URL "
            "fetching features in application libraries."
        )
    if "open redirect" in combined or "redirect" in combined:
        return (
            "Avoid using user-supplied input to construct redirect URLs. If redirects are "
            "necessary, use an allow-list of permitted destinations. Validate the redirect "
            "target against the application's own domain. Use relative URLs for internal "
            "redirects."
        )
    if "lfi" in combined or "path traversal" in combined or "directory traversal" in combined:
        return (
            "Canonicalize file paths and validate they remain within the intended directory. "
            "Use `realpath()` or equivalent to resolve symlinks before path validation. "
            "Avoid passing user input directly to file system operations. "
            "Run the application with minimal filesystem permissions."
        )
    if "rce" in combined or "remote code execution" in combined or "command injection" in combined:
        return (
            "Never pass user-supplied data to shell commands. Use language-native APIs instead "
            "of shell execution. If shell execution is unavoidable, use parameterised arguments "
            "and an allow-list for permitted commands. Apply network segmentation to limit "
            "blast radius."
        )
    if "csrf" in combined:
        return (
            "Implement CSRF tokens on all state-changing requests. Use the SameSite=Strict "
            "cookie attribute. Validate the Origin and Referer headers on sensitive endpoints."
        )
    if "ssl" in combined or "tls" in combined or "certificate" in combined:
        return (
            "Update TLS configuration to use TLS 1.2 or 1.3 only. Disable weak cipher suites "
            "and obsolete protocols (SSLv3, TLS 1.0, TLS 1.1). Ensure certificates are valid, "
            "properly chained, and renewed before expiry. Enable HSTS with a long max-age."
        )
    if "exposure" in combined or "disclosure" in combined or "information" in combined:
        return (
            "Remove or restrict access to endpoints that expose sensitive information. "
            "Disable debug modes, verbose error messages, and stack traces in production. "
            "Review server headers and remove version information. Implement proper "
            "access controls on sensitive paths."
        )

    # Generic remediation
    return (
        f"Review the affected component at `{name}` and apply the principle of least privilege. "
        "Consult the OWASP Testing Guide for vulnerability-specific remediation guidance. "
        "Implement defence-in-depth controls and conduct a targeted code review of the affected "
        "functionality."
    )


def _build_default_roadmap(analysis: AnalysisResult) -> str:
    """Build a plain-text remediation roadmap from the analysis result."""
    lines: list[str] = ["## Remediation Roadmap\n"]

    if analysis.total_critical > 0:
        lines.append(
            f"**Immediate (0-48 hours):** Address {analysis.total_critical} critical "
            "vulnerability/vulnerabilities. These represent severe risk and should be patched "
            "or mitigated immediately, even if it requires emergency maintenance windows.\n"
        )
    if analysis.total_high > 0:
        lines.append(
            f"**Short-term (1-2 weeks):** Remediate {analysis.total_high} high severity "
            "finding(s). Schedule into the next sprint and treat as a priority release.\n"
        )
    if analysis.total_medium > 0:
        lines.append(
            f"**Medium-term (1 month):** Fix {analysis.total_medium} medium severity "
            "finding(s) in the upcoming release cycle.\n"
        )
    if analysis.total_low > 0:
        lines.append(
            f"**Long-term (quarterly):** Address {analysis.total_low} low severity "
            "finding(s) as part of routine security hygiene.\n"
        )

    if analysis.high_impact_chains:
        lines.append(
            f"\n**Vulnerability Chains:** {len(analysis.high_impact_chains)} vulnerability "
            "chain(s) were identified. These should be treated as a single high-priority "
            "remediation item regardless of the individual finding severities.\n"
        )

    return "\n".join(lines)
