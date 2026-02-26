"""Reporter agent: formats findings into professional bug bounty reports."""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urlparse

from bugbounty.agents.base import AgentTool, BaseAgent
from bugbounty.core.llm import LLMProvider
from bugbounty.db.models import AnalysisResult, Finding, LiveHost, ScanRun

logger = logging.getLogger(__name__)

# CWE identifiers by vulnerability class
CWE_MAP: dict[str, str] = {
    "ssrf": "CWE-918",
    "xss": "CWE-79",
    "cors": "CWE-942",
    "open redirect": "CWE-601",
    "redirect": "CWE-601",
    "takeover": "CWE-284",
    "git": "CWE-538",
    "env": "CWE-312",
    "actuator": "CWE-215",
    "graphql": "CWE-200",
    "exposure": "CWE-200",
    "secret": "CWE-312",
    "sqli": "CWE-89",
    "lfi": "CWE-22",
    "rce": "CWE-78",
    "csrf": "CWE-352",
}

# CVSS 3.1 vector strings for common finding types
CVSS_VECTORS: dict[str, str] = {
    "ssrf_oob": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    "ssrf_error": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N",
    "xss_reflected": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "cors_critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "cors_high": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "open_redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "takeover": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "env_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "git_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
}

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

        # Determine CWE and CVSS vector
        name_lower = name.lower()
        tags_lower = [t.lower() for t in tags]
        combined_lower = name_lower + " " + " ".join(tags_lower)

        cwe_id = "CWE-200"  # default: information exposure
        for kw, cwe in CWE_MAP.items():
            if kw in combined_lower:
                cwe_id = cwe
                break

        # Determine CVSS vector
        cvss_vector = _get_cvss_vector(name_lower, tags_lower, description)

        # Build platform-ready report title
        try:
            parsed_host = urlparse(host if "://" in host else f"https://{host}")
            host_display = parsed_host.netloc or host
        except Exception:
            host_display = host
        report_title = _build_report_title(name, host_display, matched_at, description)

        # Build curl PoC
        curl_poc = _build_curl_poc(name_lower, matched_at, description)

        # Business impact statement
        business_impact = _build_business_impact(name_lower, severity, description)

        # Build formatted title (internal)
        title = report_title

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
                "cvss_vector": cvss_vector,
                "cwe_id": cwe_id,
                "formatted_description": formatted_description,
                "impact_statement": impact,
                "business_impact": business_impact,
                "poc_steps": poc_formatted,
                "curl_poc": curl_poc,
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

def _get_cvss_vector(name_lower: str, tags_lower: list[str], description: str) -> str:
    """Return an appropriate CVSS 3.1 vector string for the finding type."""
    combined = name_lower + " " + " ".join(tags_lower) + " " + description.lower()

    if "ssrf" in combined:
        if "oob" in combined or "confirmed" in combined:
            return CVSS_VECTORS["ssrf_oob"]
        return CVSS_VECTORS["ssrf_error"]
    if "xss" in combined or "cross-site scripting" in combined:
        return CVSS_VECTORS["xss_reflected"]
    if "cors" in combined:
        if "credential" in combined or "critical" in combined:
            return CVSS_VECTORS["cors_critical"]
        return CVSS_VECTORS["cors_high"]
    if "redirect" in combined:
        return CVSS_VECTORS["open_redirect"]
    if "takeover" in combined:
        return CVSS_VECTORS["takeover"]
    if ".env" in combined or "env file" in combined or "env exposure" in combined:
        return CVSS_VECTORS["env_exposure"]
    if "git" in combined and "expos" in combined:
        return CVSS_VECTORS["git_exposure"]

    # Generic: network-accessible, low complexity, no auth, information exposure
    return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"


def _build_report_title(name: str, host: str, matched_at: str, description: str) -> str:
    """Build a platform-ready, concise report title."""
    name_lower = name.lower()
    # Extract the most useful part of matched_at for the title
    try:
        from urllib.parse import urlparse as _urlparse
        parsed = _urlparse(matched_at if "://" in matched_at else f"https://{matched_at}")
        path = parsed.path or "/"
    except Exception:
        path = "/"

    if "ssrf" in name_lower:
        return f"SSRF via URL parameter on {host} allows internal network access"
    if "cors" in name_lower or "cross-origin" in name_lower:
        return f"CORS misconfiguration on {host} enables cross-origin data theft"
    if "xss" in name_lower:
        return f"Reflected XSS on {host} via {path}"
    if "redirect" in name_lower:
        return f"Open redirect on {host} enables phishing via {path}"
    if "takeover" in name_lower:
        return f"Subdomain takeover possible on {host}"
    if "git" in name_lower and "expo" in name_lower:
        return f"Exposed .git directory on {host} leaks source code"
    if ".env" in name_lower or "env file" in name_lower:
        return f"Exposed .env file on {host} leaks credentials"
    if "actuator" in name_lower:
        return f"Spring Boot Actuator endpoints exposed on {host}"
    if "graphql" in name_lower:
        return f"GraphQL introspection enabled on {host} reveals full API schema"
    if "secret" in name_lower:
        return f"Hardcoded secret in JavaScript file on {host}"
    # Generic fallback
    return f"{name} on {host}"


def _build_curl_poc(name_lower: str, matched_at: str, description: str) -> str:
    """Build a ready-to-paste curl PoC command for common vulnerability types."""
    combined = name_lower + " " + description.lower()

    if "ssrf" in combined:
        return (
            f'curl -sk "{matched_at}?url=http://169.254.169.254/latest/meta-data/" | head -20'
        )
    if "cors" in combined:
        return (
            f'curl -sk -H "Origin: https://evil.com" -I "{matched_at}"'
        )
    if "redirect" in combined:
        # Try to show a param-based example
        sep = "&" if "?" in matched_at else "?"
        return (
            f'curl -sk -L "{matched_at}{sep}next=https://evil.com" '
            f'-o /dev/null -w "%{{url_effective}}"'
        )
    if ".env" in combined or "env file" in combined:
        try:
            from urllib.parse import urlparse as _up
            base = _up(matched_at)
            base_url = f"{base.scheme}://{base.netloc}"
        except Exception:
            base_url = matched_at
        return f'curl -sk "{base_url}/.env"'
    if "git" in combined:
        try:
            from urllib.parse import urlparse as _up
            base = _up(matched_at)
            base_url = f"{base.scheme}://{base.netloc}"
        except Exception:
            base_url = matched_at
        return f'curl -sk "{base_url}/.git/config"'
    if "actuator" in combined:
        try:
            from urllib.parse import urlparse as _up
            base = _up(matched_at)
            base_url = f"{base.scheme}://{base.netloc}"
        except Exception:
            base_url = matched_at
        return f'curl -sk "{base_url}/actuator/env" | python3 -m json.tool'
    if "graphql" in combined:
        return (
            f"curl -sk -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}' "
            f"'{matched_at}'"
        )
    if "xss" in combined:
        sep = "&" if "?" in matched_at else "?"
        return (
            f'curl -sk "{matched_at}{sep}q=%3Cscript%3Ealert(1)%3C/script%3E" '
            f'| grep -i "script"'
        )

    # Generic: just fetch the endpoint
    return f'curl -sk "{matched_at}"'


def _build_business_impact(name_lower: str, severity: str, description: str) -> str:
    """Build a 2-3 sentence business risk statement."""
    combined = name_lower + " " + description.lower()

    if "ssrf" in combined:
        return (
            "Server-Side Request Forgery allows attackers to coerce the server into making "
            "outbound requests to internal services, potentially exposing cloud credentials "
            "(via AWS IMDS), internal APIs, or sensitive configuration data. "
            "In cloud-hosted environments, successful exploitation can lead to full cloud "
            "account compromise via IAM credential theft. "
            "This represents a direct path to lateral movement within the internal network."
        )
    if "cors" in combined and ("credential" in combined or "critical" in combined.lower()):
        return (
            "Critical CORS misconfiguration allows any attacker-controlled website to "
            "make authenticated cross-origin requests on behalf of logged-in users. "
            "This enables full account takeover: an attacker can read session tokens, "
            "personal data, and perform any action the victim can perform. "
            "All users who visit a malicious page while logged in are at immediate risk."
        )
    if "cors" in combined:
        return (
            "CORS misconfiguration allows cross-origin requests from untrusted origins, "
            "potentially exposing sensitive response data to attacker-controlled pages. "
            "While credentials cannot be sent with wildcard origins, any unauthenticated "
            "data visible in the response can be exfiltrated. "
            "Attackers can systematically extract API responses from any victim's browser."
        )
    if "takeover" in combined:
        return (
            "Subdomain takeover allows an attacker to host malicious content under the "
            "organisation's trusted domain, lending credibility to phishing attacks. "
            "If the parent domain uses broad cookie scope, the attacker may steal session "
            "cookies for users who visit the compromised subdomain. "
            "Users have no way to distinguish attacker-controlled content from legitimate content."
        )
    if ".env" in combined or "env file" in combined:
        return (
            "Exposed environment files contain production credentials including database "
            "passwords, API keys, and encryption secrets in plaintext. "
            "Any unauthenticated user can download this file and gain full access to "
            "connected backend services, databases, and third-party APIs. "
            "This is a critical data breach risk requiring immediate remediation."
        )
    if "git" in combined:
        return (
            "Exposed Git repository allows attackers to download the complete application "
            "source code, commit history, and any secrets ever committed to the repository. "
            "This provides a roadmap for finding additional vulnerabilities and may expose "
            "credentials, private keys, or internal architecture details. "
            "Once source code is exfiltrated, it cannot be recalled."
        )
    if "redirect" in combined:
        return (
            "Open redirects are frequently exploited in phishing campaigns to redirect "
            "victims from a trusted domain to a malicious site, bypassing URL reputation filters. "
            "When combined with OAuth flows, open redirects can be used to steal access tokens "
            "by redirecting the authorization code to an attacker-controlled server. "
            "This compounds to an account takeover risk for OAuth-enabled applications."
        )
    if "xss" in combined:
        return (
            "Cross-Site Scripting allows execution of arbitrary JavaScript in the context of "
            "the victim's browser session, enabling session hijacking, credential theft, and "
            "UI redressing attacks. "
            "Attackers can exfiltrate cookies, local storage tokens, and any data visible in "
            "the DOM, then use these credentials for account takeover. "
            "All users who can be directed to the vulnerable page are affected."
        )
    if "actuator" in combined:
        return (
            "Exposed Spring Boot Actuator endpoints reveal sensitive operational data including "
            "environment variables, configuration properties, and application internals. "
            "The /actuator/heapdump endpoint may expose in-memory credentials, session tokens, "
            "and cryptographic material. "
            "This information significantly reduces the effort required for further exploitation."
        )
    if "graphql" in combined:
        return (
            "Enabled GraphQL introspection exposes the complete API schema to unauthenticated "
            "users, revealing all types, queries, mutations, and their parameters. "
            "This provides attackers with a detailed blueprint for targeting sensitive operations, "
            "testing for authorisation bypasses, and discovering hidden functionality. "
            "Schema exposure is the first step in a GraphQL-targeted attack chain."
        )
    if "secret" in combined:
        return (
            "Hardcoded secrets in publicly accessible JavaScript files allow any user to extract "
            "API credentials that may grant access to third-party services, cloud resources, "
            "or internal APIs. "
            "Unlike server-side secrets, these cannot be protected by access controls once published. "
            "Rotation of all exposed credentials is required immediately."
        )

    # Generic
    severity_lower = severity.lower()
    return (
        f"This {severity_lower} severity vulnerability poses a tangible risk to the "
        "confidentiality, integrity, or availability of the affected system. "
        "Successful exploitation by a malicious actor could result in unauthorised data access "
        "or system compromise. "
        "Remediation should be prioritised according to the severity rating."
    )


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
    if "cors" in combined:
        return (
            "Implement a strict CORS allowlist: explicitly enumerate trusted origins rather than "
            "reflecting the request Origin header. Never use Access-Control-Allow-Origin: * with "
            "Access-Control-Allow-Credentials: true (browsers block this per spec, but explicit "
            "reflection creates the same vulnerability). Validate origins against a server-side "
            "allowlist using exact string comparison. Reject or ignore requests from unlisted origins."
        )
    if "takeover" in combined or "subdomain" in combined:
        return (
            "Immediately remove the dangling CNAME DNS record for this subdomain, or provision "
            "a valid resource on the target service to prevent registration by an attacker. "
            "Audit all subdomains for similar dangling CNAME patterns using automated tools. "
            "Implement a process to remove DNS records when cloud services are decommissioned. "
            "Consider using CNAME flattening where the DNS provider resolves CNAMEs and returns "
            "the final A record, preventing third-party service claims."
        )
    if "git" in combined and ("expos" in combined or "disclos" in combined):
        return (
            "Immediately restrict access to the /.git/ directory using web server configuration "
            "(e.g. deny all in .htaccess or Nginx location block). "
            "Rotate all credentials that may have been committed to the repository history. "
            "Review git log for historically committed secrets: git log -p | grep -i password. "
            "Consider using git-secrets or pre-commit hooks to prevent future secret commits."
        )
    if ".env" in combined or "env file" in combined:
        return (
            "Remove or restrict web server access to .env and all configuration backup files. "
            "Configure your web server to deny requests for dot-files (files starting with '.'). "
            "Immediately rotate all credentials found in the exposed file. "
            "Use a secrets management solution (AWS Secrets Manager, HashiCorp Vault) rather than "
            "storing secrets in environment files on the filesystem."
        )
    if "actuator" in combined:
        return (
            "Restrict Spring Boot Actuator endpoints to internal networks only using Spring "
            "Security or network-level access controls. In application.properties, set: "
            "management.endpoints.web.exposure.include=health,info and disable heapdump/threaddump. "
            "If Actuator must be accessible, require authentication: "
            "management.endpoint.health.show-details=when-authorized. "
            "Regularly audit which endpoints are exposed in production."
        )
    if "graphql" in combined:
        return (
            "Disable GraphQL introspection in production environments. In most GraphQL frameworks "
            "this is a single configuration flag (e.g. graphql.introspection.enabled=false). "
            "Implement query depth limiting and complexity analysis to prevent abuse. "
            "Enforce authentication on all sensitive GraphQL operations. "
            "Use a GraphQL-aware WAF rule to block introspection queries from external clients."
        )
    if "secret" in combined and "javascript" in combined:
        return (
            "Never include secrets, API keys, or credentials in client-side JavaScript files. "
            "Move all sensitive operations server-side and expose only public-facing data to the "
            "frontend. Immediately rotate all exposed credentials. "
            "Use environment variable injection at build time for build-time constants (not secrets). "
            "Implement a CI/CD secret scanning step (e.g. truffleHog, git-secrets) to prevent "
            "future secret leaks."
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
