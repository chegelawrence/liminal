"""Planner agent: creates a prioritized recon strategy."""

from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import BaseModel

from bugbounty.agents.base import AgentTool, BaseAgent
from bugbounty.core.config import ScopeConfig
from bugbounty.core.llm import LLMProvider

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are an expert bug bounty hunter and recon strategist with over a decade of
experience finding high-severity vulnerabilities in large organisations.

Your task is to analyse a bug bounty programme's scope and create a prioritised, tactical recon
plan that maximises the chance of finding high-impact vulnerabilities efficiently.

When analysing scope, consider:
- Which subdomains/assets are most likely to run interesting business logic
- Which technology stacks are historically vulnerable
- Which areas are under-tested (legacy systems, APIs, admin panels)
- Which paths lead to the highest bounty payouts

Use the available tools to reason about the scope and produce a structured plan.
Return your final plan as a JSON object matching the ReconPlan schema."""


class ReconPlan(BaseModel):
    """Structured recon strategy returned by the PlannerAgent."""

    target_domain: str
    priority_subdomains: list[str]
    recommended_scan_types: list[str]
    technology_focus: list[str]
    notes: str


class PlannerAgent(BaseAgent):
    """AI planner that creates a prioritised recon strategy for a target."""

    def __init__(self, provider: LLMProvider) -> None:
        super().__init__(provider)

    def get_tools(self) -> list[AgentTool]:
        return [
            {
                "name": "analyze_program_scope",
                "description": (
                    "Analyse the bug bounty programme's in-scope and out-of-scope assets "
                    "to identify the highest-value targets.  Returns a prioritised list of "
                    "assets and initial risk assessment."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "in_scope": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of in-scope domains/wildcards",
                        },
                        "out_of_scope": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of out-of-scope domains",
                        },
                        "program_platform": {
                            "type": "string",
                            "description": "Bug bounty platform (HackerOne, Bugcrowd, etc.)",
                        },
                    },
                    "required": ["in_scope", "out_of_scope"],
                },
            },
            {
                "name": "prioritize_attack_surface",
                "description": (
                    "Given known subdomains and detected technologies, return a prioritised "
                    "list of attack vectors and recommended scan types."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "subdomains": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Known subdomains",
                        },
                        "technologies": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Detected technologies (e.g. WordPress, Spring Boot)",
                        },
                    },
                    "required": ["subdomains"],
                },
            },
        ]

    async def process_tool_call(self, tool_name: str, tool_input: dict) -> str:
        if tool_name == "analyze_program_scope":
            return await self._analyze_scope(tool_input)
        if tool_name == "prioritize_attack_surface":
            return await self._prioritize_surface(tool_input)
        return json.dumps({"error": f"Unknown tool: {tool_name}"})

    # ------------------------------------------------------------------
    # Tool implementations
    # ------------------------------------------------------------------

    async def _analyze_scope(self, inp: dict) -> str:
        in_scope: list[str] = inp.get("in_scope", [])
        out_of_scope: list[str] = inp.get("out_of_scope", [])
        platform: str = inp.get("program_platform", "Unknown")

        # Classify assets
        wildcards = [s for s in in_scope if s.startswith("*")]
        exact = [s for s in in_scope if not s.startswith("*")]

        risk_map: dict[str, str] = {}
        for asset in in_scope:
            domain = asset.lstrip("*.")
            if any(kw in domain for kw in ["api", "admin", "internal", "dev", "staging"]):
                risk_map[asset] = "high"
            elif any(kw in domain for kw in ["auth", "login", "account", "pay", "checkout"]):
                risk_map[asset] = "high"
            elif wildcards and asset in wildcards:
                risk_map[asset] = "medium"
            else:
                risk_map[asset] = "medium"

        return json.dumps(
            {
                "total_in_scope": len(in_scope),
                "total_out_of_scope": len(out_of_scope),
                "wildcard_scopes": wildcards,
                "exact_scopes": exact,
                "platform": platform,
                "risk_classification": risk_map,
                "recommended_focus": [k for k, v in risk_map.items() if v == "high"],
                "notes": (
                    f"Found {len(wildcards)} wildcard scope entries covering potentially "
                    f"thousands of subdomains.  Prioritise API endpoints, admin panels, "
                    f"and authentication surfaces."
                ),
            }
        )

    async def _prioritize_surface(self, inp: dict) -> str:
        subdomains: list[str] = inp.get("subdomains", [])
        technologies: list[str] = inp.get("technologies", [])

        # Score subdomains based on naming conventions
        scored: list[tuple[int, str]] = []
        for sd in subdomains:
            score = 0
            lower = sd.lower()
            if any(kw in lower for kw in ["api", "graphql", "rest", "rpc"]):
                score += 10
            if any(kw in lower for kw in ["admin", "manage", "dashboard", "panel", "console"]):
                score += 9
            if any(kw in lower for kw in ["auth", "login", "oauth", "sso", "iam", "token"]):
                score += 8
            if any(kw in lower for kw in ["dev", "staging", "test", "uat", "qa", "beta"]):
                score += 7  # Often less hardened
            if any(kw in lower for kw in ["pay", "billing", "checkout", "wallet"]):
                score += 9
            if any(kw in lower for kw in ["internal", "intranet", "corp", "vpn"]):
                score += 8
            if any(kw in lower for kw in ["upload", "download", "media", "file", "cdn"]):
                score += 6
            scored.append((score, sd))

        scored.sort(reverse=True)
        priority_list = [sd for _, sd in scored[:20]]

        # Recommend scan types based on technologies
        scan_types: list[str] = ["nuclei-full", "directory-bruteforce"]
        tech_lower = [t.lower() for t in technologies]
        if any(t in tech_lower for t in ["wordpress", "joomla", "drupal"]):
            scan_types.append("cms-specific-nuclei")
            scan_types.append("wpscan")
        if any(t in tech_lower for t in ["spring", "java", "tomcat"]):
            scan_types.append("java-deserialization-check")
            scan_types.append("spring-actuator-exposure")
        if any(t in tech_lower for t in ["graphql"]):
            scan_types.append("graphql-introspection")
            scan_types.append("graphql-injection")
        if any(t in tech_lower for t in ["nginx", "apache"]):
            scan_types.append("web-server-misconfig")
        if any(t in tech_lower for t in ["aws", "azure", "gcp", "s3"]):
            scan_types.append("cloud-misconfig")

        # Technology focus for report
        tech_focus: list[str] = list({t for t in technologies if t})[:10]

        return json.dumps(
            {
                "priority_subdomains": priority_list,
                "recommended_scan_types": scan_types,
                "technology_focus": tech_focus,
                "total_subdomains_evaluated": len(subdomains),
            }
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def create_plan(
        self,
        target: str,
        scope: ScopeConfig,
        program_info: dict[str, Any],
    ) -> ReconPlan:
        """Create a ReconPlan for *target* using the configured scope.

        Args:
            target:       The primary target domain.
            scope:        ScopeConfig with in_scope/out_of_scope lists.
            program_info: Extra info about the programme (name, platform, etc.)

        Returns:
            A populated ReconPlan instance.
        """
        user_message = (
            f"Create a prioritised recon plan for the following bug bounty programme:\n\n"
            f"Target domain: {target}\n"
            f"Programme name: {program_info.get('program_name', 'Unknown')}\n"
            f"Platform: {program_info.get('platform', 'Unknown')}\n\n"
            f"In-scope assets:\n"
            + "\n".join(f"  - {s}" for s in scope.in_scope)
            + "\n\nOut-of-scope assets:\n"
            + "\n".join(f"  - {s}" for s in scope.out_of_scope)
            + "\n\n"
            "Use the available tools to analyse the scope and produce a structured recon plan. "
            "Return the final plan as a JSON object with these keys: "
            "target_domain, priority_subdomains, recommended_scan_types, "
            "technology_focus, notes."
        )

        final_text = await self.run_agentic_loop(
            system_prompt=_SYSTEM_PROMPT,
            user_message=user_message,
            max_iterations=10,
        )

        # Extract JSON from the response
        try:
            # Try to find a JSON block in the response
            json_start = final_text.find("{")
            json_end = final_text.rfind("}") + 1
            if json_start != -1 and json_end > json_start:
                plan_dict = json.loads(final_text[json_start:json_end])
            else:
                plan_dict = json.loads(final_text)

            return ReconPlan(
                target_domain=plan_dict.get("target_domain", target),
                priority_subdomains=plan_dict.get("priority_subdomains", []),
                recommended_scan_types=plan_dict.get("recommended_scan_types", []),
                technology_focus=plan_dict.get("technology_focus", []),
                notes=plan_dict.get("notes", ""),
            )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("Could not parse plan JSON: %s – using defaults", exc)
            return ReconPlan(
                target_domain=target,
                priority_subdomains=[],
                recommended_scan_types=["nuclei", "directory-bruteforce"],
                technology_focus=[],
                notes=final_text[:500] if final_text else "Planning failed",
            )
