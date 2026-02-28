"""LLM-powered anomaly analysis agent for novel vulnerability detection.

Three-stage pipeline:
  Stage 1 – analyze_anomaly:  LLM classifies the vulnerability from a closed list
  Stage 2 – design_probe:     LLM designs a targeted HTTP confirmation probe
  Stage 3 – evaluate_result:  Framework executes probe; LLM evaluates actual response

False-positive prevention is enforced at every stage:
  Gate 2a – formulate_hypothesis: rejects "other" class and low confidence
  Gate 3a – design_confirmation_probe: rejects vague "confirms_if" patterns
  Gate 3c – evaluate_confirmation: forces confirmed=False when evidence is
             empty or generic — the LLM cannot hallucinate a confirmed finding
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional

from bugbounty.agents.base import AgentTool, BaseAgent
from bugbounty.core.config import AppConfig
from bugbounty.core.llm import create_provider
from bugbounty.tools.anomaly import AnomalyResult, ResponseSummary

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ALLOWED_CLASSES: frozenset[str] = frozenset({
    "path-traversal",
    "ssrf",
    "xxe",
    "method-confusion",
    "info-disclosure",
    "injection",
    "auth-bypass",
    "header-injection",
    "content-type-confusion",
    "parameter-pollution",
    "idok-exposure",
    "debug-interface",
})

# Substrings that indicate a vague (unacceptable) confirms_if pattern
_VAGUE_CONFIRMS: tuple[str, ...] = (
    "status changes",
    "different response",
    "response length",
    "any change",
    "status code",
    "status differs",
    "different status",
    "response differs",
    "changes",
)

# Sentinel returned by process_tool_call to signal hypothesis rejection
_REJECTED = "__REJECTED__"

_SYSTEM_PROMPT = """\
You are a senior security researcher conducting authorized vulnerability confirmation.

You have received an HTTP anomaly — a specific probe produced a divergent response
compared to the baseline. Determine whether this represents a real, exploitable
vulnerability by working through three tool calls in order.

CRITICAL RULES:
1. formulate_hypothesis MUST be your first tool call. You must name a specific
   vulnerability_class from the allowed list. Set confidence="low" if uncertain.
2. design_confirmation_probe: the confirms_if field MUST be a specific content string
   that would ONLY appear in the response if vulnerable — e.g. "root:x:0:0" for path
   traversal, "JAVA_HOME=" for info-disclosure, "TRACE / HTTP/1.1" for method-confusion.
   Status codes and response lengths are NOT acceptable confirmation criteria.
3. evaluate_confirmation: set confirmed=true ONLY if the exact content pattern you
   predicted ACTUALLY appears in the response body or headers shown to you. If you are
   not certain, set confirmed=false. A false positive wastes the researcher's
   reputation — conservative is always correct.
4. Minimum reportable severity: medium. Never report low or info."""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AnomalyHypothesis:
    """LLM's classification of the anomaly."""

    vulnerability_class: str   # from _ALLOWED_CLASSES
    reasoning: str
    confidence: str            # "high" | "medium" | "low"
    impact: str


@dataclass
class ConfirmationProbe:
    """HTTP probe designed by the LLM to confirm the hypothesised vulnerability."""

    method: str
    url: str                   # full URL
    headers: dict              # str → str
    body: Optional[str]
    confirms_if: str           # specific content that MUST appear if vulnerable
    denies_if: str             # content that means not vulnerable


@dataclass
class ConfirmationResult:
    """Outcome of the probe execution + LLM evaluation."""

    confirmed: bool
    confidence: str            # "high" | "medium" | "not_confirmed"
    evidence: str              # exact text from response confirming the finding
    vulnerability_class: str
    severity: str              # critical | high | medium only
    description: str
    poc_request: str           # curl command for PoC


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class AnomalyAnalysisAgent(BaseAgent):
    """Three-stage LLM agent for novel vulnerability confirmation.

    Each stage is a separate ``run_agentic_loop`` call with ``max_iterations=4``.
    Provider instantiation follows the same pattern as ``AIPathGenerator``.
    """

    def __init__(self, config: AppConfig) -> None:
        provider = create_provider(
            name=config.ai.provider,
            anthropic_api_key=config.anthropic_api_key,
            openai_api_key=config.openai_api_key,
            claude_model=config.ai.claude_model,
            openai_model=config.ai.openai_model,
            max_tokens=4096,
            temperature=0,
        )
        super().__init__(provider)
        self._config = config
        # Mutable state updated via tool calls in each stage
        self._hypothesis: Optional[AnomalyHypothesis] = None
        self._probe: Optional[ConfirmationProbe] = None
        self._confirmation: Optional[ConfirmationResult] = None
        self._stage_rejected: bool = False

    # ------------------------------------------------------------------
    # Tool definitions
    # ------------------------------------------------------------------

    def get_tools(self) -> list[AgentTool]:
        return [
            {
                "name": "formulate_hypothesis",
                "description": (
                    "Declare your vulnerability hypothesis. Must be your first tool call. "
                    "Pick the most specific vulnerability_class from the allowed list. "
                    "Set confidence='low' if uncertain — the analysis will stop."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "vulnerability_class": {
                            "type": "string",
                            "description": (
                                "One of: path-traversal | ssrf | xxe | method-confusion | "
                                "info-disclosure | injection | auth-bypass | header-injection | "
                                "content-type-confusion | parameter-pollution | "
                                "idok-exposure | debug-interface"
                            ),
                        },
                        "reasoning": {
                            "type": "string",
                            "description": "Why you believe this class fits the observed anomaly.",
                        },
                        "confidence": {
                            "type": "string",
                            "enum": ["high", "medium", "low"],
                        },
                        "impact": {
                            "type": "string",
                            "description": "Potential security impact if confirmed.",
                        },
                    },
                    "required": [
                        "vulnerability_class", "reasoning", "confidence", "impact"
                    ],
                },
            },
            {
                "name": "design_confirmation_probe",
                "description": (
                    "Design a targeted HTTP request to confirm the vulnerability. "
                    "confirms_if MUST be a specific content string (not a description "
                    "of behaviour change) that would only appear if vulnerable."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "method": {"type": "string"},
                        "url": {
                            "type": "string",
                            "description": "Full URL to probe.",
                        },
                        "headers": {
                            "type": "object",
                            "additionalProperties": {"type": "string"},
                            "description": "Request headers.",
                        },
                        "body": {
                            "type": "string",
                            "description": "Request body or null.",
                        },
                        "confirms_if": {
                            "type": "string",
                            "description": (
                                "Specific content string that MUST appear in the response "
                                "to confirm vulnerability. Example: 'root:x:0:0' for path "
                                "traversal, 'JAVA_HOME=' for info-disclosure. "
                                "NOT acceptable: 'status changes', 'response differs', "
                                "'different status', 'response length'."
                            ),
                        },
                        "denies_if": {
                            "type": "string",
                            "description": "Content whose presence means NOT vulnerable.",
                        },
                    },
                    "required": ["method", "url", "confirms_if", "denies_if"],
                },
            },
            {
                "name": "evaluate_confirmation",
                "description": (
                    "Evaluate whether the confirmation probe response actually confirms "
                    "the vulnerability. Set confirmed=true ONLY if the specific content "
                    "you predicted is present in the response shown to you."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "confirmed": {
                            "type": "boolean",
                            "description": (
                                "True only if the specific evidence content appears in the "
                                "response. False otherwise."
                            ),
                        },
                        "confidence": {
                            "type": "string",
                            "enum": ["high", "medium", "not_confirmed"],
                        },
                        "evidence": {
                            "type": "string",
                            "description": (
                                "Exact text snippet from the response that confirms the "
                                "vulnerability. Must be a specific, non-empty string. "
                                "Empty or vague evidence will force confirmed=false."
                            ),
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium"],
                            "description": "Minimum: medium.",
                        },
                        "description": {
                            "type": "string",
                            "description": "Clear description of the confirmed vulnerability.",
                        },
                        "poc_request": {
                            "type": "string",
                            "description": "curl command to reproduce the finding.",
                        },
                    },
                    "required": [
                        "confirmed", "confidence", "evidence",
                        "severity", "description", "poc_request",
                    ],
                },
            },
        ]

    # ------------------------------------------------------------------
    # Tool handler — implements all three FP gates
    # ------------------------------------------------------------------

    async def process_tool_call(self, tool_name: str, tool_input: dict) -> str:
        """Execute a tool call and enforce FP prevention gates."""

        if tool_name == "formulate_hypothesis":
            return self._handle_formulate_hypothesis(tool_input)

        if tool_name == "design_confirmation_probe":
            return self._handle_design_probe(tool_input)

        if tool_name == "evaluate_confirmation":
            return self._handle_evaluate_confirmation(tool_input)

        return json.dumps({"error": f"Unknown tool: {tool_name}"})

    def _handle_formulate_hypothesis(self, ti: dict) -> str:
        vuln_class = ti.get("vulnerability_class", "").lower().strip()
        confidence = ti.get("confidence", "").lower()
        reasoning = ti.get("reasoning", "")
        impact = ti.get("impact", "")

        # Gate 2a: class must be in the closed list
        if vuln_class not in _ALLOWED_CLASSES:
            self._hypothesis = None
            return json.dumps({
                "status": "rejected",
                "reason": (
                    f"'{vuln_class}' is not in the allowed vulnerability class list. "
                    "Choose from the documented list."
                ),
            })

        # Gate 2b: confidence must be medium or high
        if confidence == "low":
            self._stage_rejected = True
            self._hypothesis = None
            return json.dumps({
                "status": "rejected",
                "action": _REJECTED,
                "reason": (
                    "Confidence 'low' is insufficient. "
                    "Analysis stops — this anomaly will not produce a finding."
                ),
            })

        self._hypothesis = AnomalyHypothesis(
            vulnerability_class=vuln_class,
            reasoning=reasoning,
            confidence=confidence,
            impact=impact,
        )
        return json.dumps({
            "status": "accepted",
            "vulnerability_class": vuln_class,
            "next_step": "Call design_confirmation_probe to design the confirmation request.",
        })

    def _handle_design_probe(self, ti: dict) -> str:
        method = ti.get("method", "GET").upper()
        url = ti.get("url", "").strip()
        headers = ti.get("headers") or {}
        body = ti.get("body") or None
        confirms_if = ti.get("confirms_if", "").strip()
        denies_if = ti.get("denies_if", "").strip()

        # Gate 3a: confirms_if must not be vague
        confirms_lower = confirms_if.lower()
        for vague in _VAGUE_CONFIRMS:
            if vague in confirms_lower:
                self._probe = None
                return json.dumps({
                    "status": "rejected",
                    "reason": (
                        f"confirms_if is too vague: '{confirms_if}'. "
                        "Provide a specific content string that would only appear in "
                        "the response if the endpoint is vulnerable, not a description "
                        "of how the response changes."
                    ),
                })

        if len(confirms_if) < 4:
            self._probe = None
            return json.dumps({
                "status": "rejected",
                "reason": (
                    "confirms_if is too short. Provide at least 4 characters of "
                    "specific content that would confirm vulnerability."
                ),
            })

        if not url:
            self._probe = None
            return json.dumps({"status": "rejected", "reason": "url is required."})

        self._probe = ConfirmationProbe(
            method=method,
            url=url,
            headers=headers,
            body=body,
            confirms_if=confirms_if,
            denies_if=denies_if,
        )
        return json.dumps({
            "status": "accepted",
            "next_step": (
                "The framework will now execute this probe. "
                "You will then call evaluate_confirmation with the actual response."
            ),
        })

    def _handle_evaluate_confirmation(self, ti: dict) -> str:
        confirmed: bool = bool(ti.get("confirmed", False))
        confidence: str = ti.get("confidence", "not_confirmed")
        evidence: str = (ti.get("evidence") or "").strip()
        severity: str = ti.get("severity", "medium")
        description: str = ti.get("description", "")
        poc_request: str = ti.get("poc_request", "")
        vuln_class = (
            self._hypothesis.vulnerability_class if self._hypothesis else "unknown"
        )

        # Gate 3c: confirmed=True with empty or trivially short evidence → force False
        if confirmed:
            if not evidence or len(evidence) < 8:
                confirmed = False
                confidence = "not_confirmed"
                evidence = ""
            else:
                evidence_lower = evidence.lower()
                for vague in _VAGUE_CONFIRMS + ("200 ok", "response body changed", "different"):
                    if evidence_lower == vague:
                        confirmed = False
                        confidence = "not_confirmed"
                        evidence = ""
                        break

        self._confirmation = ConfirmationResult(
            confirmed=confirmed,
            confidence=confidence,
            evidence=evidence,
            vulnerability_class=vuln_class,
            severity=severity,
            description=description,
            poc_request=poc_request,
        )
        return json.dumps({
            "status": "recorded",
            "confirmed": confirmed,
            "confidence": confidence,
        })

    # ------------------------------------------------------------------
    # Public API — three stages
    # ------------------------------------------------------------------

    async def analyze_anomaly(self, anomaly: AnomalyResult) -> Optional[AnomalyHypothesis]:
        """Stage 1: LLM classifies the anomaly.

        Returns ``None`` if confidence is low or the class is rejected.
        """
        self._hypothesis = None
        self._stage_rejected = False

        await self.run_agentic_loop(
            system_prompt=_SYSTEM_PROMPT,
            user_message=self._anomaly_message(anomaly),
            max_iterations=4,
        )

        if self._hypothesis is None:
            logger.debug(
                "[anomaly_agent] Hypothesis rejected for probe '%s' on %s",
                anomaly.probe.name,
                anomaly.url,
            )
        return self._hypothesis

    async def design_probe(
        self,
        anomaly: AnomalyResult,
        hypothesis: AnomalyHypothesis,
    ) -> Optional[ConfirmationProbe]:
        """Stage 2: LLM designs a targeted confirmation probe.

        Returns ``None`` if the LLM cannot design an acceptable specific probe.
        """
        self._hypothesis = hypothesis
        self._probe = None

        await self.run_agentic_loop(
            system_prompt=_SYSTEM_PROMPT,
            user_message=self._probe_design_message(anomaly, hypothesis),
            max_iterations=4,
        )

        if self._probe is None:
            logger.debug(
                "[anomaly_agent] No valid probe designed for %s / %s",
                anomaly.url,
                hypothesis.vulnerability_class,
            )
        return self._probe

    async def evaluate_result(
        self,
        anomaly: Optional[AnomalyResult],
        hypothesis: Optional[AnomalyHypothesis],
        probe: ConfirmationProbe,
        probe_response: ResponseSummary,
    ) -> ConfirmationResult:
        """Stage 3: LLM evaluates the actual probe response.

        Always returns a ``ConfirmationResult`` (``confirmed=False`` if
        inconclusive or if the LLM does not call the tool).
        """
        self._hypothesis = hypothesis
        self._confirmation = None

        await self.run_agentic_loop(
            system_prompt=_SYSTEM_PROMPT,
            user_message=self._evaluation_message(probe, probe_response, hypothesis),
            max_iterations=4,
        )

        if self._confirmation is None:
            vuln_class = hypothesis.vulnerability_class if hypothesis else "unknown"
            return ConfirmationResult(
                confirmed=False,
                confidence="not_confirmed",
                evidence="",
                vulnerability_class=vuln_class,
                severity="medium",
                description="LLM did not return a confirmation evaluation.",
                poc_request="",
            )

        return self._confirmation

    # ------------------------------------------------------------------
    # Message builders
    # ------------------------------------------------------------------

    @staticmethod
    def _anomaly_message(anomaly: AnomalyResult) -> str:
        reasons_str = "\n".join(f"  - {r}" for r in anomaly.divergence_reasons)
        base_hdrs = "\n".join(
            f"  {k}: {v}"
            for k, v in list(anomaly.baseline.headers.items())[:10]
        )
        probe_hdrs = "\n".join(
            f"  {k}: {v}"
            for k, v in list(anomaly.probe_response.headers.items())[:10]
        )
        return f"""\
## HTTP Anomaly Detected

**Target URL:** {anomaly.url}
**Probe name:** {anomaly.probe.name}
**Probe type:** {anomaly.probe.probe_type}
**HTTP method:** {anomaly.probe.method}
**Divergence score:** {anomaly.divergence_score}

### Divergence reasons:
{reasons_str}

### Baseline response:
- Status: {anomaly.baseline.status_code}
- Content-Type: {anomaly.baseline.content_type}
- Elapsed: {anomaly.baseline.elapsed_ms:.0f} ms
- Headers:
{base_hdrs}
- Body (first 500 chars):
{anomaly.baseline.body[:500]}

### Probe response:
- Status: {anomaly.probe_response.status_code}
- Content-Type: {anomaly.probe_response.content_type}
- Elapsed: {anomaly.probe_response.elapsed_ms:.0f} ms
- Extra headers sent: {json.dumps(anomaly.probe.extra_headers)}
- Extra params sent:  {json.dumps(anomaly.probe.extra_params)}
- Path suffix sent:   {anomaly.probe.path_suffix or "(none)"}
- Headers received:
{probe_hdrs}
- Body (first 1000 chars):
{anomaly.probe_response.body[:1000]}

---
Call formulate_hypothesis with your vulnerability class hypothesis.\
"""

    @staticmethod
    def _probe_design_message(
        anomaly: AnomalyResult,
        hypothesis: AnomalyHypothesis,
    ) -> str:
        return f"""\
## Design Confirmation Probe

**Target URL:** {anomaly.url}
**Vulnerability hypothesis:** {hypothesis.vulnerability_class}
**Confidence:** {hypothesis.confidence}
**Reasoning:** {hypothesis.reasoning}

**Triggering probe:**
- Method: {anomaly.probe.method}
- Extra headers: {json.dumps(anomaly.probe.extra_headers)}
- Extra params:  {json.dumps(anomaly.probe.extra_params)}
- Path suffix:   {anomaly.probe.path_suffix or "(none)"}

**Probe response body (first 800 chars):**
{anomaly.probe_response.body[:800]}

---
Design a targeted HTTP request that would definitively confirm
{hypothesis.vulnerability_class} on this target.

The confirms_if field MUST be a specific content string that would only
appear if truly vulnerable — NOT a description of how the response changes.
Examples:
  - path-traversal → "root:x:0:0"
  - info-disclosure → "JAVA_HOME=" or "DB_PASSWORD="
  - xxe             → "root:x:0:0" or file content
  - method-confusion→ "TRACE / HTTP/1.1"
  - debug-interface → "X-Debug-Token:" or "debug=true"

Call design_confirmation_probe.\
"""

    @staticmethod
    def _evaluation_message(
        probe: ConfirmationProbe,
        probe_response: ResponseSummary,
        hypothesis: Optional[AnomalyHypothesis],
    ) -> str:
        vuln_class = hypothesis.vulnerability_class if hypothesis else "unknown"
        return f"""\
## Evaluate Confirmation Probe Result

**Vulnerability being confirmed:** {vuln_class}
**Probe sent:**
- Method: {probe.method}
- URL:    {probe.url}
- Headers: {json.dumps(probe.headers)}
- Body:    {probe.body or "(none)"}

**Expected confirmation pattern (confirms_if):**
{probe.confirms_if}

**Would deny if found:**
{probe.denies_if}

**Actual probe response:**
- Status: {probe_response.status_code}
- Content-Type: {probe_response.content_type}
- Elapsed: {probe_response.elapsed_ms:.0f} ms
- Body (first 2000 chars):
{probe_response.body[:2000]}

---
Does the response confirm the vulnerability?
Look carefully for '{probe.confirms_if}' in the body or headers above.

Call evaluate_confirmation with your assessment.
Only set confirmed=true if that exact content ACTUALLY APPEARS above.\
"""
