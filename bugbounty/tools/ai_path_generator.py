"""AI-driven path generation for exposure scanning.

Uses the configured LLM provider to reason about likely hidden paths given
the target's detected tech stack, URL structure, and JS-extracted routes.

The LLM is called with tool use so paths always arrive as a structured
JSON array — no fragile text parsing.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from typing import Optional
from urllib.parse import urlparse

from bugbounty.core.config import AIConfig
from bugbounty.core.llm import LLMProvider, create_provider
from bugbounty.db.models import LiveHost

logger = logging.getLogger(__name__)

# Context limits — keep the prompt well under the model's context window
_MAX_TECH_ITEMS = 30
_MAX_JS_PATHS = 60
_MAX_URL_PATTERNS = 40
_MAX_GENERATED_PATHS = 200

_SUBMIT_PATHS_TOOL: dict = {
    "name": "submit_paths",
    "description": (
        "Submit the list of URL paths to probe for exposed admin panels, "
        "internal dashboards, debug interfaces, or other sensitive endpoints."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "URL paths to probe, each starting with '/'. "
                    f"Maximum {_MAX_GENERATED_PATHS} entries."
                ),
            },
            "reasoning": {
                "type": "string",
                "description": "Brief explanation of how the paths were chosen.",
            },
        },
        "required": ["paths"],
    },
}

_SYSTEM_PROMPT = """\
You are a senior security researcher conducting authorized penetration testing.

Your task: generate a targeted list of URL paths that may expose sensitive \
interfaces on the target — admin panels, internal dashboards, debug endpoints, \
management APIs, or undocumented internal routes.

Rules:
- Every path must start with '/'.
- Tailor paths to the detected tech stack and naming conventions — do NOT just \
  copy generic lists.
- Reason about what internal tooling is likely running (e.g. if Prometheus is \
  detected as a tech, internal /metrics and /prometheus paths are plausible).
- Infer hidden admin paths from URL naming patterns and JS route prefixes.
- Consider API versioning patterns (e.g. if /api/v2/ exists, probe /api/v2/admin/).
- Do NOT repeat paths that are already listed as known/discovered.
- Use the submit_paths tool to return your results."""


class AIPathGenerator:
    """Uses the LLM to generate targeted candidate paths for a specific target.

    Workflow:
    1. Aggregate tech stacks across all live hosts.
    2. Extract and normalise URL path patterns from crawled URLs.
    3. Summarise JS-extracted paths, prioritising interesting ones.
    4. Detect naming conventions (snake_case, kebab-case, camelCase).
    5. Call LLM with tool use → parse structured path list.
    6. Validate and deduplicate before returning.
    """

    def __init__(
        self,
        ai_config: AIConfig,
        anthropic_api_key: str = "",
        openai_api_key: str = "",
        groq_api_key: str = "",
    ) -> None:
        self.ai_config = ai_config
        self._provider: Optional[LLMProvider] = None
        self._anthropic_api_key = anthropic_api_key
        self._openai_api_key = openai_api_key
        self._groq_api_key = groq_api_key

    def _get_provider(self) -> LLMProvider:
        if self._provider is None:
            self._provider = create_provider(
                name=self.ai_config.provider,
                anthropic_api_key=self._anthropic_api_key,
                openai_api_key=self._openai_api_key,
                groq_api_key=self._groq_api_key,
                claude_model=self.ai_config.claude_model,
                openai_model=self.ai_config.model,
                # Path lists are short; cap tokens for cost efficiency
                max_tokens=2048,
                temperature=0,
            )
        return self._provider

    async def generate_paths(
        self,
        live_hosts: list[LiveHost],
        js_extracted_paths: list[str],
        crawled_urls: list[str],
    ) -> list[str]:
        """Generate candidate paths using LLM reasoning.

        Args:
            live_hosts:         Live hosts discovered during recon (with tech stacks).
            js_extracted_paths: Paths extracted from JS files by the JS scanner.
            crawled_urls:       All URLs discovered during recon/crawling.

        Returns:
            Validated, deduplicated list of path strings to probe.
        """
        tech_summary = self._summarize_technologies(live_hosts)
        url_patterns = self._extract_url_patterns(crawled_urls)
        js_summary = self._summarize_js_paths(js_extracted_paths)
        conventions = self._detect_naming_conventions(js_extracted_paths + url_patterns)
        known_paths = set(js_extracted_paths)

        user_message = self._build_user_message(
            tech_summary, url_patterns, js_summary, conventions, known_paths
        )

        try:
            provider = self._get_provider()
            response = await provider.create_message(
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
                tools=[_SUBMIT_PATHS_TOOL],
            )

            if response.tool_calls:
                reasoning = response.tool_calls[0].input.get("reasoning", "")
                if reasoning:
                    logger.info("AI path generator reasoning: %s", reasoning[:200])

            raw_paths = self._extract_paths_from_response(response)
            validated = [p for p in raw_paths if self._validate_path(p)]

            # Deduplicate and remove already-known paths
            seen: set[str] = set()
            unique: list[str] = []
            for p in validated:
                if p not in seen and p not in known_paths:
                    seen.add(p)
                    unique.append(p)

            logger.info(
                "AI path generator: %d raw → %d validated → %d new unique",
                len(raw_paths), len(validated), len(unique),
            )
            return unique[:_MAX_GENERATED_PATHS]

        except Exception as exc:
            logger.warning("AI path generation failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Context builders
    # ------------------------------------------------------------------

    @staticmethod
    def _summarize_technologies(live_hosts: list[LiveHost]) -> str:
        """Aggregate all detected technologies across live hosts."""
        tech_counter: Counter = Counter()
        for host in live_hosts:
            for tech in (host.technologies or []):
                if isinstance(tech, str) and tech.strip():
                    tech_counter[tech.strip()] += 1

        if not tech_counter:
            return "No technologies detected."

        lines = [
            f"- {tech} (detected on {count} host{'s' if count > 1 else ''})"
            for tech, count in tech_counter.most_common(_MAX_TECH_ITEMS)
        ]
        return "\n".join(lines)

    @staticmethod
    def _extract_url_patterns(urls: list[str]) -> list[str]:
        """Normalise crawled URLs to unique structural path patterns."""
        patterns: set[str] = set()
        for url in urls:
            try:
                path = urlparse(url).path
                if not path or path == "/":
                    continue
                parts = [p for p in path.split("/") if p]
                if not parts:
                    continue
                # Replace dynamic segments (UUIDs, numeric IDs, hashes)
                normalized: list[str] = []
                for part in parts[:4]:
                    if re.match(r'^[0-9a-f\-]{8,}$', part, re.I) or part.isdigit():
                        normalized.append("{id}")
                    else:
                        normalized.append(part)
                patterns.add("/" + "/".join(normalized))
            except Exception:
                continue

        return sorted(patterns)[:_MAX_URL_PATTERNS]

    @staticmethod
    def _summarize_js_paths(paths: list[str]) -> str:
        """Select the most interesting JS-extracted paths for the prompt."""
        if not paths:
            return "No paths extracted from JavaScript files."

        interesting_keywords = [
            "admin", "internal", "manage", "debug", "config",
            "api", "v1", "v2", "v3", "private", "secure",
            "auth", "dashboard", "panel", "console", "monitor",
        ]
        scored: list[tuple[int, str]] = []
        for p in paths:
            score = sum(1 for kw in interesting_keywords if kw in p.lower())
            scored.append((score, p))
        scored.sort(key=lambda x: (-x[0], x[1]))
        top = [p for _, p in scored[:_MAX_JS_PATHS]]
        return "\n".join(f"- {p}" for p in top)

    @staticmethod
    def _detect_naming_conventions(paths: list[str]) -> str:
        """Infer naming conventions from path segments."""
        if not paths:
            return "Insufficient data to determine conventions."

        snake_count = sum(1 for p in paths if "_" in p)
        kebab_count = sum(1 for p in paths if "-" in p)
        camel_count = sum(1 for p in paths if re.search(r'[a-z][A-Z]', p))
        total = max(len(paths), 1)

        conventions = []
        if snake_count / total > 0.25:
            conventions.append("snake_case (e.g. /user_profile/)")
        if kebab_count / total > 0.25:
            conventions.append("kebab-case (e.g. /user-profile/)")
        if camel_count / total > 0.15:
            conventions.append("camelCase (e.g. /userProfile/)")

        return ", ".join(conventions) if conventions else "No clear convention detected"

    @staticmethod
    def _build_user_message(
        tech_summary: str,
        url_patterns: list[str],
        js_summary: str,
        conventions: str,
        known_paths: set[str],
    ) -> str:
        pattern_str = "\n".join(f"- {p}" for p in url_patterns) if url_patterns else "None observed"

        # Show a sample of known paths to avoid duplication
        known_sample = sorted(known_paths)[:30]
        known_str = (
            "\n".join(f"- {p}" for p in known_sample)
            if known_sample else "None"
        )

        return f"""## Target Analysis

**Detected Technologies:**
{tech_summary}

**URL Path Patterns Observed (normalised sample):**
{pattern_str}

**Paths Extracted from JavaScript Files (highest-signal sample):**
{js_summary}

**Naming Conventions Detected:**
{conventions}

**Already Known Paths (do not repeat these):**
{known_str}

---

Generate a targeted list of paths tailored to this specific target that are \
likely to expose admin panels, internal dashboards, debug endpoints, or \
sensitive management interfaces. Use the submit_paths tool to return your results."""

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _extract_paths_from_response(self, response) -> list[str]:
        """Extract paths from a tool call or fall back to text parsing."""
        # Prefer structured tool call output
        for tool_call in (response.tool_calls or []):
            if tool_call.name == "submit_paths":
                paths = tool_call.input.get("paths", [])
                if isinstance(paths, list):
                    return [str(p).strip() for p in paths if p]

        # Fallback: parse a JSON array from free text
        if response.text:
            text = response.text.strip()
            match = re.search(r'\[[\s\S]*?\]', text)
            if match:
                try:
                    paths = json.loads(match.group(0))
                    if isinstance(paths, list):
                        return [str(p).strip() for p in paths if p]
                except json.JSONDecodeError:
                    pass
            # Last resort: lines that look like paths
            return [
                line.strip().rstrip(",").strip('"').strip("'")
                for line in text.splitlines()
                if line.strip().startswith("/")
            ]

        return []

    @staticmethod
    def _validate_path(path: str) -> bool:
        """Return True if path is safe, well-formed, and probe-worthy."""
        if not isinstance(path, str):
            return False
        path = path.strip()
        if not path.startswith("/"):
            return False
        if len(path) < 2 or len(path) > 200:
            return False
        # Must not be a full URL
        if "://" in path or "@" in path:
            return False
        # No path traversal
        if ".." in path:
            return False
        # Only URL-safe characters
        if not re.match(r'^[/a-zA-Z0-9_.~\-]+$', path):
            return False
        return True
