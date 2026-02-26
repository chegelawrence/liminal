"""Base class for all AI agents.

Uses the unified LLMProvider abstraction so agents work identically with
both Claude (Anthropic) and OpenAI backends.
"""

from __future__ import annotations

import json
import logging
from typing import Any, TypedDict

from bugbounty.core.llm import LLMProvider


class AgentTool(TypedDict):
    name: str
    description: str
    input_schema: dict


class BaseAgent:
    """Base agent implementing a provider-agnostic agentic loop with tool use.

    Subclasses should override:
    - ``get_tools()`` to declare the tools available to the agent.
    - ``process_tool_call()`` to handle tool invocations.
    """

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider
        self.logger = logging.getLogger(f"agents.{self.__class__.__name__}")

    def get_tools(self) -> list[AgentTool]:
        """Return tool definitions.  Override in subclasses."""
        return []

    async def process_tool_call(self, tool_name: str, tool_input: dict) -> str:
        """Handle a tool call and return a JSON-serialised string result.

        Override in subclasses to implement actual tool logic.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement process_tool_call"
        )

    async def run_agentic_loop(
        self,
        system_prompt: str,
        user_message: str,
        max_iterations: int = 20,
    ) -> str:
        """Run the provider-agnostic agentic loop until the model returns end_turn.

        The loop:
        1. Sends the accumulated messages to the LLM with tool definitions.
        2. If stop_reason == "tool_use":
           - Extracts all tool_use blocks from the normalised response.
           - Calls process_tool_call() for each.
           - Appends the assistant response and tool results via the provider.
           - Continues the loop.
        3. If stop_reason == "end_turn":
           - Extracts the final text content and returns it.
        4. Enforces max_iterations to prevent infinite loops.

        Returns the final text response from the model.
        """
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": user_message}
        ]

        tools = self.get_tools()
        final_text = ""

        for iteration in range(max_iterations):
            self.logger.debug(
                "Agentic loop iteration %d/%d", iteration + 1, max_iterations
            )

            response = await self.provider.create_message(
                system=system_prompt,
                messages=messages,
                tools=tools,
            )

            if response.text:
                final_text = response.text

            if response.stop_reason == "end_turn" or not response.tool_calls:
                self.logger.debug(
                    "Agentic loop finished (end_turn) at iteration %d", iteration + 1
                )
                break

            # Append the assistant's response to the message history using the
            # provider-specific format (Claude and OpenAI differ here)
            messages.append(self.provider.format_assistant_message(response))

            # Process each tool call and collect results
            tool_results: list[dict[str, Any]] = []
            for tool_call in response.tool_calls:
                self.logger.debug(
                    "Processing tool call: %s (id=%s)",
                    tool_call.name,
                    tool_call.id,
                )
                try:
                    result_str = await self.process_tool_call(
                        tool_call.name, tool_call.input
                    )
                except Exception as exc:
                    self.logger.exception(
                        "Tool '%s' raised an exception: %s", tool_call.name, exc
                    )
                    result_str = json.dumps({"error": str(exc)})

                tool_results.append(
                    self.provider.format_tool_result(tool_call.id, result_str)
                )

            # Append tool results using the provider-specific method
            # (Claude: single user message with list; OpenAI: individual tool messages)
            self.provider.append_tool_results(messages, tool_results)

        else:
            self.logger.warning(
                "Agentic loop reached max_iterations (%d) without end_turn",
                max_iterations,
            )

        return final_text

    # ------------------------------------------------------------------
    # Convenience helpers for subclasses
    # ------------------------------------------------------------------

    @staticmethod
    def _to_json(obj: Any) -> str:
        """Serialize *obj* to a compact JSON string."""
        return json.dumps(obj, default=str)

    @staticmethod
    def _from_json(s: str) -> Any:
        """Deserialize a JSON string.  Returns raw string on failure."""
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return s
