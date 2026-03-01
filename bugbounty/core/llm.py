"""Unified LLM provider abstraction supporting Claude, OpenAI, Groq, and Ollama."""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class NormalizedToolUse:
    """A normalized tool-use block, provider-agnostic."""
    id: str
    name: str
    input: dict


@dataclass
class NormalizedResponse:
    """Normalized LLM response, independent of provider wire format."""
    stop_reason: str          # "end_turn" or "tool_use"
    text: str                 # concatenated text content
    tool_calls: list[NormalizedToolUse] = field(default_factory=list)
    raw: Any = None           # original provider response object


class LLMProvider(ABC):
    """Abstract base for LLM providers."""

    def __init__(
        self,
        api_key: str,
        model: str,
        max_tokens: int = 8192,
        temperature: float = 0,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.logger = logging.getLogger(f"llm.{self.__class__.__name__}")

    @abstractmethod
    async def create_message(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict],
    ) -> NormalizedResponse:
        """Send a conversation turn and return a normalized response."""
        ...

    @abstractmethod
    def format_tool_result(self, tool_use_id: str, content: str) -> dict:
        """Format a single tool result in this provider's expected format."""
        ...

    @abstractmethod
    def format_assistant_message(self, response: NormalizedResponse) -> dict:
        """Format the assistant's response for the message history."""
        ...

    @abstractmethod
    def append_tool_results(
        self, messages: list[dict], tool_results: list[dict]
    ) -> None:
        """Append tool results to the running message history.

        Claude expects all results in a single ``user`` message.
        OpenAI expects each result as a separate ``tool`` message.
        """
        ...


class ClaudeProvider(LLMProvider):
    """Anthropic Claude provider using the async client."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-opus-4-6",
        max_tokens: int = 8192,
        temperature: float = 0,
    ) -> None:
        super().__init__(api_key, model, max_tokens, temperature)
        import anthropic  # local import so other providers don't require anthropic
        self.client = anthropic.AsyncAnthropic(api_key=api_key)

    async def create_message(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict],
    ) -> NormalizedResponse:
        kwargs: dict[str, Any] = {}
        if tools:
            kwargs["tools"] = [
                {
                    "name": t["name"],
                    "description": t["description"],
                    "input_schema": t["input_schema"],
                }
                for t in tools
            ]

        response = await self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=messages,
            **kwargs,
        )

        text_parts: list[str] = []
        tool_calls: list[NormalizedToolUse] = []

        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(
                    NormalizedToolUse(id=block.id, name=block.name, input=block.input)
                )

        stop_reason = "tool_use" if response.stop_reason == "tool_use" else "end_turn"
        return NormalizedResponse(
            stop_reason=stop_reason,
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            raw=response,
        )

    def format_tool_result(self, tool_use_id: str, content: str) -> dict:
        return {
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": content,
        }

    def format_assistant_message(self, response: NormalizedResponse) -> dict:
        return {"role": "assistant", "content": response.raw.content}

    def append_tool_results(
        self, messages: list[dict], tool_results: list[dict]
    ) -> None:
        # Claude: all results in a single user message with a list of tool_result blocks
        messages.append({"role": "user", "content": tool_results})


class OpenAIProvider(LLMProvider):
    """OpenAI-compatible provider (OpenAI, Groq, Ollama, OpenRouter, …)."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        max_tokens: int = 8192,
        temperature: float = 0,
        base_url: Optional[str] = None,
    ) -> None:
        super().__init__(api_key, model, max_tokens, temperature)
        from openai import AsyncOpenAI  # local import
        self.client = AsyncOpenAI(api_key=api_key, base_url=base_url)

    async def create_message(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict],
    ) -> NormalizedResponse:
        # Prepend system message in OpenAI format
        openai_messages = [{"role": "system", "content": system}] + messages

        kwargs: dict[str, Any] = {}
        if tools:
            kwargs["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t["description"],
                        "parameters": t["input_schema"],
                    },
                }
                for t in tools
            ]
            kwargs["tool_choice"] = "auto"

        response = await self.client.chat.completions.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            messages=openai_messages,
            **kwargs,
        )

        choice = response.choices[0]
        message = choice.message

        text = message.content or ""
        tool_calls: list[NormalizedToolUse] = []

        if message.tool_calls:
            for tc in message.tool_calls:
                try:
                    input_dict = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    input_dict = {}
                tool_calls.append(
                    NormalizedToolUse(id=tc.id, name=tc.function.name, input=input_dict)
                )

        stop_reason = (
            "tool_use" if choice.finish_reason == "tool_calls" else "end_turn"
        )
        return NormalizedResponse(
            stop_reason=stop_reason,
            text=text,
            tool_calls=tool_calls,
            raw=message,
        )

    def format_tool_result(self, tool_use_id: str, content: str) -> dict:
        return {
            "role": "tool",
            "tool_call_id": tool_use_id,
            "content": content,
        }

    def format_assistant_message(self, response: NormalizedResponse) -> dict:
        msg = response.raw
        result: dict[str, Any] = {
            "role": "assistant",
            "content": msg.content or "",
        }
        if msg.tool_calls:
            result["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in msg.tool_calls
            ]
        return result

    def append_tool_results(
        self, messages: list[dict], tool_results: list[dict]
    ) -> None:
        # OpenAI: each tool result is a separate message with role="tool"
        messages.extend(tool_results)


def create_provider(
    name: str,
    anthropic_api_key: str = "",
    openai_api_key: str = "",
    groq_api_key: str = "",
    claude_model: str = "claude-opus-4-6",
    openai_model: str = "gpt-4o",
    max_tokens: int = 8192,
    temperature: float = 0,
) -> LLMProvider:
    """Factory to instantiate the correct LLM provider.

    Args:
        name:              "claude", "openai", "groq", or "ollama"
        anthropic_api_key: Required when name=="claude"
        openai_api_key:    Required when name=="openai"
        groq_api_key:      Required when name=="groq" (free at console.groq.com)
        claude_model:      Claude model ID override
        openai_model:      Model ID for OpenAI / Groq / Ollama
        max_tokens:        Max completion tokens
        temperature:       Sampling temperature

    Returns:
        Configured LLMProvider instance.

    Raises:
        ValueError: If the provider name is unknown or the required API key is missing.
    """
    name = name.lower()
    if name == "claude":
        if not anthropic_api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY is required for the Claude provider. "
                "Set it in your environment or .env file."
            )
        return ClaudeProvider(
            api_key=anthropic_api_key,
            model=claude_model,
            max_tokens=max_tokens,
            temperature=temperature,
        )
    elif name == "openai":
        if not openai_api_key:
            raise ValueError(
                "OPENAI_API_KEY is required for the OpenAI provider. "
                "Set it in your environment or .env file."
            )
        return OpenAIProvider(
            api_key=openai_api_key,
            model=openai_model,
            max_tokens=max_tokens,
            temperature=temperature,
        )
    elif name == "groq":
        if not groq_api_key:
            raise ValueError(
                "GROQ_API_KEY is required for the Groq provider. "
                "Get a free key at https://console.groq.com"
            )
        return OpenAIProvider(
            api_key=groq_api_key,
            model=openai_model,
            max_tokens=max_tokens,
            temperature=temperature,
            base_url="https://api.groq.com/openai/v1",
        )
    elif name == "ollama":
        return OpenAIProvider(
            api_key="ollama",
            model=openai_model,
            max_tokens=max_tokens,
            temperature=temperature,
            base_url="http://localhost:11434/v1",
        )
    else:
        raise ValueError(
            f"Unknown LLM provider: '{name}'. "
            f"Valid options are 'claude', 'openai', 'groq', 'ollama'."
        )
