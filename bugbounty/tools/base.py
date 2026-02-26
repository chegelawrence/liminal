"""Abstract base class for all security tool wrappers."""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from abc import ABC, abstractmethod
from typing import Optional

from pydantic import BaseModel

from bugbounty.core.scope import ScopeValidator
from bugbounty.core.rate_limiter import RateLimiter


class ToolResult(BaseModel):
    """Standardised result returned by every tool."""

    success: bool
    tool_name: str
    raw_output: str
    error: Optional[str] = None
    duration_seconds: float


class BaseTool(ABC):
    """Abstract base for all tool wrappers.

    Sub-classes must:
    - Set ``name`` class attribute.
    - Implement ``_execute`` which returns ``(success, output, error)``.
    """

    name: str = "base"

    def __init__(
        self,
        scope_validator: ScopeValidator,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        self.scope = scope_validator
        self.rate_limiter = rate_limiter
        self.logger = logging.getLogger(f"tools.{self.name}")

    async def run(self, *args, **kwargs) -> ToolResult:
        """Time the execution, catch errors, and return a ToolResult."""
        start = time.monotonic()
        error: Optional[str] = None
        output = ""
        success = False

        try:
            success, output, error = await self._execute(*args, **kwargs)
        except Exception as exc:  # pylint: disable=broad-except
            error = str(exc)
            self.logger.exception("Unexpected error in %s", self.name)

        duration = time.monotonic() - start
        return ToolResult(
            success=success,
            tool_name=self.name,
            raw_output=output,
            error=error,
            duration_seconds=duration,
        )

    @abstractmethod
    async def _execute(self, *args, **kwargs) -> tuple[bool, str, str]:
        """Execute the tool and return (success, stdout, stderr)."""
        ...

    async def _run_subprocess(
        self,
        cmd: list[str],
        timeout: int = 300,
        stdin_data: Optional[bytes] = None,
    ) -> tuple[int, str, str]:
        """Run a command asynchronously using asyncio subprocess.

        Args:
            cmd:        Command + arguments as a list (never shell=True).
            timeout:    Maximum number of seconds to wait.
            stdin_data: Optional bytes to pipe to stdin.

        Returns:
            (returncode, stdout, stderr) tuple.
        """
        self.logger.debug("Running: %s", " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(input=stdin_data),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                self.logger.warning("%s timed out after %ds", self.name, timeout)
                return -1, "", f"Timed out after {timeout}s"

            return (
                proc.returncode or 0,
                stdout_bytes.decode("utf-8", errors="replace"),
                stderr_bytes.decode("utf-8", errors="replace"),
            )
        except FileNotFoundError:
            self.logger.warning("Tool '%s' not found in PATH", cmd[0])
            return -2, "", f"Tool not found: {cmd[0]}"

    def _check_tool_installed(self, tool_name: str) -> bool:
        """Return True if *tool_name* exists anywhere on PATH."""
        found = shutil.which(tool_name) is not None
        if not found:
            self.logger.warning(
                "Tool '%s' is not installed or not on PATH – skipping", tool_name
            )
        return found

    async def _with_rate_limit(self, coro):
        """Execute *coro* inside the rate limiter if one is configured."""
        if self.rate_limiter is not None:
            async with self.rate_limiter.acquire():
                return await coro
        return await coro
