"""Async rate limiting utilities."""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

logger = logging.getLogger(__name__)


class RateLimiter:
    """Concurrency-based rate limiter using asyncio.Semaphore.

    Controls the maximum number of simultaneous requests rather than the
    rate per second.  Suitable for capping parallelism of tool executions.
    """

    def __init__(self, max_concurrent: int = 5) -> None:
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self.max_concurrent = max_concurrent

    async def __aenter__(self) -> "RateLimiter":
        await self._semaphore.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        self._semaphore.release()

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[None]:
        """Async context manager that acquires the semaphore slot."""
        async with self._semaphore:
            yield


class AsyncRateLimiter:
    """Token-bucket rate limiter for per-second request limiting.

    Implements a token bucket algorithm:
    - Tokens refill at *rate* tokens per second.
    - Requests consume one token each.
    - If no tokens are available, the caller is suspended until one becomes
      available.

    Optionally combines a concurrency semaphore (via RateLimiter) on top of
    the token-bucket to enforce both a rate and a concurrency ceiling.

    Per-host limiting is supported via ``host_rate`` (requests/second per
    individual host).
    """

    def __init__(
        self,
        rate: float,
        max_concurrent: int = 10,
        host_rate: float | None = None,
    ) -> None:
        self.rate = rate  # tokens per second
        self._tokens: float = rate
        self._last_check: float = time.monotonic()
        self._lock = asyncio.Lock()

        self._semaphore = asyncio.Semaphore(max_concurrent)

        # Per-host token buckets
        self.host_rate = host_rate
        self._host_tokens: dict[str, float] = {}
        self._host_last_check: dict[str, float] = {}
        self._host_lock = asyncio.Lock()

    async def _refill(self) -> None:
        """Refill the global token bucket based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_check
        self._tokens = min(self.rate, self._tokens + elapsed * self.rate)
        self._last_check = now

    async def _wait_for_token(self) -> None:
        """Block until a token is available from the global bucket."""
        while True:
            async with self._lock:
                await self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Calculate how long to wait for the next token
                wait = (1.0 - self._tokens) / self.rate
            await asyncio.sleep(wait)

    async def _wait_for_host_token(self, host: str) -> None:
        """Block until a token is available for the given host."""
        if self.host_rate is None:
            return
        while True:
            async with self._host_lock:
                now = time.monotonic()
                if host not in self._host_tokens:
                    self._host_tokens[host] = self.host_rate
                    self._host_last_check[host] = now

                elapsed = now - self._host_last_check[host]
                self._host_tokens[host] = min(
                    self.host_rate,
                    self._host_tokens[host] + elapsed * self.host_rate,
                )
                self._host_last_check[host] = now

                if self._host_tokens[host] >= 1.0:
                    self._host_tokens[host] -= 1.0
                    return
                wait = (1.0 - self._host_tokens[host]) / self.host_rate
            await asyncio.sleep(wait)

    async def __aenter__(self) -> "AsyncRateLimiter":
        await self._semaphore.acquire()
        await self._wait_for_token()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        self._semaphore.release()

    @asynccontextmanager
    async def acquire(self, host: str | None = None) -> AsyncIterator[None]:
        """Context manager that enforces rate + concurrency limits.

        Args:
            host: Optional hostname for per-host rate limiting.
        """
        async with self._semaphore:
            await self._wait_for_token()
            if host is not None:
                await self._wait_for_host_token(host)
            yield


class PerHostRateLimiter:
    """Manages independent AsyncRateLimiter instances per host.

    Useful when you need strict per-host isolation rather than a shared
    bucket with optional per-host enforcement.
    """

    def __init__(self, rate: float, max_concurrent: int = 3) -> None:
        self.rate = rate
        self.max_concurrent = max_concurrent
        self._limiters: dict[str, AsyncRateLimiter] = {}
        self._lock = asyncio.Lock()

    async def _get_limiter(self, host: str) -> AsyncRateLimiter:
        async with self._lock:
            if host not in self._limiters:
                self._limiters[host] = AsyncRateLimiter(
                    rate=self.rate,
                    max_concurrent=self.max_concurrent,
                )
            return self._limiters[host]

    @asynccontextmanager
    async def acquire(self, host: str) -> AsyncIterator[None]:
        limiter = await self._get_limiter(host)
        async with limiter:
            yield
