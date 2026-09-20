from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Async token bucket that caps connection attempts per second.

    A scanner without this is indistinguishable from a flood, both to the
    target and to any IDS between here and it.
    """

    def __init__(self, rate_per_second: float, burst: int | None = None) -> None:
        self.rate = max(float(rate_per_second), 1.0)
        self.capacity = float(burst if burst is not None else max(rate_per_second, 1))
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                wait = deficit / self.rate
            await asyncio.sleep(min(wait, 0.5))
