"""
Request rate limiting.

Extracted into its own module (rather than living inline in the request
engine) so the pacing logic can be unit-tested against a controllable
clock without spinning up an HTTP client.

This is a simple minimum-interval limiter rather than a token bucket: it
enforces a steady, evenly-spaced request rate with no burst allowance.
That's the deliberate choice for a scanner -- Section 19 asks us to be
"respectful of target resources", and bursting is precisely what stresses
a target under test. A token bucket would let the scanner fire N requests
instantaneously after any idle period.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable


class RateLimiter:
    """Allows at most `rate` acquisitions per second, evenly spaced.

    A rate of 0 or below disables limiting entirely.
    """

    def __init__(
        self,
        rate: float,
        *,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], asyncio.Future] | None = None,
    ):
        self._min_interval = 1.0 / rate if rate > 0 else 0.0
        self._clock = clock or (lambda: asyncio.get_event_loop().time())
        self._sleep = sleep or asyncio.sleep
        self._last_acquired_at: float | None = None
        self._lock = asyncio.Lock()

    @property
    def enabled(self) -> bool:
        return self._min_interval > 0.0

    async def acquire(self) -> None:
        if not self.enabled:
            return

        async with self._lock:
            now = self._clock()
            if self._last_acquired_at is not None:
                elapsed = now - self._last_acquired_at
                wait = self._min_interval - elapsed
                if wait > 0:
                    await self._sleep(wait)
                    now = self._clock()
            self._last_acquired_at = now
