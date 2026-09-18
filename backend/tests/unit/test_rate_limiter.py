from __future__ import annotations

import pytest

from app.scanner.rate_limiter import RateLimiter

pytestmark = pytest.mark.asyncio


class FakeClock:
    """Controllable clock + sleep pair, so rate-limiter tests assert on
    pacing logic without actually waiting in wall-clock time."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    async def sleep(self, duration: float) -> None:
        self.sleeps.append(duration)
        self.now += duration

    def advance(self, seconds: float) -> None:
        self.now += seconds


async def test_disabled_when_rate_is_zero():
    limiter = RateLimiter(0)
    assert limiter.enabled is False
    await limiter.acquire()  # must not raise or block


async def test_first_acquire_does_not_sleep():
    clock = FakeClock()
    limiter = RateLimiter(2.0, clock=clock.time, sleep=clock.sleep)
    await limiter.acquire()
    assert clock.sleeps == []


async def test_immediate_second_acquire_sleeps_for_remaining_interval():
    clock = FakeClock()
    limiter = RateLimiter(2.0, clock=clock.time, sleep=clock.sleep)  # 0.5s interval
    await limiter.acquire()
    await limiter.acquire()
    assert len(clock.sleeps) == 1
    assert clock.sleeps[0] == pytest.approx(0.5)


async def test_no_sleep_when_enough_time_already_elapsed():
    clock = FakeClock()
    limiter = RateLimiter(2.0, clock=clock.time, sleep=clock.sleep)
    await limiter.acquire()
    clock.advance(1.0)  # longer than the 0.5s interval
    await limiter.acquire()
    assert clock.sleeps == []


async def test_partial_elapsed_time_sleeps_only_the_remainder():
    clock = FakeClock()
    limiter = RateLimiter(1.0, clock=clock.time, sleep=clock.sleep)  # 1.0s interval
    await limiter.acquire()
    clock.advance(0.3)
    await limiter.acquire()
    assert clock.sleeps[0] == pytest.approx(0.7)


async def test_steady_rate_across_several_acquires():
    clock = FakeClock()
    limiter = RateLimiter(4.0, clock=clock.time, sleep=clock.sleep)  # 0.25s interval
    for _ in range(4):
        await limiter.acquire()
    # First is free; the next three each wait a full interval.
    assert len(clock.sleeps) == 3
    assert all(s == pytest.approx(0.25) for s in clock.sleeps)
