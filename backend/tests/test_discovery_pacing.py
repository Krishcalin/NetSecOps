"""The discovery rate limiter (FR-DISC-05).

    Discovery SHALL be rate-limited (default 50 hosts/s, configurable) and
    schedulable.

These tests exist because of how easily a rate limiter passes a test without limiting
anything. Assert against the wall clock and you get either a test that takes a minute or
a tolerance wide enough that deleting the limiter still passes — and the second is the
one that gets written, because the first is unbearable in CI. So the clock is injected
and the assertions are exact: the spacing is a property of the arithmetic, and the
arithmetic is what is checked.

The mutation to try on anything here: delete the ``await self._sleep(delay)`` in
``HostPacer.acquire``. Every test that only counts calls still passes; the ones below
that read the fake clock do not.
"""

from __future__ import annotations

import asyncio

import pytest

from netsecops.core.errors import ValidationProblem
from netsecops.discovery.pacing import (
    DEFAULT_RATE_PER_SECOND,
    MAX_RATE_PER_SECOND,
    HostPacer,
)


class FakeClock:
    """A clock that only moves when something sleeps on it.

    Enough to prove the spacing without spending it. ``sleep`` advances the clock by the
    requested amount, so a limiter that computes a delay and does not wait shows up as a
    clock that never moved.
    """

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


class TestTheRateIsActuallyEnforced:
    async def test_the_first_host_goes_immediately(self, clock: FakeClock) -> None:
        """An idle limiter must not make the operator wait for the first probe."""
        pacer = HostPacer(10, clock=clock.time, sleep=clock.sleep)

        waited = await pacer.acquire()

        assert waited == 0.0
        assert clock.sleeps == []

    async def test_consecutive_hosts_are_spaced_by_the_interval(self, clock: FakeClock) -> None:
        pacer = HostPacer(10, clock=clock.time, sleep=clock.sleep)

        await pacer.acquire()
        second = await pacer.acquire()
        third = await pacer.acquire()

        # 10 hosts a second is one every 100ms, and the clock advanced by each wait.
        assert second == pytest.approx(0.1)
        assert third == pytest.approx(0.1)
        assert clock.now == pytest.approx(0.2)

    async def test_fifty_hosts_take_a_second(self, clock: FakeClock) -> None:
        """FR-DISC-05's default, measured.

        The requirement names a number; this is the test that makes the number true
        rather than documented.
        """
        pacer = HostPacer(DEFAULT_RATE_PER_SECOND, clock=clock.time, sleep=clock.sleep)

        for _ in range(51):
            await pacer.acquire()

        # 51 hosts at 50/s: the first is free and the other fifty are spaced by 20ms.
        assert clock.now == pytest.approx(1.0)

    async def test_concurrent_callers_get_distinct_slots(self, clock: FakeClock) -> None:
        """The property a counted-token bucket gets wrong.

        Several workers ask at once. If two are handed the same slot the effective rate
        doubles, which is exactly the failure a rate limit exists to prevent and exactly
        the one that a single-caller test cannot see.

        What is asserted is each caller's *departure time*, not how long it waited. Under
        concurrency those differ: the clock advances whenever any task sleeps, so a task
        that computed a 200ms slot may only wait 50ms of it because others moved the
        clock the rest of the way. The departure times are what a rate limit constrains,
        and asserting the waits instead would fail against a pacer that is behaving.
        """
        pacer = HostPacer(20, clock=clock.time, sleep=clock.sleep)

        async def depart() -> float:
            await pacer.acquire()
            return clock.time()

        departures = await asyncio.gather(*(depart() for _ in range(5)))

        # 20 hosts a second is one every 50ms: one immediate, then strictly spaced.
        assert sorted(departures) == pytest.approx([0.0, 0.05, 0.10, 0.15, 0.20])
        assert len(set(departures)) == 5

    async def test_an_idle_limiter_does_not_bank_a_burst(self, clock: FakeClock) -> None:
        """The behaviour that separates this from a token bucket.

        A bucket idle for ten minutes releases ten minutes' worth at once. That is right
        for a client protecting a server's capacity and wrong here: the point is not to
        look like a scan, and a thousand-host burst looks like nothing else.
        """
        pacer = HostPacer(10, clock=clock.time, sleep=clock.sleep)
        await pacer.acquire()

        clock.now += 600.0  # ten quiet minutes

        assert await pacer.acquire() == 0.0
        assert await pacer.acquire() == pytest.approx(0.1)

    async def test_a_burst_allowance_is_honoured_when_asked_for(self, clock: FakeClock) -> None:
        pacer = HostPacer(10, burst=3, clock=clock.time, sleep=clock.sleep)

        waits = [await pacer.acquire() for _ in range(4)]

        assert waits[:3] == [0.0, 0.0, 0.0]
        assert waits[3] == pytest.approx(0.1)


class TestTheCeilingIsNotDecorative:
    def test_a_rate_above_the_ceiling_is_refused(self) -> None:
        """ "Configurable" with no ceiling makes the requirement unenforceable."""
        with pytest.raises(ValidationProblem) as raised:
            HostPacer(MAX_RATE_PER_SECOND + 1)

        assert "port sweep" in str(raised.value)

    def test_the_ceiling_itself_is_allowed(self) -> None:
        assert HostPacer(MAX_RATE_PER_SECOND).rate == MAX_RATE_PER_SECOND

    def test_a_rate_of_zero_is_refused_rather_than_stalling(self) -> None:
        """Nought hosts a second is not a slow scope, it is one that never finishes."""
        with pytest.raises(ValidationProblem) as raised:
            HostPacer(0)

        assert "disable it" in str(raised.value)

    def test_the_schema_ceiling_and_the_pacer_ceiling_agree(self) -> None:
        """Two ceilings in two files drift apart silently; this is what notices.

        The API refuses above ``le=1000`` and the pacer refuses above
        ``MAX_RATE_PER_SECOND``. If the first were raised alone, a scope would be
        storable and unrunnable, and the failure would appear at run time on a customer's
        network rather than at configuration time.
        """
        from netsecops.schemas.discovery import DiscoveryScopeCreate

        field = DiscoveryScopeCreate.model_fields["rate_limit_per_second"]
        ceilings = [
            item.le  # type: ignore[attr-defined]
            for item in field.metadata
            if getattr(item, "le", None) is not None
        ]

        assert ceilings == [MAX_RATE_PER_SECOND]
        assert field.default == DEFAULT_RATE_PER_SECOND
