"""How fast discovery is allowed to go (FR-DISC-05).

    Discovery SHALL be rate-limited (default 50 hosts/s, configurable) and
    schedulable.

The requirement reads like a performance knob. It is not: it is the difference between
a reachability check and a port sweep, and SRS §1.2 forbids the second. Four hundred
addresses contacted as fast as an event loop can open sockets is indistinguishable, from
the far end and from the IDS watching it, from a scan — regardless of how carefully
:mod:`netsecops.discovery.probes` restricted *what* was sent to each one. Rate is the
part of a probe's character that the allow-list cannot express.

**The unit is hosts, because the requirement's unit is hosts.** A host costs several
probes — an echo, a connect per configured port, a banner read, a certificate fetch —
so a literal packets-per-second reading of "50 hosts/s" would pace roughly five times
slower than the number says. That would be defensible and confusing: an operator who
sets 50 and measures 9 stops trusting the control. Instead one token is spent when a
host's probing *begins*, and that host's probes then run in sequence rather than
together, so the packet rate stays proportional to the host rate rather than multiplying
by the port count.

**Why a virtual clock rather than counted tokens.** Discovery probes many hosts
concurrently, so several workers ask for permission at once. A bucket that decrements a
counter has to decide what happens between "there is a token" and "I took it", and the
usual answer — hold a lock across the sleep — serialises the workers into single file,
which is the opposite of the intent. Here each caller claims the next departure *slot*
under the lock, releases it, and then sleeps until its own slot arrives. Claiming is
O(1) and uncontended, waiting is concurrent, and no two callers can ever be handed the
same slot. The spacing that results is exact rather than statistical.

**Smooth by default.** ``burst`` is 1, so departures are spaced by a full interval and a
limiter idle for ten minutes does not release ten minutes' worth at once. A token bucket
would; that behaviour is right for an API client protecting a server's capacity and
wrong here, where the point is not to look like a scan.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Final

from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger

log = get_logger(__name__)

#: FR-DISC-05's default, quoted from the requirement.
DEFAULT_RATE_PER_SECOND: Final[int] = 50

#: The fastest a scope may be configured to run.
#:
#: "Configurable" without a ceiling makes the requirement unenforceable — an operator
#: who sets a million is not rate-limiting, and the control would exist only to be
#: pointed at during an audit. A thousand hosts a second is far beyond any real
#: management network's needs and still visibly a limit. Kept in step with the
#: ``le=1000`` on ``DiscoveryScopeCreate.rate_limit_per_second``.
MAX_RATE_PER_SECOND: Final[int] = 1000

Clock = Callable[[], float]
Sleep = Callable[[float], Awaitable[None]]


class HostPacer:
    """Spaces the start of each host's probing (FR-DISC-05).

    ``clock`` and ``sleep`` are injected so that a test can prove the spacing against a
    clock it controls. Testing a limiter by actually waiting means either a test that
    takes a minute or a tolerance so wide it would pass with no limiter at all — and the
    second is the one that gets written.
    """

    __slots__ = ("_clock", "_interval", "_lock", "_next_slot", "_sleep", "_tolerance", "rate")

    def __init__(
        self,
        rate_per_second: int = DEFAULT_RATE_PER_SECOND,
        *,
        burst: int = 1,
        clock: Clock | None = None,
        sleep: Sleep | None = None,
    ) -> None:
        if rate_per_second < 1:
            raise ValidationProblem(
                "A discovery rate limit must be at least one host per second. To stop a "
                "scope running, disable it rather than pacing it to zero."
            )
        if rate_per_second > MAX_RATE_PER_SECOND:
            raise ValidationProblem(
                f"{rate_per_second} hosts per second is above the {MAX_RATE_PER_SECOND} "
                "ceiling. Discovery is paced so that it is distinguishable from a port "
                "sweep (SRS §1.2); a limit set high enough stops being one."
            )
        if burst < 1:
            raise ValidationProblem("A burst allowance of less than one host would never start.")

        self.rate = rate_per_second
        self._interval = 1.0 / rate_per_second
        # How far into the past a slot may be claimed, which is what lets an idle
        # limiter release `burst` hosts immediately. At the default of 1 this is zero:
        # the first host goes now and every later one waits its full interval.
        self._tolerance = (burst - 1) * self._interval
        self._clock: Clock = clock or time.monotonic
        self._sleep: Sleep = sleep or asyncio.sleep
        self._next_slot = float("-inf")
        self._lock = asyncio.Lock()

    async def acquire(self) -> float:
        """Wait until this caller's turn. Returns the seconds spent waiting.

        The return value is not decoration: a run reports its observed pace, and a run
        that never waited is one where the limiter was not the binding constraint —
        which is the normal case for a sparse scope full of addresses that time out, and
        worth being able to tell apart from a limiter that is not working.
        """
        async with self._lock:
            now = self._clock()
            slot = max(self._next_slot, now - self._tolerance)
            self._next_slot = slot + self._interval

        delay = slot - self._clock()
        if delay <= 0:
            return 0.0
        await self._sleep(delay)
        return delay


__all__ = [
    "DEFAULT_RATE_PER_SECOND",
    "MAX_RATE_PER_SECOND",
    "HostPacer",
]
