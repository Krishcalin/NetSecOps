"""Holding the layer-3 graph between requests, without holding a stale one.

`services/topology.py` refused to cache the graph, and the reason it gave was right:
"a topology answer that silently reflects yesterday's estate is the kind of wrong that
looks right". That objection is not overridden here. It is answered.

**The cache is keyed on a fingerprint of its own inputs.** An entry is served only
while the devices and snapshots it was built from are unchanged — the counts and the
newest timestamp of each. Anything that could alter the graph moves one of those four
numbers: a collection writes a snapshot, an onboarding writes a device, an archive or
a rename touches `devices.updated_at`, a retention purge changes a count. A miss is
therefore a rebuild, and a hit is a graph that is *byte-for-byte* the one a rebuild
would produce.

**What it does not protect against** is worth stating, because a cache that claims too
much is worse than none. A change nothing records — a row edited straight in the
database, a clock that runs backwards — will not move the fingerprint. That is the
same exposure every `updated_at` in this schema already has, and the product is not
built to survive somebody editing its tables underneath it.

The reason it is worth having: the graph costs roughly 580ms to build at 650 devices
and every screen that touches topology built its own. One dashboard load built two,
independently and in parallel, for one figure each. At the 2,000-device tier this
product publishes sizing for that is several seconds of repeated work per page.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from netsecops.core.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """What the graph was built from, cheaply enough to check on every request.

    Counts *and* newest timestamps, because either alone is defeatable: a device
    archived while another is added leaves the count unmoved, and a row edited in the
    same microsecond as the previous newest leaves the timestamp unmoved. Together
    they close both, and the pair costs one query of four scalar aggregates.
    """

    org_id: int
    devices: int
    devices_changed_at: str | None
    snapshots: int
    snapshots_changed_at: str | None
    #: DR sets collapse devices into one logical node, so a change to them changes the
    #: graph without touching a device or snapshot row. Counted and timestamped for the
    #: same reason as the pairs above: a set created as another is deleted leaves the
    #: count unmoved, and the timestamp closes it.
    dr_members: int = 0
    dr_changed_at: str | None = None


@dataclass(slots=True)
class CachedGraph:
    """Everything `TopologyService` would otherwise have rebuilt."""

    fingerprint: Fingerprint
    graph: Any
    meta: dict[Any, Any]
    site_ids: dict[Any, Any]


class GraphCache:
    """One entry per organisation, replaced whenever its fingerprint moves.

    One entry rather than several: the graph is the whole estate, so a second entry
    for the same org would only ever be an older copy of the same thing. That also
    bounds the memory — a deployment holds as many graphs as it has organisations,
    not as many as it has had requests.
    """

    def __init__(self) -> None:
        self._entries: dict[int, CachedGraph] = {}
        # Two requests arriving together may both miss and both build. That is
        # wasteful and harmless — they build the same graph — so the lock guards only
        # the dictionary, never the build. Holding it across a 580ms build would
        # serialise every topology request in the process.
        self._lock = threading.Lock()

    def get(self, fingerprint: Fingerprint) -> CachedGraph | None:
        with self._lock:
            entry = self._entries.get(fingerprint.org_id)
        if entry is None or entry.fingerprint != fingerprint:
            return None
        return entry

    def put(self, entry: CachedGraph) -> None:
        with self._lock:
            self._entries[entry.fingerprint.org_id] = entry

    def clear(self) -> None:
        """Drop everything. For tests, and for an operator who wants to be certain."""
        with self._lock:
            self._entries.clear()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._entries)


#: Process-wide, deliberately. A worker process and an API process hold their own, and
#: neither can serve the other something stale because each checks the fingerprint
#: against the same database before answering.
GRAPH_CACHE = GraphCache()


__all__ = ["GRAPH_CACHE", "CachedGraph", "Fingerprint", "GraphCache"]
