"""Assembling the graph from stored snapshots (FR-TOPO-02).

The graph is built from each device's most recent snapshot.

**It is held between requests, and only while nothing it was built from has moved.**
This module used to refuse to cache it at all, on the grounds that "a topology answer
that silently reflects yesterday's estate is the kind of wrong that looks right" —
which is correct, and is the requirement the cache was built to satisfy rather than
an argument it overrides. Every entry is keyed on a fingerprint of the devices and
snapshots behind it (`topology/cache.py`), so a hit is a graph identical to the one a
rebuild would produce and any change that could alter it forces the rebuild.

What made the old rule too expensive to keep: the graph costs roughly 580ms to build
at 650 devices, and every screen that touches topology built its own. A single
dashboard load built two of them, in parallel, to show one number each. Set
`NETSECOPS_TOPOLOGY_GRAPH_CACHE=false` to go back to a rebuild per request.

**Only active devices, and only their latest snapshots.** An archived device is not part
of the estate, and including it would route paths through hardware that has been
decommissioned. This is the same exclusion the job scope makes, for the same reason.

**No credentials, anywhere.** This service takes no ``SecretVault`` and opens no device
session — the same structural guarantee as the reporting service. A path answer leaves
the product in a report, so it must be incapable of carrying anything unredacted.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.config import get_settings
from netsecops.core.logging import get_logger
from netsecops.db.models.collection import Finding, FindingStatus, Snapshot
from netsecops.db.models.inventory import Device, DeviceStatus, Site
from netsecops.ncm.models import Neighbour, Route
from netsecops.parsers.routes import interface_network
from netsecops.topology.cache import GRAPH_CACHE, CachedGraph, Fingerprint
from netsecops.topology.estate_map import (
    DeviceMeta,
    EstateMap,
    MapInterface,
    build_map,
)
from netsecops.topology.graph import DeviceNode, TopologyGraph, build_graph
from netsecops.topology.missing import MissingDevice, missing_devices
from netsecops.topology.path import PathResult, walk

log = get_logger(__name__)


def settings_cache_enabled() -> bool:
    """Read the switch per call rather than at import.

    `get_settings` is cached, so this is a dictionary lookup — and reading it at
    import time would bake the value in before a test or a container's environment
    had a chance to set it.
    """
    return get_settings().topology_graph_cache


@dataclass(slots=True)
class GraphSummary:
    """What the graph is made of, so an answer can be read with its coverage in view."""

    devices: int = 0
    devices_with_routes: int = 0
    #: Devices whose snapshot predates route parsing. They are in the graph and
    #: contribute nothing, which is worth stating rather than leaving to be inferred
    #: from a sparse result.
    devices_without_route_data: int = 0
    devices_with_rulebase: int = 0
    routes: int = 0
    unmanaged_next_hops: int = 0


@dataclass(slots=True)
class ResolvedNeighbour:
    """A neighbour entry and the device in the inventory it turned out to be.

    The match is the whole value of the data. An unresolved neighbour is still worth
    showing — it is the edge of the managed estate, the same fact `missing_devices`
    reports for layer 3 — but a resolved one is a *stated* adjacency between two devices
    this product holds configurations for, which nothing else in the graph can produce.
    """

    neighbour: Neighbour
    device_id: uuid.UUID | None = None
    #: `hostname`, `short-hostname` or `address`. Carried so the console can say how
    #: confident the join is rather than presenting all three as the same claim.
    matched_by: str | None = None


@dataclass(slots=True)
class NeighbourView:
    """What one device can see on the wire, with the reason an empty list is empty.

    `cdp_enabled` and `lldp_enabled` exist because "no neighbours" has three causes that
    look identical in a list of none: the protocol is off, the protocol is on and nothing
    answered, or the device was collected before these commands were issued. Reporting
    the first as though it were the second is this codebase's named failure mode.
    """

    snapshot_id: uuid.UUID | None = None
    cdp_enabled: bool | None = None
    lldp_enabled: bool | None = None
    neighbours: list[ResolvedNeighbour] = field(default_factory=list)

    @property
    def matched(self) -> int:
        return sum(1 for entry in self.neighbours if entry.device_id is not None)

    @property
    def unmanaged(self) -> int:
        return len(self.neighbours) - self.matched


class TopologyService:
    """Builds the graph, answers path queries, and ranks what is missing."""

    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id
        self._graph: TopologyGraph | None = None
        #: Filled while the graph is built, from rows already in hand. The map needs
        #: what the inventory knows and the routing graph deliberately does not carry —
        #: device class, criticality, the interface list — and re-reading the devices to
        #: get it would undo the single-query build NFR-PERF-01 asks for.
        self._meta: dict[uuid.UUID, DeviceMeta] = {}
        #: Kept beside the metadata rather than in it: a site *id* is a database fact
        #: that means nothing on a picture, and resolving names is one more query that
        #: only the map pays for.
        self._site_ids: dict[uuid.UUID, uuid.UUID | None] = {}

    async def graph(self) -> TopologyGraph:
        """The estate's graph, built once per change rather than once per request.

        Held across requests behind a fingerprint of the rows it was built from — see
        `topology/cache.py` for why that answers the staleness objection this module
        opens with rather than ignoring it. The service-level `self._graph` stays as
        well: within one request the fingerprint would be checked several times
        otherwise, and that is a query each.
        """
        if self._graph is not None:
            return self._graph

        fingerprint = await self._fingerprint()
        if settings_cache_enabled():
            cached = GRAPH_CACHE.get(fingerprint)
            if cached is not None:
                self._graph, self._meta, self._site_ids = (
                    cached.graph,
                    cached.meta,
                    cached.site_ids,
                )
                return self._graph

        self._graph = build_graph(await self._nodes())
        if settings_cache_enabled():
            GRAPH_CACHE.put(
                CachedGraph(
                    fingerprint=fingerprint,
                    graph=self._graph,
                    meta=dict(self._meta),
                    site_ids=dict(self._site_ids),
                )
            )
        return self._graph

    async def _fingerprint(self) -> Fingerprint:
        """What the graph depends on, in one query of four scalar aggregates.

        Archived devices are excluded from the count for the same reason `_nodes`
        excludes them — they are not part of the estate — but `updated_at` is taken
        over *all* rows, because archiving one is precisely a change the graph must
        notice and it would otherwise only shrink a count that something else might
        have grown back.
        """
        row = (
            await self.session.execute(
                select(
                    select(func.count())
                    .select_from(Device)
                    .where(
                        Device.org_id == self.org_id,
                        Device.status != DeviceStatus.ARCHIVED.value,
                    )
                    .scalar_subquery(),
                    select(func.max(Device.updated_at))
                    .where(Device.org_id == self.org_id)
                    .scalar_subquery(),
                    select(func.count())
                    .select_from(Snapshot)
                    .where(Snapshot.org_id == self.org_id)
                    .scalar_subquery(),
                    # updated_at, not created_at: a re-collection whose config_hash matches
                    # updates the existing snapshot row in place (SnapshotService dedup) —
                    # refreshing its NCM and version without inserting a row or touching
                    # created_at. Keying on created_at meant that refresh moved neither the
                    # count nor this timestamp, so the cache served the pre-refresh graph
                    # (a stale unreachable, or a stale allowed) — the 2026-09-30 audit's
                    # finding. updated_at moves on both insert and in-place refresh.
                    select(func.max(Snapshot.updated_at))
                    .where(Snapshot.org_id == self.org_id)
                    .scalar_subquery(),
                )
            )
        ).one()

        return Fingerprint(
            org_id=self.org_id,
            devices=int(row[0] or 0),
            # Rendered rather than kept as a datetime so two fingerprints compare by
            # value without depending on tzinfo objects being identical.
            devices_changed_at=row[1].isoformat() if row[1] else None,
            snapshots=int(row[2] or 0),
            snapshots_changed_at=row[3].isoformat() if row[3] else None,
        )

    async def _nodes(self) -> list[DeviceNode]:
        devices = (
            (
                await self.session.execute(
                    select(Device).where(
                        Device.org_id == self.org_id,
                        Device.status != DeviceStatus.ARCHIVED.value,
                    )
                )
            )
            .scalars()
            .all()
        )

        # The latest snapshot per device, in one query and without its configuration.
        #
        # This was a query per device inside the loop, each fetching a whole `Snapshot`.
        # On the 2,000-device tier this product publishes sizing for, that is 2,001 round
        # trips, and each row drags `config_redacted` — the entire running configuration,
        # tens to hundreds of kilobytes — which nothing below reads. The graph needs two
        # columns: the snapshot's id and its NCM.
        #
        # `DISTINCT ON` is PostgreSQL-specific and this product requires PostgreSQL 16
        # (SRS §7), so the portable-but-slower alternatives are not worth their cost.
        latest = (
            select(Snapshot.device_id, Snapshot.id, Snapshot.ncm)
            .where(Snapshot.device_id.in_([device.id for device in devices]))
            .distinct(Snapshot.device_id)
            .order_by(Snapshot.device_id, Snapshot.created_at.desc())
        )
        snapshots = {row.device_id: (row.id, row.ncm) for row in await self.session.execute(latest)}

        self._meta = {
            device.id: _meta_from(device, *snapshots.get(device.id, (None, None)))
            for device in devices
        }
        self._site_ids = {device.id: device.site_id for device in devices}
        return [_node_from(device, *snapshots.get(device.id, (None, None))) for device in devices]

    async def summary(self) -> GraphSummary:
        graph = await self.graph()
        missing = missing_devices(graph, limit=10_000)

        return GraphSummary(
            devices=len(graph.nodes),
            devices_with_routes=sum(1 for n in graph.nodes.values() if n.routes),
            devices_without_route_data=len(graph.unknown_route_tables),
            devices_with_rulebase=sum(1 for n in graph.nodes.values() if n.has_rulebase),
            routes=sum(len(n.routes) for n in graph.nodes.values()),
            unmanaged_next_hops=len(missing),
        )

    async def path(
        self, *, source: str, destination: str, protocol: str = "tcp", port: int = 443
    ) -> PathResult:
        graph = await self.graph()
        result = walk(graph, source=source, destination=destination, protocol=protocol, port=port)

        # A device in the graph with no route data cannot support a negative answer, and
        # the operator needs to know that before reading one. Stated once here rather
        # than per hop, because it is a property of the estate's collection coverage.
        stale = graph.unknown_route_tables
        if stale:
            names = ", ".join(sorted(node.hostname for node in stale)[:5])
            more = f" and {len(stale) - 5} more" if len(stale) > 5 else ""
            result.notes.append(
                f"{len(stale)} device(s) in the inventory were collected before "
                f"forwarding tables were parsed ({names}{more}), so they contribute no "
                "routes. A path that avoids them is unaffected; one that should have "
                "crossed them will stop early."
            )

        log.info(
            "topology.path_queried",
            source=source,
            destination=destination,
            protocol=protocol,
            port=port,
            routing=result.routing.value,
            policy=result.policy.value,
            hops=len(result.hops),
        )
        return result

    async def missing(self, *, limit: int = 50) -> list[MissingDevice]:
        return missing_devices(await self.graph(), limit=limit)

    async def neighbours_for(self, device: Device) -> NeighbourView:
        """What one device reported seeing on the wire (FR-TOPO-01).

        Deliberately *not* built on `graph()`. This answers a question about one device
        from one snapshot, and paying 580ms to assemble the whole estate for it would
        make the panel too slow to open — the graph exists to join routes across
        devices, which this does not need.

        The neighbours are resolved against the inventory here rather than in the parser
        because they are two different kinds of fact with different lifetimes: what the
        device said is fixed at collection time and stored on the snapshot; whether the
        estate contains a device by that name changes every time somebody onboards one.
        Baking the match into the snapshot would freeze an answer that should move.
        """
        row = (
            await self.session.execute(
                select(Snapshot.id, Snapshot.ncm)
                .where(Snapshot.device_id == device.id)
                .order_by(Snapshot.created_at.desc())
                .limit(1)
            )
        ).first()

        if row is None:
            return NeighbourView()

        ncm = row.ncm or {}
        features = ncm.get("features") or {}
        raw = (ncm.get("l2") or {}).get("neighbours") or []

        by_hostname, by_short, by_address = await self._identity_index()
        resolved = [
            _resolve(Neighbour.model_validate(entry), by_hostname, by_short, by_address)
            for entry in raw
        ]

        return NeighbourView(
            snapshot_id=row.id,
            cdp_enabled=features.get("cdp"),
            lldp_enabled=features.get("lldp"),
            neighbours=resolved,
        )

    async def _identity_index(
        self,
    ) -> tuple[dict[str, uuid.UUID], dict[str, uuid.UUID], dict[str, uuid.UUID]]:
        """Every name and address the estate answers to, in one query.

        Three indexes rather than one because a neighbour advertises whichever it feels
        like: CDP on IOS reports an FQDN, NX-OS the short name, and a device that
        advertises no name at all may still advertise an address.

        A short name claimed by two devices is dropped from that index instead of
        resolving to whichever sorted first. `core-sw01.site-a` and `core-sw01.site-b`
        are different switches, and a wrong adjacency drawn confidently is worse than
        an unmanaged one that asks a human.
        """
        rows = await self.session.execute(
            select(Device.id, Device.hostname, Device.mgmt_ip).where(
                Device.org_id == self.org_id,
                Device.status != DeviceStatus.ARCHIVED.value,
            )
        )

        by_hostname: dict[str, uuid.UUID] = {}
        by_address: dict[str, uuid.UUID] = {}
        short_counts: dict[str, set[uuid.UUID]] = {}

        for device_id, hostname, mgmt_ip in rows:
            if hostname:
                by_hostname.setdefault(hostname.strip().lower(), device_id)
                short = hostname.strip().lower().split(".", 1)[0]
                short_counts.setdefault(short, set()).add(device_id)
            if mgmt_ip:
                by_address.setdefault(str(mgmt_ip), device_id)

        by_short = {
            name: next(iter(owners)) for name, owners in short_counts.items() if len(owners) == 1
        }
        return by_hostname, by_short, by_address

    async def estate_map(self, *, limit: int = 2000) -> EstateMap:
        """The whole graph, projected into something drawable (FR-TOPO-02).

        Two queries beyond the graph build, both aggregates over the whole estate rather
        than one per device: the site names, and the open findings per device. A map
        that costs a round trip per box is one nobody opens twice.
        """
        graph = await self.graph()

        sites = {
            row.id: row.name
            for row in await self.session.execute(
                select(Site.id, Site.name).where(Site.org_id == self.org_id)
            )
        }
        findings = await self._finding_counts()

        meta = {
            device_id: replace(
                info,
                site=sites.get(self._site_ids.get(device_id)) if self._site_ids else None,
                findings=findings.get(device_id, {}),
            )
            for device_id, info in self._meta.items()
        }
        return build_map(graph, meta=meta, limit=limit)

    async def _finding_counts(self) -> dict[uuid.UUID, dict[str, int]]:
        """Open findings per device, by severity, in one grouped query."""
        rows = await self.session.execute(
            select(Finding.device_id, Finding.severity, func.count())
            .where(
                Finding.org_id == self.org_id,
                Finding.status.in_(FindingStatus.active_values()),
            )
            .group_by(Finding.device_id, Finding.severity)
        )

        counts: dict[uuid.UUID, dict[str, int]] = {}
        for device_id, severity, total in rows:
            counts.setdefault(device_id, {})[severity] = int(total)
        return counts


def _resolve(
    neighbour: Neighbour,
    by_hostname: dict[str, uuid.UUID],
    by_short: dict[str, uuid.UUID],
    by_address: dict[str, uuid.UUID],
) -> ResolvedNeighbour:
    """Which device in the inventory a neighbour entry names, if any.

    Ordered strongest first. The full name is tried before the short one because two
    estates that both run a `core-sw01` are common and a domain suffix is what tells
    them apart; the address is tried last because a neighbour advertises whichever
    interface it likes, and that is frequently not the address the inventory manages
    the device on.
    """
    name = (neighbour.remote_device or "").strip().lower()

    if name:
        if (device_id := by_hostname.get(name)) is not None:
            return ResolvedNeighbour(neighbour, device_id, "hostname")
        if (device_id := by_short.get(name.split(".", 1)[0])) is not None:
            return ResolvedNeighbour(neighbour, device_id, "short-hostname")

    if neighbour.remote_address and (
        (device_id := by_address.get(neighbour.remote_address)) is not None
    ):
        return ResolvedNeighbour(neighbour, device_id, "address")

    return ResolvedNeighbour(neighbour)


def _node_from(
    device: Device, snapshot_id: uuid.UUID | None, snapshot_ncm: dict[str, Any] | None
) -> DeviceNode:
    """One device's node, from its latest snapshot.

    Takes the two fields it uses rather than a `Snapshot`, so the caller can select them
    instead of loading whole rows — the configuration text on a snapshot is the largest
    column in the schema and nothing here reads it.

    A device with no snapshot still becomes a node. It has no routes and no rulebase, so
    it contributes nothing to a path — but it *is* in the inventory, which means its
    interface addresses would have joined two hops had they been collected. Leaving it
    out entirely would make it invisible to the missing-device report, which is exactly
    the report that should be pointing at it.
    """
    ncm = snapshot_ncm or {}
    routing = ncm.get("routing") or {}
    firewall = ncm.get("firewall") or {}

    node = DeviceNode(
        device_id=device.id,
        hostname=device.hostname or str(device.mgmt_ip),
        platform=device.platform,
        vendor=device.vendor,
        snapshot_id=snapshot_id,
        # Keyed off the snapshot existing, not off the NCM carrying a version: a
        # snapshot predating NCM 1.1 has no `ncm_version`, and reporting None for it is
        # what tells the path walker "never looked" rather than "no routes".
        ncm_version=ncm.get("ncm_version") if snapshot_id else None,
        routes=[Route.model_validate(row) for row in routing.get("routes") or []],
        routes_truncated=bool(routing.get("routes_truncated")),
        has_rulebase=bool(firewall.get("security_rules")),
        firewall=firewall,
    )

    for interface in ncm.get("interfaces") or []:
        name = interface.get("name")
        if not name:
            continue
        if zone := interface.get("zone"):
            node.zones[name] = zone

        for address in interface.get("ip_addresses") or []:
            _index_address(node, name, str(address))

    # The management address is an interface address too, and on plenty of platforms it
    # is the only one the parser records. Without it a device whose peers route to its
    # management IP would never be joined to them.
    if device.mgmt_ip:
        _index_address(node, "management", f"{device.mgmt_ip}/32")

    return node


#: How many addressed interfaces reach the map per device. A core switch can carry
#: hundreds of SVIs and the panel is not the place to read them all; the device's
#: configuration page is.
MAX_INTERFACES = 24


def _meta_from(
    device: Device, snapshot_id: uuid.UUID | None, snapshot_ncm: dict[str, Any] | None
) -> DeviceMeta:
    """What the picture needs about a device beyond its routes.

    Only addressed interfaces reach the map. A layer-3 picture is drawn from addresses,
    and an access switch's forty-eight unaddressed ports would be forty-eight rows of a
    payload that no strand on the map is drawn from — so the count of all of them is
    carried separately rather than the list being quietly filtered.
    """
    ncm = snapshot_ncm or {}
    raw = ncm.get("interfaces") or []

    addressed: list[MapInterface] = []
    for interface in raw:
        name = interface.get("name")
        addresses = tuple(str(value) for value in (interface.get("ip_addresses") or []))
        if not name or not addresses:
            continue
        addressed.append(MapInterface(name=name, addresses=addresses, zone=interface.get("zone")))

    return DeviceMeta(
        device_class=device.device_class,
        criticality=device.criticality,
        status=device.status,
        interfaces=tuple(addressed[:MAX_INTERFACES]),
        interface_count=len(raw),
        # Deliberately the snapshot and not `last_collected_at`: that column is written
        # by fact recording during a live collection, so a device whose configuration
        # arrived by upload has none — and this estate is full of them. A flag that is
        # false for most of the inventory would put "never collected" on devices with
        # a parsed configuration and hundreds of findings.
        has_snapshot=snapshot_id is not None,
    )


def _index_address(node: DeviceNode, interface: str, address: str) -> None:
    """Record an interface address as both a join key and a subnet."""
    import ipaddress

    text = address.strip()
    if " " in text:
        parts = text.split()
        if len(parts) == 2:
            text = f"{parts[0]}/{parts[1]}"

    try:
        parsed = ipaddress.ip_interface(text)
    except ValueError:
        return

    node.interface_addresses.add(int(parsed.ip))

    network = interface_network(address)
    if network:
        try:
            node.interface_networks.append((interface, ipaddress.ip_network(network)))
        except ValueError:
            return


def latest_snapshot_ids(nodes: Sequence[DeviceNode]) -> list[uuid.UUID]:
    """The snapshots a graph was built from, for a report that has to cite its evidence."""
    return [node.snapshot_id for node in nodes if node.snapshot_id is not None]


__all__ = [
    "GraphSummary",
    "NeighbourView",
    "ResolvedNeighbour",
    "TopologyService",
    "latest_snapshot_ids",
]
