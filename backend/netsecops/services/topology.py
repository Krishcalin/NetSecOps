"""Assembling the graph from stored snapshots (FR-TOPO-02).

The graph is built from each device's most recent snapshot and held for one request. It
is deliberately *not* cached across requests: a snapshot is the evidence a collection
produced, a new collection replaces it, and a topology answer that silently reflects
yesterday's estate is the kind of wrong that looks right. Building it is a read of rows
already in memory-sized JSON and costs far less than the collection it summarises.

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
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.logging import get_logger
from netsecops.db.models.collection import Snapshot
from netsecops.db.models.inventory import Device, DeviceStatus
from netsecops.ncm.models import Route
from netsecops.parsers.routes import interface_network
from netsecops.topology.graph import DeviceNode, TopologyGraph, build_graph
from netsecops.topology.missing import MissingDevice, missing_devices
from netsecops.topology.path import PathResult, walk

log = get_logger(__name__)


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


class TopologyService:
    """Builds the graph, answers path queries, and ranks what is missing."""

    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id
        self._graph: TopologyGraph | None = None

    async def graph(self) -> TopologyGraph:
        if self._graph is None:
            self._graph = build_graph(await self._nodes())
        return self._graph

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


__all__ = ["GraphSummary", "TopologyService", "latest_snapshot_ids"]
