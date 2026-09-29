"""Topology and path-analysis payloads (SRS §4.2, FR-TOPO-03 … FR-TOPO-06).

The shape of :class:`PathResponse` is the requirement, not a presentation choice.
FR-TOPO-04 asks for routing confidence and policy verdict as two separate fields, and
they stay separate all the way to the wire — a client that wanted one summary string
would have to combine them itself, and would have to decide what to do about
"every firewall permits this, and I lost the path halfway" in order to do so.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field


class PathRequest(BaseModel):
    """A packet to trace. Nothing is sent; this is simulation over stored snapshots."""

    #: A literal address or a CIDR range. Names are not resolved, so that what was
    #: analysed is what was asked and the audit record names the addresses actually
    #: reasoned about.
    #:
    #: A range asks the segmentation question — "can anything in here reach anything in
    #: there" — which a host pair cannot. Where a rulebase treats part of a range
    #: differently from the rest, the policy verdict is `partially-allowed` and the note
    #: names the rules responsible, rather than answering for a representative address.
    source: str = Field(min_length=1, max_length=45)
    destination: str = Field(min_length=1, max_length=45)
    protocol: str = Field(default="tcp", max_length=16)
    port: int = Field(default=443, ge=0, le=65535)


class HopRead(BaseModel):
    """One device on the path, and what it decided."""

    device_id: uuid.UUID
    hostname: str
    platform: str | None = None

    matched_route: str | None = None
    next_hop: str | None = None
    egress_interface: str | None = None
    ingress_zone: str | None = None
    egress_zone: str | None = None

    #: None where the device carries no rulebase. Distinct from "allow", and the UI must
    #: not render them the same: a router forwarding without an opinion is not a control
    #: that was checked.
    action: str | None = None
    rule_name: str | None = None
    rule_order: int | None = None
    limitations: list[str] = Field(default_factory=list)
    #: True where this device has a rulebase that was consulted and could not be
    #: evaluated, because a rule ahead of the answer references an object no
    #: configuration contains — a cloud security group, an SDN dynamic group, a service
    #: tag. `action` is None here too, so without this flag the UI cannot tell a router
    #: with no opinion from a firewall whose opinion is unknown.
    undecidable: bool = False
    #: What this device's NAT did to the packet, or None. Every hop after one that
    #: translates was traced with the rewritten addresses, so this is where a reader
    #: finds out the question changed part-way along the path.
    translation: str | None = None


class PathResponse(BaseModel):
    """The answer, on both axes (FR-TOPO-04)."""

    source: str
    destination: str
    protocol: str
    port: int

    #: `unreachable` | `same-zone` | `routed` | `partially-routed` | `unknown`
    routing: str
    #: `allowed` | `blocked` | `partially-allowed` | `not-routed`
    #:
    #: `allowed` is only ever paired with `routed`. A permit on a path that was not
    #: traced to the end reports as `partially-allowed`, because it speaks only for the
    #: devices actually consulted.
    policy: str

    hops: list[HopRead] = Field(default_factory=list)

    #: Where the trace stopped, when it did not finish — named so the answer is
    #: actionable rather than merely hedged (FR-TOPO-05).
    stopped_at_prefix: str | None = None
    stopped_at_next_hop: str | None = None
    stopped_at_device: str | None = None

    #: Translations the walk followed — "edge-fw: destination 203.0.113.10 →
    #: 10.20.0.10". Informational, and deliberately not a caveat: the hops after each
    #: of these were evaluated against the rewritten addresses, which is the correct
    #: question, so a followed translation does not weaken the verdict.
    translated_at: list[str] = Field(default_factory=list)
    #: NAT that may apply here and could not be followed — a pool chosen per session,
    #: an object nothing defines, a form no parser reads. This one does weaken
    #: everything after it, and non-empty implies `policy` is `partially-allowed`.
    translation_unknown_at: list[str] = Field(default_factory=list)

    #: Devices where the packet had more than one equal-cost route and this trace
    #: followed one of them. Structured beside the note for the same reason
    #: `stopped_at_*` is: a caveat a UI can render as a branch is one somebody acts on.
    #: Non-empty implies `policy` is `partially-allowed` rather than `allowed`.
    branched_at: list[str] = Field(default_factory=list)

    #: Read these beside the verdict. A caveat that lives only in a log is one nobody
    #: reads, and most of what makes a path answer trustworthy is in here.
    notes: list[str] = Field(default_factory=list)


class MissingDeviceRead(BaseModel):
    """An address routes point at that no inventoried device answers for (FR-TOPO-06)."""

    address: str
    referenced_by: list[str] = Field(default_factory=list)
    prefixes: list[str] = Field(default_factory=list)
    carries_default_route: bool = False
    #: Comparable within one report only. It ranks gaps; it does not measure anything in
    #: the world.
    score: int = 0
    #: The attached subnet it sits on, where the estate reaches one. An address beside
    #: devices already managed is far more likely to be onboardable than one across a
    #: handoff to somebody else's network.
    adjacent_to: str | None = None
    reason: str


class MapInterfaceRead(BaseModel):
    """One addressed interface, as the picture and its detail panel need it."""

    name: str
    addresses: list[str] = Field(default_factory=list)
    zone: str | None = None


class MapNodeRead(BaseModel):
    """A box on the map (FR-TOPO-02)."""

    id: str
    #: `device` or `unmanaged`. The second is an address routes point at that nothing in
    #: the inventory answers for — a hole in the evidence, never drawn as a device.
    kind: str
    label: str
    group: str
    #: Breadth-first distance from the estate boundary. The column the box is drawn in.
    tier: int

    platform: str | None = None
    vendor: str | None = None
    device_class: str | None = None
    criticality: str | None = None
    status: str | None = None
    site: str | None = None

    #: Carries security rules of any kind.
    has_rulebase: bool = False
    #: Carries rules in force on traffic crossing it. Narrower, and what the picture is
    #: drawn from: an access list bound to nothing — a vty filter, a leftover — filters
    #: no transit traffic, and badging its device as a firewall would put a control on
    #: the map where the network has none.
    inspects: bool = False
    routes: int = 0
    #: False where the snapshot predates route parsing: the device has no routes that
    #: anybody read, which is not the same as having none.
    routes_known: bool = True
    interfaces: list[MapInterfaceRead] = Field(default_factory=list)
    #: Every interface, addressed or not. `interfaces` carries only the addressed ones.
    interface_count: int = 0
    findings: dict[str, int] = Field(default_factory=dict)
    has_snapshot: bool = False

    referenced_by: list[str] = Field(default_factory=list)
    carries_default_route: bool = False


class MapLinkRead(BaseModel):
    """A strand between two boxes."""

    id: str
    source: str
    target: str
    #: The next-hop addresses that produced it, capped.
    via: list[str] = Field(default_factory=list)
    prefixes: int = 0
    carries_default: bool = False
    #: False where only one end routes to the other, which is a real asymmetry and is
    #: drawn as one rather than tidied into a plain line.
    bidirectional: bool = False
    source_interface: str | None = None
    target_interface: str | None = None
    crosses_firewall: bool = False


class MapGroupRead(BaseModel):
    """A connected component of the graph."""

    id: str
    label: str
    #: `site` | `hostname` | `index`. Where the label came from, so nobody reads an
    #: inferred one as something that was configured.
    label_source: str
    devices: int = 0
    firewalls: int = 0
    unmanaged: int = 0
    links: int = 0
    tiers: int = 1


class EstateMapRead(BaseModel):
    """The whole graph, drawable (FR-TOPO-02)."""

    nodes: list[MapNodeRead] = Field(default_factory=list)
    links: list[MapLinkRead] = Field(default_factory=list)
    groups: list[MapGroupRead] = Field(default_factory=list)

    devices: int = 0
    unmanaged: int = 0
    devices_without_route_data: int = 0
    #: Devices no strand touches. Either genuinely standalone or never collected, and
    #: the picture cannot tell those apart — so it counts them rather than hiding them.
    isolated: int = 0

    #: Whole groups dropped because the estate exceeded the cap. Whole ones, because
    #: half a component is a picture of a network that does not exist.
    omitted_groups: list[str] = Field(default_factory=list)
    omitted_devices: int = 0


class TopologySummary(BaseModel):
    """What the graph is made of, so an answer can be read with its coverage in view."""

    devices: int = 0
    devices_with_routes: int = 0
    #: Collected before forwarding tables were parsed. They are in the graph and
    #: contribute nothing — worth stating rather than leaving to be inferred from a
    #: sparse result.
    devices_without_route_data: int = 0
    devices_with_rulebase: int = 0
    routes: int = 0
    unmanaged_next_hops: int = 0


class NeighbourRead(BaseModel):
    """One entry from a device's CDP or LLDP table (FR-TOPO-01).

    Every other adjacency this product reports is inferred — a route names a next hop,
    the next hop falls inside an interface's subnet, and the two are concluded to be
    connected. This is a device *stating* that a cable runs from one port to another,
    which is a different kind of claim, and `protocol` stays on the wire so a reader can
    tell which of the two they are looking at.
    """

    protocol: str
    local_interface: str
    remote_device: str | None = None
    remote_interface: str | None = None
    remote_address: str | None = None
    platform: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    #: The device in this inventory the entry resolves to, where it resolves to one.
    #: Null is not an error: the far end may be a phone, an access point, a customer
    #: handoff or simply a switch nobody has onboarded.
    device_id: uuid.UUID | None = None
    #: `hostname`, `short-hostname` or `address` — how the match above was made, so the
    #: console can show how strong the join is instead of presenting all three alike.
    matched_by: str | None = None


class DeviceNeighboursRead(BaseModel):
    """A device's neighbour table, with the reason an empty one is empty.

    `cdp_enabled` and `lldp_enabled` are the point of this envelope. A list of no
    neighbours has three causes that look identical — the protocol is disabled, the
    protocol is enabled and nothing answered, or the device was collected before these
    commands were ever issued — and only the first two are visible from the feature
    flags. `snapshot_id` covers the third: null means nothing has been collected at all.
    """

    device_id: uuid.UUID
    snapshot_id: uuid.UUID | None = None
    cdp_enabled: bool | None = None
    lldp_enabled: bool | None = None
    neighbours: list[NeighbourRead] = Field(default_factory=list)
    #: Resolved to a device in this inventory, and not. Split out so the console does not
    #: have to count a list to say "4 of 11 are managed".
    matched: int = 0
    unmanaged: int = 0


__all__ = [
    "DeviceNeighboursRead",
    "EstateMapRead",
    "HopRead",
    "MapGroupRead",
    "MapInterfaceRead",
    "MapLinkRead",
    "MapNodeRead",
    "MissingDeviceRead",
    "NeighbourRead",
    "PathRequest",
    "PathResponse",
    "TopologySummary",
]
