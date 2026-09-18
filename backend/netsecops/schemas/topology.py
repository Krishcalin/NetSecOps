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

    #: Literal addresses. Names are not resolved, so that what was analysed is what was
    #: asked and the audit record names the address actually reasoned about.
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


__all__ = [
    "HopRead",
    "MissingDeviceRead",
    "PathRequest",
    "PathResponse",
    "TopologySummary",
]
