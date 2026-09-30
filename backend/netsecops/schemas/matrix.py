"""Connectivity-discovery matrix payloads (Slice B)."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field


class DerivedZoneRead(BaseModel):
    cidr: str
    label: str
    device_hostnames: list[str] = Field(default_factory=list)


class MatrixCellRead(BaseModel):
    source: str
    destination: str
    source_cidr: str
    destination_cidr: str
    #: Two axes, never collapsed: routing ∈ unreachable/same-zone/routed/partially-routed/
    #: unknown, policy ∈ allowed/blocked/partially-allowed/not-routed.
    routing: str
    policy: str
    hops: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class DiscoveryMatrixRead(BaseModel):
    group_id: uuid.UUID
    group_name: str
    protocol: str
    port: int
    zones: list[DerivedZoneRead] = Field(default_factory=list)
    cells: list[MatrixCellRead] = Field(default_factory=list)
    #: States that zones are the group's while paths cross the whole estate — a reader
    #: has to know the walk left the group to trust a cell.
    scope_note: str
    limitations: list[str] = Field(default_factory=list)
