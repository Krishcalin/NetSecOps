"""Segmentation policy payloads (FR-TOPO-07)."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field


class ZoneRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None = None
    prefixes: list[str] = Field(default_factory=list)


class ZoneCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    #: At least one. A zone with no addresses can neither be reached nor be a source,
    #: so every rule touching it would evaluate to "unverified" — a row of grey that
    #: reads as a broken tool rather than as the unanswerable rows it would be.
    prefixes: list[str] = Field(min_length=1, max_length=64)


class RuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_zone_id: uuid.UUID
    destination_zone_id: uuid.UUID
    expectation: str
    protocol: str
    port: int
    justification: str


class RuleCreate(BaseModel):
    source_zone_id: uuid.UUID
    destination_zone_id: uuid.UUID
    #: `allowed` or `denied`. No "these services only": that form reads well and
    #: evaluates badly, because proving a negative about every service except a named
    #: few means walking the whole port space, which the path engine does not do.
    expectation: str = Field(pattern="^(allowed|denied)$")
    protocol: str = Field(default="tcp", max_length=8)
    port: int = Field(default=443, ge=0, le=65535)
    #: Required. A matrix cell nobody can explain is one nobody dares change, and it
    #: outlives the reason it was added.
    justification: str = Field(min_length=10, max_length=2000)


class CellRead(BaseModel):
    """One zone pair, evaluated against the live graph."""

    rule_id: uuid.UUID
    source_zone: str
    destination_zone: str
    expectation: str
    protocol: str
    port: int
    #: `upheld` | `violated` | `unverified`. The third is never a pass — see
    #: `netsecops.services.segmentation`.
    status: str
    detail: str
    justification: str
    #: The prefix pairs actually walked. A cell speaks only for these.
    walked: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class MatrixRead(BaseModel):
    cells: list[CellRead] = Field(default_factory=list)
    upheld: int = 0
    violated: int = 0
    #: Counted separately from `upheld` and never folded into it. A matrix that showed
    #: green for pairs nobody could test would be a compliance artefact asserting
    #: isolation that was never checked.
    unverified: int = 0
    limitations: list[str] = Field(default_factory=list)


__all__ = [
    "CellRead",
    "MatrixRead",
    "RuleCreate",
    "RuleRead",
    "ZoneCreate",
    "ZoneRead",
]
