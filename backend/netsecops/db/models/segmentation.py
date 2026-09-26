"""Declared segmentation intent, and what the estate actually does (FR-TOPO-07).

Every other part of this product answers "what does this configuration do". This part
answers the question people actually get audited on: **"is what it does what we said it
would do"**. A segmentation policy is the statement — production must not reach the card
data environment, the guest network must reach nothing but the internet — and until it
is written down, the only way to check it is for somebody to read four rulebases and
hold the answer in their head.

Two decisions shape the model, and both are about not lying.

**A zone is defined by address space, not by a firewall's zone name.** `dmz` on one
device and `DMZ` on another may or may not be the same thing, and on a router there are
no zone names at all. Naming the addresses is unambiguous, it works across vendors, and
it is what the path walk can actually evaluate. The cost is that somebody has to write
the CIDRs down once; the alternative is a matrix whose rows mean something different on
each device it touches.

**Intent is per ordered pair.** "A may reach B" says nothing about whether B may reach
A, and a symmetric matrix would quietly assert the reverse of everything declared. Most
real segmentation is asymmetric — a web tier reaching a database tier is normal and the
reverse is an incident.

What is deliberately *not* here: the evaluation results. They are recomputed from the
current graph on every request rather than stored, because a stored verdict is a claim
about an estate that has since changed, and this is the one part of the product where a
stale "compliant" is worse than no answer at all. The report archive is where a frozen
answer belongs, and it says when it was taken.
"""

from __future__ import annotations

import uuid
from enum import StrEnum

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from netsecops.db.base import Base, OrgMixin, TimestampMixin, UUIDPrimaryKeyMixin


class SegmentationExpectation(StrEnum):
    """What the policy says about one ordered zone pair.

    Only two values, and no "allow these services only" third. That form reads well and
    evaluates badly: proving a *negative* about every service except a named few means
    walking the whole port space, which the path engine does not do. Offering it would
    produce a verdict that looked service-aware and was not. A service-scoped intent is
    expressed as a separate `ALLOWED` rule naming the ports, alongside a `DENIED` rule
    for the pair — two honest statements instead of one misleading one.
    """

    #: Traffic is expected to be permitted. A blocked path violates this.
    ALLOWED = "allowed"
    #: Traffic is expected to be blocked. A permitted path violates this, and it is the
    #: direction that matters — an unexpected permit is an exposure, an unexpected deny
    #: is an outage somebody already noticed.
    DENIED = "denied"


class SegmentationZone(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """A named piece of address space.

    Not a firewall zone. The name is for people; `prefixes` is what gets evaluated.
    """

    __tablename__ = "segmentation_zones"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_segmentation_zones_org_name"),
        # A zone with no addresses can neither be reached nor be a source, so every
        # rule touching it would evaluate to "not verified" — a matrix row of grey
        # that looks like a tooling fault. Refused at the boundary instead.
        CheckConstraint("cardinality(prefixes) > 0", name="ck_segmentation_zones_has_prefixes"),
    )

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    #: IPv4 CIDRs, as written. Stored as text rather than as `cidr` so a malformed entry
    #: is reported by the validator with a message, not by Postgres with a type error.
    prefixes: Mapped[list[str]] = mapped_column(ARRAY(String(64)), nullable=False)


class SegmentationRule(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """One cell of the matrix: what should happen from one zone to another."""

    __tablename__ = "segmentation_rules"
    __table_args__ = (
        UniqueConstraint(
            "org_id",
            "source_zone_id",
            "destination_zone_id",
            "protocol",
            "port",
            name="uq_segmentation_rules_pair",
        ),
        Index("ix_segmentation_rules_source", "org_id", "source_zone_id"),
        # A pair with itself is not segmentation. Intra-zone traffic does not cross a
        # boundary, so there is nothing for a path walk to evaluate and the row would
        # always read "not verified".
        CheckConstraint(
            "source_zone_id <> destination_zone_id", name="ck_segmentation_rules_not_self"
        ),
    )

    source_zone_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("segmentation_zones.id", ondelete="CASCADE"),
        nullable=False,
    )
    destination_zone_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("segmentation_zones.id", ondelete="CASCADE"),
        nullable=False,
    )

    expectation: Mapped[str] = mapped_column(String(16), nullable=False)
    #: The traffic the statement is about. A segmentation policy that named no port
    #: would have to mean "all traffic", and the path engine evaluates one protocol and
    #: port at a time — so the policy says which, rather than the engine guessing.
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp")
    port: Mapped[int] = mapped_column(nullable=False, default=443)

    #: Why this rule exists. Required for the same reason a finding exception's is: a
    #: matrix cell nobody can explain is one nobody dares change, and it outlives the
    #: reason it was added.
    justification: Mapped[str] = mapped_column(Text, nullable=False)


__all__ = ["SegmentationExpectation", "SegmentationRule", "SegmentationZone"]
