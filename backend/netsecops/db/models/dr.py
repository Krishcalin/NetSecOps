"""Disaster-recovery sets: two or more devices that are replicas of one another.

A DR set names a primary and its standby (or standbys). The point of recording it is
that the analysis then treats the set as **one logical device** — the standby's
near-identical rulebase is not a second firewall in the estate, a path through the pair
is one hop rather than two, and the standby is not counted, drawn or reported as an
independent node. That collapse lives in the topology service (a separate change); this
module is only the record it reads.

Two decisions shape the model.

**A device belongs to at most one DR set.** `device_id` is the primary key of the
membership table, so the database enforces it rather than a service remembering to. A
device that is a standby in two sets is not a fact about any real estate; it is a data
error, and it is refused at write time.

**Exactly one member is the primary.** The logical node is built from the primary's
configuration — its routes and its rulebase are what a packet is evaluated against — so
a set with no primary has no configuration to analyse and a set with two has an
ambiguous one. A partial unique index enforces one `primary` row per set; the service
enforces *at least* one, because a `NOT NULL` cannot say "one of these rows".
"""

from __future__ import annotations

import uuid
from enum import StrEnum

from sqlalchemy import ForeignKey, Index, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netsecops.db.base import Base, OrgMixin, TimestampMixin, UUIDPrimaryKeyMixin


class DrRole(StrEnum):
    """Which half of the pair a member is."""

    PRIMARY = "primary"
    STANDBY = "standby"


class DrSet(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """A named set of devices that are disaster-recovery replicas of one another."""

    __tablename__ = "dr_sets"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_dr_sets_org_id_name"),)

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    members: Mapped[list[DrSetMember]] = relationship(
        cascade="all, delete-orphan", lazy="selectin", back_populates="dr_set"
    )


class DrSetMember(Base, OrgMixin):
    """One device's membership in a DR set, and the role it plays.

    ``device_id`` is the primary key — not a composite with ``dr_set_id`` — because a
    device is in at most one set, and making it the key is how that is enforced rather
    than merely intended.
    """

    __tablename__ = "dr_set_members"
    __table_args__ = (
        # At most one primary per set. Partial, so any number of standbys is fine.
        Index(
            "uq_dr_set_members_one_primary",
            "dr_set_id",
            unique=True,
            postgresql_where=text("role = 'primary'"),
        ),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True
    )
    dr_set_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("dr_sets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)

    dr_set: Mapped[DrSet] = relationship(back_populates="members")
