"""Discovery scopes, runs and the review queue (SRS §5.1, FR-DISC-01 … FR-DISC-06).

Three tables, and the separation between the last two is the requirement:

- **discovery_scopes** — what may be probed, as configuration.
- **discovery_runs** — one execution, for "when did we last look, and what happened".
- **discovered_hosts** — what answered, waiting for a human.

**A discovered host is not a device, and that is the point.** FR-DISC-04 says nothing is
assessed without approval. If a discovery run created inventory directly, NetSecOps
would start authenticating to boxes nobody agreed it should touch — on a customer's
production network, found by a probe, with credentials assigned by inheritance. So a
discovered host lives in its own table with no ``devices`` row at all until somebody
approves it, and approval is the only path that creates one.

That is why this is a separate table rather than a ``devices`` row in the
``pending_review`` state. A row in ``devices`` is reachable by every query that
enumerates the estate, and keeping it out of the assessed population would mean every
one of those queries remembering to exclude it. One forgotten filter and an unapproved
host is being collected from. The status column exists on ``devices`` for a device that
was approved and is awaiting credentials — a different situation, already onboarded.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from netsecops.db.base import Base, OrgMixin, TimestampMixin, UUIDPrimaryKeyMixin


class DiscoveredHostStatus(StrEnum):
    """Where a discovered host sits in the review queue (FR-DISC-04)."""

    #: Found, fingerprinted, and waiting for a human. The default, and the only state a
    #: run can put a host into unless its scope is flagged auto-onboard.
    PENDING = "pending"
    #: A device row now exists for it and assessment may proceed.
    APPROVED = "approved"
    #: Deliberately not ours — a printer, a neighbour's box, a host out of contract.
    #: Kept rather than deleted so the next run does not re-queue it.
    REJECTED = "rejected"


class DiscoveryRunStatus(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    #: Stopped early — cancelled, or the scope's budget was exhausted.
    PARTIAL = "partial"
    FAILED = "failed"


class DiscoveryScope(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """What discovery may probe (FR-DISC-01, FR-DISC-05)."""

    __tablename__ = "discovery_scopes"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_discovery_scope_name"),)

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    #: CIDRs, ranges and single addresses, as written by the operator. Kept verbatim
    #: rather than expanded: the ceiling is enforced when the scope is built, and an
    #: operator editing "10.0.0.0/24" should see what they typed.
    targets: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list, nullable=False)
    exclusions: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list, nullable=False)
    tcp_ports: Mapped[list[int]] = mapped_column(ARRAY(Integer), default=list, nullable=False)

    #: FR-DISC-05. Stored per scope because the right rate for a lab is not the right
    #: rate for a production core.
    rate_limit_per_second: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("50")
    )

    snmp_configured: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    #: FR-DISC-04's escape hatch. False by default and deliberately hard to set: it is
    #: the difference between finding a device and connecting to one.
    auto_onboard: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))


class DiscoveryRun(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """One execution of a scope."""

    __tablename__ = "discovery_runs"
    __table_args__ = (Index("ix_discovery_runs_scope", "org_id", "scope_id", "started_at"),)

    scope_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("discovery_scopes.id", ondelete="CASCADE"), nullable=False
    )
    #: The job that executed this run (FR-DISC-05). Nullable because the run row is the
    #: domain record and outlives the job: job history is prunable operational data,
    #: and losing it must not erase the evidence that these addresses were probed.
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("clock_timestamp()")
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    addresses_probed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hosts_found: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: Hosts that answered but could not be identified. Counted separately because a
    #: run that found forty things and recognised none of them is a different outcome
    #: from one that found forty switches, and the summary should not read the same.
    hosts_unidentified: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)

    #: What the run could not do, as distinct from what went wrong. ICMP unavailable for
    #: want of a capability, SNMP unread for want of a credential: neither is an error,
    #: both change what "found 0 hosts" means. Kept out of ``error_message`` because a
    #: successful run has no error and would otherwise have nowhere to say this — and an
    #: empty estate that nobody could have detected must not print like a quiet one.
    notes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)


class DiscoveredHost(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """Something that answered a probe, awaiting review (FR-DISC-03, FR-DISC-04)."""

    __tablename__ = "discovered_hosts"
    __table_args__ = (
        # One row per address. A host found by three runs is one queue entry with a
        # last_seen, not three things for somebody to triage.
        UniqueConstraint("org_id", "address", name="uq_discovered_host_address"),
        Index("ix_discovered_hosts_status", "org_id", "status"),
    )

    address: Mapped[str] = mapped_column(INET, nullable=False)
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("discovery_runs.id", ondelete="SET NULL")
    )

    status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=DiscoveredHostStatus.PENDING.value
    )

    vendor: Mapped[str | None] = mapped_column(String(64))
    platform: Mapped[str | None] = mapped_column(String(64))
    hostname: Mapped[str | None] = mapped_column(String(255))
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    #: Every signal, verbatim, plus any conflicts. A reviewer needs what the host
    #: actually said — "Cisco, 70%" is not something anybody can check.
    fingerprint: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    #: The device created when this was approved. Null while pending or rejected, and
    #: that null is what keeps an unapproved host out of the assessed estate.
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL")
    )

    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    reviewed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Why it was rejected. Required on rejection, so the next person to see this
    #: address knows whether it was "not ours" or "not yet".
    review_note: Mapped[str | None] = mapped_column(Text)


__all__ = [
    "DiscoveredHost",
    "DiscoveredHostStatus",
    "DiscoveryRun",
    "DiscoveryRunStatus",
    "DiscoveryScope",
]
