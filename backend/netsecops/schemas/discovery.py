"""Discovery API payloads (SRS §4.2, FR-DISC-01, FR-DISC-04).

Discovery is the narrowest subsystem in the product on purpose. SRS §1.2 rules out
port sweeps, exploitation and brute-forcing; FR-DISC-02 names the five probes that are
permitted instead. These models exist partly to carry data and partly to keep that
narrowness visible at the edge: a scope names at most eight TCP ports, and the
validation says why rather than returning a bare 422.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

#: FR-DISC-02 permits "TCP connect to 22/443 (configurable list)". A list with no
#: ceiling turns a permitted probe into a port scan assembled entirely from permitted
#: probes, which is the thing §1.2 forbids. Kept in step with `discovery/probes.py`.
MAX_SCOPE_PORTS = 8


class DiscoveryScopeCreate(BaseModel):
    """What may be probed (FR-DISC-01)."""

    name: str = Field(min_length=1, max_length=128)
    description: str | None = None
    #: CIDRs, ranges or single addresses.
    targets: list[str] = Field(min_length=1)
    #: Subtracted from the address space rather than filtered at probe time, so an
    #: excluded host is never enumerated at all.
    exclusions: list[str] = Field(default_factory=list)
    tcp_ports: list[int] = Field(default_factory=list)
    rate_limit_per_second: int = Field(default=50, ge=1, le=1000)
    #: SNMP is refused outright without a configured credential: probing anyway means
    #: trying `public`, which is a credential guess and not a reachability probe.
    snmp_configured: bool = False
    #: When set, an identified host is onboarded without review. Off by default —
    #: FR-DISC-04 makes review the norm and this the exception.
    auto_onboard: bool = False
    enabled: bool = True

    @field_validator("tcp_ports")
    @classmethod
    def _bounded_ports(cls, ports: list[int]) -> list[int]:
        if len(ports) > MAX_SCOPE_PORTS:
            raise ValueError(
                f"A scope may name at most {MAX_SCOPE_PORTS} TCP ports. Discovery is "
                "reachability and fingerprinting, not a port sweep (SRS §1.2); a longer "
                "list assembles a scan out of individually permitted probes."
            )
        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError("TCP ports must be between 1 and 65535.")
        return ports


class DiscoveryScopeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None = None
    targets: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    tcp_ports: list[int] = Field(default_factory=list)
    rate_limit_per_second: int
    snmp_configured: bool
    auto_onboard: bool
    enabled: bool
    created_at: datetime | None = None
    #: Addresses the scope resolves to after exclusions are subtracted. Computed rather
    #: than stored: it is the number an operator checks before running anything, and
    #: `10.0.0.0/8` is one character from `10.0.0.0/18` and sixteen million probes from
    #: what they meant.
    address_count: int | None = None


class DiscoveryRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scope_id: uuid.UUID
    status: str
    started_at: datetime
    finished_at: datetime | None = None
    addresses_probed: int = 0
    hosts_found: int = 0
    #: Hosts that answered but which the fingerprinter could not identify. Counted
    #: separately because they are the ones a human has to look at.
    hosts_unidentified: int = 0
    error_message: str | None = None
    #: What the run could not do, which is not what went wrong. A run that sent no echo
    #: request because the container lacks CAP_NET_RAW, or read no sysObjectID because no
    #: SNMP credential can be stored yet, succeeded and still saw less than it looks like.
    #: Read these next to the counters: "0 hosts found" means two different things.
    notes: list[str] = Field(default_factory=list)


class DiscoveryRunRequest(BaseModel):
    """Options when starting a run.

    Everything that decides *what* is probed lives on the scope, not here. A per-run
    override of the targets, the ports or the rate would make the stored scope stop being
    the record of what the product is permitted to contact — and that record is what an
    operator reviews, and what the audit trail points at afterwards.
    """

    #: Repeat-safe start. A retried POST returns the job the first one created rather
    #: than probing the whole scope a second time.
    idempotency_key: str | None = Field(default=None, max_length=128)


class DiscoveryRunStart(BaseModel):
    """What a queued run hands back.

    A job id rather than a run id: the ``discovery_runs`` row does not exist yet when the
    request returns, because the executor writes it as its first act. The address count
    and rate are echoed so the operator can see what they have just set in motion, and how
    long it will take, without opening the scope again.
    """

    job_id: uuid.UUID
    scope_id: uuid.UUID
    address_count: int
    rate_limit_per_second: int


class DiscoveredHostRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    address: str
    run_id: uuid.UUID | None = None
    status: str
    vendor: str | None = None
    platform: str | None = None
    hostname: str | None = None
    #: 0-100. Low is not "probably not a device" — it is "we could not tell", which is
    #: why the queue is sorted ascending.
    confidence: int = 0
    #: The evidence behind the guess: SSH banner, TLS subject, HTTP markers, sysObjectID.
    fingerprint: dict[str, Any] = Field(default_factory=dict)
    device_id: uuid.UUID | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    reviewed_at: datetime | None = None
    review_note: str | None = None

    @field_validator("address", mode="before")
    @classmethod
    def _stringify(cls, value: Any) -> str:
        return str(value)


class HostApproval(BaseModel):
    """Onboard a discovered host (FR-DISC-04).

    The fingerprinter's guess is offered, not imposed: an operator may correct the
    vendor and platform on the way through, because a wrong platform picks the wrong
    collection profile and the wrong command allow-list.
    """

    vendor: str | None = None
    platform: str | None = None
    hostname: str | None = None
    device_class: str = "unknown"
    note: str | None = None


class HostRejection(BaseModel):
    """Mark a host as deliberately not ours.

    The note is required by the service, not merely by this model. "Rejected" with no
    reason tells the next person nothing, and the question they will have — is this a
    printer, or a switch nobody has got round to — decides whether they reopen it.
    """

    note: str = Field(min_length=1, max_length=2000)


class PaginatedHosts(BaseModel):
    data: list[DiscoveredHostRead]
    meta: dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "MAX_SCOPE_PORTS",
    "DiscoveredHostRead",
    "DiscoveryRunRead",
    "DiscoveryRunRequest",
    "DiscoveryRunStart",
    "DiscoveryScopeCreate",
    "DiscoveryScopeRead",
    "HostApproval",
    "HostRejection",
    "PaginatedHosts",
]
