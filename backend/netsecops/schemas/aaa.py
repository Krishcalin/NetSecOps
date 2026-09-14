"""AAA posture response models (FR-AAA-05, FR-AAA-06).

Two conventions run through every model here, and both exist to stop the dashboard
overstating what it knows.

**Unknown is a value, not an absence.** ``coverage_percentage`` is ``int | None`` and
``admin_mfa_enabled`` is ``bool | None``, and the UI is expected to render the ``None``
as "unknown" rather than as 0% or as "no". Collapsing those in the schema would make it
impossible for the UI to be honest even if it wanted to be.

**Every panel carries the reason it might be empty.** ``limitations`` is a first-class
field on the response rather than a footnote in documentation, because the failure mode
of a posture dashboard is a clean-looking page produced by missing data. A reader who
sees "no certificates expiring" needs to be able to tell that from "we could not read
any certificates".
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class ProtocolRead(BaseModel):
    """One authentication protocol and which servers will accept it."""

    name: str
    #: True for protocols whose presence is a finding regardless of context: PAP, CHAP,
    #: MS-CHAPv1, EAP-MD5, LEAP.
    weak: bool
    servers: list[str] = Field(default_factory=list)


class TransportRead(BaseModel):
    """Device-side: how many devices point at this kind of AAA server."""

    kind: str
    devices: int


class CertificateRead(BaseModel):
    """One certificate on the expiry timeline."""

    device_id: str
    device: str
    name: str | None = None
    subject: str | None = None
    issuer: str | None = None
    self_signed: bool | None = None
    usage: list[str] = Field(default_factory=list)
    #: ISO-8601. None when the source date could not be interpreted — the certificate
    #: still appears, undated, because an unreadable date is not a distant one.
    expires_at: str | None = None
    days_remaining: int | None = None


class CertificateTimelineRead(BaseModel):
    entries: list[CertificateRead] = Field(default_factory=list)
    total: int = 0
    expired: int = 0
    expiring_soon: int = 0
    expiring_within_horizon: int = 0
    undated: int = 0
    #: AAA servers that contributed no certificate at all. The timeline is blind to
    #: these, and saying so is the difference between "nothing expiring" and "nothing
    #: collected".
    servers_without_certificates: list[str] = Field(default_factory=list)
    soon_days: int = 30
    horizon_days: int = 90


class AaaServerRead(BaseModel):
    device_id: uuid.UUID
    hostname: str | None = None
    product: str | None = None
    clients: int = 0
    identity_stores: int = 0
    weak_protocols: list[str] = Field(default_factory=list)
    admin_mfa_enabled: bool | None = None
    snapshot_age_days: int | None = None
    certificates: int = 0


class OrphanedClientRead(BaseModel):
    """An AAA server lists this device; inventory has never heard of it."""

    name: str
    address: str | None = None
    server: str
    server_device_id: uuid.UUID
    server_snapshot_age_days: int | None = None


class UnregisteredDeviceRead(BaseModel):
    device_id: uuid.UUID
    hostname: str | None = None
    mgmt_ip: str
    configured_for_aaa: bool = False


class UnknownServerRead(BaseModel):
    address: str
    kind: str
    used_by: list[str] = Field(default_factory=list)


class SecretReuseRead(BaseModel):
    """One shared secret and everywhere it is configured — never the secret itself."""

    fingerprint: str
    used_by: list[str] = Field(default_factory=list)
    clients: int = 0


class CorrelationRead(BaseModel):
    orphaned_clients: list[OrphanedClientRead] = Field(default_factory=list)
    unregistered_devices: list[UnregisteredDeviceRead] = Field(default_factory=list)
    unknown_servers: list[UnknownServerRead] = Field(default_factory=list)
    reused_secrets: list[SecretReuseRead] = Field(default_factory=list)
    servers_examined: int = 0
    #: Clients whose server masks the shared secret. Reuse is *unknown* for these, which
    #: FR-AAA-05 requires be distinguished from "not reused".
    secrets_not_exposable: int = 0
    #: False when no AAA server was collected from. While false, the unregistered-device
    #: list is not a conclusion and the UI must not present it as one.
    registration_analysed: bool = False


class AaaPostureRead(BaseModel):
    """Everything FR-AAA-06 puts on one page."""

    #: None when no device could be assessed. Not 0 — an unassessed estate and an
    #: estate with no central authentication are different problems.
    coverage_percentage: int | None = None
    devices_total: int = 0
    devices_with_central_auth: int = 0
    devices_not_evaluated: int = 0

    accepted_protocols: list[ProtocolRead] = Field(default_factory=list)
    transports: list[TransportRead] = Field(default_factory=list)
    servers: list[AaaServerRead] = Field(default_factory=list)
    certificates: CertificateTimelineRead = Field(default_factory=CertificateTimelineRead)
    correlation: CorrelationRead = Field(default_factory=CorrelationRead)

    #: Open AAA findings by severity.
    open_findings: dict[str, int] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    generated_at: datetime


__all__ = [
    "AaaPostureRead",
    "AaaServerRead",
    "CertificateRead",
    "CertificateTimelineRead",
    "CorrelationRead",
    "OrphanedClientRead",
    "ProtocolRead",
    "SecretReuseRead",
    "TransportRead",
    "UnknownServerRead",
    "UnregisteredDeviceRead",
]
