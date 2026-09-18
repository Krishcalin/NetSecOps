"""The estate-wide AAA picture (FR-AAA-06).

FR-AAA-06 asks for four things on one page — coverage, protocols in use, orphaned
clients and a certificate expiry timeline — and the reason they belong together is that
each one is the context for the others. 94% coverage is good news until you notice the
6% is the datacentre. A list of expiring certificates is administrivia until you notice
the one expiring in nine days is the EAP certificate every wireless client on site
authenticates against.

**Three ways a posture dashboard lies, and what stops each here.**

*A percentage over a denominator nobody checked.* Coverage comes from the correlation
report, which counts devices it could not assess separately and returns ``None`` rather
than ``0`` when nothing was assessable. That ``None`` travels all the way to the UI as
"unknown", because 0% and "we have not looked" send an operator to two different places.

*An empty expiry timeline that means "no data", not "nothing expiring".* Certificates
only reach the NCM from the parsers that read them, and a server whose certificate
endpoint returned 403 contributes none. Those servers are listed by name in
``servers_without_certificates``, and a certificate whose date could not be interpreted
is counted in ``undated`` rather than dropped. A timeline is a promise that what is not
on it is not coming; it has to be able to say where it is blind.

*Protocol lists that flatten "accepts" and "requires".* What the NCM knows is which
protocols a server will *accept* if a client offers them, which is the security-relevant
question — one policy still accepting MS-CHAPv1 is a way in regardless of what the other
forty require. It is named ``accepted_protocols`` rather than "in use" for that reason:
nothing here observes live authentications, and calling it usage would imply we had.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.logging import get_logger
from netsecops.db.models.collection import Finding, FindingKind, FindingStatus
from netsecops.ncm.certificates import CertificateEntry, describe
from netsecops.ncm.models import AaaServerConfig, Certificate
from netsecops.services.aaa_correlation import (
    AaaCorrelationReport,
    AaaCorrelationService,
    active_devices,
    latest_snapshots,
)

log = get_logger(__name__)

#: Protocols whose presence is a finding on its own. Kept in step with
#: :attr:`AaaServerConfig.weak_protocols`, which is the authority — this set exists only
#: so the dashboard can mark a protocol without re-deriving it per server.
_WEAK = frozenset({"pap", "chap", "ms-chapv1", "mschapv1", "eap-md5", "leap"})

#: The horizons the timeline buckets into. Thirty days is about the shortest notice on
#: which a certificate can be reissued through a change process; ninety is the point at
#: which it should be on someone's plan rather than their calendar.
SOON_DAYS = 30
HORIZON_DAYS = 90


@dataclass(frozen=True, slots=True)
class ProtocolUsage:
    """One authentication protocol and which servers will accept it."""

    name: str
    weak: bool
    servers: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class TransportUsage:
    """Device-side: how many devices point at RADIUS, TACACS+, or both."""

    kind: str
    devices: int


@dataclass(slots=True)
class CertificateTimeline:
    """Every certificate NCM holds, ordered by how soon it stops working."""

    entries: list[CertificateEntry] = field(default_factory=list)
    expired: int = 0
    expiring_soon: int = 0
    expiring_within_horizon: int = 0
    #: Certificates whose expiry date could not be interpreted. Reported, never dropped:
    #: an unreadable date is not a distant one.
    undated: int = 0
    #: AAA servers that contributed no certificate at all — the timeline's blind spots.
    servers_without_certificates: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)


@dataclass(frozen=True, slots=True)
class ServerSummary:
    """One AAA server, as the dashboard lists it."""

    device_id: uuid.UUID
    hostname: str | None
    product: str | None
    clients: int
    identity_stores: int
    weak_protocols: list[str]
    admin_mfa_enabled: bool | None
    snapshot_age_days: int | None
    certificates: int


@dataclass(slots=True)
class AaaPosture:
    """Everything FR-AAA-06 puts on one page."""

    coverage_percentage: int | None = None
    devices_total: int = 0
    devices_with_central_auth: int = 0
    devices_not_evaluated: int = 0

    accepted_protocols: list[ProtocolUsage] = field(default_factory=list)
    transports: list[TransportUsage] = field(default_factory=list)
    servers: list[ServerSummary] = field(default_factory=list)
    certificates: CertificateTimeline = field(default_factory=CertificateTimeline)

    #: Straight from the correlation report, so the dashboard and the per-device
    #: findings cannot disagree about what was found.
    correlation: AaaCorrelationReport = field(default_factory=AaaCorrelationReport)

    #: Open AAA findings by severity, so the page can be entered from a number.
    open_findings: dict[str, int] = field(default_factory=dict)

    limitations: list[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def weak_protocols_in_use(self) -> list[str]:
        return [p.name for p in self.accepted_protocols if p.weak]


class AaaPostureService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def build(self, *, org_id: int = 1) -> AaaPosture:
        """Assemble the posture. One pass over the estate's latest snapshots."""
        posture = AaaPosture()

        posture.correlation = await AaaCorrelationService(self.session).correlate(org_id=org_id)
        coverage = posture.correlation.coverage
        posture.coverage_percentage = coverage.percentage
        posture.devices_total = coverage.devices_total
        posture.devices_with_central_auth = coverage.devices_with_central_auth
        posture.devices_not_evaluated = coverage.devices_not_evaluated

        devices = await active_devices(self.session, org_id)
        snapshots = await latest_snapshots(self.session, [d.id for d in devices])

        protocols: dict[str, set[str]] = {}
        transports: dict[str, int] = {}
        timeline: list[CertificateEntry] = []
        blind: list[str] = []
        now = datetime.now(UTC)

        for device in devices:
            snapshot = snapshots.get(device.id)
            ncm: dict[str, Any] = (snapshot.ncm if snapshot else None) or {}
            label = device.hostname or str(device.mgmt_ip)

            # ── device side: which transport, if any ────────────────────
            kinds = {
                str(entry.get("type") or "unknown").lower()
                for entry in ((ncm.get("aaa") or {}).get("servers") or [])
            }
            for kind in kinds:
                transports[kind] = transports.get(kind, 0) + 1

            certificates = _certificates(ncm)
            timeline.extend(
                describe(certificate, device_id=str(device.id), device=label, now=now)
                for certificate in certificates
            )

            # ── server side: what this server will accept ───────────────
            config = AaaServerConfig.model_validate(ncm.get("aaa_server") or {})
            if config.product is None:
                continue

            for protocol in config.allowed_protocols:
                protocols.setdefault(protocol, set()).add(label)

            if not certificates:
                # An AAA server with no certificate in the NCM is not an AAA server
                # without certificates — it is one whose certificate endpoint we did not
                # read. Naming it is what keeps the timeline from reading as complete.
                blind.append(label)

            posture.servers.append(
                ServerSummary(
                    device_id=device.id,
                    hostname=device.hostname,
                    product=config.product,
                    clients=len(config.clients),
                    identity_stores=len(config.identity_stores),
                    weak_protocols=config.weak_protocols,
                    admin_mfa_enabled=config.admin_mfa_enabled,
                    snapshot_age_days=_age_days(snapshot.created_at if snapshot else None),
                    certificates=len(certificates),
                )
            )

        posture.accepted_protocols = [
            ProtocolUsage(name=name, weak=name.strip().lower() in _WEAK, servers=sorted(servers))
            # Weak first, then alphabetical: the reason to open this panel is the weak
            # ones, and burying them under EAP-TLS makes the panel decoration.
            for name, servers in sorted(
                protocols.items(), key=lambda item: (item[0].strip().lower() not in _WEAK, item[0])
            )
        ]
        posture.transports = [
            TransportUsage(kind=kind, devices=count)
            for kind, count in sorted(transports.items(), key=lambda item: (-item[1], item[0]))
        ]
        posture.certificates = _build_timeline(timeline, blind)
        posture.open_findings = await self._open_findings(org_id)
        posture.limitations = self._limitations(posture)

        log.info(
            "aaa.posture_built",
            org_id=org_id,
            servers=len(posture.servers),
            coverage=posture.coverage_percentage,
            certificates=posture.certificates.total,
            undated_certificates=posture.certificates.undated,
        )
        return posture

    # ── findings ────────────────────────────────────────────────────────

    async def _open_findings(self, org_id: int) -> dict[str, int]:
        rows = (
            await self.session.execute(
                select(Finding.severity, func.count())
                .where(
                    Finding.org_id == org_id,
                    Finding.kind == FindingKind.AAA.value,
                    Finding.status.in_(FindingStatus.active_values()),
                )
                .group_by(Finding.severity)
            )
        ).all()
        return {str(severity): int(count) for severity, count in rows}

    # ── honesty ─────────────────────────────────────────────────────────

    def _limitations(self, posture: AaaPosture) -> list[str]:
        """The correlation's caveats, plus the ones this view adds."""
        notes = list(posture.correlation.limitations)

        if posture.certificates.undated:
            notes.append(
                f"{posture.certificates.undated} certificate(s) carry an expiry date "
                "NetSecOps could not interpret. They are listed without a date rather "
                "than omitted — an unreadable date is not a distant one."
            )

        if posture.certificates.servers_without_certificates:
            named = ", ".join(sorted(posture.certificates.servers_without_certificates))
            notes.append(
                f"No certificate was collected from {named}. The expiry timeline is "
                "blind to those servers, so an EAP certificate expiring on one of them "
                "would not appear here."
            )

        if not posture.servers:
            notes.append(
                "No AAA server has been collected from, so everything on this page is "
                "the device-side view only: what the estate is configured to talk to, "
                "not what the servers are configured to accept."
            )

        if not posture.accepted_protocols and posture.servers:
            notes.append(
                "No AAA server exposed its allowed-protocol set, so the protocols panel "
                "is empty because the data is missing, not because nothing is accepted."
            )

        return notes


def _certificates(ncm: dict[str, Any]) -> list[Certificate]:
    return [
        Certificate.model_validate(entry)
        for entry in (ncm.get("certificates") or [])
        if isinstance(entry, dict)
    ]


def _build_timeline(entries: list[CertificateEntry], blind: list[str]) -> CertificateTimeline:
    """Sort by urgency, with the undated ones last but present.

    Undated certificates sort to the end rather than being treated as never-expiring:
    they belong at the bottom of a list someone reads top-down, but they must still be
    in it, and the count above the list says how many there are.
    """
    ordered = sorted(
        entries,
        key=lambda entry: (entry.days_remaining is None, entry.days_remaining or 0, entry.device),
    )

    timeline = CertificateTimeline(
        entries=ordered,
        servers_without_certificates=sorted(set(blind)),
    )
    for entry in ordered:
        if entry.days_remaining is None:
            timeline.undated += 1
        elif entry.days_remaining < 0:
            timeline.expired += 1
        elif entry.days_remaining <= SOON_DAYS:
            timeline.expiring_soon += 1
            timeline.expiring_within_horizon += 1
        elif entry.days_remaining <= HORIZON_DAYS:
            timeline.expiring_within_horizon += 1
    return timeline


def _age_days(when: datetime | None) -> int | None:
    if when is None:
        return None
    moment = when if when.tzinfo else when.replace(tzinfo=UTC)
    return (datetime.now(UTC) - moment).days


__all__ = [
    "HORIZON_DAYS",
    "SOON_DAYS",
    "AaaPosture",
    "AaaPostureService",
    "CertificateTimeline",
    "ProtocolUsage",
    "ServerSummary",
    "TransportUsage",
]
