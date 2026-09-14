"""Correlating AAA across the estate (FR-AAA-05).

Every analysis before this one looks at a single device. This one cannot: its whole
subject is the disagreement *between* devices, and between devices and the servers that
authenticate them. Three questions, none of which can be answered from one snapshot:

**Which devices does an AAA server know about that we do not?** A switch configured on
ISE is a device someone is authenticating against. If it is absent from inventory it is
assessed by nothing, and a clean compliance percentage is measured over an estate that
does not include it. This is the highest-value output here, because it finds devices
rather than problems on devices we already knew about.

**Which devices point at an AAA server we have never collected from?** A RADIUS server
nobody assesses is a single point of compromise for every credential on the network.

**Which devices share a shared secret?** One key across forty switches means one
disclosure is forty devices. See the honesty note below — this can only be answered for
some sources.

**Three ways this analysis can lie, and what stops each.**

*Reporting "no reuse" when the secrets were never visible.* ISE and FortiAuthenticator
return `********`, so their clients carry no fingerprint. Counting those as "not reused"
would report a clean estate on the strength of data we never had. They are counted
separately as `secrets_not_exposable`, and FR-AAA-05 asks for exactly that distinction.

*Reporting every device as unregistered when no AAA server was collected.* With no
server snapshots, every device in inventory trivially appears on no client list. That
would be a catastrophic false positive across the whole estate, so the analysis refuses
to draw the conclusion and says why.

*Reporting a device as orphaned because its snapshot is stale.* A device collected
before it was added to ISE looks identical to one nobody added to inventory. The report
carries the snapshot age so a reader can tell, rather than pretending the comparison is
between two current states.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.logging import get_logger
from netsecops.db.models.collection import Snapshot
from netsecops.db.models.inventory import Device, DeviceClass, DeviceStatus
from netsecops.ncm.models import AaaServerConfig

log = get_logger(__name__)

#: Device classes that are AAA *servers*. Used to decide whether the estate has any
#: server data at all, which gates half the conclusions below.
_SERVER_PRODUCTS = frozenset({"ise", "fortiauthenticator", "freeradius", "tac_plus"})


@dataclass(frozen=True, slots=True)
class ServerRecord:
    """One AAA server's view of the world, as of its latest snapshot."""

    device_id: uuid.UUID
    hostname: str | None
    product: str | None
    config: AaaServerConfig
    collected_at: datetime | None

    @property
    def name(self) -> str:
        return self.hostname or str(self.device_id)


@dataclass(frozen=True, slots=True)
class OrphanedClient:
    """An AAA server lists this device; the inventory has never heard of it."""

    name: str
    address: str | None
    server: str
    server_device_id: uuid.UUID
    #: How old the server's snapshot is, so a reader can judge whether the gap is real
    #: or is an artefact of comparing a fresh list against a stale inventory.
    server_snapshot_age_days: int | None = None


@dataclass(frozen=True, slots=True)
class UnregisteredDevice:
    """In inventory, and on no AAA server's client list."""

    device_id: uuid.UUID
    hostname: str | None
    mgmt_ip: str
    #: True when the device's own configuration names an AAA server, which makes its
    #: absence from every client list a contradiction rather than merely a gap.
    configured_for_aaa: bool = False


@dataclass(frozen=True, slots=True)
class UnknownServer:
    """A device points at this AAA server address; nothing in inventory matches it."""

    address: str
    kind: str
    used_by: list[str] = field(default_factory=list)
    #: The devices behind those labels. Carried so the finding can be attached to each
    #: device that points at the unknown server — the label alone is a display string
    #: and two devices can share a hostname.
    used_by_ids: list[uuid.UUID] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class SecretReuse:
    """One shared secret, and everywhere it is configured."""

    fingerprint: str
    #: `<server hostname>/<client name>` for each place the key appears.
    used_by: list[str] = field(default_factory=list)
    #: The AAA server devices whose configuration exposed this key, so the finding has
    #: somewhere to live. The *clients* sharing it are frequently not in inventory —
    #: that is often the neighbouring finding — so the server is the reliable anchor.
    server_ids: list[uuid.UUID] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.used_by)


@dataclass(slots=True)
class AaaCoverage:
    devices_total: int = 0
    #: Devices whose own configuration names at least one AAA server.
    devices_with_central_auth: int = 0
    #: Devices where the parser could not determine it. Counted apart from the failures
    #: so the percentage below has an honest denominator.
    devices_not_evaluated: int = 0

    @property
    def percentage(self) -> int | None:
        """Coverage over devices we could actually assess.

        None when nothing was assessable. Zero and "we could not tell" are different
        answers, and a dashboard showing 0% for an estate nobody has collected from
        would send someone to fix a problem that has not been shown to exist.
        """
        assessable = self.devices_total - self.devices_not_evaluated
        if assessable <= 0:
            return None
        return round(100 * self.devices_with_central_auth / assessable)


@dataclass(slots=True)
class AaaCorrelationReport:
    orphaned_clients: list[OrphanedClient] = field(default_factory=list)
    unregistered_devices: list[UnregisteredDevice] = field(default_factory=list)
    unknown_servers: list[UnknownServer] = field(default_factory=list)
    reused_secrets: list[SecretReuse] = field(default_factory=list)
    coverage: AaaCoverage = field(default_factory=AaaCoverage)

    #: How many AAA servers contributed a client list. Zero means the orphan and
    #: registration conclusions could not be drawn at all.
    servers_examined: int = 0
    #: Client entries whose source masks the shared secret, so reuse is unknowable for
    #: them. FR-AAA-05 requires this be reported rather than counted as "not reused".
    secrets_not_exposable: int = 0
    #: Stated on every report rather than documented elsewhere.
    limitations: list[str] = field(default_factory=list)

    @property
    def registration_analysed(self) -> bool:
        return self.servers_examined > 0

    @property
    def counts(self) -> dict[str, int]:
        return {
            "orphaned_clients": len(self.orphaned_clients),
            "unregistered_devices": len(self.unregistered_devices),
            "unknown_servers": len(self.unknown_servers),
            "reused_secrets": len(self.reused_secrets),
            "servers_examined": self.servers_examined,
            "secrets_not_exposable": self.secrets_not_exposable,
        }


class AaaCorrelationService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def correlate(self, *, org_id: int = 1) -> AaaCorrelationReport:
        """Compare every device's AAA configuration with every AAA server's client list."""
        report = AaaCorrelationReport()

        devices = await self._devices(org_id)
        snapshots = await self._latest_snapshots([d.id for d in devices])

        servers: list[ServerRecord] = []
        client_addresses: set[str] = set()
        client_names: set[str] = set()
        fingerprints: dict[str, list[str]] = {}
        fingerprint_servers: dict[str, set[uuid.UUID]] = {}

        # ── what the AAA servers believe ────────────────────────────────
        for device in devices:
            snapshot = snapshots.get(device.id)
            if snapshot is None:
                continue

            raw = (snapshot.ncm or {}).get("aaa_server") or {}
            config = AaaServerConfig.model_validate(raw)
            if config.product not in _SERVER_PRODUCTS or not config.clients:
                continue

            record = ServerRecord(
                device_id=device.id,
                hostname=device.hostname,
                product=config.product,
                config=config,
                collected_at=snapshot.created_at,
            )
            servers.append(record)

            for client in config.clients:
                if client.address:
                    client_addresses.add(_normalise(client.address))
                client_names.add(client.name.strip().lower())

                if client.secret_fingerprint:
                    fingerprints.setdefault(client.secret_fingerprint, []).append(
                        f"{record.name}/{client.name}"
                    )
                    fingerprint_servers.setdefault(client.secret_fingerprint, set()).add(
                        record.device_id
                    )
                elif client.secret_configured:
                    # A secret exists and the source will not show it. Counted, never
                    # assumed unique — that assumption is the one FR-AAA-05 forbids.
                    report.secrets_not_exposable += 1

        report.servers_examined = len(servers)

        # ── devices the servers know and the inventory does not ─────────
        by_address = {_normalise(str(d.mgmt_ip)): d for d in devices}
        by_hostname = {d.hostname.strip().lower(): d for d in devices if d.hostname}

        for record in servers:
            age = _age_days(record.collected_at)
            for client in record.config.clients:
                address = _normalise(client.address) if client.address else None
                if address and address in by_address:
                    continue
                if client.name.strip().lower() in by_hostname:
                    continue

                report.orphaned_clients.append(
                    OrphanedClient(
                        name=client.name,
                        address=client.address,
                        server=record.name,
                        server_device_id=record.device_id,
                        server_snapshot_age_days=age,
                    )
                )

        # ── the reverse, and the device-side view ───────────────────────
        for device in devices:
            snapshot = snapshots.get(device.id)
            aaa = (snapshot.ncm or {}).get("aaa") if snapshot else None

            configured_servers = list((aaa or {}).get("servers") or [])
            central = bool(configured_servers)

            report.coverage.devices_total += 1
            if snapshot is None or aaa is None:
                # Never collected, or collected by a parser that fills no `aaa` block.
                # Not a failure — it is a device we cannot answer the question for.
                report.coverage.devices_not_evaluated += 1
            elif central:
                report.coverage.devices_with_central_auth += 1

            # An AAA server this device points at, that inventory does not contain.
            for entry in configured_servers:
                host = str(entry.get("host") or "").strip()
                if not host or _normalise(host) in by_address:
                    continue
                existing = next((u for u in report.unknown_servers if u.address == host), None)
                label = device.hostname or str(device.mgmt_ip)
                if existing is None:
                    report.unknown_servers.append(
                        UnknownServer(
                            address=host,
                            kind=str(entry.get("type") or "unknown"),
                            used_by=[label],
                            used_by_ids=[device.id],
                        )
                    )
                else:
                    if label not in existing.used_by:
                        existing.used_by.append(label)
                    if device.id not in existing.used_by_ids:
                        existing.used_by_ids.append(device.id)

            if not report.registration_analysed:
                continue
            if device.device_class == DeviceClass.MANAGER.value:
                # A manager authenticates its administrators, not itself, so it is not
                # expected on a RADIUS client list.
                continue
            if _is_aaa_server(snapshot):
                continue

            address = _normalise(str(device.mgmt_ip))
            hostname = (device.hostname or "").strip().lower()
            if address in client_addresses or (hostname and hostname in client_names):
                continue

            report.unregistered_devices.append(
                UnregisteredDevice(
                    device_id=device.id,
                    hostname=device.hostname,
                    mgmt_ip=str(device.mgmt_ip),
                    configured_for_aaa=central,
                )
            )

        # ── reuse, where it can be answered at all ──────────────────────
        report.reused_secrets = [
            SecretReuse(
                fingerprint=digest,
                used_by=sorted(set(places)),
                server_ids=sorted(fingerprint_servers.get(digest, set()), key=str),
            )
            for digest, places in sorted(fingerprints.items())
            if len(set(places)) > 1
        ]

        report.limitations = self._limitations(report)

        log.info("aaa.correlation_complete", org_id=org_id, **report.counts)
        return report

    # ── honesty ─────────────────────────────────────────────────────────

    def _limitations(self, report: AaaCorrelationReport) -> list[str]:
        """What this report could not determine. Stated, never implied by a zero."""
        notes: list[str] = []

        if not report.registration_analysed:
            notes.append(
                "No AAA server has been collected from, so NetSecOps cannot tell which "
                "devices are registered as clients. This is not a finding that every "
                "device is unregistered — it is the absence of the data needed to ask."
            )

        if report.secrets_not_exposable:
            notes.append(
                f"{report.secrets_not_exposable} client(s) have a shared secret their "
                "server does not expose — Cisco ISE and FortiAuthenticator both return "
                "a masked value. Secret reuse is unknown for those, not absent. Only "
                "FreeRADIUS and tac_plus configurations carry the real key."
            )

        if report.coverage.percentage is None and report.coverage.devices_total:
            notes.append(
                "No device has an AAA configuration NetSecOps could read, so coverage "
                "has no honest denominator and is reported as unknown rather than 0%."
            )

        stale = [
            client
            for client in report.orphaned_clients
            if client.server_snapshot_age_days is not None and client.server_snapshot_age_days > 30
        ]
        if stale:
            notes.append(
                f"{len(stale)} orphaned client(s) come from an AAA server snapshot more "
                "than 30 days old. A device added to inventory since then would still "
                "appear here; re-collect the server before acting on those."
            )

        return notes

    # ── data ────────────────────────────────────────────────────────────

    async def _devices(self, org_id: int) -> Sequence[Device]:
        return await active_devices(self.session, org_id)

    async def _latest_snapshots(self, device_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, Snapshot]:
        return await latest_snapshots(self.session, device_ids)


async def active_devices(session: AsyncSession, org_id: int) -> Sequence[Device]:
    """Every device an estate-wide report should consider. Archived ones are not."""
    return (
        (
            await session.execute(
                select(Device).where(
                    Device.org_id == org_id,
                    Device.status != DeviceStatus.ARCHIVED.value,
                )
            )
        )
        .scalars()
        .all()
    )


async def latest_snapshots(
    session: AsyncSession, device_ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, Snapshot]:
    """The newest snapshot per device, in one query rather than N.

    A five-hundred-device estate would otherwise issue five hundred round trips for a
    report someone refreshes on a dashboard.
    """
    if not device_ids:
        return {}

    rows = (
        (
            await session.execute(
                select(Snapshot)
                .where(Snapshot.device_id.in_(device_ids))
                .order_by(Snapshot.device_id, Snapshot.created_at.desc())
            )
        )
        .scalars()
        .all()
    )

    latest: dict[uuid.UUID, Snapshot] = {}
    for row in rows:
        latest.setdefault(row.device_id, row)
    return latest


def _is_aaa_server(snapshot: Snapshot | None) -> bool:
    if snapshot is None:
        return False
    product = ((snapshot.ncm or {}).get("aaa_server") or {}).get("product")
    return product in _SERVER_PRODUCTS


def _normalise(address: str) -> str:
    """Compare addresses as addresses, not as strings.

    `10.0.0.1`, `10.0.0.1/32` and `010.000.000.001` are one host, and an estate that
    writes them inconsistently — which every estate does — would otherwise produce
    orphans and unregistered devices that are the same box seen twice.
    """
    token = address.strip()
    try:
        return str(ipaddress.ip_network(token, strict=False).network_address)
    except ValueError:
        return token.lower()


def _age_days(when: datetime | None) -> int | None:
    if when is None:
        return None
    moment = when if when.tzinfo else when.replace(tzinfo=UTC)
    return (datetime.now(UTC) - moment).days


def summarise(report: AaaCorrelationReport) -> dict[str, Any]:
    """A compact form for the dashboard and for storing on a finding."""
    return {
        **report.counts,
        "coverage_percentage": report.coverage.percentage,
        "devices_total": report.coverage.devices_total,
        "devices_with_central_auth": report.coverage.devices_with_central_auth,
        "devices_not_evaluated": report.coverage.devices_not_evaluated,
        "registration_analysed": report.registration_analysed,
        "limitations": report.limitations,
    }


__all__ = [
    "AaaCorrelationReport",
    "AaaCorrelationService",
    "AaaCoverage",
    "OrphanedClient",
    "SecretReuse",
    "ServerRecord",
    "UnknownServer",
    "UnregisteredDevice",
    "active_devices",
    "latest_snapshots",
    "summarise",
]
