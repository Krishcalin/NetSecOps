"""The discovery review queue (FR-DISC-04).

    Discovered hosts SHALL land in a "Pending review" queue; users approve/assign
    credentials/reject. Nothing is assessed automatically without approval unless
    a scope is flagged "auto-onboard".

One sentence, and it is the whole safety boundary of the discovery feature. Everything
before it only reads: a probe opens a TCP connection and reads a banner. Approval is
where NetSecOps stops looking at a host and starts *authenticating* to it, with
credentials that may be inherited from a group the operator did not think about.

So approval is the only path that creates a device, and it is explicit, audited and
attributable. A discovered host carries no `devices` row until somebody says so, which
means no scan, no compliance figure and no credential assignment can reach it — not
because every query remembers to exclude it, but because there is nothing to find.

**Auto-onboard exists and is deliberately awkward.** FR-DISC-04 allows it per scope, and
a lab or a known-good management VLAN is a reasonable place for it. It is off by
default, set on the scope rather than per host, and every device it creates is audited
as auto-onboarded rather than approved, so the distinction survives into the record.
Somebody reviewing how a device entered the estate can tell whether a human agreed.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ConflictError, NotFoundError, ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Principal
from netsecops.db.models.audit import AuditAction, AuditOutcome
from netsecops.db.models.discovery import DiscoveredHost, DiscoveredHostStatus
from netsecops.db.models.inventory import Device, DeviceClass, DeviceStatus, Vendor
from netsecops.discovery.fingerprint import Fingerprint
from netsecops.services.audit import AuditService
from netsecops.services.inventory import InventoryService

log = get_logger(__name__)


class DiscoveryReviewService:
    """Record what discovery found, and turn approved entries into devices."""

    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id
        self.audit = AuditService(session)

    # ── recording what a run found ──────────────────────────────────────

    async def record(
        self,
        address: str,
        *,
        fingerprint: Fingerprint,
        run_id: uuid.UUID | None = None,
        hostname: str | None = None,
    ) -> DiscoveredHost:
        """Queue a host a run found, or refresh the entry it already has.

        A host seen by three runs is one queue entry with a ``last_seen_at``, not three
        things to triage. A previously *rejected* host stays rejected — re-queueing it
        every night would train reviewers to clear the queue without reading it, which
        is how the one host that mattered gets waved through.
        """
        now = datetime.now(UTC)
        existing = (
            await self.session.execute(
                select(DiscoveredHost).where(
                    DiscoveredHost.org_id == self.org_id, DiscoveredHost.address == address
                )
            )
        ).scalar_one_or_none()

        payload = {
            "confidence": fingerprint.confidence,
            "conflicts": list(fingerprint.conflicts),
            "evidence": [
                {
                    "signal": item.signal.value,
                    "raw": item.raw,
                    "vendor": item.vendor,
                    "platform": item.platform,
                }
                for item in fingerprint.evidence
            ],
        }

        if existing is not None:
            existing.last_seen_at = now
            existing.confidence = fingerprint.confidence
            existing.fingerprint = payload
            # The identity is only updated while the entry is still pending. Once a
            # human has ruled on it, a later run must not silently relabel what they
            # approved — that would change what a device is after somebody agreed to it.
            if existing.status == DiscoveredHostStatus.PENDING.value:
                existing.vendor = fingerprint.vendor
                existing.platform = fingerprint.platform
                existing.hostname = hostname or existing.hostname
            await self.session.flush()
            return existing

        host = DiscoveredHost(
            org_id=self.org_id,
            address=address,
            run_id=run_id,
            status=DiscoveredHostStatus.PENDING.value,
            vendor=fingerprint.vendor,
            platform=fingerprint.platform,
            hostname=hostname,
            confidence=fingerprint.confidence,
            fingerprint=payload,
            first_seen_at=now,
            last_seen_at=now,
        )
        self.session.add(host)
        await self.session.flush()
        return host

    # ── the boundary ────────────────────────────────────────────────────

    async def approve(
        self,
        host: DiscoveredHost,
        *,
        actor: Principal,
        vendor: str | None = None,
        platform: str | None = None,
        hostname: str | None = None,
        device_class: DeviceClass = DeviceClass.UNKNOWN,
        note: str | None = None,
    ) -> Device:
        """Create the device. The only path by which a discovered host becomes one.

        The reviewer may override the fingerprint's guess, and frequently should: the
        confidence score is capped below certainty precisely because nothing discovery
        reads is authenticated. What they confirm is what gets stored.
        """
        if host.status == DiscoveredHostStatus.APPROVED.value:
            raise ConflictError(f"{host.address} has already been approved.")

        chosen_vendor = (vendor or host.vendor or "").strip().lower()
        if not chosen_vendor:
            # Without a vendor there is no platform, no parser and no collection
            # profile, so the device would be created and immediately unusable.
            raise ValidationProblem(
                f"{host.address} could not be identified and no vendor was supplied. "
                "Discovery reads banners, which are not authoritative — confirm what "
                "this device is before onboarding it."
            )

        try:
            vendor_enum = Vendor(chosen_vendor)
        except ValueError:
            vendor_enum = Vendor.UNKNOWN

        device = await InventoryService(self.session).create_device(
            mgmt_ip=str(host.address),
            actor=actor,
            hostname=hostname or host.hostname,
            vendor=vendor_enum,
            platform=platform or host.platform,
            device_class=device_class,
            # Approved, but nothing has been collected and no credential is assigned
            # yet. The device exists and is not yet assessable, which is the honest
            # state rather than pretending onboarding is finished.
            #
            # `.value` because this reaches the Device constructor through `**extra`,
            # and the column is a String — an enum member would be stored as its repr.
            status=DeviceStatus.PENDING_REVIEW.value,
        )

        host.status = DiscoveredHostStatus.APPROVED.value
        host.device_id = device.id
        host.reviewed_by_id = actor.id
        host.reviewed_at = datetime.now(UTC)
        host.review_note = note
        await self.session.flush()

        await self.audit.record(
            AuditAction.DEVICE_CREATED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="discovered_host",
            object_id=host.id,
            device_id=device.id,
            details={
                "address": str(host.address),
                "origin": "discovery.approved",
                "confidence": host.confidence,
                "fingerprint_vendor": host.vendor,
                "confirmed_vendor": vendor_enum.value,
                "overridden": bool(vendor and host.vendor and vendor.lower() != host.vendor),
            },
            org_id=self.org_id,
        )

        log.info(
            "discovery.host_approved",
            address=str(host.address),
            device_id=str(device.id),
            actor=actor.username,
        )
        return device

    async def reject(self, host: DiscoveredHost, *, actor: Principal, note: str) -> DiscoveredHost:
        """Mark a host as deliberately not ours.

        The note is required. "Rejected" with no reason tells the next person nothing,
        and the question they will have — is this a printer, or a switch somebody has
        not got round to? — is exactly what determines whether they re-open it.
        """
        if not note or not note.strip():
            raise ValidationProblem(
                "Rejecting a discovered host needs a reason. The next person to see this "
                "address needs to know whether it is not ours or merely not yet."
            )

        host.status = DiscoveredHostStatus.REJECTED.value
        host.reviewed_by_id = actor.id
        host.reviewed_at = datetime.now(UTC)
        host.review_note = note.strip()
        await self.session.flush()

        await self.audit.record(
            AuditAction.DEVICE_UPDATED,
            outcome=AuditOutcome.SUCCESS,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="discovered_host",
            object_id=host.id,
            details={"address": str(host.address), "origin": "discovery.rejected", "note": note},
            org_id=self.org_id,
        )
        return host

    async def auto_onboard(self, host: DiscoveredHost, *, actor: Principal) -> Device | None:
        """Approve without a human, for a scope that opted in (FR-DISC-04).

        Refuses on anything it is not sure about. Auto-onboarding a host whose signals
        disagreed, or one nothing could identify, is how the escape hatch turns into the
        thing the requirement was written to prevent — so those still queue for review
        even on an auto-onboard scope.
        """
        if host.vendor is None:
            log.info(
                "discovery.auto_onboard_declined", address=str(host.address), reason="unidentified"
            )
            return None
        if host.fingerprint.get("conflicts"):
            log.info(
                "discovery.auto_onboard_declined", address=str(host.address), reason="contested"
            )
            return None

        device = await self.approve(host, actor=actor, note="Auto-onboarded by scope policy.")

        # Re-recorded with a distinct origin so the audit trail can answer "did a human
        # agree to this device?" without inferring it from a timestamp.
        await self.audit.record(
            AuditAction.DEVICE_CREATED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="discovered_host",
            object_id=host.id,
            device_id=device.id,
            details={"address": str(host.address), "origin": "discovery.auto_onboarded"},
            org_id=self.org_id,
        )
        return device

    # ── reads ───────────────────────────────────────────────────────────

    async def pending(self, *, limit: int = 200) -> Sequence[DiscoveredHost]:
        """The queue, worst-understood first.

        Sorted by ascending confidence on purpose: the entries that most need a human
        are the ones the fingerprinter was least sure about, and a queue sorted by
        confidence descending puts the easy ones on page one.
        """
        return (
            (
                await self.session.execute(
                    select(DiscoveredHost)
                    .where(
                        DiscoveredHost.org_id == self.org_id,
                        DiscoveredHost.status == DiscoveredHostStatus.PENDING.value,
                    )
                    .order_by(DiscoveredHost.confidence.asc(), DiscoveredHost.address)
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )

    async def get(self, host_id: uuid.UUID) -> DiscoveredHost:
        host = (
            await self.session.execute(
                select(DiscoveredHost).where(
                    DiscoveredHost.org_id == self.org_id, DiscoveredHost.id == host_id
                )
            )
        ).scalar_one_or_none()
        if host is None:
            raise NotFoundError(f"No discovered host {host_id}.")
        return host


__all__ = ["DiscoveryReviewService"]
