"""Importing a manager's managed devices into inventory (FR-INV-04, FR-DISC-06).

FR-INV-04 says managers may auto-populate the inventory **with user approval**, and the
whole design follows from taking that seriously rather than treating it as a
confirmation dialog.

**Enumerating and importing are separate operations.** :meth:`preview` reads the
manager's response and says exactly what would change — which devices are new, which are
already known, and which known devices the manager no longer reports. It writes nothing.
:meth:`import_children` performs it, and only for identities the caller names. A single
call that enumerated and created would mean a Panorama with four hundred firewalls turns
one API call into four hundred devices nobody chose.

**Imported devices land as `pending_review`, not `active`.** They are visible, they are
attributed to the manager that reported them, and they are *not* assessed until someone
approves them. That is the approval, and it is only real because job targeting excludes
`pending_review` — without that exclusion the status would be decoration and the first
scheduled job would reach every device the manager has ever heard of.

**Nothing is deleted.** A device the manager no longer reports is surfaced as a
*disappeared* proposal for a human to act on, never archived automatically. A manager
that fails to list a device because of an API error, a permissions change or a domain
filter looks exactly like one that no longer manages it, and silently archiving on that
basis would remove devices from assessment at the moment the manager is misbehaving.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.adapters.children import ChildDevice, enumerate_children, supports_enumeration
from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Principal
from netsecops.db.models.audit import AuditAction
from netsecops.db.models.inventory import (
    Criticality,
    Device,
    DeviceClass,
    DeviceStatus,
    Vendor,
)
from netsecops.services.audit import AuditService
from netsecops.services.inventory import InventoryService

log = get_logger(__name__)

#: Device classes a child is imported as, by platform. A manager only ever manages
#: firewalls in the three products supported here; anything unrecognised is imported as
#: unknown rather than guessed, because the class decides which checks apply.
_CHILD_CLASS: dict[str, DeviceClass] = {
    "panos": DeviceClass.FIREWALL,
    "fortios": DeviceClass.FIREWALL,
    "checkpoint_gaia": DeviceClass.FIREWALL,
}


@dataclass(frozen=True, slots=True)
class ChildProposal:
    """One child, and what importing it would do."""

    child: ChildDevice
    #: `new`, `known`, or `unimportable`.
    disposition: str
    #: Set when the child already exists in inventory.
    device_id: uuid.UUID | None = None
    #: Why it cannot be imported, where it cannot.
    reason: str | None = None

    @property
    def identity(self) -> str:
        return self.child.identity


@dataclass(slots=True)
class EnumerationPreview:
    """What a manager reports, and what acting on it would change. Writes nothing."""

    manager_id: uuid.UUID
    manager_hostname: str | None
    platform: str | None
    proposals: list[ChildProposal] = field(default_factory=list)
    #: Devices previously imported from this manager that it no longer reports. Surfaced
    #: for a human, never archived automatically — see the module docstring.
    disappeared: list[dict[str, Any]] = field(default_factory=list)

    @property
    def new(self) -> list[ChildProposal]:
        return [p for p in self.proposals if p.disposition == "new"]

    @property
    def known(self) -> list[ChildProposal]:
        return [p for p in self.proposals if p.disposition == "known"]

    @property
    def unimportable(self) -> list[ChildProposal]:
        return [p for p in self.proposals if p.disposition == "unimportable"]

    @property
    def counts(self) -> dict[str, int]:
        return {
            "reported": len(self.proposals),
            "new": len(self.new),
            "known": len(self.known),
            "unimportable": len(self.unimportable),
            "disappeared": len(self.disappeared),
        }


@dataclass(slots=True)
class ImportResult:
    created: list[uuid.UUID] = field(default_factory=list)
    updated: list[uuid.UUID] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return {
            "created": len(self.created),
            "updated": len(self.updated),
            "skipped": len(self.skipped),
        }


class ManagerEnumerationService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.inventory = InventoryService(session)
        self.audit = AuditService(session)

    # ─────────────────────────── preview ────────────────────────────────

    async def preview(self, manager: Device, payload: str) -> EnumerationPreview:
        """Read the manager's response and say what importing it would change.

        Writes nothing. The caller shows this to a human, who names the identities they
        want, and only then is :meth:`import_children` called.
        """
        self._assert_is_a_manager(manager)

        children = enumerate_children(manager.platform or "", payload)
        preview = EnumerationPreview(
            manager_id=manager.id,
            manager_hostname=manager.hostname,
            platform=manager.platform,
        )

        existing_children = await self._children_of(manager)
        by_serial = {d.serial_number: d for d in existing_children if d.serial_number}
        by_ip = {str(d.mgmt_ip): d for d in existing_children}

        seen: set[uuid.UUID] = set()

        for child in children:
            match = None
            if child.serial_number and child.serial_number in by_serial:
                match = by_serial[child.serial_number]
            elif child.mgmt_ip and child.mgmt_ip in by_ip:
                match = by_ip[child.mgmt_ip]
            else:
                # Not a child of this manager, but possibly already in inventory from a
                # CSV import or another manager. Adopting it is better than refusing the
                # address and better than creating a duplicate.
                match = await self._find_anywhere(child, manager.org_id)

            if match is not None:
                seen.add(match.id)
                preview.proposals.append(
                    ChildProposal(child=child, disposition="known", device_id=match.id)
                )
                continue

            if not child.mgmt_ip:
                # The manager knows about it but reports no address, so there is nothing
                # to collect from. Surfaced rather than dropped: a firewall the manager
                # manages and we cannot reach is a gap worth seeing.
                preview.proposals.append(
                    ChildProposal(
                        child=child,
                        disposition="unimportable",
                        reason=(
                            "The manager reports no management address for this device, "
                            "so NetSecOps has nothing to connect to. Add it by hand if "
                            "the device should be assessed."
                        ),
                    )
                )
                continue

            preview.proposals.append(ChildProposal(child=child, disposition="new"))

        preview.disappeared = [
            {
                "device_id": str(device.id),
                "hostname": device.hostname,
                "mgmt_ip": str(device.mgmt_ip),
                "serial_number": device.serial_number,
                "status": device.status,
            }
            for device in existing_children
            if device.id not in seen
        ]

        log.info(
            "manager.enumeration_previewed",
            manager_id=str(manager.id),
            platform=manager.platform,
            **preview.counts,
        )
        return preview

    # ─────────────────────────── the import ─────────────────────────────

    async def import_children(
        self,
        manager: Device,
        preview: EnumerationPreview,
        *,
        identities: list[str],
        actor: Principal,
        criticality: Criticality = Criticality.MEDIUM,
    ) -> ImportResult:
        """Create or adopt the named children. Nothing else is touched.

        ``identities`` is the approval: only children the caller names are imported, and
        naming one that is not in the preview is an error rather than a silent no-op —
        it means the preview the human approved is not the one being acted on.
        """
        self._assert_is_a_manager(manager)

        wanted = set(identities)
        by_identity = {p.identity: p for p in preview.proposals}

        unknown = sorted(wanted - set(by_identity))
        if unknown:
            raise ValidationProblem(
                f"These devices are not in the enumeration being imported: "
                f"{', '.join(unknown)}. Re-run the enumeration and approve from the "
                f"current list — the manager's answer may have changed since."
            )

        result = ImportResult()

        for identity in identities:
            proposal = by_identity[identity]

            if proposal.disposition == "unimportable":
                result.skipped.append(identity)
                continue

            if proposal.disposition == "known" and proposal.device_id is not None:
                device = await self.inventory.get_device(proposal.device_id)
                if self._adopt(device, manager, proposal.child):
                    result.updated.append(device.id)
                continue

            device = await self._create(manager, proposal.child, actor, criticality)
            result.created.append(device.id)

        await self.session.flush()

        await self.audit.record(
            AuditAction.DEVICE_CREATED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="device",
            object_id=manager.id,
            device_id=manager.id,
            details={
                "action": "manager_enumeration_import",
                "manager": manager.hostname,
                "platform": manager.platform,
                **result.counts,
            },
        )

        log.info(
            "manager.children_imported",
            manager_id=str(manager.id),
            actor=actor.username,
            **result.counts,
        )
        return result

    async def _create(
        self,
        manager: Device,
        child: ChildDevice,
        actor: Principal,
        criticality: Criticality,
    ) -> Device:
        return await self.inventory.create_device(
            mgmt_ip=child.mgmt_ip or "",
            actor=actor,
            hostname=child.hostname,
            vendor=_vendor(child.vendor),
            platform=child.platform,
            device_class=_CHILD_CLASS.get(child.platform, DeviceClass.UNKNOWN),
            criticality=criticality,
            org_id=manager.org_id,
            parent_device_id=manager.id,
            # The approval gate. Job targeting excludes this status, so an imported
            # device is visible and attributed but is not collected from or assessed
            # until a human moves it to active.
            status=DeviceStatus.PENDING_REVIEW.value,
            serial_number=child.serial_number,
            model=child.model,
            os_version=child.os_version,
            facts=_facts(manager, child),
        )

    def _adopt(self, device: Device, manager: Device, child: ChildDevice) -> bool:
        """Attach an already-known device to this manager, refreshing what it reports.

        Deliberately narrow. It never changes the device's status — adopting a device
        someone has already approved must not send it back for review — and never
        changes its management address, because the address in inventory is the one that
        has been shown to work and the manager's may be a different interface.
        """
        changed = False

        if device.parent_device_id != manager.id:
            device.parent_device_id = manager.id
            changed = True

        for attribute, value in (
            ("serial_number", child.serial_number),
            ("model", child.model),
            ("os_version", child.os_version),
        ):
            # Only fill gaps and refresh what the manager is authoritative for. A None
            # from the manager means "not reported", which must not erase a value the
            # device itself supplied during a collection.
            if value and getattr(device, attribute) != value:
                setattr(device, attribute, value)
                changed = True

        facts = dict(device.facts or {})
        facts.update(_facts(manager, child))
        if facts != device.facts:
            device.facts = facts
            changed = True

        return changed

    # ─────────────────────────── approval ───────────────────────────────

    async def approve(self, device: Device, *, actor: Principal) -> Device:
        """Move an imported device into assessment (FR-INV-04, FR-DISC-04)."""
        if device.status != DeviceStatus.PENDING_REVIEW.value:
            raise ValidationProblem(
                f"'{device.hostname or device.mgmt_ip}' is not awaiting review — its "
                f"status is '{device.status}'."
            )

        device.status = DeviceStatus.ACTIVE.value
        await self.session.flush()

        await self.audit.record(
            AuditAction.DEVICE_UPDATED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="device",
            object_id=device.id,
            device_id=device.id,
            details={"action": "approved_for_assessment", "from": "pending_review"},
        )
        return device

    async def pending(self, manager: Device | None = None, *, org_id: int = 1) -> list[Device]:
        """Devices awaiting approval, optionally only those from one manager."""
        stmt = select(Device).where(
            Device.org_id == org_id,
            Device.status == DeviceStatus.PENDING_REVIEW.value,
        )
        if manager is not None:
            stmt = stmt.where(Device.parent_device_id == manager.id)
        return list((await self.session.execute(stmt.order_by(Device.hostname))).scalars().all())

    # ─────────────────────────── helpers ────────────────────────────────

    def _assert_is_a_manager(self, manager: Device) -> None:
        if manager.device_class != DeviceClass.MANAGER.value:
            raise ValidationProblem(
                f"'{manager.hostname or manager.mgmt_ip}' is not recorded as a manager. "
                f"Set its device class to 'manager' if it is a Panorama, FortiManager or "
                f"Check Point management server."
            )
        if not supports_enumeration(manager.platform):
            raise ValidationProblem(
                f"NetSecOps cannot enumerate managed devices from platform '{manager.platform}'."
            )

    async def _children_of(self, manager: Device) -> list[Device]:
        return list(
            (
                await self.session.execute(
                    select(Device).where(Device.parent_device_id == manager.id)
                )
            )
            .scalars()
            .all()
        )

    async def _find_anywhere(self, child: ChildDevice, org_id: int) -> Device | None:
        """A device already in inventory that this child is — from a CSV import, say.

        Matched on serial first: an estate that re-addresses a firewall would otherwise
        get a duplicate, and two records for one device means two risk scores and two
        sets of findings for the same box.
        """
        if child.serial_number:
            found = (
                await self.session.execute(
                    select(Device).where(
                        Device.org_id == org_id,
                        Device.serial_number == child.serial_number,
                    )
                )
            ).scalar_one_or_none()
            if found is not None:
                return found

        if child.mgmt_ip:
            return (
                await self.session.execute(
                    select(Device).where(Device.org_id == org_id, Device.mgmt_ip == child.mgmt_ip)
                )
            ).scalar_one_or_none()

        return None


def _vendor(name: str) -> Vendor:
    try:
        return Vendor(name)
    except ValueError:
        return Vendor.UNKNOWN


def _facts(manager: Device, child: ChildDevice) -> dict[str, Any]:
    """What the manager said, kept so a later enumeration can be compared with it."""
    return {
        "managed_by": str(manager.id),
        "manager_hostname": manager.hostname,
        "manager_group": child.group,
        "manager_reports_reachable": child.reachable,
        "enumerated_at": datetime.now(UTC).isoformat(),
        **{k: v for k, v in child.facts.items() if v is not None},
    }


__all__ = [
    "ChildProposal",
    "EnumerationPreview",
    "ImportResult",
    "ManagerEnumerationService",
]
