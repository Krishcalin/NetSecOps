"""Access points as assets, derived from the controller that knows them (SRS §1.3.1).

A CAPWAP access point holds no configuration of its own. Its WLANs, its RF settings and
its management access all live on the controller, which is why NetSecOps never contacts
one: reaching out over SSH would either fail or return the controller's settings second
hand. That is settled, and it is why there is no `cisco_ap` platform.

**It is still an asset**, and how many access points an estate has — and where — is a
question people ask of an inventory. The controller already answers it: `show ap
summary` is collected and parsed into `wireless.aps`. This turns that list into
inventory rows so the answer is reachable from the Inventory page rather than only from
one device's NCM.

Three decisions hold this together, and each is the difference between a useful record
and a harmful one.

**The rows are `inventory_only`, not `active`.** An access point that can never be
collected from, counted as an ordinary device, is a device that is permanently
unassessed — and a wireless estate would then drag every coverage figure, every grade
distribution and the estate roll-up towards "uncollected". `DeviceStatus.INVENTORY_ONLY`
is outside all of them, and `JobService` refuses to target one.

**There is no approval queue.** A device imported from a Panorama waits for a human
because somebody has to decide whether to connect to it. Nothing will ever be sent to
an access point, so there is nothing to approve, and a queue of hundreds of them would
be a chore with no decision in it.

**They are linked to their controller and re-derived from it.** `parent_device_id` is
the same field a managed FortiGate uses for its FortiManager. An AP that stops
appearing in its controller's list has been removed or has stopped joining, and either
way the record should say so rather than lingering as an asset nobody can find — so a
missing AP is archived, not deleted. Deleting would lose the fact that it was ever
there, which is the question somebody asks afterwards.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.logging import get_logger
from netsecops.db.models.inventory import Device, DeviceClass, DeviceStatus

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ApSyncResult:
    added: int = 0
    updated: int = 0
    archived: int = 0
    #: Reported by the controller and not recorded, because the summary carried no
    #: address for them. Counted rather than silently dropped — see `_create`.
    skipped: int = 0

    @property
    def total(self) -> int:
        return self.added + self.updated


def _name_of(entry: Mapping[str, Any]) -> str | None:
    name = str(entry.get("name") or "").strip()
    return name or None


class AccessPointInventory:
    """Keeps a controller's access points in the inventory as non-assessable assets."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def sync(self, controller: Device, ncm: Mapping[str, Any]) -> ApSyncResult:
        """Record the access points this controller reports, and retire the ones it does not.

        Called after a controller's snapshot is stored. Does nothing at all when the
        NCM carries no AP list — which is every non-wireless device, and also a
        wireless controller whose `show ap summary` did not come back. **That
        distinction is why the guard below exists**: an empty list and a missing one
        are the same `[]` here, and archiving every access point in the estate because
        one command failed would be a far worse outcome than recording none.
        """
        wireless = ncm.get("wireless")
        if not isinstance(wireless, Mapping):
            return ApSyncResult()

        reported = wireless.get("aps")
        if not isinstance(reported, list):
            return ApSyncResult()

        declared = wireless.get("aps_declared")
        if not reported and declared in (None, 0):
            # No list and no count. The controller either has no access points or was
            # never asked — and nothing here can tell those apart, so nothing is
            # changed. An existing record is left alone rather than archived.
            return ApSyncResult()

        if declared is not None and len(reported) != declared:
            # The parser's own shortfall signal, acted on rather than logged. A partial
            # list would archive the access points that did not parse, turning a
            # parsing problem into an inventory one.
            log.warning(
                "access_points.shortfall_not_synced",
                controller_id=str(controller.id),
                declared=declared,
                parsed=len(reported),
            )
            return ApSyncResult()

        existing = await self._derived_access_points(controller)
        seen: set[str] = set()
        added = updated = skipped = 0

        for entry in reported:
            if not isinstance(entry, Mapping):
                continue
            name = _name_of(entry)
            if name is None:
                continue

            seen.add(name)
            if current := existing.get(name):
                updated += 1 if self._apply(current, entry, controller) else 0
                continue

            address = str(entry.get("ip") or "").strip()
            if not address:
                # `devices` is unique on `(org_id, mgmt_ip)` and the column is not
                # nullable, so an access point with no address cannot be stored — and
                # borrowing the controller's would collide with the controller on the
                # first AP and with itself on the second.
                #
                # `show ap summary` carries an address for every joined access point,
                # so a missing one means either a radio still joining or a row this
                # parser read incompletely. Skipped and counted, never invented: a
                # placeholder address in an inventory is worse than an absent row,
                # because somebody will eventually try to reach it.
                skipped += 1
                continue

            self.session.add(self._create(name, address, entry, controller))
            added += 1

        archived = 0
        for name, device in existing.items():
            # **Only this controller's.** `existing` spans the whole estate so a roam
            # is recognised rather than duplicated, and archiving on that set would
            # mean every controller retired every *other* controller's access points
            # each time it was collected from.
            if device.parent_device_id != controller.id:
                continue
            if name in seen or device.status == DeviceStatus.ARCHIVED.value:
                continue
            # Archived, never deleted. "This access point used to be here" is the
            # question somebody asks after it goes missing, and a deleted row cannot
            # answer it.
            device.status = DeviceStatus.ARCHIVED.value
            archived += 1

        await self.session.flush()
        result = ApSyncResult(added=added, updated=updated, archived=archived, skipped=skipped)
        if result.added or result.archived:
            log.info(
                "access_points.synced",
                controller_id=str(controller.id),
                added=result.added,
                archived=result.archived,
            )
        if result.skipped:
            log.warning(
                "access_points.skipped_without_address",
                controller_id=str(controller.id),
                skipped=result.skipped,
            )
        return result

    async def _derived_access_points(self, controller: Device) -> dict[str, Device]:
        """Every access point this service has recorded in the org, keyed by name.

        **Deliberately not scoped to this controller.** An access point that roams to
        another controller — a failover, a site rebuild — is the same radio, and
        looking only under the current parent would not find it: the insert would then
        collide on `(org_id, mgmt_ip)` and abort the controller's whole collection.
        That is what happened, and `test_an_access_point_that_roams_to_another_
        controller_moves` is the reason it was found before a real estate hit it.

        Restricted to rows this service created — `parent_device_id` is set and the
        class is `wireless_ap` — so a device somebody entered by hand is never adopted,
        renamed or archived by a controller's collection.

        The name is the key because it is the only stable identifier `show ap summary`
        carries that the NCM keeps: the MAC is read to recognise a row and is not
        stored, and the serial is not in the table at all.
        """
        rows: Sequence[Device] = (
            (
                await self.session.execute(
                    select(Device).where(
                        Device.org_id == controller.org_id,
                        Device.device_class == DeviceClass.WIRELESS_AP.value,
                        Device.parent_device_id.is_not(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        return {device.hostname: device for device in rows if device.hostname}

    def _create(
        self, name: str, address: str, entry: Mapping[str, Any], controller: Device
    ) -> Device:
        return Device(
            org_id=controller.org_id,
            hostname=name,
            mgmt_ip=address,
            vendor=controller.vendor,
            device_class=DeviceClass.WIRELESS_AP.value,
            status=DeviceStatus.INVENTORY_ONLY.value,
            parent_device_id=controller.id,
            model=str(entry.get("model") or "") or None,
            serial_number=str(entry.get("serial") or "") or None,
            # Inherited from the controller: an access point in a plant room is as
            # critical as the controller serving it, and leaving it at the default
            # would quietly reclassify a whole estate.
            criticality=controller.criticality,
            # No platform. There is nothing to collect, so there is nothing to choose a
            # profile or a parser with, and naming one would imply otherwise.
            platform=None,
        )

    def _apply(self, device: Device, entry: Mapping[str, Any], controller: Device) -> bool:
        """Refresh what the controller reports. Returns whether anything moved."""
        changed = False
        for field, value in (
            ("model", str(entry.get("model") or "") or None),
            ("serial_number", str(entry.get("serial") or "") or None),
        ):
            if value is not None and getattr(device, field) != value:
                setattr(device, field, value)
                changed = True

        address = str(entry.get("ip") or "") or None
        if address and str(device.mgmt_ip) != address:
            device.mgmt_ip = address
            changed = True

        if device.parent_device_id != controller.id:
            # It moved to another controller, which is a roam worth recording rather
            # than a second inventory row for the same radio.
            device.parent_device_id = controller.id
            changed = True

        if device.status == DeviceStatus.ARCHIVED.value:
            # It came back. Restored to the same non-assessable status it had before,
            # never to `active` — rejoining a controller does not make it collectable.
            device.status = DeviceStatus.INVENTORY_ONLY.value
            changed = True

        return changed


async def sync_access_points(
    session: AsyncSession, controller: Device, ncm: Mapping[str, Any]
) -> ApSyncResult:
    return await AccessPointInventory(session).sync(controller, ncm)


__all__ = ["AccessPointInventory", "ApSyncResult", "sync_access_points"]
