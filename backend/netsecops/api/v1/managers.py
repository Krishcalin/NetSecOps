"""Manager child enumeration and approval (FR-INV-04, FR-DISC-06).

Four routes, and the split between them is the requirement rather than a convenience.
FR-INV-04 permits managers to auto-populate the inventory *with user approval*, so:

``preview`` reads and writes nothing. ``import`` acts only on identities the caller
names. ``pending`` lists what is awaiting a decision. ``approve`` is what actually
admits a device to assessment — and it means something because job targeting excludes
``pending_review``, so an imported device is visible and attributed but is never
connected to until a human says so.

Importing is a device write; approving is the decision to start assessing a device, and
both stay with the roles that already own inventory (SRS §2.3).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends

from netsecops.api.deps import PrincipalDep, SessionDep, require, verify_csrf
from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.db.models.inventory import Criticality
from netsecops.schemas.managers import (
    ChildDeviceRead,
    ChildProposalRead,
    DisappearedDevice,
    EnumerationPreviewRead,
    EnumerationRequest,
    ImportRequest,
    ImportResultRead,
    PendingDeviceRead,
)
from netsecops.services.inventory import InventoryService
from netsecops.services.manager_enumeration import (
    EnumerationPreview,
    ManagerEnumerationService,
)

log = get_logger(__name__)
router = APIRouter(tags=["managers"])


def _to_read(preview: EnumerationPreview) -> EnumerationPreviewRead:
    return EnumerationPreviewRead(
        manager_id=preview.manager_id,
        manager_hostname=preview.manager_hostname,
        platform=preview.platform,
        counts=preview.counts,
        proposals=[
            ChildProposalRead(
                identity=proposal.identity,
                disposition=proposal.disposition,
                device_id=proposal.device_id,
                reason=proposal.reason,
                child=ChildDeviceRead(
                    hostname=proposal.child.hostname,
                    mgmt_ip=proposal.child.mgmt_ip,
                    vendor=proposal.child.vendor,
                    platform=proposal.child.platform,
                    serial_number=proposal.child.serial_number,
                    model=proposal.child.model,
                    os_version=proposal.child.os_version,
                    reachable=proposal.child.reachable,
                    group=proposal.child.group,
                ),
            )
            for proposal in preview.proposals
        ],
        disappeared=[DisappearedDevice(**entry) for entry in preview.disappeared],
    )


@router.post(
    "/devices/{device_id}/children/preview",
    response_model=EnumerationPreviewRead,
    dependencies=[Depends(require(Permission.DEVICE_READ)), Depends(verify_csrf)],
    summary="What a manager reports managing, and what importing it would change",
)
async def preview_children(
    device_id: uuid.UUID,
    request: EnumerationRequest,
    session: SessionDep,
    principal: PrincipalDep,
) -> EnumerationPreviewRead:
    """Reads the manager's response. Writes nothing.

    A POST because the manager's response body does not fit in a URL, not because it
    changes anything — hence the read permission rather than the write one.
    """
    manager = await InventoryService(session).get_device(device_id, scope=principal.scope)
    preview = await ManagerEnumerationService(session).preview(manager, request.payload)
    return _to_read(preview)


@router.post(
    "/devices/{device_id}/children/import",
    response_model=ImportResultRead,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Import the approved children into inventory (FR-INV-04)",
)
async def import_children(
    device_id: uuid.UUID,
    request: ImportRequest,
    session: SessionDep,
    principal: PrincipalDep,
) -> ImportResultRead:
    """Creates only the devices the caller named, as `pending_review`.

    The preview is re-derived from the payload supplied here rather than being read from
    a store, so the import always acts on what the manager says now. An identity that
    has since disappeared from the manager's list is an error, not a silent skip: the
    list the human approved is no longer the list being acted on, and they should see
    that rather than have it resolved for them.
    """
    inventory = InventoryService(session)
    manager = await inventory.get_device(device_id, scope=principal.scope)

    service = ManagerEnumerationService(session)
    preview = await service.preview(manager, request.payload)

    try:
        criticality = Criticality(request.criticality)
    except ValueError as exc:
        raise ValidationProblem(
            f"'{request.criticality}' is not a criticality. Use one of: "
            f"{', '.join(c.value for c in Criticality)}."
        ) from exc

    result = await service.import_children(
        manager,
        preview,
        identities=request.identities,
        actor=principal,
        criticality=criticality,
    )
    return ImportResultRead(
        created=result.created,
        updated=result.updated,
        skipped=result.skipped,
        counts=result.counts,
    )


@router.get(
    "/devices/pending-review",
    response_model=list[PendingDeviceRead],
    dependencies=[Depends(require(Permission.DEVICE_READ))],
    summary="Devices imported or discovered but not yet approved for assessment",
)
async def list_pending(
    session: SessionDep,
    principal: PrincipalDep,
    manager_id: uuid.UUID | None = None,
) -> list[PendingDeviceRead]:
    service = ManagerEnumerationService(session)
    manager = None
    if manager_id is not None:
        manager = await InventoryService(session).get_device(manager_id, scope=principal.scope)

    devices = await service.pending(manager)
    return [PendingDeviceRead.model_validate(device) for device in devices]


@router.post(
    "/devices/{device_id}/approve",
    response_model=PendingDeviceRead,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Admit a pending device to assessment (FR-INV-04, FR-DISC-04)",
)
async def approve_device(
    device_id: uuid.UUID,
    session: SessionDep,
    principal: PrincipalDep,
) -> PendingDeviceRead:
    """The approval itself.

    Until this is called the device is in inventory and excluded from every job, so
    nothing has connected to it. Afterwards it is assessed like any other device.
    """
    inventory = InventoryService(session)
    device = await inventory.get_device(device_id, scope=principal.scope)
    approved = await ManagerEnumerationService(session).approve(device, actor=principal)
    return PendingDeviceRead.model_validate(approved)


__all__ = ["router"]
