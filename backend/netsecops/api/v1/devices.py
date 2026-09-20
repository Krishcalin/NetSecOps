"""Device, group, site and tag endpoints (FR-INV-01 … FR-INV-08)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, File, Query, UploadFile, status

from netsecops.api.deps import PrincipalDep, SessionDep, require, verify_csrf
from netsecops.core.errors import ValidationProblem
from netsecops.core.rbac import Permission
from netsecops.db.models.inventory import (
    Criticality,
    Device,
    DeviceClass,
    DeviceStatus,
    Vendor,
)
from netsecops.schemas.inventory import (
    DeviceCreate,
    DeviceDetail,
    DeviceGroupCreate,
    DeviceGroupMove,
    DeviceGroupRead,
    DeviceRead,
    DeviceUpdate,
    ImportApplyResponse,
    ImportPreviewResponse,
    ImportRowResult,
    PaginatedDevices,
    SiteCreate,
    SiteRead,
    TagRead,
)
from netsecops.services.inventory import ImportPreview, InventoryService

router = APIRouter(tags=["inventory"])

#: A CSV big enough to be a mistake rather than an inventory (SEC-05).
MAX_IMPORT_BYTES = 5 * 1024 * 1024


def inventory_service(session: SessionDep) -> InventoryService:
    return InventoryService(session)


InventoryDep = Annotated[InventoryService, Depends(inventory_service)]


async def _to_detail(inventory: InventoryService, device: Device) -> DeviceDetail:
    """Assemble the detail view.

    Everything relational is queried rather than read off the ORM relationships: a
    device that was just created has them unloaded, and touching one there emits lazy
    IO that fails under async SQLAlchemy.
    """
    from sqlalchemy import select

    from netsecops.db.models.inventory import (
        Credential,
        CredentialAssignment,
        DeviceGroupMember,
        DeviceTag,
        Tag,
    )

    group_ids = (
        (
            await inventory.session.execute(
                select(DeviceGroupMember.group_id).where(DeviceGroupMember.device_id == device.id)
            )
        )
        .scalars()
        .all()
    )
    tag_names = (
        (
            await inventory.session.execute(
                select(Tag.name)
                .join(DeviceTag, DeviceTag.tag_id == Tag.id)
                .where(DeviceTag.device_id == device.id)
            )
        )
        .scalars()
        .all()
    )
    credential_names = (
        (
            await inventory.session.execute(
                select(Credential.name)
                .join(CredentialAssignment, CredentialAssignment.credential_id == Credential.id)
                .where(CredentialAssignment.device_id == device.id)
            )
        )
        .scalars()
        .all()
    )

    base = DeviceRead.model_validate(device).model_dump()
    return DeviceDetail(
        **base,
        group_ids=list(group_ids),
        tags=sorted(tag_names),
        credential_names=sorted(credential_names),
    )


# ──────────────────────────────── devices ───────────────────────────────────


@router.get(
    "/devices",
    response_model=PaginatedDevices,
    dependencies=[Depends(require(Permission.DEVICE_READ))],
    summary="List devices visible to you",
)
async def list_devices(
    inventory: InventoryDep,
    principal: PrincipalDep,
    search: str | None = None,
    vendor: Vendor | None = None,
    platform: str | None = None,
    device_class: DeviceClass | None = None,
    criticality: Criticality | None = None,
    status_filter: Annotated[DeviceStatus | None, Query(alias="status")] = None,
    site_id: uuid.UUID | None = None,
    group_id: uuid.UUID | None = None,
    tag: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedDevices:
    rows, total = await inventory.list_devices(
        scope=principal.scope,
        search=search,
        vendor=vendor,
        platform=platform,
        device_class=device_class,
        criticality=criticality,
        status=status_filter,
        site_id=site_id,
        group_id=group_id,
        tag=tag,
        limit=limit,
        offset=offset,
    )
    return PaginatedDevices(
        data=[DeviceRead.model_validate(d) for d in rows],
        meta={"total": total, "limit": limit, "offset": offset},
    )


@router.post(
    "/devices",
    response_model=DeviceDetail,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Add a device",
)
async def create_device(
    payload: DeviceCreate, inventory: InventoryDep, principal: PrincipalDep
) -> DeviceDetail:
    device = await inventory.create_device(
        mgmt_ip=str(payload.mgmt_ip),
        actor=principal,
        hostname=payload.hostname,
        fqdn=payload.fqdn,
        vendor=payload.vendor,
        platform=payload.platform,
        device_class=payload.device_class,
        site_id=payload.site_id,
        criticality=payload.criticality,
        group_ids=payload.group_ids,
        tags=payload.tags,
        notes=payload.notes,
        ssh_port=payload.ssh_port,
        https_port=payload.https_port,
        connect_timeout=payload.connect_timeout,
        command_timeout=payload.command_timeout,
        allow_expert=payload.allow_expert,
        allow_sudo_read=payload.allow_sudo_read,
    )
    return await _to_detail(inventory, device)


@router.get(
    "/devices/{device_id}",
    response_model=DeviceDetail,
    dependencies=[Depends(require(Permission.DEVICE_READ))],
    summary="Fetch one device",
)
async def get_device(
    device_id: uuid.UUID, inventory: InventoryDep, principal: PrincipalDep
) -> DeviceDetail:
    device = await inventory.get_device(device_id, scope=principal.scope)
    return await _to_detail(inventory, device)


@router.patch(
    "/devices/{device_id}",
    response_model=DeviceDetail,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Update a device",
)
async def update_device(
    device_id: uuid.UUID,
    payload: DeviceUpdate,
    inventory: InventoryDep,
    principal: PrincipalDep,
) -> DeviceDetail:
    device = await inventory.get_device(device_id, scope=principal.scope)
    fields = payload.model_dump(exclude_unset=True, exclude={"group_ids", "tags"})
    if "mgmt_ip" in fields and fields["mgmt_ip"] is not None:
        fields["mgmt_ip"] = str(fields["mgmt_ip"])

    updated = await inventory.update_device(
        device, actor=principal, group_ids=payload.group_ids, tags=payload.tags, **fields
    )
    return await _to_detail(inventory, updated)


@router.post(
    "/devices/{device_id}/archive",
    response_model=DeviceRead,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Archive a device, keeping its history",
)
async def archive_device(
    device_id: uuid.UUID, inventory: InventoryDep, principal: PrincipalDep
) -> DeviceRead:
    device = await inventory.get_device(device_id, scope=principal.scope)
    return DeviceRead.model_validate(await inventory.archive_device(device, actor=principal))


@router.delete(
    "/devices/{device_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Delete a device and its history",
)
async def delete_device(
    device_id: uuid.UUID, inventory: InventoryDep, principal: PrincipalDep
) -> None:
    device = await inventory.get_device(device_id, scope=principal.scope)
    await inventory.delete_device(device, actor=principal)


# ────────────────────────────── CSV import ──────────────────────────────────


@router.post(
    "/devices/import/preview",
    response_model=ImportPreviewResponse,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Validate a device CSV without writing anything (FR-INV-02)",
)
async def preview_import(
    inventory: InventoryDep,
    file: Annotated[UploadFile, File(description="CSV with at least a mgmt_ip column")],
) -> ImportPreviewResponse:
    preview = await _read_preview(inventory, file)
    return _preview_response(preview)


@router.post(
    "/devices/import",
    response_model=ImportApplyResponse,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Import devices from CSV",
)
async def apply_import(
    inventory: InventoryDep,
    principal: PrincipalDep,
    file: Annotated[UploadFile, File()],
) -> ImportApplyResponse:
    # Re-validated here rather than trusting a preview token: the inventory may have
    # changed since the preview, and a stale plan could create a duplicate.
    preview = await _read_preview(inventory, file)
    result = await inventory.apply_import(preview, actor=principal)
    return ImportApplyResponse(**result)


async def _read_preview(inventory: InventoryService, file: UploadFile) -> ImportPreview:
    raw = await file.read()
    if len(raw) > MAX_IMPORT_BYTES:
        raise ValidationProblem(
            f"The file is larger than {MAX_IMPORT_BYTES // (1024 * 1024)} MB.",
            size_bytes=len(raw),
        )
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationProblem("The file must be UTF-8 encoded text.") from exc

    return await inventory.preview_import(content)


def _preview_response(preview: ImportPreview) -> ImportPreviewResponse:
    return ImportPreviewResponse(
        ok=preview.ok,
        creates=preview.creates,
        updates=preview.updates,
        invalid=preview.invalid,
        rows=[
            ImportRowResult(
                line=row.line,
                valid=row.valid,
                action=("error" if not row.valid else ("update" if row.existing_id else "create")),
                errors=row.errors,
                mgmt_ip=row.data.get("mgmt_ip"),
            )
            for row in preview.rows
        ],
    )


# ───────────────────────────── device groups ────────────────────────────────


@router.get(
    "/device-groups",
    response_model=list[DeviceGroupRead],
    dependencies=[Depends(require(Permission.DEVICE_READ))],
    summary="List device groups",
)
async def list_groups(inventory: InventoryDep) -> list[DeviceGroupRead]:
    return [DeviceGroupRead.model_validate(g) for g in await inventory.list_groups()]


@router.post(
    "/device-groups",
    response_model=DeviceGroupRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Create a device group",
)
async def create_group(
    payload: DeviceGroupCreate, inventory: InventoryDep, principal: PrincipalDep
) -> DeviceGroupRead:
    group = await inventory.create_group(
        name=payload.name,
        actor=principal,
        parent_id=payload.parent_id,
        description=payload.description,
    )
    return DeviceGroupRead.model_validate(group)


@router.put(
    "/device-groups/{group_id}/parent",
    response_model=DeviceGroupRead,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Move a group, rewriting its subtree's paths",
)
async def move_group(
    group_id: uuid.UUID,
    payload: DeviceGroupMove,
    inventory: InventoryDep,
    principal: PrincipalDep,
) -> DeviceGroupRead:
    group = await inventory.get_group(group_id)
    moved = await inventory.move_group(group, new_parent_id=payload.parent_id, actor=principal)
    return DeviceGroupRead.model_validate(moved)


# ───────────────────────────── sites and tags ───────────────────────────────


@router.get(
    "/sites",
    response_model=list[SiteRead],
    dependencies=[Depends(require(Permission.DEVICE_READ))],
    summary="List sites",
)
async def list_sites(inventory: InventoryDep) -> list[SiteRead]:
    return [SiteRead.model_validate(s) for s in await inventory.list_sites()]


@router.post(
    "/sites",
    response_model=SiteRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Create a site",
)
async def create_site(
    payload: SiteCreate, inventory: InventoryDep, principal: PrincipalDep
) -> SiteRead:
    site = await inventory.create_site(
        name=payload.name,
        actor=principal,
        description=payload.description,
        # Passed through explicitly because it was not: `SiteCreate` accepted a location,
        # `SiteRead` returned one, the column existed, and nothing in between carried it —
        # so a location submitted was silently discarded and always read back as null.
        location=payload.location,
    )
    return SiteRead.model_validate(site)


@router.get(
    "/tags",
    response_model=list[TagRead],
    dependencies=[Depends(require(Permission.DEVICE_READ))],
    summary="List tags",
)
async def list_tags(inventory: InventoryDep) -> list[TagRead]:
    return [TagRead.model_validate(t) for t in await inventory.list_tags()]
