"""Disaster-recovery sets (FR-INV-04 adjacent).

A DR set is a statement about the estate's shape — "these two devices are one" — so it
is governed by the same permission as the devices themselves: `DEVICE_READ` to see the
sets and the suggestions, `DEVICE_WRITE` to declare or remove one. The topology change
that acts on a set is read-only against the devices; nothing here or downstream writes
to a device, so §8 is untouched.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status

from netsecops.api.deps import PrincipalDep, SessionDep, require, verify_csrf
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.db.models.audit import AuditAction
from netsecops.schemas.dr import DrSetCreate, DrSetRead, DrSuggestionRead
from netsecops.services.audit import AuditService
from netsecops.services.dr import DrService

log = get_logger(__name__)
router = APIRouter(tags=["dr-sets"])


@router.get(
    "/dr-sets",
    response_model=list[DrSetRead],
    dependencies=[Depends(require(Permission.DEVICE_READ))],
    summary="The disaster-recovery sets declared for this estate",
)
async def list_dr_sets(session: SessionDep) -> list[DrSetRead]:
    return await DrService(session).list_sets()


@router.get(
    "/dr-sets/suggestions",
    response_model=list[DrSuggestionRead],
    dependencies=[Depends(require(Permission.DEVICE_READ))],
    summary="DR sets the estate's own HA facts imply, for a human to confirm",
)
async def suggest_dr_sets(session: SessionDep) -> list[DrSuggestionRead]:
    """Declared before ``/dr-sets/{dr_set_id}`` so ``suggestions`` is not read as an id.

    Nothing here is created: a suggestion is a resolved HA peer string offered for
    confirmation, and the resolver says what it matched on so the match can be checked.
    """
    return await DrService(session).suggestions()


@router.post(
    "/dr-sets",
    response_model=DrSetRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Declare a DR set",
)
async def create_dr_set(
    payload: DrSetCreate,
    session: SessionDep,
    principal: PrincipalDep,
) -> DrSetRead:
    dr_set = await DrService(session).create_set(
        name=payload.name, description=payload.description, members=payload.members
    )
    await AuditService(session).record(
        AuditAction.DR_SET_CREATED,
        actor_id=principal.id,
        actor_username=principal.username,
        object_type="dr_set",
        object_id=dr_set.id,
        details={
            "name": dr_set.name,
            "members": [
                {"device_id": str(m.device_id), "role": m.role} for m in dr_set.members
            ],
        },
    )
    return dr_set


@router.delete(
    "/dr-sets/{dr_set_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Remove a DR set (the devices are untouched)",
)
async def delete_dr_set(
    dr_set_id: uuid.UUID,
    session: SessionDep,
    principal: PrincipalDep,
) -> None:
    # Read before the delete: the audit entry names what went, and the row it pointed
    # at is gone afterwards.
    dr_set = await DrService(session).delete_set(dr_set_id)
    await AuditService(session).record(
        AuditAction.DR_SET_DELETED,
        actor_id=principal.id,
        actor_username=principal.username,
        object_type="dr_set",
        object_id=dr_set_id,
        details={"deleted": True, "name": dr_set.name},
    )


__all__ = ["router"]
