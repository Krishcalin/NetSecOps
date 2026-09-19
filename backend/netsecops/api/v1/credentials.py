"""Credential vault endpoints (FR-CRED-01 … FR-CRED-07).

No endpoint here returns secret material. ``POST`` accepts it, ``GET`` never emits it,
and the test endpoint reports only whether a login worked.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from netsecops.api.deps import PrincipalDep, SessionDep, VaultDep, require, verify_csrf
from netsecops.core.rbac import Permission
from netsecops.db.models.inventory import CredentialType
from netsecops.schemas.inventory import (
    CredentialAssignmentCreate,
    CredentialAssignmentRead,
    CredentialCreate,
    CredentialRead,
    CredentialTestRequest,
    CredentialTestResponse,
    CredentialUpdate,
    PaginatedCredentials,
)
from netsecops.services.credentials import CredentialService

router = APIRouter(prefix="/credentials", tags=["credentials"])


def credential_service(session: SessionDep, vault: VaultDep) -> CredentialService:
    return CredentialService(session, vault=vault)


CredentialDep = Annotated[CredentialService, Depends(credential_service)]


@router.get(
    "",
    response_model=PaginatedCredentials,
    dependencies=[Depends(require(Permission.CREDENTIAL_READ))],
    summary="List credentials — names and metadata only, never secrets",
)
async def list_credentials(
    credentials: CredentialDep,
    search: str | None = None,
    credential_type: CredentialType | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedCredentials:
    rows, total = await credentials.list(
        search=search, credential_type=credential_type, limit=limit, offset=offset
    )
    return PaginatedCredentials(
        data=[CredentialRead.model_validate(c, from_attributes=True) for c in rows],
        meta={"total": total, "limit": limit, "offset": offset},
    )


@router.post(
    "",
    response_model=CredentialRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.CREDENTIAL_WRITE)), Depends(verify_csrf)],
    summary="Store a credential — the secret is sealed and never returned",
)
async def create_credential(
    payload: CredentialCreate, credentials: CredentialDep, principal: PrincipalDep
) -> CredentialRead:
    credential = await credentials.create(
        name=payload.name,
        credential_type=payload.credential_type,
        secret_data=dict(payload.secret_data),
        description=payload.description,
        actor=principal,
    )
    return CredentialRead.model_validate(credential, from_attributes=True)


@router.get(
    "/{credential_id}",
    response_model=CredentialRead,
    dependencies=[Depends(require(Permission.CREDENTIAL_READ))],
    summary="Fetch one credential's metadata",
)
async def get_credential(credential_id: uuid.UUID, credentials: CredentialDep) -> CredentialRead:
    credential = await credentials.get(credential_id)
    return CredentialRead.model_validate(credential, from_attributes=True)


@router.patch(
    "/{credential_id}",
    response_model=CredentialRead,
    dependencies=[Depends(require(Permission.CREDENTIAL_WRITE)), Depends(verify_csrf)],
    summary="Rename a credential or rotate its secret",
)
async def update_credential(
    credential_id: uuid.UUID,
    payload: CredentialUpdate,
    credentials: CredentialDep,
    principal: PrincipalDep,
) -> CredentialRead:
    credential = await credentials.get(credential_id)
    updated = await credentials.update(
        credential,
        actor=principal,
        name=payload.name,
        description=payload.description,
        secret_data=dict(payload.secret_data) if payload.secret_data else None,
    )
    return CredentialRead.model_validate(updated, from_attributes=True)


@router.delete(
    "/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.CREDENTIAL_WRITE)), Depends(verify_csrf)],
    summary="Delete a credential",
)
async def delete_credential(
    credential_id: uuid.UUID, credentials: CredentialDep, principal: PrincipalDep
) -> None:
    await credentials.delete(await credentials.get(credential_id), actor=principal)


# ──────────────────────────── assignments ───────────────────────────────────


@router.post(
    "/{credential_id}/assignments",
    response_model=CredentialAssignmentRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.CREDENTIAL_WRITE)), Depends(verify_csrf)],
    summary="Assign a credential to a device or group (FR-CRED-04)",
)
async def assign_credential(
    credential_id: uuid.UUID,
    payload: CredentialAssignmentCreate,
    credentials: CredentialDep,
    principal: PrincipalDep,
) -> CredentialAssignmentRead:
    credential = await credentials.get(credential_id)
    assignment = await credentials.assign(
        credential,
        device_id=payload.device_id,
        group_id=payload.group_id,
        priority=payload.priority,
        actor=principal,
    )
    return CredentialAssignmentRead.model_validate(assignment)


@router.get(
    "/{credential_id}/assignments",
    response_model=list[CredentialAssignmentRead],
    dependencies=[Depends(require(Permission.CREDENTIAL_READ))],
    summary="Where this credential is bound (FR-CRED-04)",
)
async def list_assignments(
    credential_id: uuid.UUID, credentials: CredentialDep
) -> list[CredentialAssignmentRead]:
    """Read the bindings, so they can be audited and revoked.

    Without this the DELETE below is unreachable outside the response to the POST that
    created the assignment: nothing else emits an assignment id, so a binding made last
    month could not be removed at all. For a credential vault that is the wrong way for
    an omission to fail — granting access is recoverable, being unable to withdraw it is
    not.
    """
    credential = await credentials.get(credential_id)
    rows = await credentials.assignments(credential)
    return [CredentialAssignmentRead.model_validate(row) for row in rows]


@router.delete(
    "/assignments/{assignment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.CREDENTIAL_WRITE)), Depends(verify_csrf)],
    summary="Remove a credential assignment",
)
async def unassign_credential(
    assignment_id: uuid.UUID, credentials: CredentialDep, principal: PrincipalDep
) -> None:
    await credentials.unassign(assignment_id, actor=principal)


# ────────────────────────────── testing ─────────────────────────────────────


@router.post(
    "/{credential_id}/test",
    response_model=CredentialTestResponse,
    dependencies=[Depends(require(Permission.CREDENTIAL_WRITE)), Depends(verify_csrf)],
    summary="Test a credential against a device: login plus one read (FR-CRED-05)",
)
async def test_credential(
    credential_id: uuid.UUID,
    payload: CredentialTestRequest,
    credentials: CredentialDep,
    principal: PrincipalDep,
    session: SessionDep,
    vault: VaultDep,
) -> CredentialTestResponse:
    """Prove a credential works without running a collection.

    Exactly one command is issued — the platform's cheapest allow-listed read — and it
    is named in the response, so an operator can see precisely what was run.
    """
    from netsecops.services.inventory import InventoryService
    from netsecops.workers.probe import probe_credential

    credential = await credentials.get(credential_id)
    device = await InventoryService(session).get_device(payload.device_id, scope=principal.scope)

    result = await probe_credential(
        session, device=device, credential=credential, actor=principal, vault=vault
    )

    await credentials.record_test(
        credential,
        device=device,
        succeeded=result.succeeded,
        actor=principal,
        detail=result.detail,
    )
    return CredentialTestResponse(
        succeeded=result.succeeded,
        device_id=device.id,
        detail=result.detail,
        command=result.command,
        host_key_fingerprint=result.host_key_fingerprint,
    )
