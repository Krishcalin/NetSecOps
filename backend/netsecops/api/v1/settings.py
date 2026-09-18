"""Platform settings (FR-ADM-01).

The `settings` table has existed since Phase 0 with nothing reading it. This is the
surface FR-ADM-01 asks for: retention, concurrency, branding, feature flags — the knobs
that are neither environment configuration nor per-device state.

**Some keys are managed, not edited.** SIEM forwarding and notification scanning store
their watermarks here, because a watermark is exactly a small piece of durable platform
state. Letting an administrator PUT one by hand would let them silently skip a stretch of
the audit trail, or re-send a month of it — so those keys are readable and refused for
write, and the refusal says why rather than 404ing.

**What does *not* live here:** anything secret, and anything needed before the database
is reachable. Credentials belong in the vault, and `DATABASE_URL` and `MASTER_KEY` are
environment variables by necessity — a setting that has to be read in order to open the
connection cannot be stored in the connection.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from netsecops.api.deps import PrincipalDep, SessionDep, require, verify_csrf
from netsecops.core.errors import NotFoundError, ValidationProblem
from netsecops.core.rbac import Permission
from netsecops.db.models.audit import AuditAction, Setting
from netsecops.services.audit import AuditService

router = APIRouter(tags=["settings"])

#: Prefixes the API will not let anyone write.
#:
#: These are advanced automatically as work is done. A hand-edited watermark silently
#: skips or repeats a stretch of forwarding, and neither shows up as an error anywhere.
MANAGED_PREFIXES = ("integrations.siem.watermark.", "integrations.notify.watermark.")


class SettingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key: str
    value: dict[str, Any]
    description: str | None = None
    #: True when this key is maintained by the product and refused for write.
    managed: bool = False


class SettingWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: dict[str, Any]
    description: str | None = Field(default=None, max_length=1000)


def _managed(key: str) -> bool:
    return key.startswith(MANAGED_PREFIXES)


@router.get(
    "/settings",
    response_model=list[SettingRead],
    dependencies=[Depends(require(Permission.SETTINGS_READ))],
    summary="Platform settings (FR-ADM-01)",
)
async def list_settings(session: SessionDep) -> list[SettingRead]:
    rows = (await session.execute(select(Setting).order_by(Setting.key))).scalars().all()
    return [
        SettingRead(
            key=row.key, value=row.value, description=row.description, managed=_managed(row.key)
        )
        for row in rows
    ]


@router.get(
    "/settings/{key}",
    response_model=SettingRead,
    dependencies=[Depends(require(Permission.SETTINGS_READ))],
    summary="One setting",
)
async def get_setting(
    session: SessionDep, key: Annotated[str, Path(max_length=150)]
) -> SettingRead:
    row = (await session.execute(select(Setting).where(Setting.key == key))).scalar_one_or_none()
    if row is None:
        raise NotFoundError(f"No setting called {key!r}.")
    return SettingRead(
        key=row.key, value=row.value, description=row.description, managed=_managed(row.key)
    )


@router.put(
    "/settings/{key}",
    response_model=SettingRead,
    dependencies=[Depends(require(Permission.SETTINGS_WRITE)), Depends(verify_csrf)],
    summary="Set a platform setting",
)
async def put_setting(
    body: SettingWrite,
    session: SessionDep,
    principal: PrincipalDep,
    key: Annotated[str, Path(max_length=150)],
) -> SettingRead:
    """Create or replace one setting.

    Every change is audited with the key and the new value. Values here are not secret by
    contract — anything that is belongs in the vault — so recording them is safe and is
    what makes "who turned that off, and when" answerable.
    """
    if _managed(key):
        raise ValidationProblem(
            f"{key!r} is maintained by NetSecOps and cannot be set by hand. It records how "
            "far forwarding has reached; editing it would silently skip or repeat part of "
            "the stream."
        )

    row = (await session.execute(select(Setting).where(Setting.key == key))).scalar_one_or_none()
    if row is None:
        row = Setting(org_id=1, key=key, value=body.value, description=body.description)
        session.add(row)
    else:
        row.value = body.value
        if body.description is not None:
            row.description = body.description

    row.updated_by_id = principal.id
    await session.flush()

    await AuditService(session).record(
        AuditAction.SETTINGS_CHANGED,
        actor_id=principal.id,
        actor_username=principal.username,
        object_type="setting",
        details={"key": key, "value": body.value},
    )
    return SettingRead(key=row.key, value=row.value, description=row.description, managed=False)


__all__ = ["MANAGED_PREFIXES", "router"]
