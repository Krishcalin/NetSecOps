"""Audit log endpoints (FR-AUD-01, FR-AUD-02)."""

from __future__ import annotations

import csv
import io
import uuid
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import Select, func, select

from netsecops.api.deps import AuditServiceDep, PrincipalDep, SessionDep, require
from netsecops.core.rbac import Permission
from netsecops.db.models.audit import AuditLog
from netsecops.schemas.audit import (
    AuditLogRead,
    ChainVerificationResponse,
    PaginatedAuditLog,
)

router = APIRouter(prefix="/audit-log", tags=["audit"])

#: Rows buffered before a chunk is flushed to the client. Large enough that the per-chunk
#: overhead is irrelevant, small enough that the memory held is a few tens of kilobytes
#: rather than the whole export.
_EXPORT_CHUNK = 500

_EXPORT_COLUMNS = [
    "id",
    "ts",
    "actor_username",
    "action",
    "outcome",
    "object_type",
    "object_id",
    "ip_address",
    "correlation_id",
    "hash",
]


def _filtered(
    action: str | None,
    actor_id: uuid.UUID | None,
    object_type: str | None,
    outcome: str | None,
    since: datetime | None,
    until: datetime | None,
) -> Select[tuple[AuditLog]]:
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor_id:
        stmt = stmt.where(AuditLog.actor_id == actor_id)
    if object_type:
        stmt = stmt.where(AuditLog.object_type == object_type)
    if outcome:
        stmt = stmt.where(AuditLog.outcome == outcome)
    if since:
        stmt = stmt.where(AuditLog.ts >= since)
    if until:
        stmt = stmt.where(AuditLog.ts <= until)
    return stmt


@router.get(
    "",
    response_model=PaginatedAuditLog,
    dependencies=[Depends(require(Permission.AUDIT_READ))],
    summary="Query the audit log",
)
async def list_audit_log(
    session: SessionDep,
    action: str | None = None,
    actor_id: uuid.UUID | None = None,
    object_type: str | None = None,
    outcome: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedAuditLog:
    stmt = _filtered(action, actor_id, object_type, outcome, since, until)

    total = int(
        (await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    )
    rows = (
        (await session.execute(stmt.order_by(AuditLog.id.desc()).limit(limit).offset(offset)))
        .scalars()
        .all()
    )

    return PaginatedAuditLog(
        data=[AuditLogRead.model_validate(r) for r in rows],
        meta={"total": total, "limit": limit, "offset": offset},
    )


@router.get(
    "/verify",
    response_model=ChainVerificationResponse,
    dependencies=[Depends(require(Permission.AUDIT_READ))],
    summary="Replay the hash chain to prove the log has not been altered (FR-AUD-02)",
)
async def verify_chain(audit: AuditServiceDep) -> ChainVerificationResponse:
    result = await audit.verify_chain()
    return ChainVerificationResponse(
        total=result.total,
        valid=result.valid,
        first_invalid_id=result.first_invalid_id,
        reason=result.reason,
    )


@router.get(
    "/export",
    dependencies=[Depends(require(Permission.AUDIT_READ))],
    summary="Export the audit log as CSV (FR-AUD-02)",
    response_class=StreamingResponse,
)
async def export_audit_log(
    session: SessionDep,
    principal: PrincipalDep,
    audit: AuditServiceDep,
    action: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=100_000)] = 10_000,
) -> StreamingResponse:
    # Columns, not entities. The export writes ten fields; hydrating whole `AuditLog`
    # objects to read ten attributes off each costs the identity map and the full row
    # — `details` included, which is the large one — for a hundred thousand rows.
    columns = [getattr(AuditLog, name) for name in _EXPORT_COLUMNS]
    statement = (
        _filtered(action, None, None, None, since, until)
        .with_only_columns(*columns)
        .order_by(AuditLog.id.asc())
        .limit(limit)
    )

    async def rows() -> AsyncIterator[str]:
        """Yield the CSV a chunk at a time.

        This route has always been declared a `StreamingResponse` and did not stream: it
        loaded every row with `.all()`, wrote the whole file into a `StringIO`, and
        handed back `iter([buffer.getvalue()])` — a one-element iterator holding the
        entire export. At the 100,000-row ceiling that is the result set and the
        finished CSV both resident at once, on a deployment whose smallest supported
        tier has 4 GB, and an operator pressing Export twice doubles it.

        Rows are streamed from the database and flushed every `_EXPORT_CHUNK`, so the
        memory held is one chunk rather than the whole export.
        """
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(_EXPORT_COLUMNS)

        pending = 0
        async for row in await session.stream(statement):
            writer.writerow(list(row))
            pending += 1
            if pending >= _EXPORT_CHUNK:
                yield buffer.getvalue()
                buffer.seek(0)
                buffer.truncate(0)
                pending = 0

        if remainder := buffer.getvalue():
            yield remainder

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return StreamingResponse(
        rows(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="netsecops_audit_{stamp}.csv"'},
    )
