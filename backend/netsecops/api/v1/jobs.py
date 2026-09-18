"""Job and schedule endpoints (FR-JOB-01 … FR-JOB-06, FR-COL-12)."""

from __future__ import annotations

import asyncio
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, status

from netsecops.api.deps import PrincipalDep, SessionDep, require, verify_csrf
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.db.models.jobs import JobStatus, JobType
from netsecops.schemas.jobs import (
    JobCreate,
    JobDetail,
    JobDeviceRead,
    JobProgress,
    JobRead,
    PaginatedJobs,
    ScheduleCreate,
    ScheduleRead,
    ScheduleUpdate,
)
from netsecops.services.jobs import JobScope, JobService
from netsecops.services.schedules import ScheduleService

log = get_logger(__name__)
router = APIRouter(tags=["jobs"])

#: How often the WebSocket re-reads progress. Fast enough to feel live, slow enough
#: that a hundred watchers do not become a hundred queries per second.
PROGRESS_INTERVAL_SECONDS = 2.0


def job_service(session: SessionDep) -> JobService:
    return JobService(session)


JobDep = Annotated[JobService, Depends(job_service)]


@router.get(
    "/jobs",
    response_model=PaginatedJobs,
    dependencies=[Depends(require(Permission.JOB_READ))],
    summary="List assessment runs",
)
async def list_jobs(
    jobs: JobDep,
    job_type: JobType | None = None,
    status_filter: Annotated[JobStatus | None, Query(alias="status")] = None,
    device_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedJobs:
    rows, total = await jobs.list(
        job_type=job_type,
        status=status_filter,
        device_id=device_id,
        limit=limit,
        offset=offset,
    )
    return PaginatedJobs(
        data=[JobRead.model_validate(j) for j in rows],
        meta={"total": total, "limit": limit, "offset": offset},
    )


@router.post(
    "/jobs",
    response_model=JobRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.JOB_EXECUTE)), Depends(verify_csrf)],
    summary="Start an assessment",
)
async def create_job(payload: JobCreate, jobs: JobDep, principal: PrincipalDep) -> JobRead:
    """Create a job and hand it to the queue.

    The scope is resolved against the caller's own visibility, so a group-scoped user
    cannot widen their reach by naming a group they cannot see.
    """
    from netsecops.workers.queue import get_queue

    job = await jobs.create(
        job_type=payload.job_type,
        scope=JobScope(
            device_ids=tuple(payload.scope.device_ids),
            group_ids=tuple(payload.scope.group_ids),
            tags=tuple(payload.scope.tags),
            include_archived=payload.scope.include_archived,
        ),
        actor=principal,
        principal_scope=principal.scope,
        idempotency_key=payload.idempotency_key,
    )

    # Committed before the worker can see it: enqueueing a job id the worker could
    # read before the row is visible is the classic queue race.
    await jobs.session.commit()
    await get_queue().enqueue_job(job.id, correlation_id=job.correlation_id)

    return JobRead.model_validate(job)


@router.get(
    "/jobs/{job_id}",
    response_model=JobDetail,
    dependencies=[Depends(require(Permission.JOB_READ))],
    summary="Job detail with per-device outcomes",
)
async def get_job(job_id: uuid.UUID, jobs: JobDep) -> JobDetail:
    job = await jobs.get(job_id)
    devices = await jobs.device_results(job)

    return JobDetail(
        **JobRead.model_validate(job).model_dump(),
        devices=[JobDeviceRead.model_validate(d) for d in devices],
    )


@router.post(
    "/jobs/{job_id}/cancel",
    response_model=JobRead,
    dependencies=[Depends(require(Permission.JOB_EXECUTE)), Depends(verify_csrf)],
    summary="Cancel gracefully: in-flight devices finish, no new sessions open",
)
async def cancel_job(job_id: uuid.UUID, jobs: JobDep, principal: PrincipalDep) -> JobRead:
    job = await jobs.get(job_id)
    return JobRead.model_validate(await jobs.cancel(job, actor=principal))


@router.post(
    "/jobs/{job_id}/rerun-failed",
    response_model=JobRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.JOB_EXECUTE)), Depends(verify_csrf)],
    summary="Re-run only the devices that failed",
)
async def rerun_failed(job_id: uuid.UUID, jobs: JobDep, principal: PrincipalDep) -> JobRead:
    from netsecops.workers.queue import get_queue

    job = await jobs.get(job_id)
    new_job = await jobs.rerun_failed(job, actor=principal)

    await jobs.session.commit()
    await get_queue().enqueue_job(new_job.id, correlation_id=new_job.correlation_id)

    return JobRead.model_validate(new_job)


@router.get(
    "/jobs/{job_id}/progress",
    response_model=JobProgress,
    dependencies=[Depends(require(Permission.JOB_READ))],
    summary="Progress snapshot (poll this where a WebSocket is impractical)",
)
async def job_progress(job_id: uuid.UUID, jobs: JobDep) -> JobProgress:
    job = await jobs.get(job_id)
    return JobProgress(**await jobs.progress(job))


# ── schedules (FR-JOB-02) ────────────────────────────────────────────────────
#
# Under `/schedules` rather than `/jobs/schedules`: a schedule is not a job, it is the
# thing that makes jobs. Nesting it would put a resource with its own lifecycle inside
# one that is created and completed, and `/jobs/{job_id}` would shadow the literal.


def schedule_service(session: SessionDep) -> ScheduleService:
    return ScheduleService(session)


ScheduleDep = Annotated[ScheduleService, Depends(schedule_service)]


@router.get(
    "/schedules",
    response_model=list[ScheduleRead],
    dependencies=[Depends(require(Permission.JOB_READ))],
    summary="Recurring assessments (FR-JOB-02)",
)
async def list_schedules(schedules: ScheduleDep) -> list[ScheduleRead]:
    return [ScheduleRead.model_validate(row) for row in await schedules.list_all()]


@router.post(
    "/schedules",
    response_model=ScheduleRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.JOB_EXECUTE)), Depends(verify_csrf)],
    summary="Create a recurring assessment (FR-JOB-02)",
)
async def create_schedule(
    payload: ScheduleCreate, schedules: ScheduleDep, principal: PrincipalDep
) -> ScheduleRead:
    """Define work that will run unattended, repeatedly.

    Behind `job:execute` rather than a lesser permission: a schedule is a standing
    instruction to touch the estate, and whoever may not run a job once should not be
    able to arrange for one to run every night.

    The response carries `next_run_at`, computed before the row is stored. It is the only
    way to notice that a cron expression means something other than what was intended,
    and it is the first thing anybody checks.
    """
    schedule = await schedules.create(
        name=payload.name,
        job_type=payload.job_type,
        scope=payload.scope.model_dump(mode="json"),
        cron=payload.cron,
        actor=principal,
        timezone=payload.timezone,
        description=payload.description,
        enabled=payload.enabled,
        blackout=payload.blackout,
    )
    return ScheduleRead.model_validate(schedule)


@router.patch(
    "/schedules/{schedule_id}",
    response_model=ScheduleRead,
    dependencies=[Depends(require(Permission.JOB_EXECUTE)), Depends(verify_csrf)],
    summary="Change a recurring assessment",
)
async def update_schedule(
    schedule_id: uuid.UUID,
    payload: ScheduleUpdate,
    schedules: ScheduleDep,
    principal: PrincipalDep,
) -> ScheduleRead:
    schedule = await schedules.get(schedule_id)
    updated = await schedules.update(
        schedule, actor=principal, **payload.model_dump(exclude_unset=True)
    )
    return ScheduleRead.model_validate(updated)


@router.delete(
    "/schedules/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.JOB_EXECUTE)), Depends(verify_csrf)],
    summary="Remove a recurring assessment",
)
async def delete_schedule(
    schedule_id: uuid.UUID, schedules: ScheduleDep, principal: PrincipalDep
) -> None:
    await schedules.delete(await schedules.get(schedule_id), actor=principal)


@router.websocket("/ws/jobs/{job_id}")
async def job_progress_socket(websocket: WebSocket, job_id: uuid.UUID, session: SessionDep) -> None:
    """Stream job progress (FR-COL-12).

    The payload carries counts and status only — never device output or command text.
    A live console that echoed device output would stream secrets to the browser, which
    C-2 forbids; the audit log is where the command record belongs.

    Authentication rides on the same cookie as the REST API, because a WebSocket from
    the SPA is a same-origin request.
    """
    from netsecops.api.deps import ACCESS_COOKIE
    from netsecops.core.errors import AuthenticationError
    from netsecops.core.rbac import Permission as P
    from netsecops.core.security import TokenType, decode_token
    from netsecops.services.users import UserService

    token = websocket.cookies.get(ACCESS_COOKIE)
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Not authenticated")
        return

    try:
        claims = decode_token(token, expected_type=TokenType.ACCESS)
        user = await UserService(session).get(uuid.UUID(claims["sub"]))
        from netsecops.services.auth import AuthService

        principal = await AuthService(session).principal_for_user(user)
    except (AuthenticationError, ValueError, KeyError):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Not authenticated")
        return

    if not principal.has(P.JOB_READ):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Permission denied")
        return

    await websocket.accept()
    jobs = JobService(session)

    try:
        while True:
            # Expire the identity map so each tick reads committed worker progress
            # rather than this connection's first snapshot.
            session.expire_all()
            job = await jobs.get(job_id)
            payload = await jobs.progress(job)
            await websocket.send_json(payload)

            if JobStatus(job.status).is_terminal:
                break
            await asyncio.sleep(PROGRESS_INTERVAL_SECONDS)

    except WebSocketDisconnect:
        log.info("ws.job_progress_disconnected", job_id=str(job_id))
    finally:
        with_suppress = getattr(websocket, "client_state", None)
        if with_suppress is not None:
            try:
                await websocket.close()
            except RuntimeError:  # pragma: no cover - already closed by the client
                pass
