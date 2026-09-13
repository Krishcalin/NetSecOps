"""Job orchestration (FR-JOB-01 … FR-JOB-06).

Scope resolution deserves a note. A job records *how* the target set was expressed
(device ids, groups, tags) alongside the devices it resolved to. Keeping both means a
re-run can either repeat exactly what ran, or re-resolve the scope to pick up devices
added since — and the caller chooses, rather than the system guessing.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ConflictError, NotFoundError, ValidationProblem
from netsecops.core.logging import correlation_id, get_logger
from netsecops.core.rbac import Principal, Scope
from netsecops.db.models.audit import AuditAction, AuditOutcome
from netsecops.db.models.inventory import Device, DeviceGroup, DeviceGroupMember, DeviceTag, Tag
from netsecops.db.models.jobs import (
    DeviceJobStatus,
    ErrorClass,
    Job,
    JobDevice,
    JobStatus,
    JobType,
)
from netsecops.services.audit import AuditService

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class JobScope:
    """How a caller expressed the target set (FR-JOB-01)."""

    device_ids: tuple[uuid.UUID, ...] = ()
    group_ids: tuple[uuid.UUID, ...] = ()
    tags: tuple[str, ...] = ()
    #: Only devices whose status is active are ever targeted; archived ones are excluded
    #: even when named explicitly, so an archived device cannot be collected by accident.
    include_archived: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "device_ids": [str(d) for d in self.device_ids],
            "group_ids": [str(g) for g in self.group_ids],
            "tags": list(self.tags),
            "include_archived": self.include_archived,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> JobScope:
        return cls(
            device_ids=tuple(uuid.UUID(d) for d in data.get("device_ids", [])),
            group_ids=tuple(uuid.UUID(g) for g in data.get("group_ids", [])),
            tags=tuple(data.get("tags", [])),
            include_archived=bool(data.get("include_archived", False)),
        )

    @property
    def is_empty(self) -> bool:
        return not (self.device_ids or self.group_ids or self.tags)


class JobService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.audit = AuditService(session)

    # ─────────────────────────────── create ─────────────────────────────

    async def create(
        self,
        *,
        job_type: JobType,
        scope: JobScope,
        actor: Principal,
        principal_scope: Scope | None = None,
        schedule_id: uuid.UUID | None = None,
        idempotency_key: str | None = None,
        org_id: int = 1,
    ) -> Job:
        """Create a job and resolve its scope to concrete devices.

        Resolution happens now, not at execution time, so the job records what it was
        asked to do even if the inventory changes before a worker picks it up.
        """
        if scope.is_empty:
            raise ValidationProblem("A job must target at least one device, group or tag.")

        if idempotency_key:
            existing = (
                await self.session.execute(
                    select(Job).where(Job.idempotency_key == idempotency_key)
                )
            ).scalar_one_or_none()
            if existing is not None:
                # A retried POST returns the original job rather than starting a second
                # run against the same devices.
                return existing

        devices = await self.resolve_scope(scope, principal_scope or Scope.all(), org_id=org_id)
        if not devices:
            raise ValidationProblem(
                "The scope matched no devices you have access to.", scope=scope.to_json()
            )

        job = Job(
            org_id=org_id,
            job_type=job_type.value,
            status=JobStatus.QUEUED.value,
            scope=scope.to_json(),
            requested_by_id=actor.id,
            schedule_id=schedule_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id.get(),
            stats={"total": len(devices), "pending": len(devices), "succeeded": 0, "failed": 0},
        )
        self.session.add(job)
        await self.session.flush()

        for device in devices:
            self.session.add(
                JobDevice(
                    org_id=org_id,
                    job_id=job.id,
                    device_id=device.id,
                    status=DeviceJobStatus.PENDING.value,
                )
            )
        await self.session.flush()

        await self.audit.record(
            AuditAction.JOB_STARTED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="job",
            object_id=job.id,
            details={
                "job_type": job_type.value,
                "device_count": len(devices),
                "scope": scope.to_json(),
            },
            org_id=org_id,
        )
        return job

    async def resolve_scope(
        self, scope: JobScope, principal_scope: Scope, *, org_id: int = 1
    ) -> Sequence[Device]:
        """Turn a scope into devices, intersected with what the caller may see."""
        from netsecops.services.inventory import InventoryService

        conditions = []

        if scope.device_ids:
            conditions.append(Device.id.in_(list(scope.device_ids)))

        if scope.group_ids:
            group_paths = (
                (
                    await self.session.execute(
                        select(DeviceGroup.path).where(DeviceGroup.id.in_(list(scope.group_ids)))
                    )
                )
                .scalars()
                .all()
            )
            if group_paths:
                # Subtree semantics: targeting a site targets everything beneath it.
                subtree = select(DeviceGroup.id).where(
                    or_(*[DeviceGroup.path.op("<@")(p) for p in group_paths])
                )
                conditions.append(
                    Device.id.in_(
                        select(DeviceGroupMember.device_id).where(
                            DeviceGroupMember.group_id.in_(subtree)
                        )
                    )
                )

        if scope.tags:
            conditions.append(
                Device.id.in_(
                    select(DeviceTag.device_id)
                    .join(Tag, Tag.id == DeviceTag.tag_id)
                    .where(Tag.name.in_(list(scope.tags)))
                )
            )

        if not conditions:
            return []

        stmt: Select[tuple[Device]] = select(Device).where(
            Device.org_id == org_id, or_(*conditions)
        )
        if not scope.include_archived:
            stmt = stmt.where(Device.status != "archived")

        inventory = InventoryService(self.session)
        stmt = await inventory._apply_scope(stmt, principal_scope)

        return (await self.session.execute(stmt.order_by(Device.mgmt_ip))).scalars().all()

    # ──────────────────────────────── read ──────────────────────────────

    async def get(self, job_id: uuid.UUID) -> Job:
        job = (await self.session.execute(select(Job).where(Job.id == job_id))).scalar_one_or_none()
        if job is None:
            raise NotFoundError("Job not found.")
        return job

    async def list(
        self,
        *,
        job_type: JobType | None = None,
        status: JobStatus | None = None,
        device_id: uuid.UUID | None = None,
        limit: int = 50,
        offset: int = 0,
        org_id: int = 1,
    ) -> tuple[Sequence[Job], int]:
        stmt = select(Job).where(Job.org_id == org_id)

        if job_type is not None:
            stmt = stmt.where(Job.job_type == job_type.value)
        if status is not None:
            stmt = stmt.where(Job.status == status.value)
        if device_id is not None:
            stmt = stmt.where(
                Job.id.in_(select(JobDevice.job_id).where(JobDevice.device_id == device_id))
            )

        total = int(
            (
                await self.session.execute(select(func.count()).select_from(stmt.subquery()))
            ).scalar_one()
        )
        rows = (
            (
                await self.session.execute(
                    stmt.order_by(Job.created_at.desc()).limit(limit).offset(offset)
                )
            )
            .scalars()
            .all()
        )
        return rows, total

    async def device_results(self, job: Job) -> Sequence[JobDevice]:
        return (
            (
                await self.session.execute(
                    select(JobDevice)
                    .where(JobDevice.job_id == job.id)
                    .order_by(JobDevice.created_at)
                )
            )
            .scalars()
            .all()
        )

    # ───────────────────────────── execution ────────────────────────────

    async def claim_next_device(self, job: Job) -> JobDevice | None:
        """Take the next pending device for this job, or None when there are none left.

        ``FOR UPDATE SKIP LOCKED`` is what lets several workers share a job without
        two of them collecting the same device (FR-COL-06). It also means a worker
        that dies mid-device releases its claim when its transaction dies with it.
        """
        result = await self.session.execute(
            select(JobDevice)
            .where(
                JobDevice.job_id == job.id,
                JobDevice.status == DeviceJobStatus.PENDING.value,
            )
            .order_by(JobDevice.created_at)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        job_device = result.scalar_one_or_none()
        if job_device is None:
            return None

        job_device.status = DeviceJobStatus.RUNNING.value
        job_device.started_at = datetime.now(UTC)
        await self.session.flush()
        return job_device

    async def start(self, job: Job) -> Job:
        if job.status != JobStatus.QUEUED.value:
            raise ConflictError(f"Job is {job.status}, not queued.")
        job.status = JobStatus.RUNNING.value
        job.started_at = datetime.now(UTC)
        await self.session.flush()
        return job

    async def finish_device(
        self,
        job_device: JobDevice,
        *,
        succeeded: bool,
        error_class: ErrorClass | None = None,
        error_message: str | None = None,
        credential_id: uuid.UUID | None = None,
        command_count: int = 0,
    ) -> JobDevice:
        job_device.status = (
            DeviceJobStatus.SUCCEEDED.value if succeeded else DeviceJobStatus.FAILED.value
        )
        job_device.finished_at = datetime.now(UTC)
        if job_device.started_at:
            delta = job_device.finished_at - job_device.started_at
            job_device.duration_ms = int(delta.total_seconds() * 1000)
        job_device.error_class = error_class.value if error_class else None
        # Truncated: an error message is for a human, and some libraries produce
        # enormous ones. The full detail is in the logs under the correlation id.
        job_device.error_message = (error_message or None) and error_message[:2000]
        job_device.credential_id = credential_id
        job_device.command_count = command_count

        await self.session.flush()
        await self._refresh_stats(job_device.job_id)
        return job_device

    async def complete(self, job: Job) -> Job:
        """Close a job, choosing its final status from its device outcomes."""
        counts = await self._counts(job.id)

        if job.cancel_requested_at is not None:
            job.status = JobStatus.CANCELLED.value
        elif counts["failed"] == 0:
            job.status = JobStatus.SUCCEEDED.value
        elif counts["succeeded"] == 0:
            job.status = JobStatus.FAILED.value
        else:
            # Partial is its own state: "some devices failed" needs different handling
            # from "everything failed", and collapsing them loses that.
            job.status = JobStatus.PARTIAL.value

        job.finished_at = datetime.now(UTC)
        job.stats = {**job.stats, **counts}
        await self.session.flush()

        await self.audit.record(
            AuditAction.JOB_COMPLETED,
            outcome=(
                AuditOutcome.SUCCESS
                if job.status == JobStatus.SUCCEEDED.value
                else AuditOutcome.FAILURE
            ),
            object_type="job",
            object_id=job.id,
            details={"status": job.status, **counts},
            org_id=job.org_id,
        )
        return job

    # ────────────────────────────── control ─────────────────────────────

    async def cancel(self, job: Job, *, actor: Principal) -> Job:
        """Request a graceful cancel (FR-JOB-03).

        Devices already in flight finish; no new sessions are opened. Killing a session
        mid-collection could leave a device with a half-read config and an open channel,
        which is exactly what SRS §8.1.6 asks us to avoid.
        """
        if JobStatus(job.status).is_terminal:
            raise ConflictError(f"Job is already {job.status}.")

        job.cancel_requested_at = datetime.now(UTC)
        job.cancel_requested_by_id = actor.id
        job.status = JobStatus.CANCELLING.value

        pending = (
            (
                await self.session.execute(
                    select(JobDevice).where(
                        JobDevice.job_id == job.id,
                        JobDevice.status == DeviceJobStatus.PENDING.value,
                    )
                )
            )
            .scalars()
            .all()
        )
        for job_device in pending:
            job_device.status = DeviceJobStatus.CANCELLED.value
            job_device.finished_at = datetime.now(UTC)

        await self.session.flush()
        await self.audit.record(
            AuditAction.JOB_CANCELLED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="job",
            object_id=job.id,
            details={"cancelled_pending": len(pending)},
            org_id=job.org_id,
        )
        return job

    async def rerun_failed(self, job: Job, *, actor: Principal) -> Job:
        """Create a new job targeting only the devices that failed (FR-JOB-03)."""
        failed = (
            (
                await self.session.execute(
                    select(JobDevice.device_id).where(
                        JobDevice.job_id == job.id,
                        JobDevice.status == DeviceJobStatus.FAILED.value,
                    )
                )
            )
            .scalars()
            .all()
        )
        if not failed:
            raise ConflictError("This job has no failed devices to re-run.")

        return await self.create(
            job_type=JobType(job.job_type),
            scope=JobScope(device_ids=tuple(failed)),
            actor=actor,
            org_id=job.org_id,
        )

    # ────────────────────────────── helpers ─────────────────────────────

    async def _counts(self, job_id: uuid.UUID) -> dict[str, int]:
        rows = (
            await self.session.execute(
                select(JobDevice.status, func.count())
                .where(JobDevice.job_id == job_id)
                .group_by(JobDevice.status)
            )
        ).all()
        by_status = {str(status): int(count) for status, count in rows}

        return {
            "total": sum(by_status.values()),
            "pending": by_status.get(DeviceJobStatus.PENDING.value, 0),
            "running": by_status.get(DeviceJobStatus.RUNNING.value, 0),
            "succeeded": by_status.get(DeviceJobStatus.SUCCEEDED.value, 0),
            "failed": by_status.get(DeviceJobStatus.FAILED.value, 0),
            "cancelled": by_status.get(DeviceJobStatus.CANCELLED.value, 0),
        }

    async def _refresh_stats(self, job_id: uuid.UUID) -> None:
        job = await self.get(job_id)
        job.stats = {**job.stats, **await self._counts(job_id)}
        await self.session.flush()

    async def progress(self, job: Job) -> dict[str, Any]:
        """Progress snapshot, for the WebSocket stream (FR-COL-12)."""
        counts = await self._counts(job.id)
        done = counts["succeeded"] + counts["failed"] + counts["cancelled"]

        return {
            "job_id": str(job.id),
            "status": job.status,
            "percent": round(100 * done / counts["total"]) if counts["total"] else 0,
            **counts,
        }


def classify_error(exc: BaseException) -> tuple[ErrorClass, str]:
    """Map an exception to an FR-COL-07 error class.

    The classes exist so job history is triageable: "unreachable" is a network problem,
    "auth failed" is a credential problem, and "readonly violation" is our bug.
    """
    from netsecops.adapters.transport import (
        DeviceAuthError,
        DeviceUnreachableError,
        HostKeyChangedError,
    )
    from netsecops.core.errors import ReadOnlyViolationError

    match exc:
        case ReadOnlyViolationError():
            return ErrorClass.READONLY_VIOLATION, str(exc)
        case HostKeyChangedError():
            return ErrorClass.HOST_KEY_CHANGED, str(exc)
        case DeviceAuthError():
            return ErrorClass.AUTH_FAILED, str(exc)
        case DeviceUnreachableError():
            return ErrorClass.UNREACHABLE, str(exc)
        case TimeoutError():
            return ErrorClass.TIMEOUT, "The device did not respond in time."
        case _:
            return ErrorClass.INTERNAL_ERROR, str(exc)


__all__ = ["JobScope", "JobService", "classify_error"]
