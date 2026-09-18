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
from netsecops.db.models.inventory import (
    Device,
    DeviceGroup,
    DeviceGroupMember,
    DeviceStatus,
    DeviceTag,
    Tag,
)
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

    async def create_discovery(
        self,
        *,
        discovery_scope_id: uuid.UUID,
        actor: Principal,
        schedule_id: uuid.UUID | None = None,
        idempotency_key: str | None = None,
        org_id: int = 1,
    ) -> Job:
        """Queue a discovery run (FR-DISC-05).

        Deliberately not a branch inside :meth:`create`. Every other job type targets
        devices, and ``create`` is built around that: it refuses an empty scope, resolves
        it against the caller's visible estate, and writes a ``job_devices`` row per
        device. A discovery job has no devices *by definition* — it is looking for them —
        so threading it through that method would mean disabling the device checks for
        one job type, and a disabled check is one nobody notices has stopped applying.

        The absence of ``job_devices`` rows is also load-bearing. ``_run_one_device``
        refuses a discovery job outright, so a row appearing here would be the only way
        for discovery to reach the credential resolver and open an authenticated session
        against a host nobody has approved. There is no code that writes one; this
        docstring is here so that nobody adds it.
        """
        if idempotency_key:
            existing = (
                await self.session.execute(
                    select(Job).where(Job.idempotency_key == idempotency_key)
                )
            ).scalar_one_or_none()
            if existing is not None:
                return existing

        job = Job(
            org_id=org_id,
            job_type=JobType.DISCOVERY.value,
            status=JobStatus.QUEUED.value,
            scope={"discovery_scope_id": str(discovery_scope_id)},
            requested_by_id=actor.id,
            schedule_id=schedule_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id.get(),
            stats={"addresses_probed": 0, "hosts_found": 0, "hosts_unidentified": 0},
        )
        self.session.add(job)
        await self.session.flush()

        await self.audit.record(
            AuditAction.JOB_STARTED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="job",
            object_id=job.id,
            details={
                "job_type": JobType.DISCOVERY.value,
                "discovery_scope_id": str(discovery_scope_id),
            },
            org_id=org_id,
        )
        return job

    async def create_feed_sync(
        self,
        *,
        sources: Sequence[str],
        actor: Principal,
        schedule_id: uuid.UUID | None = None,
        idempotency_key: str | None = None,
        org_id: int = 1,
    ) -> Job:
        """Queue a vulnerability feed sync (FR-VUL-07).

        Device-less for the same reason discovery is, and more so: this job never opens a
        session to customer equipment at all, it talks to CISA, FIRST and NVD. Routing it
        through :meth:`create` would resolve a device scope it has no use for and write
        ``job_devices`` rows that ``_run_one_device`` would then have to refuse.

        It is a *job* rather than a background coroutine in the API so that it inherits
        what jobs already have and operators already know how to read: a queue position,
        a status, cancellation, an audit record, and a history that survives the process.
        """
        if idempotency_key:
            existing = (
                await self.session.execute(
                    select(Job).where(Job.idempotency_key == idempotency_key)
                )
            ).scalar_one_or_none()
            if existing is not None:
                return existing

        job = Job(
            org_id=org_id,
            job_type=JobType.FEED_SYNC.value,
            status=JobStatus.QUEUED.value,
            scope={"feed_sources": list(sources)},
            requested_by_id=actor.id,
            schedule_id=schedule_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id.get(),
            stats={"feeds_synced": 0, "feeds_failed": 0, "records_ingested": 0},
        )
        self.session.add(job)
        await self.session.flush()

        await self.audit.record(
            AuditAction.JOB_STARTED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="job",
            object_id=job.id,
            details={"job_type": JobType.FEED_SYNC.value, "feed_sources": list(sources)},
            org_id=org_id,
        )
        return job

    async def create_siem_forward(
        self,
        *,
        actor: Principal,
        schedule_id: uuid.UUID | None = None,
        idempotency_key: str | None = None,
        org_id: int = 1,
    ) -> Job:
        """Queue a SIEM forwarding run (FR-INT-02).

        Device-less like the feed sync, and for the same structural reason: it has no
        device scope to resolve and no `job_devices` rows to claim. It is a job rather
        than a loop inside the API because forwarding must survive a restart knowing how
        far it reached, and because a collector outage should show up somewhere an
        operator already looks.
        """
        if idempotency_key:
            existing = (
                await self.session.execute(
                    select(Job).where(Job.idempotency_key == idempotency_key)
                )
            ).scalar_one_or_none()
            if existing is not None:
                return existing

        job = Job(
            org_id=org_id,
            job_type=JobType.SIEM_FORWARD.value,
            status=JobStatus.QUEUED.value,
            scope={},
            requested_by_id=actor.id,
            schedule_id=schedule_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id.get(),
            stats={"audit_forwarded": 0, "findings_forwarded": 0},
        )
        self.session.add(job)
        await self.session.flush()
        return job

    async def create_notify(
        self,
        *,
        actor: Principal,
        schedule_id: uuid.UUID | None = None,
        idempotency_key: str | None = None,
        org_id: int = 1,
    ) -> Job:
        """Queue a notification dispatch run (FR-INT-01).

        Device-less, like the feed sync and the SIEM forwarder. Raising a notification is
        a database write inside whatever transaction produced the event; *sending* it is
        this job, so a slow SMTP server cannot slow the assessment that raised the alert.
        """
        if idempotency_key:
            existing = (
                await self.session.execute(
                    select(Job).where(Job.idempotency_key == idempotency_key)
                )
            ).scalar_one_or_none()
            if existing is not None:
                return existing

        job = Job(
            org_id=org_id,
            job_type=JobType.NOTIFY.value,
            status=JobStatus.QUEUED.value,
            scope={},
            requested_by_id=actor.id,
            schedule_id=schedule_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id.get(),
            stats={"sent": 0, "failed": 0, "dead": 0},
        )
        self.session.add(job)
        await self.session.flush()
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
            stmt = stmt.where(Device.status != DeviceStatus.ARCHIVED.value)

        # A device discovered from a manager (FR-INV-04) or by a scan is never collected
        # from until a human approves it. This exclusion is the whole approval gate:
        # without it, `pending_review` would be a label with no behaviour behind it, and
        # importing four hundred firewalls from a Panorama would put every one of them
        # into the next scheduled job — connecting to devices nobody chose to assess.
        # There is deliberately no flag to include them: "assess this device" is
        # expressed by approving it, not by widening a job.
        stmt = stmt.where(Device.status != DeviceStatus.PENDING_REVIEW.value)

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

    async def complete(self, job: Job, *, status_override: JobStatus | None = None) -> Job:
        """Close a job, choosing its final status from its device outcomes.

        ``status_override`` exists for the one job type that has no device outcomes to
        choose from. A discovery job's result is "how many addresses were probed and what
        answered", and the device-count rule below would read its empty ``job_devices``
        table as "nothing failed" and call a run that aborted a success. The override is
        narrow on purpose: the caller must know its own outcome, and every job type that
        does have devices still gets it decided here.
        """
        counts = await self._counts(job.id)

        if status_override is not None and job.cancel_requested_at is None:
            job.status = status_override.value
        elif job.cancel_requested_at is not None:
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

        # FR-INT-01's job trigger, raised in the one place every job type passes through.
        #
        # Notification jobs are excluded, and that exclusion is load-bearing rather than
        # tidiness: a notify job raising its own completion would queue an event that the
        # *next* notify job delivers before completing and raising another — a generator
        # that produces one notification per run, for ever, and looks like a working
        # integration while doing it. The SIEM forwarder is excluded for the same reason.
        if job.job_type not in {JobType.NOTIFY.value, JobType.SIEM_FORWARD.value}:
            from netsecops.integrations.triggers import job_event
            from netsecops.services.notifications import NotificationService

            await NotificationService(self.session, org_id=job.org_id).raise_event(job_event(job))

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
