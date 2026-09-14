"""Job execution (FR-JOB-03/05, FR-COL-06/07, FR-CRED-05).

This is where a job row becomes real work against devices. It is deliberately free of
any queue library, so it can be called directly by a test, inline in development, or
from a Procrastinate task in production — and behave identically in all three.

Device-level failure never fails the job. A collection across 500 devices will always
have some unreachable, and FR-COL-07 wants each classified and recorded so the run
still produces useful results for the rest.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.adapters.policies import get_policy
from netsecops.adapters.profiles import get_profile, has_profile
from netsecops.adapters.readonly import ReadOnlyGuard
from netsecops.adapters.recorder import AuditingRecorder
from netsecops.adapters.session import DeviceSession
from netsecops.adapters.transport import (
    DeviceAuthError,
    SSHCredentials,
    SSHTransport,
)
from netsecops.core.config import get_settings
from netsecops.core.crypto import SecretVault
from netsecops.core.errors import ReadOnlyViolationError, ValidationProblem
from netsecops.core.logging import correlation_id, get_logger
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.collection import Collection
from netsecops.db.models.inventory import Credential, CredentialType, Device
from netsecops.db.models.jobs import ErrorClass, Job, JobDevice, JobStatus, JobType
from netsecops.db.session import session_scope
from netsecops.ncm.models import NCM_VERSION
from netsecops.services.assessment import AssessmentService
from netsecops.services.audit import AuditService
from netsecops.services.credentials import CredentialService, ResolvedCredential
from netsecops.services.jobs import JobService, classify_error
from netsecops.services.snapshots import SnapshotService

log = get_logger(__name__)

#: The cheapest possible read that proves a session works (FR-CRED-05). One command,
#: on every platform's allow-list, whose failure is unambiguous.
PROBE_COMMANDS: dict[str, str] = {
    "cisco_ios": "show version",
    "cisco_iosxe": "show version",
    "cisco_nxos": "show version",
    "cisco_iosxr": "show version",
    "cisco_asa": "show version",
    "cisco_wlc_aireos": "show sysinfo",
    "checkpoint_gaia": "show version all",
    "checkpoint_gaia_expert": "show version all",
    "fortios": "get system status",
    "fortimanager": "get system status",
    "linux_aaa": "cat /etc/os-release",
    "linux_aaa_sudo": "cat /etc/os-release",
}


@dataclass(slots=True)
class DeviceOutcome:
    device_id: uuid.UUID
    succeeded: bool
    error_class: ErrorClass | None = None
    error_message: str | None = None
    credential_id: uuid.UUID | None = None
    command_count: int = 0
    output: str = ""
    #: Phase 2 results. Populated for a collection, left None by a credential test.
    snapshot_id: uuid.UUID | None = None
    collection_id: uuid.UUID | None = None
    #: Some supplementary command failed; the configuration still arrived (FR-COL-08).
    partial: bool = False
    drift_detected: bool = False
    #: Phase 3 results. Zero for a job type that does not assess.
    checks_run: int = 0
    findings_opened: int = 0
    findings_resolved: int = 0
    risk_score: int | None = None


async def run_job(job_id: uuid.UUID, **context: Any) -> None:
    """Execute a job to completion. Safe to call from any of the three call sites."""
    if cid := context.get("correlation_id"):
        correlation_id.set(str(cid))

    async with session_scope() as session:
        await execute_job(session, job_id)


async def execute_job(
    session: AsyncSession, job_id: uuid.UUID, *, vault: SecretVault | None = None
) -> Job:
    """Run every pending device in a job, then close it.

    ``vault`` is injected rather than built from global config so a test can supply one
    backed by a throwaway master key; production passes None and the service builds the
    configured one.
    """
    jobs = JobService(session)
    job = await jobs.get(job_id)

    if job.correlation_id:
        correlation_id.set(job.correlation_id)

    if job.status == JobStatus.QUEUED.value:
        await jobs.start(job)

    log.info("job.started", job_id=str(job.id), job_type=job.job_type)

    while True:
        # A cancel is honoured between devices, never mid-session (FR-JOB-03).
        await session.refresh(job)
        if job.cancel_requested_at is not None:
            log.info("job.cancel_observed", job_id=str(job.id))
            break

        job_device = await jobs.claim_next_device(job)
        if job_device is None:
            break

        outcome = await _run_one_device(session, job, job_device, vault)
        await jobs.finish_device(
            job_device,
            succeeded=outcome.succeeded,
            error_class=outcome.error_class,
            error_message=outcome.error_message,
            credential_id=outcome.credential_id,
            command_count=outcome.command_count,
        )

    completed = await jobs.complete(job)
    log.info("job.finished", job_id=str(job.id), status=completed.status, **completed.stats)
    return completed


async def _run_one_device(
    session: AsyncSession, job: Job, job_device: JobDevice, vault: SecretVault | None = None
) -> DeviceOutcome:
    """Collect from a single device, trying its credentials in order.

    A device failure is caught and classified here rather than propagating: one
    unreachable switch must not abandon the other 499.
    """
    from netsecops.services.inventory import InventoryService

    inventory = InventoryService(session)
    credentials = CredentialService(session, vault=vault)

    device = await inventory.get_device(job_device.device_id)
    job_type = JobType(job.job_type)

    try:
        if job_type is JobType.ASSESS_ONLY:
            # Re-run checks against the stored snapshot. No session is opened, which is
            # the point: an assessment after a policy change should not mean touching
            # five hundred devices again (FR-JOB-01).
            return await _assess_stored_snapshot(session, job, device, vault)

        candidates = await credentials.resolve_for_device(device)
        if not candidates:
            return DeviceOutcome(
                device_id=device.id,
                succeeded=False,
                error_class=ErrorClass.AUTH_FAILED,
                error_message="No credential is assigned to this device or its groups.",
            )

        return await _try_credentials(session, job, device, candidates, vault)

    except Exception as exc:
        error_class, message = classify_error(exc)
        log.warning(
            "job.device_failed",
            job_id=str(job.id),
            device_id=str(device.id),
            error_class=error_class.value,
            error=message,
        )
        return DeviceOutcome(
            device_id=device.id,
            succeeded=False,
            error_class=error_class,
            error_message=message,
        )


async def _try_credentials(
    session: AsyncSession,
    job: Job,
    device: Device,
    candidates: list[ResolvedCredential] | Any,
    vault: SecretVault | None = None,
) -> DeviceOutcome:
    """Walk the credential fallback list until one authenticates (FR-CRED-04).

    Only an *authentication* failure moves to the next credential. An unreachable
    device or a read-only violation stops immediately: trying three more credentials
    against a device that is switched off just triples the wait.
    """
    credentials = CredentialService(session, vault=vault)
    last_error: Exception | None = None

    for resolved in candidates:
        credential = resolved.credential
        try:
            outcome = await _collect_with(session, job, device, credential, vault)
        except DeviceAuthError as exc:
            last_error = exc
            await credentials.record_use(
                credential,
                device=device,
                succeeded=False,
                job_id=job.id,
                detail="authentication rejected",
            )
            log.info(
                "job.credential_rejected",
                device_id=str(device.id),
                credential=credential.name,
                source=resolved.source,
            )
            continue

        await credentials.record_use(
            credential,
            device=device,
            succeeded=outcome.succeeded,
            job_id=job.id,
            detail=outcome.error_message,
        )
        return outcome

    error_class, message = (
        classify_error(last_error)
        if last_error
        else (
            ErrorClass.AUTH_FAILED,
            "Every assigned credential was rejected.",
        )
    )
    return DeviceOutcome(
        device_id=device.id, succeeded=False, error_class=error_class, error_message=message
    )


async def _collect_with(
    session: AsyncSession,
    job: Job,
    device: Device,
    credential: Credential,
    vault: SecretVault | None = None,
) -> DeviceOutcome:
    """Open a guarded session with one credential and run the job's commands."""
    settings = get_settings()
    credentials = CredentialService(session, vault=vault)

    platform = device.effective_platform
    if not platform:
        raise ValidationProblem(
            f"Device {device.mgmt_ip} has no platform set, so no read-only policy applies."
        )

    guard = ReadOnlyGuard(get_policy(platform))
    transport = _build_transport(session, device, credential, credentials, settings)

    recorder = AuditingRecorder(
        AuditService(session),
        actor=_system_principal(job),
        job_id=job.id,
        org_id=job.org_id,
    )

    device_session = DeviceSession(
        transport,
        guard,
        recorder=recorder,
        device_id=device.id,
        command_timeout=device.command_timeout or settings.device_command_timeout,
    )

    job_type = JobType(job.job_type)

    async with device_session:
        # Pin the host key on first contact (FR-COL-10).
        if device.host_key_fingerprint is None and transport.observed_fingerprint:
            device.host_key_fingerprint = transport.observed_fingerprint
            await session.flush()

        if job_type is JobType.CREDENTIAL_TEST or not has_profile(platform):
            # A credential test proves the session works and stops there; collecting a
            # full configuration to answer "do these credentials work" would be a
            # needless read of sensitive data (FR-CRED-05).
            results = await device_session.run_all(_probe_commands(platform))
            return DeviceOutcome(
                device_id=device.id,
                succeeded=all(r.succeeded for r in results),
                credential_id=credential.id,
                command_count=device_session.commands_sent,
                output="\n".join(r.output for r in results),
            )

        outcome = await _collect_profile(
            session, job, device, device_session, platform, vault=vault
        )

    outcome.credential_id = credential.id
    outcome.command_count = device_session.commands_sent
    return outcome


async def _collect_profile(
    session: AsyncSession,
    job: Job,
    device: Device,
    device_session: DeviceSession,
    platform: str,
    *,
    vault: SecretVault | None = None,
) -> DeviceOutcome:
    """Run a platform's collection profile and turn the result into stored evidence.

    A command that fails marks the collection *partial* rather than failing it
    (FR-COL-08) — except the configuration itself, without which there is nothing to
    assess. A read-only violation is never caught here: it means NetSecOps attempted
    something it guarantees it never does, and the collection must stop (FR-COL-04).
    """
    profile = get_profile(platform)
    snapshots = SnapshotService(session, vault=vault)

    collection = Collection(
        org_id=job.org_id,
        device_id=device.id,
        adapter=platform,
        adapter_version=NCM_VERSION,
        started_at=datetime.now(UTC),
    )
    session.add(collection)
    await session.flush()

    # Setup commands are session-only (paging, width). They produce no evidence, so
    # they are sent but never stored — an artefact of "terminal length 0" would be
    # noise in the very place an auditor needs signal.
    for command in profile.setup:
        try:
            await device_session.run(command)
        except ReadOnlyViolationError:
            raise
        except Exception as exc:
            log.info("collect.setup_failed", command=command, error=str(exc))

    config_text: str | None = None
    failures: list[str] = []

    for ordinal, entry in enumerate(profile.commands):
        try:
            result = await device_session.run(entry.command)
        except ReadOnlyViolationError:
            raise
        except Exception as exc:
            if entry.required:
                raise
            failures.append(entry.command)
            log.info(
                "collect.command_failed",
                device_id=str(device.id),
                command=entry.command,
                error=str(exc),
            )
            await snapshots.store_artifact(
                collection,
                command=entry.command,
                response="",
                ordinal=ordinal,
                succeeded=False,
            )
            continue

        await snapshots.store_artifact(
            collection,
            command=entry.command,
            response=result.output,
            ordinal=ordinal,
            duration_ms=result.duration_ms,
            succeeded=result.succeeded,
        )
        if entry.yields_config:
            config_text = result.output
        if not result.succeeded:
            failures.append(entry.command)

    collection.finished_at = datetime.now(UTC)
    collection.partial = bool(failures)
    if failures:
        # Named, not counted: a check reported "not evaluated" is only actionable if
        # the operator can see which command was missing.
        collection.error_message = "Commands that produced no usable output: " + ", ".join(failures)
    await session.flush()

    if not config_text:
        raise ValidationProblem(
            f"Device {device.mgmt_ip} returned no configuration for '{profile.config_command}'."
        )

    snapshot = await snapshots.create_snapshot(
        device,
        config_text=config_text,
        collection=collection,
        platform=platform,
        command=profile.config_command,
    )

    drift = await snapshots.detect_drift(device, snapshot)
    if drift.changed:
        await snapshots.record_drift_finding(device, snapshot, drift)
    else:
        await snapshots.resolve_drift_finding(device)

    await session.flush()

    outcome = DeviceOutcome(
        device_id=device.id,
        # Partial is a success: the configuration arrived and the device is assessable.
        succeeded=True,
        output=f"snapshot {snapshot.id}",
        snapshot_id=snapshot.id,
        collection_id=collection.id,
        partial=collection.partial,
        drift_detected=drift.changed,
    )

    if JobType(job.job_type) is JobType.COLLECT_AND_ASSESS:
        # A partial collection is still assessed. The checks whose data is missing
        # report Not Evaluated, which is the honest answer and the one FR-COL-08 asks
        # for — far better than skipping the assessment and reporting nothing at all.
        assessment = await AssessmentService(session).assess(device, snapshot, job_id=job.id)
        outcome.checks_run = len(assessment.results)
        outcome.findings_opened = assessment.findings_opened
        outcome.findings_resolved = assessment.findings_resolved
        outcome.risk_score = assessment.risk.score if assessment.risk else None

    return outcome


def _build_transport(
    session: AsyncSession,
    device: Device,
    credential: Credential,
    credentials: CredentialService,
    settings: Any,
) -> SSHTransport:
    secret = credentials.open_secret(credential)
    public = credential.metadata_

    credential_type = CredentialType(credential.credential_type)
    if credential_type not in {CredentialType.SSH_PASSWORD, CredentialType.SSH_KEY}:
        raise ValidationProblem(
            f"Credential '{credential.name}' is a {credential_type.value}; "
            "SSH collection needs an SSH password or key."
        )

    ssh_credentials = SSHCredentials(
        username=str(public.get("username", "")),
        password=secret.get("password"),
        private_key=secret.get("private_key"),
        passphrase=secret.get("passphrase"),
    )

    jump_host = None
    if device.jump_host_id is not None:
        # Resolved lazily in Phase 2, when jump-host credentials get their own
        # assignment path. Declared here so the wiring is visible.
        log.info("job.jump_host_configured", device_id=str(device.id))

    return SSHTransport(
        str(device.mgmt_ip),
        ssh_credentials,
        port=device.ssh_port,
        known_fingerprint=device.host_key_fingerprint,
        strict_host_key=True,
        connect_timeout=device.connect_timeout or settings.device_connect_timeout,
        jump_host=jump_host,
        legacy_algorithms=settings.allow_legacy_ssh_ciphers,
    )


def _probe_commands(platform: str) -> list[str]:
    """The cheapest read that proves a session works (FR-CRED-05)."""
    probe = PROBE_COMMANDS.get(platform)
    if probe is None:
        raise ValidationProblem(f"No probe command is defined for platform '{platform}'.")
    return [probe]


async def _assess_stored_snapshot(
    session: AsyncSession, job: Job, device: Device, vault: SecretVault | None
) -> DeviceOutcome:
    """Run the device's policy against its latest snapshot, without contacting it."""
    snapshots = SnapshotService(session, vault=vault)
    snapshot = await snapshots.latest(device)

    if snapshot is None:
        return DeviceOutcome(
            device_id=device.id,
            succeeded=False,
            error_class=ErrorClass.INTERNAL_ERROR,
            error_message=(
                "This device has no configuration snapshot to assess. Run a collection "
                "first, or upload a configuration."
            ),
        )

    outcome = await AssessmentService(session).assess(device, snapshot, job_id=job.id)
    return _assessed_outcome(device, snapshot.id, outcome)


def _assessed_outcome(device: Device, snapshot_id: uuid.UUID, assessment: Any) -> DeviceOutcome:
    return DeviceOutcome(
        device_id=device.id,
        succeeded=True,
        snapshot_id=snapshot_id,
        output=f"{len(assessment.results)} checks",
        checks_run=len(assessment.results),
        findings_opened=assessment.findings_opened,
        findings_resolved=assessment.findings_resolved,
        risk_score=assessment.risk.score if assessment.risk else None,
    )


def _system_principal(job: Job) -> Principal:
    """The actor recorded for work a scheduler started rather than a person."""
    return Principal(
        id=job.requested_by_id or uuid.UUID(int=0),
        username="scheduler" if job.schedule_id else "job-runner",
        roles=frozenset({Role.API_SERVICE}),
        scope=Scope.all(),
    )


__all__ = ["DeviceOutcome", "execute_job", "run_job"]
