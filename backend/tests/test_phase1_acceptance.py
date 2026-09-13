"""Phase 1 acceptance (SRS §12).

    create device -> test credential (against fake SSH server)
      -> job history recorded -> audit shows commands

Written as one continuous path rather than four isolated tests, because the criterion
is that the chain works end to end. The individual links have their own unit tests; this
asserts they connect.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.adapters.profiles import get_profile
from netsecops.core.crypto import SecretVault
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import AuditLog, Device
from netsecops.db.models.inventory import CredentialType, DeviceClass, Vendor
from netsecops.db.models.jobs import DeviceJobStatus, JobStatus, JobType
from netsecops.services.credentials import CredentialService
from netsecops.services.inventory import InventoryService
from netsecops.services.jobs import JobScope, JobService
from netsecops.workers.probe import probe_credential
from netsecops.workers.runner import execute_job
from tests.conftest import make_user
from tests.fake_device import fake_device

DEVICE_USER = "netsecops"
DEVICE_PASSWORD = "device-pass"


@pytest.fixture
async def device_server():
    async for server in fake_device(username=DEVICE_USER, password=DEVICE_PASSWORD):
        yield server


@pytest.fixture
async def analyst_principal(session: AsyncSession) -> Principal:
    user = await make_user(session, username="phase1_analyst", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def _onboard(
    session: AsyncSession,
    server,
    actor: Principal,
    vault: SecretVault,
) -> tuple[Device, object]:
    """Create a device and give it a credential — the first link in the chain."""
    inventory = InventoryService(session)
    credentials = CredentialService(session, vault=vault)

    device = await inventory.create_device(
        mgmt_ip=server.host,
        actor=actor,
        hostname="lab-sw-01",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
        ssh_port=server.port,
    )
    credential = await credentials.create(
        name="lab-readonly",
        credential_type=CredentialType.SSH_PASSWORD,
        secret_data={"username": DEVICE_USER, "password": DEVICE_PASSWORD},
        actor=actor,
    )
    await credentials.assign(credential, device_id=device.id, actor=actor)
    return device, credential


class TestPhase1Acceptance:
    async def test_the_whole_chain(
        self,
        session: AsyncSession,
        device_server,
        analyst_principal: Principal,
        vault: SecretVault,
    ) -> None:
        actor = analyst_principal
        credentials = CredentialService(session, vault=vault)
        jobs = JobService(session)

        # ── 1. create device ────────────────────────────────────────────
        device, credential = await _onboard(session, device_server, actor, vault)
        assert device.id is not None
        assert device.platform == "cisco_ios"

        resolved = await credentials.resolve_for_device(device)
        assert [r.credential.id for r in resolved] == [credential.id]

        # ── 2. test credential against the fake SSH server ──────────────
        probe = await probe_credential(
            session, device=device, credential=credential, actor=actor, vault=vault
        )
        assert probe.succeeded, probe.detail
        assert probe.command == "show version"
        assert device_server.received == ["show version"]
        # First contact pins the host key (FR-COL-10).
        assert device.host_key_fingerprint is not None
        assert probe.host_key_fingerprint == device.host_key_fingerprint

        # ── 3. run a job, and check its history ─────────────────────────
        job = await jobs.create(
            job_type=JobType.COLLECT,
            scope=JobScope(device_ids=(device.id,)),
            actor=actor,
        )
        assert job.status == JobStatus.QUEUED.value
        assert job.stats["total"] == 1

        completed = await execute_job(session, job.id, vault=vault)

        assert completed.status == JobStatus.SUCCEEDED.value
        assert completed.started_at is not None and completed.finished_at is not None
        assert completed.stats["succeeded"] == 1

        results = await jobs.device_results(completed)
        assert len(results) == 1
        result = results[0]
        assert result.status == DeviceJobStatus.SUCCEEDED.value
        assert result.device_id == device.id
        assert result.credential_id == credential.id
        assert result.duration_ms is not None
        assert result.error_class is None

        # From Phase 2 a collection runs the platform's whole profile, not just a
        # probe. The fake device answers only some of those commands, and that is the
        # point: the collection still succeeds (FR-COL-08).
        profile = get_profile("cisco_ios")
        assert result.command_count == len(profile.all_commands())

        # ── 4. the audit log shows the commands ─────────────────────────
        await session.flush()
        commands = (
            (
                await session.execute(
                    select(AuditLog)
                    .where(AuditLog.action == "device.command")
                    .order_by(AuditLog.id)
                )
            )
            .scalars()
            .all()
        )

        # Two sessions ran: the credential probe, then the job's full profile. Every
        # command in both is in the trail, in the order it was sent (FR-AUD-01).
        assert [c.command_text for c in commands] == [
            "show version",
            *profile.all_commands(),
        ]
        assert all(c.device_id == device.id for c in commands)

        # Nothing reached the device that the profile did not ask for.
        assert device_server.received == ["show version", *profile.all_commands()]

        # Everything else in the chain is audited too.
        actions = (
            (await session.execute(select(AuditLog.action).order_by(AuditLog.id))).scalars().all()
        )
        for expected in (
            "device.created",
            "credential.created",
            "credential.used",
            "device.command",
            "job.started",
            "job.completed",
        ):
            assert expected in actions, f"{expected} was not audited"

        # And the chain is still intact after all of it (FR-AUD-02).
        verification = await jobs.audit.verify_chain()
        assert verification.valid, verification.reason

    async def test_no_secret_reaches_the_audit_log(
        self,
        session: AsyncSession,
        device_server,
        analyst_principal: Principal,
        vault: SecretVault,
    ) -> None:
        """C-2 — the device password must appear nowhere in the trail."""
        device, credential = await _onboard(session, device_server, analyst_principal, vault)

        await probe_credential(
            session,
            device=device,
            credential=credential,
            actor=analyst_principal,
            vault=vault,
        )
        await session.flush()

        rows = (await session.execute(select(AuditLog))).scalars().all()
        for row in rows:
            haystack = " ".join(
                str(part) for part in (row.command_text, row.details, row.object_id)
            )
            assert DEVICE_PASSWORD not in haystack

    async def test_secret_is_not_stored_in_plaintext(
        self,
        session: AsyncSession,
        device_server,
        analyst_principal: Principal,
        vault: SecretVault,
    ) -> None:
        """FR-CRED-02 — the vault row must not contain the password."""
        _, credential = await _onboard(session, device_server, analyst_principal, vault)

        assert DEVICE_PASSWORD.encode() not in credential.encrypted_blob
        assert DEVICE_PASSWORD not in str(credential.metadata_)
        # ...but it round-trips for the collector.
        opened = CredentialService(session, vault=vault).open_secret(credential)
        assert opened["password"] == DEVICE_PASSWORD


class TestJobFailureHandling:
    """FR-COL-07 — a device failure is classified, and never fails the whole job."""

    async def test_wrong_credential_is_classified_as_auth_failure(
        self,
        session: AsyncSession,
        device_server,
        analyst_principal: Principal,
        vault: SecretVault,
    ) -> None:
        inventory = InventoryService(session)
        credentials = CredentialService(session, vault=vault)

        device = await inventory.create_device(
            mgmt_ip=device_server.host,
            actor=analyst_principal,
            platform="cisco_ios",
            vendor=Vendor.CISCO,
            ssh_port=device_server.port,
        )
        bad = await credentials.create(
            name="wrong-password",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": DEVICE_USER, "password": "not-the-password"},
            actor=analyst_principal,
        )
        await credentials.assign(bad, device_id=device.id, actor=analyst_principal)

        jobs = JobService(session)
        job = await jobs.create(
            job_type=JobType.COLLECT,
            scope=JobScope(device_ids=(device.id,)),
            actor=analyst_principal,
        )
        completed = await execute_job(session, job.id, vault=vault)

        assert completed.status == JobStatus.FAILED.value
        result = (await jobs.device_results(completed))[0]
        assert result.status == DeviceJobStatus.FAILED.value
        assert result.error_class == "auth_failed"

    async def test_credential_fallback_tries_the_next_one(
        self,
        session: AsyncSession,
        device_server,
        analyst_principal: Principal,
        vault: SecretVault,
    ) -> None:
        """FR-CRED-04 — a rejected credential moves to the next, in priority order."""
        inventory = InventoryService(session)
        credentials = CredentialService(session, vault=vault)

        device = await inventory.create_device(
            mgmt_ip=device_server.host,
            actor=analyst_principal,
            platform="cisco_ios",
            vendor=Vendor.CISCO,
            ssh_port=device_server.port,
        )

        stale = await credentials.create(
            name="stale-credential",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": DEVICE_USER, "password": "rotated-away"},
            actor=analyst_principal,
        )
        current = await credentials.create(
            name="current-credential",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": DEVICE_USER, "password": DEVICE_PASSWORD},
            actor=analyst_principal,
        )
        await credentials.assign(stale, device_id=device.id, priority=10, actor=analyst_principal)
        await credentials.assign(current, device_id=device.id, priority=20, actor=analyst_principal)

        jobs = JobService(session)
        job = await jobs.create(
            job_type=JobType.COLLECT,
            scope=JobScope(device_ids=(device.id,)),
            actor=analyst_principal,
        )
        completed = await execute_job(session, job.id, vault=vault)

        assert completed.status == JobStatus.SUCCEEDED.value
        result = (await jobs.device_results(completed))[0]
        assert result.credential_id == current.id, "the working credential should be recorded"

    async def test_device_without_a_credential_fails_clearly(
        self,
        session: AsyncSession,
        device_server,
        analyst_principal: Principal,
        vault: SecretVault,
    ) -> None:
        inventory = InventoryService(session)
        device = await inventory.create_device(
            mgmt_ip=device_server.host,
            actor=analyst_principal,
            platform="cisco_ios",
            ssh_port=device_server.port,
        )

        jobs = JobService(session)
        job = await jobs.create(
            job_type=JobType.COLLECT,
            scope=JobScope(device_ids=(device.id,)),
            actor=analyst_principal,
        )
        completed = await execute_job(session, job.id, vault=vault)

        result = (await jobs.device_results(completed))[0]
        assert result.error_class == "auth_failed"
        assert "No credential is assigned" in (result.error_message or "")

    async def test_one_bad_device_does_not_stop_the_others(
        self,
        session: AsyncSession,
        device_server,
        analyst_principal: Principal,
        vault: SecretVault,
    ) -> None:
        """The point of per-device classification: 499 devices still get assessed."""
        inventory = InventoryService(session)
        credentials = CredentialService(session, vault=vault)

        good = await inventory.create_device(
            mgmt_ip=device_server.host,
            actor=analyst_principal,
            platform="cisco_ios",
            ssh_port=device_server.port,
        )
        unreachable = await inventory.create_device(
            mgmt_ip="198.51.100.200",
            actor=analyst_principal,
            platform="cisco_ios",
            ssh_port=1,
            connect_timeout=2,
        )

        credential = await credentials.create(
            name="shared-readonly",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": DEVICE_USER, "password": DEVICE_PASSWORD},
            actor=analyst_principal,
        )
        for device in (good, unreachable):
            await credentials.assign(credential, device_id=device.id, actor=analyst_principal)

        jobs = JobService(session)
        job = await jobs.create(
            job_type=JobType.COLLECT,
            scope=JobScope(device_ids=(good.id, unreachable.id)),
            actor=analyst_principal,
        )
        completed = await execute_job(session, job.id, vault=vault)

        assert completed.status == JobStatus.PARTIAL.value
        assert completed.stats["succeeded"] == 1
        assert completed.stats["failed"] == 1

        by_device = {r.device_id: r for r in await jobs.device_results(completed)}
        assert by_device[good.id].status == DeviceJobStatus.SUCCEEDED.value
        assert by_device[unreachable.id].error_class == "unreachable"


class TestJobControl:
    async def test_cancel_marks_pending_devices_cancelled(
        self, session: AsyncSession, analyst_principal: Principal
    ) -> None:
        inventory = InventoryService(session)
        devices = [
            await inventory.create_device(
                mgmt_ip=f"198.51.100.{n}", actor=analyst_principal, platform="cisco_ios"
            )
            for n in range(10, 13)
        ]

        jobs = JobService(session)
        job = await jobs.create(
            job_type=JobType.COLLECT,
            scope=JobScope(device_ids=tuple(d.id for d in devices)),
            actor=analyst_principal,
        )
        cancelled = await jobs.cancel(job, actor=analyst_principal)

        assert cancelled.status == JobStatus.CANCELLING.value
        results = await jobs.device_results(cancelled)
        assert all(r.status == DeviceJobStatus.CANCELLED.value for r in results)

    async def test_a_cancelled_job_runs_nothing(
        self,
        session: AsyncSession,
        device_server,
        analyst_principal: Principal,
        vault: SecretVault,
    ) -> None:
        device, _ = await _onboard(session, device_server, analyst_principal, vault)
        device_server.received.clear()

        jobs = JobService(session)
        job = await jobs.create(
            job_type=JobType.COLLECT,
            scope=JobScope(device_ids=(device.id,)),
            actor=analyst_principal,
        )
        await jobs.cancel(job, actor=analyst_principal)
        completed = await execute_job(session, job.id, vault=vault)

        assert completed.status == JobStatus.CANCELLED.value
        assert device_server.received == [], "a cancelled job must not touch the device"

    async def test_idempotency_key_prevents_a_duplicate_run(
        self, session: AsyncSession, analyst_principal: Principal
    ) -> None:
        inventory = InventoryService(session)
        device = await inventory.create_device(
            mgmt_ip="198.51.100.50", actor=analyst_principal, platform="cisco_ios"
        )

        jobs = JobService(session)
        scope = JobScope(device_ids=(device.id,))
        first = await jobs.create(
            job_type=JobType.COLLECT,
            scope=scope,
            actor=analyst_principal,
            idempotency_key="retry-me",
        )
        second = await jobs.create(
            job_type=JobType.COLLECT,
            scope=scope,
            actor=analyst_principal,
            idempotency_key="retry-me",
        )

        assert first.id == second.id

    async def test_rerun_failed_targets_only_failures(
        self,
        session: AsyncSession,
        device_server,
        analyst_principal: Principal,
        vault: SecretVault,
    ) -> None:
        inventory = InventoryService(session)
        credentials = CredentialService(session, vault=vault)

        good = await inventory.create_device(
            mgmt_ip=device_server.host,
            actor=analyst_principal,
            platform="cisco_ios",
            ssh_port=device_server.port,
        )
        bad = await inventory.create_device(
            mgmt_ip="198.51.100.201",
            actor=analyst_principal,
            platform="cisco_ios",
            ssh_port=1,
            connect_timeout=2,
        )
        credential = await credentials.create(
            name="rerun-credential",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": DEVICE_USER, "password": DEVICE_PASSWORD},
            actor=analyst_principal,
        )
        for device in (good, bad):
            await credentials.assign(credential, device_id=device.id, actor=analyst_principal)

        jobs = JobService(session)
        job = await jobs.create(
            job_type=JobType.COLLECT,
            scope=JobScope(device_ids=(good.id, bad.id)),
            actor=analyst_principal,
        )
        completed = await execute_job(session, job.id, vault=vault)

        retry = await jobs.rerun_failed(completed, actor=analyst_principal)
        retry_devices = await jobs.device_results(retry)

        assert [r.device_id for r in retry_devices] == [bad.id]


class TestScopeEnforcement:
    """FR-AUTH-05 — a job cannot reach outside the caller's Device Groups."""

    async def test_scope_narrows_the_targets(
        self, session: AsyncSession, analyst_principal: Principal
    ) -> None:
        from tests.conftest import make_group

        inventory = InventoryService(session)
        visible_group = await make_group(session, name="visible")
        hidden_group = await make_group(session, name="hidden")

        visible = await inventory.create_device(
            mgmt_ip="198.51.100.60",
            actor=analyst_principal,
            platform="cisco_ios",
            group_ids=[visible_group.id],
        )
        hidden = await inventory.create_device(
            mgmt_ip="198.51.100.61",
            actor=analyst_principal,
            platform="cisco_ios",
            group_ids=[hidden_group.id],
        )

        jobs = JobService(session)
        restricted = Scope(unrestricted=False, device_group_ids=frozenset({visible_group.id}))
        resolved = await jobs.resolve_scope(
            JobScope(device_ids=(visible.id, hidden.id)), restricted
        )

        assert [d.id for d in resolved] == [visible.id]

    async def test_a_scope_matching_nothing_is_refused(
        self, session: AsyncSession, analyst_principal: Principal
    ) -> None:
        from netsecops.core.errors import ValidationProblem

        jobs = JobService(session)
        with pytest.raises(ValidationProblem, match="matched no devices"):
            await jobs.create(
                job_type=JobType.COLLECT,
                scope=JobScope(device_ids=(uuid.uuid4(),)),
                actor=analyst_principal,
            )
