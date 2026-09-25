"""Artefact retention (FR-ADM-01, DATA-02).

`docs/deployment.md` described a ninety-day artefact window since Phase 7 and based its
database sizing on one. Nothing enforced it: artefacts accumulated for the life of the
deployment while the documentation said they would not, so the published figure described
a system that did not exist and the disk filled instead.

This is the only thing in the product that deletes collected evidence, so most of what is
pinned here is what it must *not* touch. Getting a purge slightly too enthusiastic is not
a performance regression; it is a customer's audit trail.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, User
from netsecops.db.models.audit import Setting
from netsecops.db.models.collection import (
    Artifact,
    ArtifactKind,
    Collection,
    Finding,
    FindingKind,
    FindingStatus,
    Snapshot,
)
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.services.inventory import InventoryService
from netsecops.services.retention import ARTIFACT_RETENTION_KEY, RetentionService
from tests.conftest import make_user

NOW = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user: User = await make_user(session, username="retention_admin", roles={Role.SUPER_ADMIN})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
async def device(session: AsyncSession, actor: Principal) -> Device:
    return await InventoryService(session).create_device(
        mgmt_ip="10.60.0.1",
        actor=actor,
        hostname="ret-sw-01",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )


async def set_window(session: AsyncSession, days: int | object) -> None:
    session.add(Setting(key=ARTIFACT_RETENTION_KEY, value={"days": days}, org_id=1))
    await session.flush()


async def add_collection(
    session: AsyncSession, device: Device, *, age_days: int, artifacts: int = 2
) -> Collection:
    """A collection `age_days` old, with artefacts attached."""
    created = NOW - timedelta(days=age_days)
    collection = Collection(
        org_id=1,
        device_id=device.id,
        adapter="cisco_ios",
        adapter_version="1.1",
        started_at=created,
        finished_at=created,
        created_at=created,
    )
    session.add(collection)
    await session.flush()

    for ordinal in range(artifacts):
        session.add(
            Artifact(
                org_id=1,
                collection_id=collection.id,
                kind=ArtifactKind.COMMAND.value,
                request_text=f"show run {ordinal}",
                response_encrypted=b"sealed",
                response_redacted="! config",
                sha256=uuid.uuid4().hex * 2,
                size_bytes=32,
                ordinal=ordinal,
                succeeded=True,
                created_at=created,
            )
        )
    await session.flush()
    return collection


async def artifact_count(session: AsyncSession, collection: Collection) -> int:
    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(Artifact)
                .where(Artifact.collection_id == collection.id)
            )
        ).scalar_one()
    )


class TestTheWindow:
    async def test_nothing_is_removed_when_retention_is_not_configured(
        self, session: AsyncSession, device: Device
    ) -> None:
        """Off by default.

        A product that starts deleting evidence because somebody upgraded has made a
        decision for an operator who may be under a retention obligation nobody told it
        about.
        """
        old = await add_collection(session, device, age_days=400)

        outcome = await RetentionService(session).purge_artifacts(now=NOW)

        assert outcome.enabled is False
        assert outcome.artifacts_removed == 0
        assert await artifact_count(session, old) == 2

    async def test_artefacts_past_the_window_are_removed(
        self, session: AsyncSession, device: Device
    ) -> None:
        await set_window(session, 90)
        old = await add_collection(session, device, age_days=120)

        outcome = await RetentionService(session).purge_artifacts(now=NOW)

        assert outcome.artifacts_removed == 2
        assert outcome.collections_purged == 1
        assert await artifact_count(session, old) == 0

    async def test_artefacts_inside_the_window_are_kept(
        self, session: AsyncSession, device: Device
    ) -> None:
        """The boundary is where an off-by-one deletes evidence somebody still needs."""
        await set_window(session, 90)
        recent = await add_collection(session, device, age_days=89)

        await RetentionService(session).purge_artifacts(now=NOW)

        assert await artifact_count(session, recent) == 2

    async def test_a_malformed_setting_disables_retention_rather_than_guessing(
        self, session: AsyncSession, device: Device
    ) -> None:
        """A default here would be a number nobody chose, applied to deleting evidence."""
        await set_window(session, "ninety")
        old = await add_collection(session, device, age_days=400)

        outcome = await RetentionService(session).purge_artifacts(now=NOW)

        assert outcome.enabled is False
        assert await artifact_count(session, old) == 2

    async def test_zero_days_means_keep_everything_not_delete_everything(
        self, session: AsyncSession, device: Device
    ) -> None:
        """The reading that costs least if somebody types it by accident."""
        await set_window(session, 0)
        old = await add_collection(session, device, age_days=400)

        outcome = await RetentionService(session).purge_artifacts(now=NOW)

        assert outcome.enabled is False
        assert await artifact_count(session, old) == 2


class TestWhatItMustNeverTouch:
    async def test_the_collection_row_survives_its_artefacts(
        self, session: AsyncSession, device: Device
    ) -> None:
        """The record that a session happened outlives the output it produced.

        It is a few hundred bytes, and an auditor asking "was this device collected from
        in March" is asking about the row, not the command output.
        """
        await set_window(session, 90)
        old = await add_collection(session, device, age_days=200)

        await RetentionService(session).purge_artifacts(now=NOW)

        still_there = (
            await session.execute(select(Collection).where(Collection.id == old.id))
        ).scalar_one_or_none()
        assert still_there is not None
        assert still_there.adapter == "cisco_ios"
        assert still_there.artifacts_purged_at is not None

    async def test_snapshots_are_never_purged(self, session: AsyncSession, device: Device) -> None:
        """Not a preference — a foreign key.

        `check_results.snapshot_id` cascades, so deleting a snapshot would take the
        assessment history behind every finding it produced. Findings are documented as
        never purged, and removing the evidence under them would honour the letter of
        that and not the point.
        """
        await set_window(session, 90)
        old = await add_collection(session, device, age_days=300)
        digest = uuid.uuid4().hex
        session.add(
            Snapshot(
                org_id=1,
                device_id=device.id,
                collection_id=old.id,
                config_hash=digest,
                normalized_hash=digest,
                ncm={},
                ncm_version="1.1",
                config_redacted="! old",
                created_at=NOW - timedelta(days=300),
            )
        )
        await session.flush()

        await RetentionService(session).purge_artifacts(now=NOW)

        snapshots = int(
            (
                await session.execute(
                    select(func.count())
                    .select_from(Snapshot)
                    .where(Snapshot.device_id == device.id)
                )
            ).scalar_one()
        )
        assert snapshots == 1

    async def test_findings_are_never_purged(self, session: AsyncSession, device: Device) -> None:
        """DATA-02. Findings history outlives the artefacts that produced it."""
        await set_window(session, 90)
        await add_collection(session, device, age_days=300)
        session.add(
            Finding(
                org_id=1,
                device_id=device.id,
                kind=FindingKind.CONFIG.value,
                fingerprint=f"config:old:{device.id}",
                title="an old finding",
                severity="high",
                status=FindingStatus.OPEN.value,
                first_seen_at=NOW - timedelta(days=300),
                last_seen_at=NOW - timedelta(days=300),
            )
        )
        await session.flush()

        await RetentionService(session).purge_artifacts(now=NOW)

        findings = int(
            (
                await session.execute(
                    select(func.count()).select_from(Finding).where(Finding.device_id == device.id)
                )
            ).scalar_one()
        )
        assert findings == 1


class TestRunningItTwice:
    async def test_a_purged_collection_is_not_purged_again(
        self, session: AsyncSession, device: Device
    ) -> None:
        """The marker is what stops the second run rescanning the whole table."""
        await set_window(session, 90)
        await add_collection(session, device, age_days=200)

        first = await RetentionService(session).purge_artifacts(now=NOW)
        second = await RetentionService(session).purge_artifacts(now=NOW)

        assert first.collections_purged == 1
        assert second.collections_purged == 0

    async def test_a_backlog_is_reported_rather_than_silently_left(
        self, session: AsyncSession, device: Device, monkeypatch
    ) -> None:
        """A run that did part of the job must say so, or it reads as having finished."""
        import netsecops.services.retention as retention_module

        monkeypatch.setattr(retention_module, "BATCH", 2)
        await set_window(session, 90)
        for age in (200, 201, 202):
            await add_collection(session, device, age_days=age, artifacts=1)

        outcome = await RetentionService(session).purge_artifacts(now=NOW)

        assert outcome.collections_purged == 2
        assert outcome.more_remaining is True

        rest = await RetentionService(session).purge_artifacts(now=NOW)
        assert rest.collections_purged == 1
        assert rest.more_remaining is False
