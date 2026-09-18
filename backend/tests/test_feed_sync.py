"""Scheduled and on-demand feed synchronisation (FR-VUL-07).

`test_feed_fetch.py` covers the network half in isolation. This covers what happens once
the bytes arrive: that they go through the *same* ingest an uploaded bundle does, that the
run is recorded truthfully, and that one publisher having a bad morning does not cost the
others their sync.

Every request is served by `httpx.MockTransport`; nothing here reaches CISA, FIRST or NVD.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.config import Settings
from netsecops.core.errors import ValidationProblem
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.jobs import JobStatus, JobType
from netsecops.db.models.vulnerability import FeedSync
from netsecops.services.feeds import FeedImportService, SyncStatus
from netsecops.services.jobs import JobService
from netsecops.vuln.fetch import MAX_NVD_WINDOW
from tests.conftest import make_user

KEV_BODY = json.dumps(
    {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.09.18",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Cisco",
                "product": "ASA",
                "vulnerabilityName": "Cisco ASA RCE",
                "dateAdded": "2026-09-01",
                "shortDescription": "Remote code execution.",
                "requiredAction": "Apply updates.",
                "dueDate": "2026-09-22",
                "knownRansomwareCampaignUse": "Known",
            }
        ],
    }
).encode()


def settings(**overrides) -> Settings:
    base = {
        "secret_key": "x" * 48,
        "master_key": "y" * 48,
        "database_url": "postgresql+asyncpg://u:p@localhost/db",
    }
    return Settings(**{**base, **overrides})


def serving(body: bytes = KEV_BODY, status: int = 200) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(status, content=body))
    )


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="feed_syncer", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
def feeds(session: AsyncSession) -> FeedImportService:
    return FeedImportService(session)


# ══════════════════════════ the shared ingest path ═══════════════════════════


class TestSyncUsesTheBundlePath:
    async def test_it_records_the_run_as_online(
        self, feeds: FeedImportService, actor: Principal
    ) -> None:
        # The only thing distinguishing an online sync from an uploaded bundle. If this
        # were not recorded, a feed page could not tell an operator whether last night's
        # data came from the internet or from a USB stick they have not been given yet.
        result = await feeds.sync_online("kev", actor=actor, settings=settings(), client=serving())

        assert result.sync.mode == "online"
        assert result.sync.status == SyncStatus.SUCCEEDED.value

    async def test_the_records_actually_land(
        self, feeds: FeedImportService, actor: Principal
    ) -> None:
        result = await feeds.sync_online("kev", actor=actor, settings=settings(), client=serving())
        assert result.kev_entries == 1

    async def test_the_bundle_digest_is_recorded(
        self, feeds: FeedImportService, actor: Principal
    ) -> None:
        # Same accounting as an offline import: what arrived is hashed and kept, so a
        # later question about which version of the catalogue produced a finding has an
        # answer.
        result = await feeds.sync_online("kev", actor=actor, settings=settings(), client=serving())
        assert result.sync.bundle_sha256

    async def test_an_unknown_source_is_refused_by_name(
        self, feeds: FeedImportService, actor: Principal
    ) -> None:
        with pytest.raises(ValidationProblem) as caught:
            await feeds.sync_online("nist-rss", actor=actor, settings=settings())
        assert "nist-rss" in str(caught.value)

    async def test_a_fetch_failure_is_recorded_not_swallowed(
        self, feeds: FeedImportService, actor: Principal, session: AsyncSession
    ) -> None:
        # "When did this last work?" is the question asked the morning somebody notices
        # the vulnerability page looks thin, and it needs the failures to be there.
        with pytest.raises(ValidationProblem):
            await feeds.sync_online(
                "kev", actor=actor, settings=settings(), client=serving(status=503)
            )

        # The fetch fails before any sync row is written — there are no bytes to account
        # for — so the record of the attempt is the job's, asserted below.
        rows = (await session.execute(select(FeedSync).where(FeedSync.feed == "kev"))).scalars()
        assert list(rows) == []


# ═══════════════════════ the incremental NVD watermark ═══════════════════════


class TestTheWatermark:
    async def test_a_partial_sync_still_advances_it(
        self, feeds: FeedImportService, actor: Principal, session: AsyncSession
    ) -> None:
        """A run that imported 9,000 of 10,000 records made progress for the 9,000.

        Treating partial as no progress would re-fetch the same window every night for as
        long as one record stayed unreadable, which on a feed of NVD's size is forever.
        """
        earlier = datetime.now(UTC) - timedelta(days=2)
        session.add(
            FeedSync(
                org_id=1,
                feed="nvd",
                mode="online",
                status=SyncStatus.PARTIAL.value,
                started_at=earlier,
                advisories_ingested=0,
                cves_ingested=9_000,
                eol_records_ingested=0,
                records_rejected=1_000,
            )
        )
        await session.flush()

        assert await feeds._last_success_at("nvd") is not None

    async def test_a_failed_sync_does_not_advance_it(
        self, feeds: FeedImportService, session: AsyncSession
    ) -> None:
        # Otherwise a night of failures silently narrows the next window and the CVEs
        # changed in between are never fetched at all.
        session.add(
            FeedSync(
                org_id=1,
                feed="nvd",
                mode="online",
                status=SyncStatus.FAILED.value,
                started_at=datetime.now(UTC) - timedelta(days=1),
                advisories_ingested=0,
                cves_ingested=0,
                eol_records_ingested=0,
                records_rejected=0,
            )
        )
        await session.flush()

        assert await feeds._last_success_at("nvd") is None

    async def test_a_gap_wider_than_nvd_answers_is_reported_as_partial(
        self, feeds: FeedImportService, actor: Principal, session: AsyncSession
    ) -> None:
        """The most dangerous case in this module.

        NVD will not answer a window wider than 120 days, so the fetch clamps it — and a
        run that reported plain success would be claiming currency over a stretch it never
        asked about. It is marked partial with the gap stated.
        """
        session.add(
            FeedSync(
                org_id=1,
                feed="nvd",
                mode="online",
                status=SyncStatus.SUCCEEDED.value,
                started_at=datetime.now(UTC) - (MAX_NVD_WINDOW + timedelta(days=45)),
                advisories_ingested=0,
                cves_ingested=1,
                eol_records_ingested=0,
                records_rejected=0,
            )
        )
        await session.flush()

        empty = json.dumps(
            {"totalResults": 0, "startIndex": 0, "resultsPerPage": 0, "vulnerabilities": []}
        ).encode()
        result = await feeds.sync_online(
            "nvd", actor=actor, settings=settings(), client=serving(empty)
        )

        assert result.sync.status == SyncStatus.PARTIAL.value
        assert "120-day window" in (result.sync.error_message or "")


# ═══════════════════════════ the job that runs it ════════════════════════════


class TestTheFeedSyncJob:
    async def test_it_targets_no_devices(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The property that keeps this job away from customer equipment entirely.

        A `job_devices` row would be the only route by which a feed sync could reach the
        credential resolver and open a session to a device. There is no code that writes
        one, and this asserts none appears.
        """
        from netsecops.db.models.jobs import JobDevice

        job = await JobService(session).create_feed_sync(sources=["kev"], actor=actor)
        await session.flush()

        rows = (
            await session.execute(select(JobDevice).where(JobDevice.job_id == job.id))
        ).scalars()
        assert list(rows) == []
        assert job.job_type == JobType.FEED_SYNC.value

    async def test_the_sources_are_carried_on_the_job(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        job = await JobService(session).create_feed_sync(sources=["kev", "epss"], actor=actor)
        assert job.scope == {"feed_sources": ["kev", "epss"]}

    async def test_it_is_idempotent(self, session: AsyncSession, actor: Principal) -> None:
        jobs = JobService(session)
        first = await jobs.create_feed_sync(sources=["kev"], actor=actor, idempotency_key="nightly")
        second = await jobs.create_feed_sync(
            sources=["kev"], actor=actor, idempotency_key="nightly"
        )
        assert first.id == second.id

    async def test_one_failing_source_does_not_sink_the_others(
        self, session: AsyncSession, actor: Principal, monkeypatch
    ) -> None:
        """CISA being down is no reason to skip EPSS.

        Three unrelated services with independent outages and independent rate limits. A
        job that abandoned the run on the first failure would leave two feeds stale
        because a third had a bad morning.
        """
        from netsecops.workers import runner

        calls: list[str] = []

        async def fake_sync(self, source_name, *, actor, settings, client=None):
            calls.append(source_name)
            if source_name == "kev":
                raise ValidationProblem("CISA returned HTTP 503")
            return type("R", (), {"cves": 2, "advisories": 0, "kev_entries": 0, "epss_scores": 0})()

        monkeypatch.setattr(FeedImportService, "sync_online", fake_sync)

        job = await JobService(session).create_feed_sync(
            sources=["kev", "epss", "nvd"], actor=actor
        )
        await session.flush()

        finished = await runner._run_feed_sync(session, job, JobService(session))

        assert calls == ["kev", "epss", "nvd"], "the run stopped at the first failure"
        assert finished.status == JobStatus.PARTIAL.value
        assert finished.stats["feeds_synced"] == 2
        assert finished.stats["feeds_failed"] == 1
        assert "CISA" in (finished.error_message or "")

    async def test_every_source_failing_is_a_failure(
        self, session: AsyncSession, actor: Principal, monkeypatch
    ) -> None:
        # Distinguishes "the internet is gone" from "one publisher is having a morning",
        # which are different problems with different remedies.
        from netsecops.workers import runner

        async def always_fails(self, source_name, *, actor, settings, client=None):
            raise ValidationProblem("no route to host")

        monkeypatch.setattr(FeedImportService, "sync_online", always_fails)

        job = await JobService(session).create_feed_sync(sources=["kev", "epss"], actor=actor)
        await session.flush()

        finished = await runner._run_feed_sync(session, job, JobService(session))
        assert finished.status == JobStatus.FAILED.value
