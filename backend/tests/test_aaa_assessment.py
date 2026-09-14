"""Storing AAA correlation as per-device findings (FR-AAA-06, FR-FIND-01).

FR-AAA-06 says AAA findings appear *both* per device and on the posture dashboard. The
dashboard is a live read; this is the other half, and it is the half that can do damage,
because it writes to the findings table and can close rows.

Two properties matter more than the rest.

**Where each finding lands.** Every conclusion here was reached by looking somewhere
other than the device it is about, so the anchor has to be chosen rather than assumed.
An orphaned client has no device row at all — that *is* the finding — so it attaches to
the server that named it.

**What happens when the analysis could not run.** With no AAA server collected, every
device trivially appears on no client list. A run in that state that closed last week's
findings would quietly erase real work, and it would do so silently, on a schedule.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.collection import Finding, FindingKind, FindingStatus
from netsecops.services.aaa_assessment import AaaAssessmentService
from tests.conftest import make_user
from tests.test_aaa_correlation import add_device, client, client_ncm, server_ncm, snapshot


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="aaa_writer", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def findings_for(session: AsyncSession, device_id: uuid.UUID) -> list[Finding]:
    rows = (
        (
            await session.execute(
                select(Finding).where(
                    Finding.device_id == device_id, Finding.kind == FindingKind.AAA.value
                )
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


# ══════════════════════════ where findings land ═════════════════════════════


class TestAnchoring:
    async def test_an_orphaned_client_is_a_finding_on_the_server_that_named_it(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The orphan itself has no device row — that is the finding. The server's owner
        is also the person who can say whether the entry is stale or the device is real."""
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        await snapshot(session, ise, server_ncm("ise", [client("ghost-sw", "10.88.0.1")]))

        outcome = await AaaAssessmentService(session).assess()

        assert outcome.findings_opened == 1
        finding = (await findings_for(session, ise.id))[0]
        assert "ghost-sw" in finding.title
        assert finding.evidence["client_address"] == "10.88.0.1"
        assert finding.severity == "medium"

    async def test_an_orphan_from_a_stale_snapshot_is_downgraded_and_says_so(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """A device added to inventory after the server was last collected looks exactly
        like a device nobody ever added. A medium finding that turns out to be a
        collection gap teaches people to ignore the next one."""
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        await snapshot(
            session, ise, server_ncm("ise", [client("ghost-sw", "10.88.0.1")]), age_days=60
        )

        await AaaAssessmentService(session).assess()

        finding = (await findings_for(session, ise.id))[0]
        assert finding.severity == "low"
        assert finding.evidence["server_snapshot_age_days"] == 60
        assert "re-collect the server" in (finding.description or "")

    async def test_an_unregistered_device_is_a_finding_on_that_device(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        switch = await add_device(session, actor, ip="198.51.100.1", hostname="sw-a")
        await snapshot(session, ise, server_ncm("ise", [client("sw-known", "198.51.100.99")]))
        await snapshot(session, switch, client_ncm([]))

        await AaaAssessmentService(session).assess()

        finding = (await findings_for(session, switch.id))[0]
        assert finding.evidence["configured_for_aaa"] is False
        # No AAA at all is worse than pointing at a server we have not collected from:
        # the credentials are not centrally revocable and the logins are not logged.
        assert finding.severity == "high"
        assert "local-only" in (finding.description or "")

    async def test_a_device_configured_for_aaa_but_absent_is_the_milder_case(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        switch = await add_device(session, actor, ip="198.51.100.1", hostname="sw-a")
        await snapshot(session, ise, server_ncm("ise", [client("sw-known", "198.51.100.99")]))
        await snapshot(session, switch, client_ncm([{"type": "radius", "host": "10.100.0.50"}]))

        await AaaAssessmentService(session).assess()

        finding = next(
            f for f in await findings_for(session, switch.id) if "on no AAA server" in f.title
        )
        assert finding.severity == "medium"

    async def test_an_unknown_server_produces_a_finding_on_every_device_using_it(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """Not one representative device. If four switches authenticate against a server
        nobody assesses, all four carry that risk, and closing it on one must not close
        it on the others."""
        users = []
        for index in range(3):
            device = await add_device(
                session, actor, ip=f"198.51.100.{index + 1}", hostname=f"sw-{index}"
            )
            await snapshot(session, device, client_ncm([{"type": "radius", "host": "10.200.0.9"}]))
            users.append(device)

        await AaaAssessmentService(session).assess()

        for device in users:
            finding = next(
                f for f in await findings_for(session, device.id) if "10.200.0.9" in f.title
            )
            assert finding.evidence["server_address"] == "10.200.0.9"
            # The other devices sharing the exposure are named, so the reader can see
            # the scope without opening three more pages.
            assert len(finding.evidence["also_used_by"]) == 2

    async def test_a_reused_secret_is_a_finding_on_the_servers_that_exposed_it(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        radius = await add_device(
            session, actor, ip="10.100.0.51", hostname="radius-01", platform="freeradius"
        )
        await snapshot(
            session,
            radius,
            server_ncm(
                "freeradius",
                [
                    client("sw-a", "198.51.100.1", fingerprint="deadbeef"),
                    client("sw-b", "198.51.100.2", fingerprint="deadbeef"),
                ],
            ),
        )

        await AaaAssessmentService(session).assess()

        finding = next(
            f for f in await findings_for(session, radius.id) if "shared secret" in f.title
        )
        assert finding.severity == "high"
        assert finding.evidence["clients"] == 2
        assert finding.evidence["secret_fingerprint"] == "deadbeef"

    async def test_a_finding_carries_no_snapshot_id(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """Pointing at the device's own snapshot would invite a reader to go looking for
        the evidence in a file that does not contain it — the conclusion came from
        comparing two devices, not from reading one."""
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        await snapshot(session, ise, server_ncm("ise", [client("ghost-sw", "10.88.0.1")]))

        await AaaAssessmentService(session).assess()

        assert (await findings_for(session, ise.id))[0].snapshot_id is None


# ═══════════════════════════ the lifecycle ══════════════════════════════════


class TestLifecycle:
    async def test_running_twice_updates_rather_than_duplicates(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        await snapshot(session, ise, server_ncm("ise", [client("ghost-sw", "10.88.0.1")]))

        first = await AaaAssessmentService(session).assess()
        second = await AaaAssessmentService(session).assess()

        assert first.findings_opened == 1
        assert second.findings_opened == 0
        rows = await findings_for(session, ise.id)
        assert len(rows) == 1
        assert rows[0].occurrences == 2
        # The first-seen date is the point of the whole table; a duplicate row would
        # reset it and make an eight-month-old problem look like today's.
        assert rows[0].first_seen_at is not None

    async def test_a_problem_that_goes_away_is_resolved(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        await snapshot(session, ise, server_ncm("ise", [client("ghost-sw", "10.88.0.1")]))
        await AaaAssessmentService(session).assess()

        # The ghost is now in inventory, so it is no longer an orphan.
        await add_device(session, actor, ip="10.88.0.1", hostname="ghost-sw")
        await snapshot(session, ise, server_ncm("ise", [client("ghost-sw", "10.88.0.1")]))

        outcome = await AaaAssessmentService(session).assess()

        orphan = next(f for f in await findings_for(session, ise.id) if "ghost-sw" in f.title)
        assert outcome.findings_resolved >= 1
        assert orphan.status == FindingStatus.RESOLVED.value
        assert orphan.resolved_at is not None

    async def test_a_problem_that_comes_back_is_reopened(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        await snapshot(session, ise, server_ncm("ise", [client("ghost-sw", "10.88.0.1")]))
        await AaaAssessmentService(session).assess()

        row = (await findings_for(session, ise.id))[0]
        row.status = FindingStatus.RESOLVED.value
        await session.flush()

        outcome = await AaaAssessmentService(session).assess()

        assert outcome.findings_opened == 1
        assert (await findings_for(session, ise.id))[0].status == FindingStatus.REOPENED.value

    async def test_nothing_is_resolved_when_no_aaa_server_was_collected(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The gate this module exists to hold. With no server data every device appears
        on no client list, so the correlation refuses to draw the conclusion — and this
        must refuse to act on the silence, or a collection outage would close every real
        AAA finding in the estate overnight."""
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        await snapshot(session, ise, server_ncm("ise", [client("ghost-sw", "10.88.0.1")]))
        await AaaAssessmentService(session).assess()
        assert len(await findings_for(session, ise.id)) == 1

        # The server's collection now fails, so its latest snapshot carries no clients.
        await snapshot(session, ise, {"device": {}})

        outcome = await AaaAssessmentService(session).assess()

        assert outcome.registration_analysed is False
        assert outcome.findings_resolved == 0
        assert (await findings_for(session, ise.id))[0].status == FindingStatus.NEW.value

    async def test_a_clean_estate_writes_nothing(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        switch = await add_device(session, actor, ip="198.51.100.1", hostname="sw-a")
        await snapshot(session, ise, server_ncm("ise", [client("sw-a", "198.51.100.1")]))
        await snapshot(session, switch, client_ncm([{"type": "radius", "host": "10.100.0.50"}]))

        outcome = await AaaAssessmentService(session).assess()

        assert outcome.findings_opened == 0
        assert await findings_for(session, switch.id) == []
        assert await findings_for(session, ise.id) == []

    async def test_an_empty_estate_does_not_fail(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        outcome = await AaaAssessmentService(session).assess()

        assert outcome.findings_opened == 0
        assert outcome.findings_resolved == 0
        assert outcome.registration_analysed is False


class TestFingerprints:
    async def test_the_fingerprint_does_not_change_when_the_description_does(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The fingerprint is the identity of the problem. If it included anything that
        moves — an address the server re-formats, a count, a date — every run would
        close the old row and open an identical new one, destroying the first-seen date
        that makes the row worth having."""
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        row = await snapshot(session, ise, server_ncm("ise", [client("ghost-sw", "10.88.0.1")]))
        await AaaAssessmentService(session).assess()
        before = (await findings_for(session, ise.id))[0].fingerprint

        # Same orphan, but the collection has since gone stale — which changes both the
        # severity and the prose. Ageing the existing snapshot rather than adding an old
        # one, because the correlation reads the *latest* snapshot and a back-dated
        # insert would simply be ignored.
        row.created_at = datetime.now(UTC) - timedelta(days=90)
        await session.flush()
        await AaaAssessmentService(session).assess()

        rows = await findings_for(session, ise.id)
        assert len(rows) == 1
        assert rows[0].fingerprint == before
        assert rows[0].severity == "low", "the severity moved, the identity did not"
