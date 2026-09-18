"""What would upgrading actually fix? (FR-VUL-10)

The assertions here cluster around one property, because it is the one a plausible
implementation gets wrong: a CVE that *cannot be ranked* against a candidate release is
neither eliminated nor remaining. Cisco IOS trains make that a routine case rather than a
corner one — `15.2(7)E3` and `15.2(4)M5` are parallel, with independent fix schedules, and
neither is later than the other.

Calling such a CVE eliminated tells somebody a vulnerability is fixed when it is not.
Calling it remaining is safer and still wrong: it makes a good upgrade look worse than it
is and steers the engineer toward a release that closes less.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.inventory import Device, DeviceClass, Vendor
from netsecops.db.models.vulnerability import VulnAdvisory, VulnCve, VulnMatch
from netsecops.services.inventory import InventoryService
from netsecops.services.upgrade_path import UpgradePathService
from tests.conftest import make_user


@pytest.fixture
async def principal(session: AsyncSession) -> Principal:
    user = await make_user(session, username="upgrade_planner", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def make_device(
    session: AsyncSession, principal: Principal, *, version: str | None, ip: str = "10.9.9.9"
) -> Device:
    device = await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=principal,
        hostname="sw-upgrade",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )
    device.os_version = version
    await session.flush()
    return device


async def add_match(
    session: AsyncSession,
    device: Device,
    *,
    advisory_id: str,
    cves: list[str],
    fixed: list[str],
    confidence: str = "confirmed",
    kev: bool = False,
) -> None:
    advisory = VulnAdvisory(
        org_id=device.org_id,
        source="test",
        advisory_id=advisory_id,
        title=advisory_id,
        cve_ids=cves,
        cwe_ids=[],
    )
    session.add(advisory)
    await session.flush()

    session.add(
        VulnMatch(
            org_id=device.org_id,
            device_id=device.id,
            advisory_id=advisory.id,
            confidence=confidence,
            cve_ids=cves,
            reasoning=["test"],
            fixed_versions=fixed,
        )
    )
    # One row per CVE, not per advisory: the same CVE routinely appears in two, and
    # `vuln_cves` is keyed on (org, cve).
    for cve in cves:
        existing = (
            await session.execute(
                select(VulnCve).where(VulnCve.org_id == device.org_id, VulnCve.cve_id == cve)
            )
        ).scalar_one_or_none()
        if existing is None:
            session.add(VulnCve(org_id=device.org_id, cve_id=cve, kev=kev))
        elif kev:
            existing.kev = True
    await session.flush()


def candidate(report, version: str):
    match = [c for c in report.candidates if c.version == version]
    assert match, f"{version} not offered; got {[c.version for c in report.candidates]}"
    return match[0]


# ══════════════════════════ the ordinary case ════════════════════════════════


class TestRanking:
    async def test_the_release_closing_most_ranks_first(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        device = await make_device(session, principal, version="17.3.1")
        await add_match(session, device, advisory_id="A-1", cves=["CVE-2026-1"], fixed=["17.6.1"])
        await add_match(session, device, advisory_id="A-2", cves=["CVE-2026-2"], fixed=["17.9.4"])
        await add_match(session, device, advisory_id="A-3", cves=["CVE-2026-3"], fixed=["17.9.4"])

        report = await UpgradePathService(session).for_device(device.id)

        assert report is not None
        assert report.candidates[0].version == "17.9.4"
        # 17.9.4 is later than 17.6.1, so it picks up that fix too.
        assert set(report.candidates[0].eliminates) == {
            "CVE-2026-1",
            "CVE-2026-2",
            "CVE-2026-3",
        }

    async def test_one_kev_outranks_several_that_are_not(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """The whole point of the view: make the next maintenance window count.

        A release closing one vulnerability under active exploitation beats one closing
        three nobody has ever attacked.

        The two candidates are on *parallel trains* on purpose. Put them on the same one
        and the higher release closes both sets, so it wins on volume and the KEV term
        never decides anything — which is exactly how an earlier version of this test
        passed while ranking by count alone.
        """
        device = await make_device(session, principal, version="15.2(4)M1")
        await add_match(
            session,
            device,
            advisory_id="KEV-1",
            cves=["CVE-2026-9"],
            fixed=["15.2(4)M5"],
            kev=True,
        )
        await add_match(
            session,
            device,
            advisory_id="QUIET",
            cves=["CVE-2026-10", "CVE-2026-11", "CVE-2026-12"],
            fixed=["15.2(7)E3"],
        )

        report = await UpgradePathService(session).for_device(device.id)

        assert report is not None
        assert report.candidates[0].version == "15.2(4)M5"
        assert report.candidates[0].kev_eliminated == 1
        # The release closing three times as many CVEs is still offered, just second.
        assert len(candidate(report, "15.2(7)E3").eliminates) == 3

    async def test_a_release_that_closes_nothing_is_not_offered(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        device = await make_device(session, principal, version="17.9.9")
        await add_match(session, device, advisory_id="OLD", cves=["CVE-2026-4"], fixed=["17.3.1"])

        report = await UpgradePathService(session).for_device(device.id)

        assert report is not None
        # The device is already past the fix, so there is nothing to recommend.
        assert report.candidates == []


# ═══════════════════════ what it refuses to claim ════════════════════════════


class TestParallelTrains:
    async def test_an_unrankable_cve_is_undetermined(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """Neither eliminated nor remaining — the property this module exists for."""
        device = await make_device(session, principal, version="15.2(4)M1")
        await add_match(
            session, device, advisory_id="E-TRAIN", cves=["CVE-2026-20"], fixed=["15.2(7)E3"]
        )
        await add_match(
            session, device, advisory_id="M-TRAIN", cves=["CVE-2026-21"], fixed=["15.2(4)M5"]
        )

        report = await UpgradePathService(session).for_device(device.id)
        assert report is not None

        m5 = candidate(report, "15.2(4)M5")
        assert "CVE-2026-21" in m5.eliminates
        # The E-train CVE cannot be ranked against an M-train release.
        assert "CVE-2026-20" in m5.undetermined
        assert "CVE-2026-20" not in m5.eliminates
        assert "CVE-2026-20" not in m5.remaining

    async def test_a_parallel_release_is_still_offered(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        # Moving between trains is a real migration an engineer may choose, and dropping
        # it would hide the only option that fixes some of these CVEs.
        device = await make_device(session, principal, version="15.2(4)M1")
        await add_match(
            session, device, advisory_id="E-TRAIN", cves=["CVE-2026-20"], fixed=["15.2(7)E3"]
        )

        report = await UpgradePathService(session).for_device(device.id)
        assert report is not None
        assert candidate(report, "15.2(7)E3").eliminates == ["CVE-2026-20"]

    async def test_an_unparseable_fixed_version_is_undetermined(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        # The advisory said something this reader did not understand. That cannot rule
        # the CVE out, and must not rule it in either.
        device = await make_device(session, principal, version="17.3.1")
        await add_match(session, device, advisory_id="GOOD", cves=["CVE-2026-30"], fixed=["17.9.4"])
        await add_match(
            session,
            device,
            advisory_id="PROSE",
            cves=["CVE-2026-31"],
            fixed=["see vendor bulletin"],
        )

        report = await UpgradePathService(session).for_device(device.id)
        assert report is not None
        assert "CVE-2026-31" in candidate(report, "17.9.4").undetermined


class TestHonestyAboutInputs:
    async def test_candidates_are_never_synthesised(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """Only versions an advisory actually names.

        Suggesting "try 17.9.5" because 17.9.4 is fixed would recommend a release that
        may not exist, and an engineer who schedules an outage for it does not get a
        second one.
        """
        device = await make_device(session, principal, version="17.3.1")
        await add_match(session, device, advisory_id="A", cves=["CVE-2026-40"], fixed=["17.9.4"])

        report = await UpgradePathService(session).for_device(device.id)
        assert report is not None
        assert [c.version for c in report.candidates] == ["17.9.4"]

    async def test_an_unparseable_current_version_is_flagged(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        # Every candidate is then reported without being filtered against it. Saying so
        # is the difference between a caveated answer and a wrong one.
        device = await make_device(session, principal, version="Version <unknown>")
        await add_match(session, device, advisory_id="A", cves=["CVE-2026-50"], fixed=["17.9.4"])

        report = await UpgradePathService(session).for_device(device.id)
        assert report is not None
        assert report.current_version_unparsed is True
        assert report.candidates

    async def test_unevaluated_advisories_do_not_credit_a_release(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """An upgrade plan built on unevaluated advisories credits a release with fixing
        things nobody established were broken."""
        device = await make_device(session, principal, version="17.3.1")
        await add_match(
            session,
            device,
            advisory_id="UNKNOWN",
            cves=["CVE-2026-60"],
            fixed=["17.9.4"],
            confidence="not_evaluated",
        )

        report = await UpgradePathService(session).for_device(device.id)
        assert report is not None
        assert report.candidates == []
        assert report.total_open_cves == 0

    async def test_a_cve_open_in_another_advisory_still_counts_as_remaining(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        # The same CVE fixed by one advisory and open in another is still open. Trusting
        # the per-advisory verdicts alone credits a release with a fix it only partly
        # delivers.
        device = await make_device(session, principal, version="17.3.1")
        await add_match(
            session, device, advisory_id="PARTIAL", cves=["CVE-2026-70"], fixed=["17.6.1"]
        )
        await add_match(session, device, advisory_id="FULL", cves=["CVE-2026-70"], fixed=["17.9.4"])

        report = await UpgradePathService(session).for_device(device.id)
        assert report is not None

        # Only the release that satisfies *both* advisories may claim it.
        claimed_by = {c.version for c in report.candidates if "CVE-2026-70" in c.eliminates}
        assert claimed_by == {"17.9.4"}

        # And 17.6.1 closes no CVE at all, so it is not worth offering as an upgrade.
        assert "17.6.1" not in {c.version for c in report.candidates}

    async def test_a_device_with_nothing_open_reports_cleanly(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        device = await make_device(session, principal, version="17.9.9")
        report = await UpgradePathService(session).for_device(device.id)

        assert report is not None
        assert (report.total_open_cves, report.candidates) == (0, [])

    async def test_an_unknown_device_is_not_found(self, session: AsyncSession) -> None:
        import uuid

        assert await UpgradePathService(session).for_device(uuid.uuid4()) is None
