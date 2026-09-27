"""Is the estate getting better? (FR-FIND-05, FR-CHK-09)

The data has been accumulating since Phase 3 and nothing has ever read it as a series:
`risk_scores` keeps a row per computation *because* a single number cannot show a
direction, and no page has shown either the direction or the number.

Most of what follows pins the honesty of the answer rather than its arithmetic, because
a trend is the one chart people read without checking. Three specific ways it could
mislead:

* **A gap drawn as a slope.** A day with nothing on it has to appear as zero, or a line
  joins two distant points and reads as gradual change.
* **An empty window drawn as success.** No resolutions is not a mean time-to-resolve of
  zero, which reads as "fixed instantly".
* **A retrospective open-count.** The one the requirement asks for and the schema cannot
  support — reopening clears `resolved_at`, so the curve would be most wrong in the
  estates most worth charting. It is not offered, and a test holds it to that.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Scope
from netsecops.db.models import Device
from netsecops.db.models.collection import Finding, FindingKind, FindingSeverity, FindingStatus
from netsecops.db.models.inventory import DeviceClass, DeviceGroupMember, Vendor
from netsecops.db.models.policy import RiskScore
from netsecops.services.trends import MAX_DAYS, TrendService
from tests.conftest import make_group

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


async def make_device(session: AsyncSession, *, name: str = "core-sw-01", ip: str) -> Device:
    device = Device(
        org_id=1,
        hostname=name,
        mgmt_ip=ip,
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )
    session.add(device)
    await session.flush()
    return device


async def make_finding(
    session: AsyncSession,
    device: Device,
    *,
    fingerprint: str,
    severity: FindingSeverity = FindingSeverity.HIGH,
    status: FindingStatus = FindingStatus.OPEN,
    first_seen: datetime,
    resolved: datetime | None = None,
) -> Finding:
    finding = Finding(
        org_id=device.org_id,
        device_id=device.id,
        kind=FindingKind.CONFIG.value,
        fingerprint=fingerprint,
        title=fingerprint,
        severity=severity.value,
        status=status.value,
        first_seen_at=first_seen,
        last_seen_at=first_seen,
        resolved_at=resolved,
    )
    session.add(finding)
    await session.flush()
    return finding


@pytest.fixture
async def device(session: AsyncSession) -> Device:
    return await make_device(session, ip="198.51.100.10")


@pytest.fixture
def trends(session: AsyncSession) -> TrendService:
    return TrendService(session)


class TestItRefusesToDrawWhatItCannotKnow:
    """The requirement asks for open findings by severity over time. The schema keeps
    one row per problem carrying its current status, and reopening sets `resolved_at`
    back to NULL — so that series would be asserted, not measured."""

    @pytest.mark.anyio
    async def test_no_retrospective_open_count_is_offered(self, trends, device, session) -> None:
        await make_finding(session, device, fingerprint="a", first_seen=NOW - timedelta(days=10))

        trend = await trends.findings(scope=Scope.all(), days=30, now=NOW)

        # Each day carries what happened on it, never a reconstructed standing total.
        assert all(not hasattr(point, "open") for point in trend.points)
        assert all(not hasattr(point, "open_by_severity") for point in trend.points)

    @pytest.mark.anyio
    async def test_the_open_count_it_does_give_is_today_not_history(
        self, trends, device, session
    ) -> None:
        await make_finding(
            session,
            device,
            fingerprint="a",
            severity=FindingSeverity.CRITICAL,
            first_seen=NOW - timedelta(days=200),
        )

        trend = await trends.findings(scope=Scope.all(), days=7, now=NOW)

        # Outside the seven-day window, and still counted — because this is the current
        # state of the estate, not an event in the window.
        assert trend.open_by_severity["critical"] == 1

    @pytest.mark.anyio
    async def test_it_says_how_much_the_resolved_series_cannot_see(
        self, trends, device, session
    ) -> None:
        """A reopened finding's earlier resolution is gone from the row. Reporting the
        count of them is the difference between a series with a known blind spot and
        one that quietly under-reports."""
        await make_finding(
            session,
            device,
            fingerprint="came-back",
            status=FindingStatus.REOPENED,
            first_seen=NOW - timedelta(days=30),
        )

        trend = await trends.findings(scope=Scope.all(), days=30, now=NOW)

        assert trend.reopened_now == 1


class TestTheSeriesIsContinuous:
    @pytest.mark.anyio
    async def test_a_day_with_nothing_on_it_is_a_zero_not_a_gap(
        self, trends, device, session
    ) -> None:
        """Skipping empty days draws a line between two distant points, which reads as
        a gradual change rather than as no activity."""
        await make_finding(session, device, fingerprint="a", first_seen=NOW - timedelta(days=6))
        await make_finding(session, device, fingerprint="b", first_seen=NOW)

        trend = await trends.findings(scope=Scope.all(), days=7, now=NOW)

        assert len(trend.points) == 7
        assert [p.first_seen for p in trend.points] == [1, 0, 0, 0, 0, 0, 1]

    @pytest.mark.anyio
    async def test_the_window_ends_today(self, trends, device, session) -> None:
        trend = await trends.findings(scope=Scope.all(), days=7, now=NOW)

        assert trend.points[-1].day == NOW.date()
        assert trend.since == (NOW - timedelta(days=6)).date()

    @pytest.mark.anyio
    async def test_an_absurd_window_is_clamped_rather_than_refused(
        self, trends, device, session
    ) -> None:
        """A chart asking for ten years should get a year, not a 422 — and certainly
        not 3,650 rows."""
        trend = await trends.findings(scope=Scope.all(), days=3650, now=NOW)

        assert trend.days == MAX_DAYS


class TestFirstSeenIsExact:
    """`first_seen_at` is written once at creation and never cleared by anything —
    which is what makes this the one series that is true for all time."""

    @pytest.mark.anyio
    async def test_first_sightings_are_counted_on_their_day(self, trends, device, session) -> None:
        for i in range(3):
            await make_finding(
                session, device, fingerprint=f"f{i}", first_seen=NOW - timedelta(days=2)
            )

        trend = await trends.findings(scope=Scope.all(), days=5, now=NOW)

        assert {p.day: p.first_seen for p in trend.points}[(NOW - timedelta(days=2)).date()] == 3
        assert trend.total_first_seen == 3

    @pytest.mark.anyio
    async def test_first_sightings_are_split_by_severity(self, trends, device, session) -> None:
        await make_finding(
            session, device, fingerprint="c", severity=FindingSeverity.CRITICAL, first_seen=NOW
        )
        await make_finding(
            session, device, fingerprint="l", severity=FindingSeverity.LOW, first_seen=NOW
        )

        trend = await trends.findings(scope=Scope.all(), days=2, now=NOW)

        today = trend.points[-1]
        assert today.first_seen_by_severity["critical"] == 1
        assert today.first_seen_by_severity["low"] == 1
        # Every severity present, including the empty ones: a chart stacking four keys
        # on one day and five on the next is a chart with a hole in it.
        assert set(today.first_seen_by_severity) == {
            "critical",
            "high",
            "medium",
            "low",
            "info",
        }


class TestResolutionsThatStillStand:
    @pytest.mark.anyio
    async def test_a_resolution_is_counted_on_the_day_it_happened(
        self, trends, device, session
    ) -> None:
        await make_finding(
            session,
            device,
            fingerprint="fixed",
            status=FindingStatus.RESOLVED,
            first_seen=NOW - timedelta(days=10),
            resolved=NOW - timedelta(days=3),
        )

        trend = await trends.findings(scope=Scope.all(), days=14, now=NOW)

        assert {p.day: p.resolved for p in trend.points}[(NOW - timedelta(days=3)).date()] == 1

    @pytest.mark.anyio
    async def test_an_accepted_risk_is_not_a_resolution(self, trends, device, session) -> None:
        """Risk Accepted closes the finding without the problem going away. Counting it
        as resolved would let an estate improve its trend by accepting everything."""
        await make_finding(
            session,
            device,
            fingerprint="accepted",
            status=FindingStatus.RISK_ACCEPTED,
            first_seen=NOW - timedelta(days=10),
            resolved=NOW - timedelta(days=2),
        )

        trend = await trends.findings(scope=Scope.all(), days=14, now=NOW)

        assert trend.total_resolved == 0

    @pytest.mark.anyio
    async def test_a_false_positive_is_not_a_resolution_either(
        self, trends, device, session
    ) -> None:
        await make_finding(
            session,
            device,
            fingerprint="fp",
            status=FindingStatus.FALSE_POSITIVE,
            first_seen=NOW - timedelta(days=10),
            resolved=NOW - timedelta(days=2),
        )

        trend = await trends.findings(scope=Scope.all(), days=14, now=NOW)

        assert trend.total_resolved == 0


class TestTimeToResolve:
    @pytest.mark.anyio
    async def test_nothing_resolved_is_not_a_time_of_zero(self, trends, device, session) -> None:
        """Zero reads as "fixed instantly", which is the opposite of what an empty
        window means."""
        await make_finding(session, device, fingerprint="open", first_seen=NOW)

        trend = await trends.findings(scope=Scope.all(), days=30, now=NOW)

        assert trend.median_days_to_resolve is None
        assert trend.mean_days_to_resolve is None
        assert trend.resolved_in_window == 0

    @pytest.mark.anyio
    async def test_it_measures_from_the_first_sighting(self, trends, device, session) -> None:
        await make_finding(
            session,
            device,
            fingerprint="a",
            status=FindingStatus.RESOLVED,
            first_seen=NOW - timedelta(days=10),
            resolved=NOW - timedelta(days=4),
        )

        trend = await trends.findings(scope=Scope.all(), days=30, now=NOW)

        assert trend.median_days_to_resolve == 6.0
        assert trend.resolved_in_window == 1

    @pytest.mark.anyio
    async def test_the_median_is_reported_beside_the_mean(self, trends, device, session) -> None:
        """One finding left open for a year drags a mean somewhere no individual
        finding has ever been. Both are given so the skew is visible."""
        for i, age in enumerate([1, 1, 1, 365]):
            await make_finding(
                session,
                device,
                fingerprint=f"f{i}",
                status=FindingStatus.RESOLVED,
                first_seen=NOW - timedelta(days=age + 1),
                resolved=NOW - timedelta(days=1),
            )

        trend = await trends.findings(scope=Scope.all(), days=30, now=NOW)

        assert trend.median_days_to_resolve == 1.0
        assert trend.mean_days_to_resolve is not None
        assert trend.mean_days_to_resolve > 90


class TestItRespectsDeviceGroupScope:
    """A trend is an aggregate, and an unscoped one leaks the shape of devices a
    restricted operator cannot list — a slower version of leaking the devices."""

    @pytest.mark.anyio
    async def test_a_restricted_principal_sees_only_their_groups(self, trends, session) -> None:
        mine = await make_device(session, name="mine", ip="198.51.100.21")
        theirs = await make_device(session, name="theirs", ip="198.51.100.22")

        group = await make_group(session)
        session.add(DeviceGroupMember(org_id=1, group_id=group.id, device_id=mine.id))
        await session.flush()

        await make_finding(session, mine, fingerprint="a", first_seen=NOW)
        await make_finding(session, theirs, fingerprint="b", first_seen=NOW)

        scoped = await trends.findings(
            scope=Scope(device_group_ids=frozenset({group.id})), days=2, now=NOW
        )
        everything = await trends.findings(scope=Scope.all(), days=2, now=NOW)

        assert scoped.total_first_seen == 1
        assert everything.total_first_seen == 2

    @pytest.mark.anyio
    async def test_an_unrestricted_principal_can_still_narrow_to_one_group(
        self, trends, session
    ) -> None:
        """FR-FIND-05 asks for the trend "per group/org". Scope is what a caller *may*
        see; `group_id` is what they asked to see, and an administrator comparing two
        sites needs the second without giving up the first."""
        one = await make_device(session, name="site-a", ip="198.51.100.41")
        two = await make_device(session, name="site-b", ip="198.51.100.42")

        group = await make_group(session)
        session.add(DeviceGroupMember(org_id=1, group_id=group.id, device_id=one.id))
        await session.flush()

        await make_finding(session, one, fingerprint="a", first_seen=NOW)
        await make_finding(session, two, fingerprint="b", first_seen=NOW)

        narrowed = await trends.findings(scope=Scope.all(), days=2, group_id=group.id, now=NOW)
        everything = await trends.findings(scope=Scope.all(), days=2, now=NOW)

        assert narrowed.total_first_seen == 1
        assert sum(narrowed.open_by_severity.values()) == 1
        assert everything.total_first_seen == 2

    @pytest.mark.anyio
    async def test_the_current_open_count_is_scoped_too(self, trends, session) -> None:
        """The easiest half to forget: the series is filtered and the headline number
        beside it is not, so the chart and the total disagree."""
        mine = await make_device(session, name="mine2", ip="198.51.100.31")
        theirs = await make_device(session, name="theirs2", ip="198.51.100.32")

        group = await make_group(session)
        session.add(DeviceGroupMember(org_id=1, group_id=group.id, device_id=mine.id))
        await session.flush()

        await make_finding(session, mine, fingerprint="a", first_seen=NOW)
        await make_finding(session, theirs, fingerprint="b", first_seen=NOW)

        scoped = await trends.findings(
            scope=Scope(device_group_ids=frozenset({group.id})), days=2, now=NOW
        )

        assert sum(scoped.open_by_severity.values()) == 1


class TestRiskOverTime:
    """The series that was already exact and already ignored."""

    @pytest.mark.anyio
    async def test_the_points_come_back_oldest_first(self, trends, device, session) -> None:
        for offset, score in [(3, 70), (1, 40), (2, 55)]:
            session.add(
                RiskScore(
                    org_id=1,
                    device_id=device.id,
                    score=score,
                    checks_evaluated=10,
                    created_at=NOW - timedelta(days=offset),
                )
            )
        await session.flush()

        trend = await trends.risk(device.id, days=30, now=NOW)

        assert [p.score for p in trend.points] == [70, 55, 40]

    @pytest.mark.anyio
    async def test_a_falling_score_is_improving(self, trends, device, session) -> None:
        """Risk counts down to nothing, so the arrow points the opposite way to the
        number. Naming the direction on the server stops a report and the console
        disagreeing about the same two figures."""
        for offset, score in [(5, 80), (1, 20)]:
            session.add(
                RiskScore(
                    org_id=1,
                    device_id=device.id,
                    score=score,
                    checks_evaluated=10,
                    created_at=NOW - timedelta(days=offset),
                )
            )
        await session.flush()

        assert (await trends.risk(device.id, days=30, now=NOW)).direction == "improving"

    @pytest.mark.anyio
    async def test_a_rising_score_is_worsening(self, trends, device, session) -> None:
        for offset, score in [(5, 20), (1, 80)]:
            session.add(
                RiskScore(
                    org_id=1,
                    device_id=device.id,
                    score=score,
                    checks_evaluated=10,
                    created_at=NOW - timedelta(days=offset),
                )
            )
        await session.flush()

        assert (await trends.risk(device.id, days=30, now=NOW)).direction == "worsening"

    @pytest.mark.anyio
    async def test_one_assessment_has_no_direction(self, trends, device, session) -> None:
        """Not "steady", which claims a comparison that has not been made."""
        session.add(
            RiskScore(org_id=1, device_id=device.id, score=50, checks_evaluated=10, created_at=NOW)
        )
        await session.flush()

        assert (await trends.risk(device.id, days=30, now=NOW)).direction == "unknown"

    @pytest.mark.anyio
    async def test_a_device_never_assessed_has_no_points_and_no_direction(
        self, trends, device
    ) -> None:
        trend = await trends.risk(device.id, days=30, now=NOW)

        assert trend.points == []
        assert trend.direction == "unknown"

    @pytest.mark.anyio
    async def test_readings_are_not_bucketed_into_days(self, trends, device, session) -> None:
        """Two assessments on one day are two points. Averaging them into one would
        hide a device that was broken at nine and fixed by noon."""
        for hour, score in [(9, 80), (12, 10)]:
            session.add(
                RiskScore(
                    org_id=1,
                    device_id=device.id,
                    score=score,
                    checks_evaluated=10,
                    created_at=NOW.replace(hour=hour),
                )
            )
        await session.flush()

        trend = await trends.risk(device.id, days=30, now=NOW)

        assert [p.score for p in trend.points] == [80, 10]
