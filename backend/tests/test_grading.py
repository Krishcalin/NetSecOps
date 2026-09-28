"""Letter grades and closure priorities (FR-CHK-09, FR-FIND-03).

A letter beside a firewall's name is the strongest claim this product makes in the
fewest characters, and the tests that matter are the ones that keep it from claiming
more than the data supports. Four things it could get wrong, in order of how badly:

* **Grade a device nobody has assessed.** `A` says clean, `F` says broken; the truth is
  that nobody looked, and only `None` says that.
* **Drift from the score.** The letter is a band of the stored risk score. The moment it
  is recomputed from anything else, a device can show `B` on one page and 62 on another.
* **Keep a second copy of the thresholds.** The priority matrix is computed from the
  same severity weights and criticality multipliers the score sums. A `CASE` expression
  in SQL, or a table in the console, would be free to disagree with the function.
* **Summarise the slice instead of the estate.** The grade table is capped at the worst
  N devices. A distribution computed from those rows is a distribution of the worst N,
  which is not a summary of anything and would look exactly like one.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import pairwise

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Scope
from netsecops.db.models import Device
from netsecops.db.models.collection import Finding, FindingKind, FindingSeverity, FindingStatus
from netsecops.db.models.inventory import (
    Criticality,
    DeviceClass,
    DeviceGroupMember,
    DeviceStatus,
    Vendor,
)
from netsecops.db.models.policy import RiskScore
from netsecops.services.grading import (
    GRADE_LETTERS,
    GRADES,
    PRIORITIES,
    PRIORITY_CODES,
    GradingService,
    grade_for,
    priority_for,
    priority_matrix,
    priority_weight,
)
from netsecops.services.risk import score_device
from tests.conftest import make_group

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


class _Result:
    """The shape `score_device` reads: an outcome and a severity."""

    def __init__(self, outcome: str, severity: str) -> None:
        self.outcome = outcome
        self.severity = severity


async def make_device(
    session: AsyncSession,
    *,
    ip: str,
    name: str | None = "core-sw-01",
    device_class: DeviceClass = DeviceClass.SWITCH,
    criticality: Criticality = Criticality.MEDIUM,
    status: DeviceStatus = DeviceStatus.ACTIVE,
) -> Device:
    device = Device(
        org_id=1,
        hostname=name,
        mgmt_ip=ip,
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=device_class.value,
        criticality=criticality.value,
        status=status.value,
    )
    session.add(device)
    await session.flush()
    return device


async def score(session: AsyncSession, device: Device, value: int, *, days_ago: int = 0) -> None:
    session.add(
        RiskScore(
            org_id=1,
            device_id=device.id,
            score=value,
            checks_evaluated=10,
            created_at=NOW - timedelta(days=days_ago),
        )
    )
    await session.flush()


async def make_finding(
    session: AsyncSession,
    device: Device,
    *,
    fingerprint: str,
    severity: FindingSeverity = FindingSeverity.HIGH,
    status: FindingStatus = FindingStatus.OPEN,
    first_seen: datetime | None = None,
    due_at: datetime | None = None,
) -> Finding:
    finding = Finding(
        org_id=device.org_id,
        device_id=device.id,
        kind=FindingKind.CONFIG.value,
        fingerprint=fingerprint,
        title=fingerprint,
        severity=severity.value,
        status=status.value,
        first_seen_at=first_seen or NOW,
        last_seen_at=first_seen or NOW,
        due_at=due_at,
    )
    session.add(finding)
    await session.flush()
    return finding


@pytest.fixture
def grading(session: AsyncSession) -> GradingService:
    return GradingService(session)


class TestTheLetterIsTheScore:
    """Not a second opinion about it."""

    def test_a_device_nobody_assessed_has_no_letter(self) -> None:
        # The whole reason `grade_for` returns an optional. `A` would call an
        # uncollected device clean and `F` would call it broken; both are inventions.
        assert grade_for(None) is None

    @pytest.mark.parametrize(
        ("findings", "criticality", "expected"),
        [
            # The scores these produce are what the band boundaries were placed at, so
            # each row is also a check that the boundary is still where it was put.
            ([], Criticality.MEDIUM, "A"),
            ([FindingSeverity.MEDIUM], Criticality.MEDIUM, "B"),
            ([FindingSeverity.HIGH], Criticality.MEDIUM, "C"),
            ([FindingSeverity.CRITICAL], Criticality.MEDIUM, "D"),
            ([FindingSeverity.CRITICAL], Criticality.CRITICAL, "E"),
            ([FindingSeverity.CRITICAL] * 2, Criticality.CRITICAL, "F"),
        ],
    )
    def test_each_letter_names_a_state_you_can_describe(
        self, findings: list[FindingSeverity], criticality: Criticality, expected: str
    ) -> None:
        """Run the real scorer, then band the real score.

        Asserting `grade_for(33) == "D"` would pass with the formula changed underneath
        it. This fails if either half moves, which is the pairing that makes the letter
        mean what the meaning string says it means.
        """
        results = [_Result("fail", severity.value) for severity in findings]
        breakdown = score_device(results, criticality=criticality)

        assert grade_for(breakdown.score) == expected

    def test_the_bands_tile_the_whole_range_with_no_gap_or_overlap(self) -> None:
        # A score landing between two bands would raise no error; `grade_for` would
        # simply fall through to F, and one device in the estate would silently be
        # graded by the fallback rather than by its score.
        assert GRADES[0].floor == 0
        assert GRADES[-1].ceiling == 100
        for lower, upper in pairwise(GRADES):
            assert upper.floor == lower.ceiling + 1

    def test_every_score_in_range_lands_on_a_letter(self) -> None:
        letters = {grade_for(n) for n in range(101)}
        assert letters == set(GRADE_LETTERS)

    def test_a_score_above_the_scale_still_grades_rather_than_crashing(self) -> None:
        """`score_device` caps at 100, but `risk_scores.score` is a plain integer with
        no check constraint. A row written by anything else must not fall off the end
        of the band list."""
        assert grade_for(150) == "F"

    def test_the_letters_are_ordered_worst_first(self) -> None:
        # The distribution is read in this order, and a reversed constant would put A
        # at the head of a list whose whole job is to lead with the bad news.
        assert GRADE_LETTERS == ("F", "E", "D", "C", "B", "A")


class TestThePriorityIsTheSameTwoNumbers:
    """Severity weight × criticality multiplier — what the risk score already sums."""

    @pytest.mark.parametrize(
        ("severity", "criticality", "expected"),
        [
            # Every critical finding is P1 wherever it sits: a `criticality` column is
            # set once at import and rarely revisited, and letting a stale field demote
            # a critical finding would be wrong in the direction that matters.
            (FindingSeverity.CRITICAL, Criticality.CRITICAL, "P1"),
            (FindingSeverity.CRITICAL, Criticality.LOW, "P1"),
            # Below that, criticality lifts exactly one band.
            (FindingSeverity.HIGH, Criticality.CRITICAL, "P1"),
            (FindingSeverity.HIGH, Criticality.HIGH, "P2"),
            (FindingSeverity.HIGH, Criticality.LOW, "P2"),
            (FindingSeverity.MEDIUM, Criticality.CRITICAL, "P2"),
            (FindingSeverity.MEDIUM, Criticality.MEDIUM, "P3"),
            (FindingSeverity.LOW, Criticality.CRITICAL, "P3"),
            (FindingSeverity.LOW, Criticality.MEDIUM, "P4"),
            (FindingSeverity.INFO, Criticality.CRITICAL, "P4"),
        ],
    )
    def test_the_matrix_is_what_it_claims_to_be(
        self, severity: FindingSeverity, criticality: Criticality, expected: str
    ) -> None:
        assert priority_for(severity.value, criticality.value) == expected

    def test_the_weight_is_the_score_formula_and_not_a_copy_of_it(self) -> None:
        """If someone re-tunes `Severity.weight` or `CRITICALITY_MULTIPLIER` for the
        risk score, the priorities have to move with it — which they do only because
        this is the same multiplication rather than a similar one."""
        one_finding = score_device(
            [_Result("fail", FindingSeverity.HIGH.value)], criticality=Criticality.CRITICAL
        )

        assert priority_weight(
            FindingSeverity.HIGH.value, Criticality.CRITICAL.value
        ) == pytest.approx(one_finding.weighted_total)

    def test_the_grid_is_computed_from_the_function_that_assigns_the_buckets(self) -> None:
        # The console draws this grid. Were it a literal table anywhere — here, in the
        # schema, in the front end — it could say P2 while `priority_for` said P1.
        cells = priority_matrix()

        assert len(cells) == len(FindingSeverity) * len(Criticality)
        for cell in cells:
            assert cell.priority == priority_for(cell.severity, cell.criticality)
            assert cell.weight == pytest.approx(
                priority_weight(cell.severity, cell.criticality), abs=0.005
            )

    def test_the_bands_are_ordered_worst_first_and_the_last_one_catches_everything(
        self,
    ) -> None:
        assert PRIORITY_CODES == ("P1", "P2", "P3", "P4")
        assert [band.floor for band in PRIORITIES] == sorted(
            (band.floor for band in PRIORITIES), reverse=True
        )
        # An info finding on a low-criticality device weighs nothing at all, and still
        # has to land somewhere — a finding with no priority is a finding nobody sees.
        assert PRIORITIES[-1].floor == 0.0
        assert priority_for(FindingSeverity.INFO.value, Criticality.LOW.value) == "P4"


class TestTheGradeTable:
    @pytest.mark.anyio
    async def test_it_leads_with_the_worst_device(self, grading, session) -> None:
        good = await make_device(session, name="quiet-sw", ip="198.51.100.10")
        bad = await make_device(session, name="loud-fw", ip="198.51.100.11")
        await score(session, good, 3)
        await score(session, bad, 88)

        report = await grading.grades(scope=Scope.all())

        assert [d.hostname for d in report.devices] == ["loud-fw", "quiet-sw"]
        assert [d.grade for d in report.devices] == ["F", "A"]

    @pytest.mark.anyio
    async def test_it_uses_the_most_recent_score_not_the_worst_one(self, grading, session) -> None:
        """A device that was bad in June and was fixed in July grades on July. Taking
        the maximum would mean no device could ever improve its letter."""
        device = await make_device(session, ip="198.51.100.12")
        await score(session, device, 90, days_ago=30)
        await score(session, device, 2, days_ago=1)

        report = await grading.grades(scope=Scope.all())

        assert report.devices[0].score == 2
        assert report.devices[0].grade == "A"

    @pytest.mark.anyio
    async def test_a_never_assessed_device_is_listed_last_and_counted_apart(
        self, grading, session
    ) -> None:
        assessed = await make_device(session, name="seen", ip="198.51.100.13")
        await score(session, assessed, 50)
        await make_device(session, name="unseen", ip="198.51.100.14")

        report = await grading.grades(scope=Scope.all())

        assert [d.hostname for d in report.devices] == ["seen", "unseen"]
        assert report.devices[-1].grade is None
        assert report.devices[-1].score is None
        assert report.ungraded == 1
        # Not folded into A, which is the bug this separates out: an estate of
        # uncollected devices would otherwise read as an estate in perfect health.
        assert report.by_grade["A"] == 0

    @pytest.mark.anyio
    async def test_the_distribution_covers_the_estate_even_when_the_table_is_capped(
        self, grading, session
    ) -> None:
        """The table is the worst N; the summary beside it is not. Computing both from
        the capped rows would show a three-hundred-device estate the distribution of
        its worst twenty, in a panel captioned as the whole estate."""
        for index, value in enumerate([95, 80, 40, 3]):
            device = await make_device(session, name=f"d{index}", ip=f"198.51.100.2{index}")
            await score(session, device, value)

        report = await grading.grades(scope=Scope.all(), limit=2)

        assert len(report.devices) == 2
        assert report.total_devices == 4
        assert report.by_grade["F"] == 2
        assert report.by_grade["D"] == 1
        assert report.by_grade["A"] == 1

    @pytest.mark.anyio
    async def test_the_estate_score_is_weighted_towards_the_worst_device(
        self, grading, session
    ) -> None:
        # `roll_up`'s contract: a hundred clean switches must not average away one
        # catastrophic firewall.
        for index, value in enumerate([100, 0, 0, 0]):
            device = await make_device(session, name=f"e{index}", ip=f"198.51.100.3{index}")
            await score(session, device, value)

        report = await grading.grades(scope=Scope.all())

        assert report.estate_score == 70
        assert report.estate_grade == "E"

    @pytest.mark.anyio
    async def test_an_estate_nobody_has_assessed_has_no_score_rather_than_nought(
        self, grading, session
    ) -> None:
        await make_device(session, ip="198.51.100.40")

        report = await grading.grades(scope=Scope.all())

        assert report.estate_score is None
        assert report.estate_grade is None

    @pytest.mark.anyio
    async def test_it_filters_to_one_class_of_appliance(self, grading, session) -> None:
        firewall = await make_device(
            session, name="fw", ip="198.51.100.50", device_class=DeviceClass.FIREWALL
        )
        switch = await make_device(
            session, name="sw", ip="198.51.100.51", device_class=DeviceClass.SWITCH
        )
        await score(session, firewall, 60)
        await score(session, switch, 60)

        report = await grading.grades(scope=Scope.all(), device_class=DeviceClass.FIREWALL.value)

        assert [d.hostname for d in report.devices] == ["fw"]
        # The summary narrows with the table, or the page shows a distribution of
        # everything above a list of firewalls and invites the reader to add them up.
        assert report.total_devices == 1

    @pytest.mark.anyio
    async def test_archived_devices_are_not_graded(self, grading, session) -> None:
        """They are not part of the estate any more. Listing them would pad the
        ungraded count with devices nobody expects a letter for."""
        await make_device(session, name="retired", ip="198.51.100.60", status=DeviceStatus.ARCHIVED)
        live = await make_device(session, name="live", ip="198.51.100.61")
        await score(session, live, 10)

        report = await grading.grades(scope=Scope.all())

        assert [d.hostname for d in report.devices] == ["live"]
        assert report.ungraded == 0

    @pytest.mark.anyio
    async def test_each_row_carries_the_worst_open_priority_on_that_device(
        self, grading, session
    ) -> None:
        """The grade says how bad the device is; this says what to do about it. A
        graded device with nothing open and one nobody has triaged read identically
        from the letter alone."""
        device = await make_device(session, ip="198.51.100.70", criticality=Criticality.LOW)
        await score(session, device, 40)
        await make_finding(session, device, fingerprint="a", severity=FindingSeverity.LOW)
        await make_finding(session, device, fingerprint="b", severity=FindingSeverity.CRITICAL)

        report = await grading.grades(scope=Scope.all())

        assert report.devices[0].open_findings == 2
        # Critical on a low-criticality device is still P1.
        assert report.devices[0].worst_priority == "P1"

    @pytest.mark.anyio
    async def test_a_resolved_finding_is_not_counted_against_a_device(
        self, grading, session
    ) -> None:
        device = await make_device(session, ip="198.51.100.71")
        await score(session, device, 10)
        await make_finding(session, device, fingerprint="done", status=FindingStatus.RESOLVED)

        report = await grading.grades(scope=Scope.all())

        assert report.devices[0].open_findings == 0
        assert report.devices[0].worst_priority is None


class TestThePriorityBuckets:
    @pytest.mark.anyio
    async def test_findings_land_in_the_band_the_matrix_says(self, grading, session) -> None:
        lab = await make_device(session, ip="198.51.100.80", criticality=Criticality.LOW)
        core = await make_device(session, ip="198.51.100.81", criticality=Criticality.CRITICAL)
        await make_finding(session, lab, fingerprint="a", severity=FindingSeverity.HIGH)
        await make_finding(session, core, fingerprint="b", severity=FindingSeverity.HIGH)

        report = await grading.priorities(scope=Scope.all())
        buckets = {b.code: b for b in report.buckets}

        # The same severity on two devices, one band apart — which is the only thing
        # criticality is doing in this scheme, and the thing worth a test.
        assert buckets["P1"].open == 1
        assert buckets["P2"].open == 1
        assert report.total_open == 2

    @pytest.mark.anyio
    async def test_every_band_is_returned_even_when_empty(self, grading, session) -> None:
        # A band that vanishes when it is empty makes "no P1s" look like a rendering
        # bug, and makes the four columns move about between refreshes.
        device = await make_device(session, ip="198.51.100.82")
        await make_finding(session, device, fingerprint="a", severity=FindingSeverity.LOW)

        report = await grading.priorities(scope=Scope.all())

        assert [b.code for b in report.buckets] == list(PRIORITY_CODES)
        assert all(b.open == 0 for b in report.buckets if b.code != "P4")

    @pytest.mark.anyio
    async def test_it_counts_devices_once_however_many_findings_they_have(
        self, grading, session
    ) -> None:
        """Two critical findings on one firewall is one firewall to visit. Summing the
        per-group device counts would say two."""
        device = await make_device(session, ip="198.51.100.83")
        await make_finding(session, device, fingerprint="a", severity=FindingSeverity.CRITICAL)
        await make_finding(session, device, fingerprint="b", severity=FindingSeverity.CRITICAL)

        report = await grading.priorities(scope=Scope.all())
        p1 = next(b for b in report.buckets if b.code == "P1")

        assert p1.open == 2
        assert p1.devices == 1

    @pytest.mark.anyio
    async def test_it_reports_the_oldest_and_the_mean_age_of_a_band(self, grading, session) -> None:
        device = await make_device(session, ip="198.51.100.84")
        for days, name in [(10, "a"), (20, "b")]:
            await make_finding(
                session,
                device,
                fingerprint=name,
                severity=FindingSeverity.CRITICAL,
                first_seen=NOW - timedelta(days=days),
            )

        report = await grading.priorities(scope=Scope.all(), now=NOW)
        p1 = next(b for b in report.buckets if b.code == "P1")

        assert p1.oldest_first_seen == NOW - timedelta(days=20)
        assert p1.mean_age_days == pytest.approx(15.0, abs=0.1)

    @pytest.mark.anyio
    async def test_an_empty_band_has_no_age_rather_than_an_age_of_nought(
        self, grading, session
    ) -> None:
        # Nought days would read as "everything here was found this morning", which is
        # the opposite of "there is nothing here".
        await make_device(session, ip="198.51.100.85")

        report = await grading.priorities(scope=Scope.all(), now=NOW)

        assert all(b.mean_age_days is None for b in report.buckets)
        assert all(b.oldest_first_seen is None for b in report.buckets)

    @pytest.mark.anyio
    async def test_it_separates_nothing_overdue_from_nobody_setting_dates(
        self, grading, session
    ) -> None:
        """`due_at` is only ever set by hand, so a nought in `overdue` usually means
        the column is unused. Reporting both makes that readable rather than
        reassuring."""
        device = await make_device(session, ip="198.51.100.86")
        await make_finding(
            session,
            device,
            fingerprint="late",
            severity=FindingSeverity.CRITICAL,
            due_at=NOW - timedelta(days=1),
        )
        await make_finding(
            session,
            device,
            fingerprint="soon",
            severity=FindingSeverity.CRITICAL,
            due_at=NOW + timedelta(days=7),
        )
        await make_finding(
            session, device, fingerprint="undated", severity=FindingSeverity.CRITICAL
        )

        report = await grading.priorities(scope=Scope.all(), now=NOW)
        p1 = next(b for b in report.buckets if b.code == "P1")

        assert p1.open == 3
        assert p1.with_due_date == 2
        assert p1.overdue == 1

    @pytest.mark.anyio
    async def test_resolved_and_accepted_findings_are_not_waiting_to_be_closed(
        self, grading, session
    ) -> None:
        device = await make_device(session, ip="198.51.100.87")
        for status in (
            FindingStatus.RESOLVED,
            FindingStatus.RISK_ACCEPTED,
            FindingStatus.FALSE_POSITIVE,
        ):
            await make_finding(
                session,
                device,
                fingerprint=status.value,
                severity=FindingSeverity.CRITICAL,
                status=status,
            )

        report = await grading.priorities(scope=Scope.all())

        assert report.total_open == 0

    @pytest.mark.anyio
    async def test_a_reopened_finding_is_open(self, grading, session) -> None:
        # It is the status most easily left out of an `IN` list, and the one that most
        # deserves to be in it: a problem that came back is a problem.
        device = await make_device(session, ip="198.51.100.88")
        await make_finding(
            session,
            device,
            fingerprint="back",
            severity=FindingSeverity.CRITICAL,
            status=FindingStatus.REOPENED,
        )

        report = await grading.priorities(scope=Scope.all())

        assert report.total_open == 1


class TestItShowsOnlyWhatTheCallerMaySee:
    """A grade is an aggregate, and an unscoped one leaks the shape of an estate a
    group-restricted operator cannot list."""

    @pytest.mark.anyio
    async def test_grades_are_restricted_to_the_callers_groups(self, grading, session) -> None:
        mine = await make_device(session, name="mine", ip="198.51.100.90")
        theirs = await make_device(session, name="theirs", ip="198.51.100.91")
        await score(session, mine, 10)
        await score(session, theirs, 90)

        group = await make_group(session)
        session.add(DeviceGroupMember(org_id=1, group_id=group.id, device_id=mine.id))
        await session.flush()

        report = await grading.grades(scope=Scope(device_group_ids=frozenset({group.id})))

        assert [d.hostname for d in report.devices] == ["mine"]
        assert report.total_devices == 1
        # The roll-up is scoped too, or the summary above the table describes an estate
        # the table cannot show.
        assert report.estate_score == 10

    @pytest.mark.anyio
    async def test_priorities_are_restricted_to_the_callers_groups(self, grading, session) -> None:
        mine = await make_device(session, name="mine2", ip="198.51.100.92")
        theirs = await make_device(session, name="theirs2", ip="198.51.100.93")
        await make_finding(session, mine, fingerprint="a", severity=FindingSeverity.CRITICAL)
        await make_finding(session, theirs, fingerprint="b", severity=FindingSeverity.CRITICAL)

        group = await make_group(session)
        session.add(DeviceGroupMember(org_id=1, group_id=group.id, device_id=mine.id))
        await session.flush()

        report = await grading.priorities(scope=Scope(device_group_ids=frozenset({group.id})))

        assert report.total_open == 1

    @pytest.mark.anyio
    async def test_a_group_scope_reaches_its_child_groups(self, grading, session) -> None:
        """The inventory walks the `ltree` path, so an operator scoped to a parent
        group lists devices in its children. A grade table that matched groups exactly
        would show fewer devices than the page they arrived from."""
        parent = await make_group(session, name="datacentre")
        child = await make_group(session, name="rack-1", parent=parent)

        device = await make_device(session, name="nested", ip="198.51.100.94")
        session.add(DeviceGroupMember(org_id=1, group_id=child.id, device_id=device.id))
        await session.flush()
        await score(session, device, 40)

        report = await grading.grades(scope=Scope(device_group_ids=frozenset({parent.id})))

        assert [d.hostname for d in report.devices] == ["nested"]

    @pytest.mark.anyio
    async def test_a_principal_scoped_to_nothing_sees_nothing(self, grading, session) -> None:
        # Failing open here would hand a newly created account with no groups yet the
        # whole estate's grades.
        device = await make_device(session, ip="198.51.100.95")
        await score(session, device, 40)
        await make_finding(session, device, fingerprint="a", severity=FindingSeverity.CRITICAL)

        grades = await grading.grades(scope=Scope(device_group_ids=frozenset()))
        priorities = await grading.priorities(scope=Scope(device_group_ids=frozenset()))

        assert grades.devices == []
        assert grades.total_devices == 0
        assert priorities.total_open == 0
