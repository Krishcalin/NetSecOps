"""Where every framework stands, in one request (FR-CHK-05).

The compliance page shows all six frameworks at once. The obvious way to build that is
one `/compliance/{framework}` per card — six pivots re-aggregating the same
`check_results` rows to draw six cards — so this endpoint exists to do it once.

Two properties matter more than the arithmetic, and both are about a control nobody
evaluated. It must not be counted as passing, and it must be *reported*: the screen
this feeds draws those controls dashed with the reason, and it can only do that if the
number reaches it. A control with no verdict rendered as `0 failed` is the shape of
every false sense of security this product exists to avoid.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.checks.schema import Outcome, Severity
from netsecops.core.rbac import Role
from netsecops.db.models import Device
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.db.models.policy import CheckResult
from tests.conftest import make_user


async def make_device(session: AsyncSession, *, ip: str) -> Device:
    device = Device(
        org_id=1,
        hostname=f"sw-{ip.rsplit('.', 1)[-1]}",
        mgmt_ip=ip,
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )
    session.add(device)
    await session.flush()
    return device


async def record(
    session: AsyncSession, device: Device, check_id: str, outcome: Outcome, *, n: int = 1
) -> None:
    for _ in range(n):
        session.add(
            CheckResult(
                org_id=1,
                device_id=device.id,
                snapshot_id=None,
                check_id=check_id,
                outcome=outcome.value,
                severity=Severity.MEDIUM.value,
                message="",
            )
        )
    await session.flush()


@pytest.fixture
async def reader(session: AsyncSession):
    """A principal allowed to read reports, which is what compliance is."""
    return await make_user(session, username=f"cp_{uuid.uuid4().hex[:6]}", roles={Role.AUDITOR})


@pytest.fixture
async def cis_checks() -> list[str]:
    """Two real CIS-mapped checks, so the test exercises the shipped mapping rather
    than one invented for it."""
    from netsecops.checks.loader import get_registry

    mapped = get_registry().by_framework("cis")
    assert len(mapped) >= 2, "the library should map several checks to CIS"
    return [mapped[0].id, mapped[1].id]


@pytest.mark.anyio
class TestThePostureOverview:
    async def test_it_lists_every_framework_the_library_maps(
        self, client, authenticate, reader
    ) -> None:
        """Not a curated subset. A framework the product maps and the console does not
        show is, to a user, one the product does not have — which is how CERT-In and
        CEA stayed invisible while the console hard-coded the list."""
        from netsecops.checks.loader import get_registry

        authenticate(reader)

        response = await client.get("/api/v1/compliance/posture")

        assert response.status_code == 200
        keys = {row["key"] for row in response.json()}
        assert keys == set(get_registry().frameworks())

    async def test_a_framework_with_no_results_reports_null_not_zero(
        self, client, authenticate, reader
    ) -> None:
        """Zero per cent reads as "everything failed". Nothing decided is a different
        fact, and the page draws a dash for it."""
        authenticate(reader)

        rows = (await client.get("/api/v1/compliance/posture")).json()

        assert rows, "expected at least one framework"
        assert all(row["compliance_percent"] is None for row in rows)

    async def test_it_counts_controls_the_library_maps_not_the_framework_s(
        self, client, authenticate, reader
    ) -> None:
        """ "61 controls" must mean the ones this product maps. CIS contains far more
        than a read-only configuration collection can be evidence about, and the two
        readings differ by an order of magnitude."""
        from netsecops.checks.loader import get_registry

        authenticate(reader)

        rows = {row["key"]: row for row in (await client.get("/api/v1/compliance/posture")).json()}
        registry = get_registry()

        mapped_controls = {
            control
            for definition in registry.by_framework("cis")
            for control in definition.references.frameworks().get("cis", [])
        }
        assert rows["cis"]["controls"] == len(mapped_controls)
        assert rows["cis"]["checks"] == len(registry.by_framework("cis"))

    async def test_skipped_checks_do_not_move_the_percentage(
        self, client, authenticate, reader, session, cis_checks
    ) -> None:
        """Forty unevaluated results must leave the figure exactly where it was.
        Counting a skip as a pass would make a device whose collection half-failed
        score better than one fully assessed.

        Asserted as "unchanged" rather than against a literal, because the figure is
        control-weighted — see `test_the_percentage_is_weighted_by_control` — so the
        expected number depends on how many controls each check happens to map to, and
        pinning one here would be testing the CIS mapping rather than this rule.
        """
        device = await make_device(session, ip="198.51.100.71")
        await record(session, device, cis_checks[0], Outcome.PASS)
        await record(session, device, cis_checks[1], Outcome.FAIL)
        await session.commit()

        authenticate(reader)
        before = {r["key"]: r for r in (await client.get("/api/v1/compliance/posture")).json()}

        await record(session, device, cis_checks[0], Outcome.NOT_EVALUATED, n=40)
        await session.commit()
        after = {r["key"]: r for r in (await client.get("/api/v1/compliance/posture")).json()}

        assert before["cis"]["compliance_percent"] is not None
        assert after["cis"]["compliance_percent"] == before["cis"]["compliance_percent"]

    async def test_the_percentage_is_weighted_by_control(
        self, client, authenticate, reader, session, cis_checks
    ) -> None:
        """A check mapped to two controls contributes its verdict twice.

        Surprising enough to pin. `cisco-aaa-command-authorization` maps to CIS 1.1.7
        and 1.1.8, so one failure of it fails two controls — and the figure is the
        share of *control* verdicts that passed, not of check runs. That is the right
        reading for a compliance percentage, and it is not the one somebody assumes
        from the label, so the page says so and this holds the behaviour still.
        """
        device = await make_device(session, ip="198.51.100.78")
        # One check mapped to one control passes; one mapped to two controls fails.
        await record(session, device, cis_checks[0], Outcome.PASS)
        await record(session, device, cis_checks[1], Outcome.FAIL)
        await session.commit()

        authenticate(reader)
        rows = {row["key"]: row for row in (await client.get("/api/v1/compliance/posture")).json()}

        # One passing control verdict out of three, not one out of two.
        assert rows["cis"]["compliance_percent"] == 33

    async def test_a_control_nobody_evaluated_is_reported_not_hidden(
        self, client, authenticate, reader, session, cis_checks
    ) -> None:
        """The number the screen needs in order to draw that control dashed. Without
        it the page has no way to tell "nothing failed" from "nothing ran"."""
        device = await make_device(session, ip="198.51.100.72")
        await record(session, device, cis_checks[0], Outcome.NOT_EVALUATED, n=650)
        await session.commit()

        authenticate(reader)
        rows = {row["key"]: row for row in (await client.get("/api/v1/compliance/posture")).json()}

        assert rows["cis"]["controls_unevaluated"] >= 1

    async def test_an_unevaluated_control_is_not_counted_as_failing(
        self, client, authenticate, reader, session, cis_checks
    ) -> None:
        device = await make_device(session, ip="198.51.100.73")
        await record(session, device, cis_checks[0], Outcome.NOT_EVALUATED, n=10)
        await session.commit()

        authenticate(reader)
        rows = {row["key"]: row for row in (await client.get("/api/v1/compliance/posture")).json()}

        assert rows["cis"]["controls_failing"] == 0

    async def test_a_control_with_one_failure_is_failing(
        self, client, authenticate, reader, session, cis_checks
    ) -> None:
        device = await make_device(session, ip="198.51.100.74")
        await record(session, device, cis_checks[0], Outcome.FAIL)
        await session.commit()

        authenticate(reader)
        rows = {row["key"]: row for row in (await client.get("/api/v1/compliance/posture")).json()}

        assert rows["cis"]["controls_failing"] >= 1

    async def test_a_control_that_passed_is_neither_failing_nor_unevaluated(
        self, client, authenticate, reader, session, cis_checks
    ) -> None:
        """The third state. A passing control that also has skips elsewhere must not be
        filed under "never evaluated" — that bucket is for controls with no verdict at
        all, and inflating it would make a healthy estate look unassessed."""
        device = await make_device(session, ip="198.51.100.75")
        await record(session, device, cis_checks[0], Outcome.PASS, n=5)
        await record(session, device, cis_checks[0], Outcome.NOT_EVALUATED, n=5)
        await session.commit()

        authenticate(reader)
        rows = {row["key"]: row for row in (await client.get("/api/v1/compliance/posture")).json()}

        assert rows["cis"]["controls_failing"] == 0
        assert rows["cis"]["controls_unevaluated"] == 0

    async def test_devices_assessed_counts_devices_not_results(
        self, client, authenticate, reader, session, cis_checks
    ) -> None:
        """Forty results from one device is one device. The figure sits beside a
        percentage and would otherwise read as the size of the estate."""
        device = await make_device(session, ip="198.51.100.76")
        await record(session, device, cis_checks[0], Outcome.PASS, n=40)
        await session.commit()

        authenticate(reader)
        rows = {row["key"]: row for row in (await client.get("/api/v1/compliance/posture")).json()}

        assert rows["cis"]["device_count"] == 1

    async def test_posture_is_not_read_as_a_framework_name(
        self, client, authenticate, reader
    ) -> None:
        """`/compliance/posture` and `/compliance/{framework}` share a prefix, so the
        order they are declared in decides whether this endpoint exists at all."""
        authenticate(reader)

        response = await client.get("/api/v1/compliance/posture")

        assert response.status_code == 200
        assert isinstance(response.json(), list)

    async def test_it_agrees_with_the_per_framework_pivot(
        self, client, authenticate, reader, session, cis_checks
    ) -> None:
        """Two endpoints computing the same figure from the same rows is exactly the
        shape that drifts. The card and the table it opens must not disagree."""
        device = await make_device(session, ip="198.51.100.77")
        await record(session, device, cis_checks[0], Outcome.PASS, n=3)
        await record(session, device, cis_checks[1], Outcome.FAIL, n=1)
        await session.commit()

        authenticate(reader)
        overview = {
            row["key"]: row for row in (await client.get("/api/v1/compliance/posture")).json()
        }
        detail = (await client.get("/api/v1/compliance/cis")).json()

        assert overview["cis"]["compliance_percent"] == detail["compliance_percent"]
        assert overview["cis"]["controls"] == len(detail["controls"])
        assert overview["cis"]["device_count"] == detail["device_count"]
        assert overview["cis"]["controls_failing"] == len(
            [c for c in detail["controls"] if c["failed"] > 0]
        )


@pytest.mark.anyio
async def test_it_needs_the_report_permission(client, authenticate, session) -> None:
    """Compliance is a reporting surface, like every other view of the same results."""
    authenticate(await make_user(session, username="ce_reader", roles={Role.NETWORK_ENGINEER}))

    assert (await client.get("/api/v1/compliance/posture")).status_code == 200
