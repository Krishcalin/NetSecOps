"""The executive summary must not read the estate to count it (NFR-PERF-01, FR-RPT-02).

`_executive_summary` loaded every active finding in the estate, joined to its device, and
then counted them in Python. Its entire output is a dozen integers and a top-ten list —
so on a 2,000-device estate it materialised the findings table, with each row's JSONB
evidence and details and a duplicated device row apiece, to produce a page of numbers.
The cheapest thing in a report conceptually was the most expensive read in the product.

It is aggregated in SQL now. These pin the property rather than an implementation: the
number of queries must not grow with the number of findings, and the rows that carry the
weight must not be fetched at all.

No timing is asserted. This machine's DB-heavy timings vary by more than the effect being
measured, while a query count is exact on any hardware.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, User
from netsecops.db.models.collection import Finding, FindingKind, FindingStatus
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.services.inventory import InventoryService
from netsecops.services.reporting import ReportingService
from tests.conftest import make_user


@pytest.fixture
async def principal(session: AsyncSession) -> Principal:
    user: User = await make_user(session, username="report_cost", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@contextmanager
def counted(session: AsyncSession) -> Iterator[list[str]]:
    """Record every statement the session issues inside the block."""
    statements: list[str] = []
    bind = session.get_bind()

    def before(conn: Any, cursor: Any, statement: str, *_: Any) -> None:
        statements.append(statement)

    event.listen(bind, "before_cursor_execute", before)
    try:
        yield statements
    finally:
        event.remove(bind, "before_cursor_execute", before)


async def device_with_findings(
    session: AsyncSession, principal: Principal, *, number: int, findings: int
) -> Device:
    device = await InventoryService(session).create_device(
        mgmt_ip=f"10.70.{number // 250}.{number % 250 + 1}",
        actor=principal,
        hostname=f"rep-{number:03d}",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )
    now = datetime.now(UTC)
    for index in range(findings):
        session.add(
            Finding(
                org_id=1,
                device_id=device.id,
                kind=FindingKind.CONFIG.value,
                fingerprint=f"config:c{index}:{device.id}",
                title=f"check-{index} failed",
                severity=("critical", "high", "medium")[index % 3],
                status=FindingStatus.OPEN.value,
                check_id=f"check-{index}",
                first_seen_at=now,
                last_seen_at=now,
            )
        )
    await session.flush()
    return device


class TestExecutiveSummaryCost:
    async def test_the_query_count_does_not_grow_with_the_findings(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """The regression. Before the fix this read every finding to count them."""
        await device_with_findings(session, principal, number=0, findings=3)
        with counted(session) as small:
            await ReportingService(session)._executive_summary(Scope.all())

        for number in range(1, 5):
            await device_with_findings(session, principal, number=number, findings=6)
        with counted(session) as larger:
            await ReportingService(session)._executive_summary(Scope.all())

        assert len(larger) == len(small), (
            f"the summary cost {len(small)} queries over 3 findings and {len(larger)} "
            f"over 27. It is a page of counts; it must not scale with the estate."
        )

    async def test_the_finding_rows_are_never_fetched(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """A count does not need the row.

        `evidence` is JSONB and `description` and `remediation` are unbounded text; they
        are the bulk of a finding. Selecting them to discard them is most of what made
        this expensive, and it is invisible in a test that only checks the numbers.

        The columns are named individually rather than by a blanket `SELECT findings.*`
        check, and they are named from the model: an earlier draft asserted on
        `findings.details`, which is not a column, so it could never have failed.
        """
        await device_with_findings(session, principal, number=10, findings=4)

        with counted(session) as statements:
            await ReportingService(session)._executive_summary(Scope.all())

        issued = " ".join(statements).lower()
        for column in ("findings.evidence", "findings.description", "findings.remediation"):
            assert column not in issued, f"the summary fetched {column} to count rows"

    async def test_the_numbers_are_still_right(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """A faster wrong answer is not the goal.

        Six findings over two devices: severities cycle critical, high, medium, so each
        device carries one of each and the totals are exact rather than approximate.
        """
        await device_with_findings(session, principal, number=20, findings=3)
        await device_with_findings(session, principal, number=21, findings=3)

        summary = await ReportingService(session)._executive_summary(Scope.all())

        assert summary["totals"]["findings"] == 6
        assert summary["totals"]["devices_with_findings"] == 2
        assert summary["by_severity"]["critical"] == 2
        assert summary["by_severity"]["high"] == 2
        assert summary["by_severity"]["medium"] == 2
        # Zero-filled, so a severity with none reads as none rather than as absent.
        assert summary["by_severity"]["low"] == 0
        assert summary["by_kind"] == {"config": 6}

    async def test_the_worst_devices_are_ranked_and_capped_at_ten(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """Critical first, then high, then total — and only ten rows come back.

        The Python version built an entry for every device in the estate and sliced the
        top ten off the end; the ordering is the part that must survive moving into SQL.
        """
        await device_with_findings(session, principal, number=30, findings=1)  # 1 critical
        await device_with_findings(session, principal, number=31, findings=9)  # 3 critical
        for number in range(32, 45):
            await device_with_findings(session, principal, number=number, findings=2)

        summary = await ReportingService(session)._executive_summary(Scope.all())
        top = summary["top_devices"]

        assert len(top) == 10
        assert top[0]["hostname"] == "rep-031"
        assert top[0]["critical"] == 3
        assert top[0]["findings"] == 9
        # Descending by critical, so no later row may carry more than an earlier one.
        assert [row["critical"] for row in top] == sorted(
            (row["critical"] for row in top), reverse=True
        )
