"""Reports as dated artefacts (FR-RPT-02, FR-RPT-03).

Most of this file exists to pin one property: **a stored report does not change when
the estate does.** That is what separates an archive from a saved query, and it is the
thing a future refactor is most likely to quietly undo — someone notices `content`
duplicates data that lives in `findings`, normalises it to ids, and every historical
report silently starts rewriting itself.

The test that matters is `test_a_report_does_not_change_when_the_estate_does`. If that
one goes, the feature is gone whether or not anything else still passes.

The rest covers the states that must not be confused: a pending report is not a clean
one, a failed report says why, and a template that exists in the catalogue but cannot be
assembled is refused rather than returned empty — an empty compliance report reads as a
compliant estate.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, User
from netsecops.db.models.collection import Finding, FindingKind, FindingStatus
from netsecops.db.models.inventory import Criticality, DeviceClass, Vendor
from netsecops.db.models.policy import ExceptionScope, FindingException
from netsecops.db.models.reporting import ReportFormat, ReportStatus, ReportTemplate
from netsecops.services.inventory import InventoryService
from netsecops.services.report_render import render
from netsecops.services.reporting import ReportingService, canonical_hash
from tests.conftest import make_user

REPORTS = "/api/v1/reports"
TEMPLATES = "/api/v1/reports/templates"


@pytest.fixture
async def analyst_user(session: AsyncSession) -> User:
    return await make_user(session, username="report_analyst", roles={Role.SECURITY_ANALYST})


@pytest.fixture
async def principal(analyst_user: User) -> Principal:
    return Principal(
        id=analyst_user.id,
        username=analyst_user.username,
        roles=analyst_user.role_set,
        scope=Scope.all(),
    )


async def add_device(
    session: AsyncSession, principal: Principal, *, ip: str, hostname: str
) -> Device:
    return await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=principal,
        hostname=hostname,
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
        criticality=Criticality.HIGH,
    )


async def add_finding(
    session: AsyncSession, device: Device, *, severity: str, check_id: str
) -> Finding:
    now = datetime.now(UTC)
    row = Finding(
        org_id=1,
        device_id=device.id,
        kind=FindingKind.CONFIG.value,
        fingerprint=f"config:{check_id}:{device.id}",
        title=f"{check_id} failed",
        severity=severity,
        status=FindingStatus.OPEN.value,
        check_id=check_id,
        first_seen_at=now,
        last_seen_at=now,
    )
    session.add(row)
    await session.flush()
    return row


@pytest.fixture
async def estate(session: AsyncSession, principal: Principal, analyst_user: User, authenticate):
    """Two devices, one clearly worse than the other."""
    bad = await add_device(session, principal, ip="10.0.1.1", hostname="sw-bad")
    ok = await add_device(session, principal, ip="10.0.1.2", hostname="sw-ok")

    await add_finding(session, bad, severity="critical", check_id="telnet-disabled")
    await add_finding(session, bad, severity="high", check_id="ssh-version-2")
    await add_finding(session, ok, severity="low", check_id="login-banner-present")

    await session.commit()
    authenticate(analyst_user)
    return {"bad": bad, "ok": ok}


class TestTheArchiveProperty:
    """The reason this subsystem exists."""

    async def test_a_report_does_not_change_when_the_estate_does(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """Generate, then resolve every finding, then re-read.

        If this fails, reports have become a saved query and the product can no longer
        answer "what did you know on 31 March".
        """
        service = ReportingService(session)
        report = await service.generate(ReportTemplate.EXECUTIVE_SUMMARY, actor=principal)
        await session.commit()

        before = json.dumps(report.content, sort_keys=True)
        assert report.content["totals"]["findings"] == 3

        # The estate moves on: everything is fixed.
        for finding in (await session.execute(select(Finding))).scalars().all():
            finding.status = FindingStatus.RESOLVED.value
        await session.commit()

        reread = await ReportingService(session).get(report.id)

        assert json.dumps(reread.content, sort_keys=True) == before
        assert reread.content["totals"]["findings"] == 3, "the archive was recomputed"

    async def test_a_second_report_reflects_the_new_reality(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """Freezing must not mean staleness — a NEW report sees the new state."""
        service = ReportingService(session)
        first = await service.generate(ReportTemplate.EXECUTIVE_SUMMARY, actor=principal)
        await session.commit()

        for finding in (await session.execute(select(Finding))).scalars().all():
            finding.status = FindingStatus.RESOLVED.value
        await session.commit()

        second = await ReportingService(session).generate(
            ReportTemplate.EXECUTIVE_SUMMARY, actor=principal
        )
        await session.commit()

        assert first.content["totals"]["findings"] == 3
        assert second.content["totals"]["findings"] == 0
        assert first.id != second.id

    async def test_the_hash_identifies_the_content(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        report = await ReportingService(session).generate(
            ReportTemplate.EXECUTIVE_SUMMARY, actor=principal
        )
        await session.commit()

        assert report.content_hash == canonical_hash(report.content)
        assert len(report.content_hash) == 64

    async def test_the_hash_is_insensitive_to_key_order(self) -> None:
        """Otherwise a recipient checking the hash gets spurious mismatches, and a check
        that cries wolf is one nobody runs twice."""
        a = {"totals": {"findings": 3}, "by_severity": {"critical": 1}}
        b = {"by_severity": {"critical": 1}, "totals": {"findings": 3}}

        assert canonical_hash(a) == canonical_hash(b)


class TestExecutiveSummary:
    async def test_it_ranks_the_worst_device_first(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        report = await ReportingService(session).generate(
            ReportTemplate.EXECUTIVE_SUMMARY, actor=principal
        )

        assert [d["hostname"] for d in report.content["top_devices"]] == ["sw-bad", "sw-ok"]
        assert report.content["top_devices"][0]["critical"] == 1

    async def test_devices_without_findings_are_not_called_clean(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """A device with no findings may never have been assessed. The report counts
        them, and deliberately does not name the count "clean"."""
        report = await ReportingService(session).generate(
            ReportTemplate.EXECUTIVE_SUMMARY, actor=principal
        )

        totals = report.content["totals"]
        assert "devices_without_findings" in totals
        assert "devices_clean" not in totals

    async def test_the_content_carries_its_own_provenance(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """A file mailed onward must be placeable without the console."""
        report = await ReportingService(session).generate(
            ReportTemplate.EXECUTIVE_SUMMARY, actor=principal
        )

        meta = report.content["meta"]
        assert meta["generated_by"] == principal.username
        assert meta["template"] == "executive_summary"
        assert meta["scope"] == "estate"
        assert meta["generated_at"]


class TestExceptionsRegister:
    """The report AlgoSec has no equivalent of."""

    async def test_it_records_who_accepted_the_risk_and_until_when(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        session.add(
            FindingException(
                org_id=1,
                check_id="telnet-disabled",
                scope=ExceptionScope.DEVICE.value,
                device_id=estate["bad"].id,
                justification="Lab switch, scheduled for decommission in Q4.",
                approver="ciso@example.com",
                expires_at=datetime.now(UTC) + timedelta(days=30),
                created_by_id=principal.id,
            )
        )
        await session.commit()

        report = await ReportingService(session).generate(
            ReportTemplate.EXCEPTIONS_REGISTER, actor=principal
        )

        entry = report.content["exceptions"][0]
        assert entry["approver"] == "ciso@example.com"
        assert entry["justification"].startswith("Lab switch")
        assert entry["expires_at"]
        assert entry["expired_at_generation"] is False

    async def test_expiry_is_judged_at_generation_not_at_read(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """An exception that lapses in April was still live in March, and March's
        report has to keep saying so."""
        session.add(
            FindingException(
                org_id=1,
                check_id="ssh-version-2",
                scope=ExceptionScope.GLOBAL.value,
                justification="Vendor fix pending, tracked in CHG0012345.",
                approver="ciso@example.com",
                expires_at=datetime.now(UTC) - timedelta(days=1),
                created_by_id=principal.id,
            )
        )
        await session.commit()

        report = await ReportingService(session).generate(
            ReportTemplate.EXCEPTIONS_REGISTER, actor=principal
        )

        assert report.content["totals"]["expired"] == 1
        assert report.content["exceptions"][0]["expired_at_generation"] is True


class TestTrend:
    async def test_it_compares_against_the_stored_report_not_live_data(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """Recomputing the old side would give a different answer every run."""
        service = ReportingService(session)
        first = await service.generate(ReportTemplate.EXECUTIVE_SUMMARY, actor=principal)
        await session.commit()

        for finding in (await session.execute(select(Finding))).scalars().all():
            finding.status = FindingStatus.RESOLVED.value
        await session.commit()

        trend = await ReportingService(session).generate(
            ReportTemplate.TREND, actor=principal, compare_to_id=first.id
        )
        await session.commit()

        assert trend.content["previous"]["findings"] == 3
        assert trend.content["current"]["findings"] == 0
        assert trend.content["findings_delta"] == -3
        assert trend.content["compared_to"]["content_hash"] == first.content_hash

    async def test_a_trend_without_a_comparison_is_refused(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        report = await ReportingService(session).generate(ReportTemplate.TREND, actor=principal)

        assert report.status == ReportStatus.FAILED.value
        assert "compare_to_id" in (report.error_message or "")


class TestStatesAreNotConfused:
    async def test_a_failed_report_says_why(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        report = await ReportingService(session).generate(ReportTemplate.TREND, actor=principal)
        await session.commit()

        assert report.status == ReportStatus.FAILED.value
        assert report.error_message
        assert report.content_hash is None

    async def test_a_failed_report_cannot_be_downloaded(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """A partial artefact must not leave the product looking like an assessment."""
        from netsecops.core.errors import ValidationProblem

        report = await ReportingService(session).generate(ReportTemplate.TREND, actor=principal)

        with pytest.raises(ValidationProblem, match="completed report"):
            render(report, ReportFormat.JSON)

    async def test_a_scope_cannot_be_both_a_device_and_a_group(
        self, session: AsyncSession, principal: Principal, estate, group_factory
    ) -> None:
        from netsecops.core.errors import ValidationProblem

        group = await group_factory(name="report-scope-group")
        with pytest.raises(ValidationProblem, match="not both"):
            await ReportingService(session).generate(
                ReportTemplate.EXECUTIVE_SUMMARY,
                actor=principal,
                scope_device_id=estate["bad"].id,
                scope_group_id=group.id,
            )


class TestRendering:
    async def test_json_carries_the_hash_so_a_recipient_can_check_it(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        report = await ReportingService(session).generate(
            ReportTemplate.EXECUTIVE_SUMMARY, actor=principal
        )

        payload = json.loads(render(report, ReportFormat.JSON))

        assert payload["content_hash"] == report.content_hash
        assert canonical_hash(payload["content"]) == report.content_hash

    async def test_csv_carries_a_provenance_header(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """A CSV detached from the console is otherwise a grid of numbers with no date."""
        report = await ReportingService(session).generate(
            ReportTemplate.EXECUTIVE_SUMMARY, actor=principal
        )

        text = render(report, ReportFormat.CSV).decode()

        assert "# generated_at," in text
        assert f"# content_hash,{report.content_hash}" in text
        assert "hostname,mgmt_ip,platform" in text
        assert "sw-bad" in text

    async def test_csv_columns_are_fixed_not_taken_from_the_first_row(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """A row missing an optional field would otherwise drop that column for every
        row, and the reader would never know it had existed."""
        report = await ReportingService(session).generate(
            ReportTemplate.EXECUTIVE_SUMMARY, actor=principal
        )
        report.content["top_devices"][0].pop("platform", None)

        text = render(report, ReportFormat.CSV).decode()

        assert "platform" in text.splitlines()[4]

    async def test_an_empty_csv_says_it_is_empty_rather_than_failed(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """No `estate` fixture here — an estate with nothing in it."""
        report = await ReportingService(session).generate(
            ReportTemplate.EXECUTIVE_SUMMARY, actor=principal
        )

        text = render(report, ReportFormat.CSV).decode()

        assert "no rows" in text
        assert "hostname,mgmt_ip" in text, "the columns must survive an empty result"

    async def test_a_template_with_no_csv_projection_is_refused(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """Rather than emit a blank spreadsheet, which reads as "no findings"."""
        from netsecops.core.errors import ValidationProblem

        service = ReportingService(session)
        first = await service.generate(ReportTemplate.EXECUTIVE_SUMMARY, actor=principal)
        await session.commit()
        trend = await ReportingService(session).generate(
            ReportTemplate.TREND, actor=principal, compare_to_id=first.id
        )

        with pytest.raises(ValidationProblem, match="no CSV projection"):
            render(trend, ReportFormat.CSV)

    async def test_the_filename_carries_the_date(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        from netsecops.services.report_render import filename_for

        report = await ReportingService(session).generate(
            ReportTemplate.EXECUTIVE_SUMMARY, actor=principal
        )

        name = filename_for(report, ReportFormat.JSON)
        assert name.startswith("netsecops-executive-summary-")
        assert name.endswith(".json")


class TestTheApi:
    async def test_templates_say_which_can_be_generated(self, client: AsyncClient, estate) -> None:
        rows = (await client.get(TEMPLATES)).json()

        assert len(rows) == 9
        implemented = {r["id"] for r in rows if r["implemented"]}
        assert implemented == {"executive_summary", "exceptions_register", "trend"}

    async def test_an_unimplemented_template_is_refused_not_returned_empty(
        self, client: AsyncClient, estate
    ) -> None:
        response = await client.post(REPORTS, json={"template": "group_compliance"})

        assert response.status_code == 422
        assert "not implemented" in response.text

    async def test_an_unknown_template_lists_the_known_ones(
        self, client: AsyncClient, estate
    ) -> None:
        response = await client.post(REPORTS, json={"template": "made_up"})

        assert response.status_code == 422
        assert "executive_summary" in response.text

    async def test_generate_then_download(self, client: AsyncClient, estate) -> None:
        created = await client.post(REPORTS, json={"template": "executive_summary"})
        assert created.status_code == 201, created.text
        report_id = created.json()["id"]

        download = await client.get(f"{REPORTS}/{report_id}/download", params={"format": "csv"})

        assert download.status_code == 200
        assert download.headers["content-type"].startswith("text/csv")
        assert "attachment" in download.headers["content-disposition"]
        assert "sw-bad" in download.text

    async def test_every_format_of_one_report_shares_its_hash(
        self, client: AsyncClient, estate
    ) -> None:
        """They are one report rendered differently, not three assessments."""
        created = (await client.post(REPORTS, json={"template": "executive_summary"})).json()

        as_json = await client.get(f"{REPORTS}/{created['id']}/download", params={"format": "json"})
        body = json.loads(as_json.text)

        assert body["content_hash"] == created["content_hash"]

    async def test_an_unknown_format_is_refused(self, client: AsyncClient, estate) -> None:
        created = (await client.post(REPORTS, json={"template": "executive_summary"})).json()

        response = await client.get(
            f"{REPORTS}/{created['id']}/download", params={"format": "xlsx"}
        )

        assert response.status_code == 422
        assert "json" in response.text

    async def test_reports_are_listed_newest_first(self, client: AsyncClient, estate) -> None:
        await client.post(REPORTS, json={"template": "executive_summary", "title": "First"})
        await client.post(REPORTS, json={"template": "executive_summary", "title": "Second"})

        body = (await client.get(REPORTS)).json()

        assert body["meta"]["total"] == 2
        assert body["data"][0]["title"] == "Second"

    async def test_generating_and_downloading_are_audited_separately(
        self, client: AsyncClient, session: AsyncSession, estate
    ) -> None:
        """Downloading is what puts the artefact outside the product."""
        from netsecops.db.models.audit import AuditAction, AuditLog

        created = (await client.post(REPORTS, json={"template": "executive_summary"})).json()
        await client.get(f"{REPORTS}/{created['id']}/download")

        actions = {row.action for row in (await session.execute(select(AuditLog))).scalars().all()}
        assert AuditAction.REPORT_GENERATED.value in actions
        assert AuditAction.REPORT_DOWNLOADED.value in actions
