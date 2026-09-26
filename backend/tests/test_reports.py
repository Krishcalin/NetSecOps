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

import inspect
import json
from datetime import UTC, datetime, timedelta
from typing import Any

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
from netsecops.schemas.reporting import PathSpec
from netsecops.services.inventory import InventoryService
from netsecops.services.report_render import NO_TABLE, TABLE_PROJECTIONS, render
from netsecops.services.reporting import TEMPLATE_CATALOGUE, ReportingService, canonical_hash
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


class TestEveryTemplateIsFullyRegistered:
    """Adding a template means touching five places that know nothing about each other.

    Before this, nothing checked that they agreed. A member added to the enum and the
    catalogue but missing from `_assemble` fails only when someone generates it, and a
    member missing from `TABLE_PROJECTIONS` fails only when someone downloads it as
    CSV — both long after the change that caused it.
    """

    def test_every_template_is_registered_everywhere(self) -> None:
        catalogued = set(TEMPLATE_CATALOGUE)
        projected = set(TABLE_PROJECTIONS) | set(NO_TABLE)
        missing_catalogue = {t.value for t in ReportTemplate if t not in catalogued}
        missing_projection = {t.value for t in ReportTemplate if t.value not in projected}

        assert not missing_catalogue, f"no TEMPLATE_CATALOGUE entry: {missing_catalogue}"
        assert not missing_projection, (
            f"no TABLE_PROJECTIONS or NO_TABLE entry: {missing_projection}"
        )

    def test_every_template_has_an_assembly_method_reachable_from_dispatch(self) -> None:
        """`_assemble` is a `match` over the enum, so a missing arm falls through to the
        defensive raise rather than to a type error. Reading the source for the arm is
        the only way to tell the two apart without generating every report."""
        source = inspect.getsource(ReportingService._assemble)

        for template in ReportTemplate:
            assert f"ReportTemplate.{template.name}:" in source, (
                f"{template.value} has no arm in _assemble, so it would fall through "
                "to the defensive raise"
            )

    def test_every_projection_names_a_content_key_its_template_produces(self) -> None:
        """A projection pointing at a key the assembler never writes renders an empty
        grid, which reads as "nothing to report" rather than as a wiring mistake."""
        for template in ReportTemplate:
            if template.value in NO_TABLE:
                continue
            key, columns = TABLE_PROJECTIONS[template.value]
            assert key, f"{template.value} projection names no content key"
            assert columns, f"{template.value} projection names no columns"


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

    async def test_a_template_with_no_table_projection_is_refused(
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

        for fmt in (ReportFormat.CSV, ReportFormat.XLSX):
            with pytest.raises(ValidationProblem, match="no table projection"):
                render(trend, fmt)

    async def test_a_template_with_no_table_still_renders_as_pdf(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """PDF can carry a nested document honestly, so it is not refused."""
        service = ReportingService(session)
        first = await service.generate(ReportTemplate.EXECUTIVE_SUMMARY, actor=principal)
        await session.commit()
        trend = await ReportingService(session).generate(
            ReportTemplate.TREND, actor=principal, compare_to_id=first.id
        )

        assert render(trend, ReportFormat.PDF).startswith(b"%PDF")

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

        # Against the enum rather than a literal count: the endpoint's job is to offer
        # every template there is, and a hardcoded number only ever fails on the commit
        # that adds one, which is the commit least in need of the reminder.
        assert {r["id"] for r in rows} == {t.value for t in ReportTemplate}
        assert all(r["implemented"] for r in rows), "every catalogued template assembles"

    async def test_a_template_needing_a_scope_says_so_before_generating(
        self, client: AsyncClient, estate
    ) -> None:
        """A 422 naming the field, not a 201 holding a failed report to open and read."""
        response = await client.post(REPORTS, json={"template": "device_detail"})

        assert response.status_code == 422
        assert "scope_device_id" in response.text
        assert "one device" in response.text

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

        response = await client.get(f"{REPORTS}/{created['id']}/download", params={"format": "doc"})

        assert response.status_code == 422
        assert "json" in response.text
        assert "pdf" in response.text

    async def test_all_four_formats_download(self, client: AsyncClient, estate) -> None:
        created = (await client.post(REPORTS, json={"template": "executive_summary"})).json()

        expected = {
            "json": "application/json",
            "csv": "text/csv",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "pdf": "application/pdf",
        }
        for fmt, content_type in expected.items():
            response = await client.get(
                f"{REPORTS}/{created['id']}/download", params={"format": fmt}
            )
            assert response.status_code == 200, f"{fmt}: {response.text[:200]}"
            assert response.headers["content-type"].startswith(content_type)
            assert f".{fmt}" in response.headers["content-disposition"]

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


class TestScopedTemplates:
    """The templates that are about one thing, and refuse to be about everything."""

    @pytest.mark.parametrize(
        ("template", "field"),
        [
            (ReportTemplate.DEVICE_DETAIL, "scope_device_id"),
            (ReportTemplate.FIREWALL_RULEBASE, "scope_device_id"),
            (ReportTemplate.GROUP_COMPLIANCE, "scope_group_id"),
        ],
    )
    async def test_a_missing_scope_fails_rather_than_widening_to_the_estate(
        self,
        session: AsyncSession,
        principal: Principal,
        estate,
        template: ReportTemplate,
        field: str,
    ) -> None:
        """Silently widening would file a document that answers a different question."""
        report = await ReportingService(session).generate(template, actor=principal)

        assert report.status == ReportStatus.FAILED.value
        assert field in (report.error_message or "")

    async def test_a_device_outside_the_scope_is_not_reportable(
        self, session: AsyncSession, analyst_user: User, estate, group_factory
    ) -> None:
        """A frozen artefact is worse than a live leak: it keeps working afterwards."""
        from netsecops.core.errors import NotFoundError

        group = await group_factory(name="somewhere-else")
        restricted = Principal(
            id=analyst_user.id,
            username=analyst_user.username,
            roles=analyst_user.role_set,
            scope=Scope(device_group_ids=frozenset({group.id})),
        )

        with pytest.raises(NotFoundError):
            await ReportingService(session)._require_device(estate["bad"].id, restricted.scope)


class TestDeviceDetail:
    async def test_it_carries_the_findings_and_the_assessment_date(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        report = await ReportingService(session).generate(
            ReportTemplate.DEVICE_DETAIL, actor=principal, scope_device_id=estate["bad"].id
        )

        assert report.status == ReportStatus.READY.value
        content = report.content
        assert content["device"]["hostname"] == "sw-bad"
        assert content["totals"]["findings"] == 2
        assert {f["check_id"] for f in content["findings"]} == {
            "telnet-disabled",
            "ssh-version-2",
        }

    async def test_a_device_never_assessed_says_so_rather_than_looking_clean(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """No snapshot is not a clean bill of health."""
        device = await add_device(session, principal, ip="10.0.9.9", hostname="sw-untouched")
        await session.commit()

        report = await ReportingService(session).generate(
            ReportTemplate.DEVICE_DETAIL, actor=principal, scope_device_id=device.id
        )

        assessment = report.content["assessment"]
        assert assessment["never_assessed"] is True
        assert assessment["assessed_at"] is None
        assert report.content["totals"]["findings"] == 0


class TestGroupCompliance:
    async def test_it_needs_a_framework(
        self, session: AsyncSession, principal: Principal, estate, group_factory
    ) -> None:
        group = await group_factory(name="compliance-group")
        await session.commit()

        report = await ReportingService(session).generate(
            ReportTemplate.GROUP_COMPLIANCE, actor=principal, scope_group_id=group.id
        )

        assert report.status == ReportStatus.FAILED.value
        assert "framework" in (report.error_message or "")

    async def test_an_empty_group_is_refused_rather_than_reported_compliant(
        self, session: AsyncSession, principal: Principal, estate, group_factory
    ) -> None:
        group = await group_factory(name="empty-group")
        await session.commit()

        report = await ReportingService(session).generate(
            ReportTemplate.GROUP_COMPLIANCE,
            actor=principal,
            scope_group_id=group.id,
            framework="cis",
        )

        assert report.status == ReportStatus.FAILED.value
        assert "no devices" in (report.error_message or "")

    async def test_not_evaluated_is_never_counted_as_a_pass(
        self, session: AsyncSession, principal: Principal, estate, group_factory
    ) -> None:
        """The arithmetic that makes compliance reports overstate posture."""
        from netsecops.checks.loader import get_registry
        from netsecops.db.models.inventory import DeviceGroupMember

        framework = sorted(get_registry().frameworks())[0]
        group = await group_factory(name="scored-group")
        session.add(DeviceGroupMember(org_id=1, group_id=group.id, device_id=estate["bad"].id))
        await session.commit()

        report = await ReportingService(session).generate(
            ReportTemplate.GROUP_COMPLIANCE,
            actor=principal,
            scope_group_id=group.id,
            framework=framework,
        )

        totals = report.content["totals"]
        # No check results exist, so nothing was decided. The percentage must be null
        # rather than 100 — an empty denominator is "no evidence", not "fully compliant".
        assert totals["denominator"] == 0
        assert totals["compliance_percentage"] is None
        assert totals["controls_never_assessed"] == totals["controls"]

    async def test_the_percentage_excludes_not_evaluated_from_its_denominator(
        self, session: AsyncSession, principal: Principal, estate, group_factory
    ) -> None:
        """One pass, one fail and two not-evaluated is 50%, not 25% and not 75%.

        This is the arithmetic the template exists to get right. Counting
        not-evaluated as a pass inflates to 75%; counting it as a fail deflates to 25%.
        Both are defensible-sounding and both are wrong: the honest statement is "of
        what we could decide, half passed, and two controls we could not decide".
        """
        from netsecops.checks.loader import get_registry
        from netsecops.db.models.inventory import DeviceGroupMember
        from netsecops.db.models.policy import CheckResult

        registry = get_registry()
        framework = next(
            f for f in sorted(registry.frameworks()) if len(registry.by_framework(f)) >= 4
        )
        mapped = registry.by_framework(framework)[:4]

        group = await group_factory(name="denominator-group")
        session.add(DeviceGroupMember(org_id=1, group_id=group.id, device_id=estate["bad"].id))

        outcomes = ["pass", "fail", "not_evaluated", "not_evaluated"]
        for definition, outcome in zip(mapped, outcomes, strict=True):
            session.add(
                CheckResult(
                    org_id=1,
                    device_id=estate["bad"].id,
                    check_id=definition.id,
                    outcome=outcome,
                    severity="medium",
                    message=f"{definition.id} -> {outcome}",
                    reason=None if outcome != "not_evaluated" else "NCM path not populated",
                )
            )
        await session.commit()

        report = await ReportingService(session).generate(
            ReportTemplate.GROUP_COMPLIANCE,
            actor=principal,
            scope_group_id=group.id,
            framework=framework,
        )

        totals = report.content["totals"]
        assert totals["passed"] == 1
        assert totals["failed"] == 1
        assert totals["not_evaluated"] == 2
        assert totals["denominator"] == 2, "not_evaluated must stay out of the denominator"
        assert totals["compliance_percentage"] == 50


class TestVulnerabilityReport:
    async def test_it_carries_the_unassessed_count_into_the_totals(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """ "12 CVEs" over an estate nobody scanned is not a posture statement."""
        report = await ReportingService(session).generate(
            ReportTemplate.VULNERABILITY, actor=principal
        )

        assert report.status == ReportStatus.READY.value
        assert "devices_unassessed" in report.content["totals"]

    async def test_it_says_the_kev_flags_are_unknown_not_false(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        report = await ReportingService(session).generate(
            ReportTemplate.VULNERABILITY, actor=principal
        )

        caveats = report.content["caveats"]
        assert caveats["kev_feed_ingested"] is False
        assert "unknown rather than false" in caveats["kev_note"]


class TestAaaReview:
    async def test_the_limitations_are_part_of_the_report(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """With no AAA server collected every device trivially appears on no client
        list, and the report has to say that rather than imply mass non-registration."""
        report = await ReportingService(session).generate(
            ReportTemplate.AAA_REVIEW, actor=principal
        )

        assert report.status == ReportStatus.READY.value
        caveats = report.content["caveats"]
        assert caveats["servers_examined"] == 0
        assert caveats["registration_analysed"] is False

    async def test_coverage_is_null_when_nothing_could_be_assessed(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        report = await ReportingService(session).generate(
            ReportTemplate.AAA_REVIEW, actor=principal
        )

        assert report.content["totals"]["coverage_percentage"] is None


class TestDriftReport:
    async def test_a_device_with_no_baseline_is_not_reported_in_sync(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """Nothing to compare against and nothing changed mean opposite things."""
        report = await ReportingService(session).generate(ReportTemplate.DRIFT, actor=principal)

        totals = report.content["totals"]
        assert totals["drifted"] == 0
        assert totals["never_assessed"] == 2, "neither device has a snapshot"
        assert totals["in_sync"] == 0

    async def test_the_states_are_distinct_in_the_rows(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        report = await ReportingService(session).generate(ReportTemplate.DRIFT, actor=principal)

        assert {d["state"] for d in report.content["devices"]} == {"never_assessed"}


@pytest.fixture
async def routed_estate(session: AsyncSession, principal: Principal):
    """edge-fw — core-rtr — dmz-fw, the same shape the topology tests walk.

    Built here rather than imported so this file stays readable on its own; the point
    of interest is that dmz-fw denies telnet and permits 443, so the same path answers
    differently on two ports.
    """
    from netsecops.db.models.collection import Snapshot

    async def add(hostname: str, mgmt_ip: str, body: dict[str, Any]) -> None:
        device = await InventoryService(session).create_device(
            mgmt_ip=mgmt_ip,
            actor=principal,
            hostname=hostname,
            vendor=Vendor.CISCO,
            platform="cisco_asa",
            device_class=DeviceClass.FIREWALL,
        )
        digest = f"{hostname:x<64}"[:64]
        session.add(
            Snapshot(
                org_id=1,
                device_id=device.id,
                ncm=body,
                ncm_version="1.1",
                config_hash=digest,
                normalized_hash=digest,
                config_redacted=f"! {hostname}",
            )
        )
        await session.flush()

    def ncm(interfaces, routes, firewall=None):
        return {
            "ncm_version": "1.1",
            "interfaces": interfaces,
            "routing": {"routes": routes, "protocols": []},
            "firewall": firewall or {},
        }

    def connected(prefix, interface):
        return {"destination": prefix, "interface": interface, "protocol": "connected"}

    def static(prefix, via, interface=None):
        return {
            "destination": prefix,
            "next_hop": via,
            "interface": interface,
            "protocol": "static",
        }

    await add(
        "edge-fw",
        "10.0.0.1",
        ncm(
            [
                {"name": "outside", "ip_addresses": ["203.0.113.2/29"], "zone": "outside"},
                {"name": "inside", "ip_addresses": ["10.0.0.1/30"], "zone": "inside"},
            ],
            [
                connected("203.0.113.0/29", "outside"),
                connected("10.0.0.0/30", "inside"),
                static("0.0.0.0/0", "203.0.113.1", "outside"),
                static("10.10.0.0/24", "10.0.0.2", "inside"),
            ],
            {"security_rules": [{"order": 1, "name": "permit-any", "action": "allow"}]},
        ),
    )
    await add(
        "core-rtr",
        "10.0.0.2",
        ncm(
            [
                {"name": "up", "ip_addresses": ["10.0.0.2/30"]},
                {"name": "lan", "ip_addresses": ["10.10.0.1/24"]},
                {"name": "dmz", "ip_addresses": ["10.0.1.1/30"]},
            ],
            [
                connected("10.0.0.0/30", "up"),
                connected("10.10.0.0/24", "lan"),
                connected("10.0.1.0/30", "dmz"),
                static("0.0.0.0/0", "10.0.0.1", "up"),
                static("10.20.0.0/24", "10.0.1.2", "dmz"),
            ],
        ),
    )
    await add(
        "dmz-fw",
        "10.0.1.2",
        ncm(
            [
                {"name": "up", "ip_addresses": ["10.0.1.2/30"], "zone": "trust"},
                {"name": "dmz", "ip_addresses": ["10.20.0.1/24"], "zone": "dmz"},
            ],
            [
                connected("10.0.1.0/30", "up"),
                connected("10.20.0.0/24", "dmz"),
                static("0.0.0.0/0", "10.0.1.1", "up"),
            ],
            {
                "security_rules": [
                    {"order": 1, "name": "no-telnet", "action": "deny", "services": ["tcp/23"]},
                    {"order": 2, "name": "permit-web", "action": "allow", "services": ["tcp/443"]},
                ]
            },
        ),
    )
    await session.commit()


class TestPathAnalysisReport:
    """The report a change ticket carries: one reachability question, frozen.

    Every other template summarises the estate. This one records an *answer*, which is
    why its parameters are part of the evidence rather than metadata — "allowed" means
    nothing without the question it answers.
    """

    async def test_it_records_the_question_alongside_the_answer(
        self, session: AsyncSession, principal: Principal, routed_estate
    ) -> None:
        report = await ReportingService(session).generate(
            ReportTemplate.PATH_ANALYSIS,
            actor=principal,
            path=PathSpec(source="10.10.0.5", destination="10.20.0.5", protocol="tcp", port=443),
        )

        assert report.status == ReportStatus.READY.value
        assert report.content["question"] == {
            "source": "10.10.0.5",
            "destination": "10.20.0.5",
            "protocol": "tcp",
            "port": 443,
        }
        # And on the row too, so "generate that again" is answerable without opening it.
        assert report.parameters["path"]["destination"] == "10.20.0.5"

    async def test_the_same_path_on_a_denied_port_reports_blocked_and_names_the_rule(
        self, session: AsyncSession, principal: Principal, routed_estate
    ) -> None:
        """The rule that decided is the whole point. "Blocked" without naming where is
        not evidence anyone can act on."""
        report = await ReportingService(session).generate(
            ReportTemplate.PATH_ANALYSIS,
            actor=principal,
            path=PathSpec(source="10.10.0.5", destination="10.20.0.5", protocol="tcp", port=23),
        )

        assert report.content["verdict"]["policy"] == "blocked"
        assert report.content["verdict"]["blocked_by"] == {
            "hostname": "dmz-fw",
            "rule_name": "no-telnet",
            "rule_order": 1,
        }
        denied = [h for h in report.content["hops"] if h["action"] == "deny"]
        assert [h["rule_name"] for h in denied] == ["no-telnet"]

    async def test_the_two_verdict_axes_are_never_merged(
        self, session: AsyncSession, principal: Principal, routed_estate
    ) -> None:
        """`allowed` only ever appears with `routed`. A single verdict would lose the
        case that matters most: a permit on the hops that were traced, where the trace
        stopped early and an untraced remainder may hold another firewall."""
        report = await ReportingService(session).generate(
            ReportTemplate.PATH_ANALYSIS,
            actor=principal,
            path=PathSpec(source="10.10.0.5", destination="10.20.0.5", protocol="tcp", port=443),
        )

        verdict = report.content["verdict"]
        assert set(verdict) >= {"routing", "policy"}
        if verdict["policy"] == "allowed":
            assert verdict["routing"] == "routed"

    async def test_a_hop_with_no_rulebase_is_not_recorded_as_a_permit(
        self, session: AsyncSession, principal: Principal, routed_estate
    ) -> None:
        """core-rtr is a router with no policy. It forwarded the packet without deciding
        anything, and printing "allow" there would credit it with a security decision it
        never made."""
        report = await ReportingService(session).generate(
            ReportTemplate.PATH_ANALYSIS,
            actor=principal,
            path=PathSpec(source="10.10.0.5", destination="10.20.0.5", protocol="tcp", port=443),
        )

        router_hop = next(h for h in report.content["hops"] if h["hostname"] == "core-rtr")
        assert router_hop["action"] is None
        assert report.content["totals"]["hops_without_a_rulebase"] >= 1

    async def test_it_cites_the_snapshots_it_was_computed_from(
        self, session: AsyncSession, principal: Principal, routed_estate
    ) -> None:
        """A path answer is only as current as the configurations behind it, so a report
        that cannot be traced back to them cannot settle a later argument."""
        report = await ReportingService(session).generate(
            ReportTemplate.PATH_ANALYSIS,
            actor=principal,
            path=PathSpec(source="10.10.0.5", destination="10.20.0.5", protocol="tcp", port=443),
        )

        evidence = report.content["evidence"]
        assert len(evidence["snapshot_ids"]) == 3
        assert evidence["devices_in_graph"] == 3

    async def test_hops_keep_their_order_explicitly(
        self, session: AsyncSession, principal: Principal, routed_estate
    ) -> None:
        """A hop means nothing except in relation to the one before it, and the CSV
        rendering can be re-sorted by any column. `sequence` is what lets it be put
        back."""
        report = await ReportingService(session).generate(
            ReportTemplate.PATH_ANALYSIS,
            actor=principal,
            path=PathSpec(source="10.10.0.5", destination="10.20.0.5", protocol="tcp", port=443),
        )

        hops = report.content["hops"]
        assert [h["sequence"] for h in hops] == list(range(1, len(hops) + 1))

    async def test_it_says_the_graph_was_the_whole_estate(
        self, session: AsyncSession, principal: Principal, routed_estate
    ) -> None:
        """Unlike every other template this one does not narrow to the reader's scope,
        because a graph truncated to what they may see produces a *wrong* path rather
        than a redacted one — it stops at the first hop outside their scope and calls it
        unreachable. That is a disclosure property and it is stated, not inferred."""
        report = await ReportingService(session).generate(
            ReportTemplate.PATH_ANALYSIS,
            actor=principal,
            path=PathSpec(source="10.10.0.5", destination="10.20.0.5", protocol="tcp", port=443),
        )

        assert report.content["caveats"]["graph_is_whole_estate"] is True

    async def test_a_report_with_no_path_is_refused_not_generated_empty(
        self, session: AsyncSession, principal: Principal, routed_estate
    ) -> None:
        """An empty path report would read as "nothing reaches anything"."""
        report = await ReportingService(session).generate(
            ReportTemplate.PATH_ANALYSIS, actor=principal
        )

        assert report.status == ReportStatus.FAILED.value
        assert "needs the path" in (report.error_message or "")

    async def test_the_api_names_the_missing_parameter_rather_than_failing_the_report(
        self, client: AsyncClient, routed_estate, analyst_user: User, authenticate
    ) -> None:
        authenticate(analyst_user)
        response = await client.post(REPORTS, json={"template": "path_analysis"})

        assert response.status_code == 422
        assert "path" in response.json()["detail"]

    async def test_it_renders_as_csv_with_the_hops_in_order(
        self, session: AsyncSession, principal: Principal, routed_estate
    ) -> None:
        report = await ReportingService(session).generate(
            ReportTemplate.PATH_ANALYSIS,
            actor=principal,
            path=PathSpec(source="10.10.0.5", destination="10.20.0.5", protocol="tcp", port=443),
        )
        body = render(report, ReportFormat.CSV).decode()

        rows = [line for line in body.splitlines() if line and not line.startswith("#")]
        assert rows[0].startswith("sequence,hostname")
        assert "core-rtr" in body
        assert "dmz-fw" in body


class TestFirewallRulebaseReport:
    async def test_a_device_with_no_rulebase_is_refused(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """Reporting zero shadowed rules for a switch would read as a clean rulebase."""
        report = await ReportingService(session).generate(
            ReportTemplate.FIREWALL_RULEBASE, actor=principal, scope_device_id=estate["bad"].id
        )

        assert report.status == ReportStatus.FAILED.value
        assert "no stored configuration" in (report.error_message or "")

    async def test_a_snapshot_without_rules_is_refused_not_reported_as_zero(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """A switch has no rulebase. "0 shadowed rules" would read as a clean one."""
        from netsecops.db.models.collection import Snapshot

        session.add(
            Snapshot(
                org_id=1,
                device_id=estate["bad"].id,
                config_hash="a" * 64,
                normalized_hash="b" * 64,
                config_redacted="hostname sw-bad\n",
                # A parsed switch: real NCM, no firewall section.
                ncm={"management": {"services": {}}},
                parser_platform="cisco_ios",
            )
        )
        await session.commit()

        report = await ReportingService(session).generate(
            ReportTemplate.FIREWALL_RULEBASE, actor=principal, scope_device_id=estate["bad"].id
        )

        assert report.status == ReportStatus.FAILED.value
        assert "no firewall rulebase" in (report.error_message or "")

    async def test_a_real_rulebase_is_analysed_and_its_caveats_frozen_with_it(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        """The success path. Whether external zones were supplied or guessed changes
        what a NAT exposure finding means, so it is stored beside the count rather than
        left in the console where a mailed file loses it."""
        from netsecops.db.models.collection import Snapshot

        def rule(order: int, name: str, **extra: Any) -> dict[str, Any]:
            return {
                "order": order,
                "name": name,
                "enabled": True,
                "src": ["any"],
                "dst": ["any"],
                "services": ["any"],
                "action": "allow",
                "src_zones": ["untrust"],
                "dst_zones": ["dmz"],
                **extra,
            }

        session.add(
            Snapshot(
                org_id=1,
                device_id=estate["bad"].id,
                config_hash="c" * 64,
                normalized_hash="d" * 64,
                config_redacted="",
                ncm={
                    "device": {"hostname": "fw-01", "vendor": "paloalto", "platform": "panos"},
                    "firewall": {
                        "security_rules": [
                            # Rule 2 is shadowed by rule 1: same zones, narrower source.
                            rule(1, "Permit everything"),
                            rule(2, "Partner access", src=["198.51.100.0/24"]),
                        ],
                        "zones": ["untrust", "dmz"],
                    },
                },
                parser_platform="panos",
            )
        )
        await session.commit()

        report = await ReportingService(session).generate(
            ReportTemplate.FIREWALL_RULEBASE, actor=principal, scope_device_id=estate["bad"].id
        )

        assert report.status == ReportStatus.READY.value, report.error_message
        content = report.content
        assert content["totals"]["rules_total"] == 2
        assert content["caveats"]["external_zones_inferred"] is True
        assert "zones" in content["caveats"]
        # The shadowed rule is the point of the report.
        assert content["totals"]["rules_with_issues"] >= 1


class TestRetention:
    async def test_an_expired_report_is_flagged_and_still_there(
        self, session: AsyncSession, principal: Principal, estate, client: AsyncClient
    ) -> None:
        """Nothing deletes evidence. An auditor cannot be told a cron removed it."""
        from netsecops.schemas.reporting import ReportRead

        report = await ReportingService(session).generate(
            ReportTemplate.EXECUTIVE_SUMMARY, actor=principal
        )
        report.expires_at = datetime.now(UTC) - timedelta(days=1)
        await session.commit()

        rows = (await client.get(REPORTS)).json()["data"]
        assert len(rows) == 1, "an expired report is still readable"
        assert rows[0]["retention_expired"] is True
        assert ReportRead.model_validate(report).retention_expired is True

    async def test_a_report_with_no_expiry_is_never_expired(
        self, session: AsyncSession, principal: Principal, estate
    ) -> None:
        from netsecops.schemas.reporting import ReportRead

        report = await ReportingService(session).generate(
            ReportTemplate.EXECUTIVE_SUMMARY, actor=principal
        )

        assert report.expires_at is None
        assert ReportRead.model_validate(report).retention_expired is False
