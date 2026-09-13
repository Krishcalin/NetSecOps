"""Phase 3 acceptance (SRS §12).

    CIS Cisco IOS L1 policy runs end-to-end with evidence and line provenance.

Written as one continuous path, because the criterion is that the chain connects:
seed the shipped policy → assign it to the device's group → collect a configuration →
assess it → get findings that cite the operator's own configuration lines → fix the
device → watch the findings resolve themselves.

The individual links have their own tests in test_check_engine.py, test_policies.py and
test_risk.py. This asserts they join up, and that the two things an auditor actually
asks for — *which control failed* and *show me where* — both come out of the far end.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.checks.schema import Outcome, Severity
from netsecops.core.crypto import SecretVault
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import AuditLog, Device, Finding, User
from netsecops.db.models.collection import FindingKind, FindingStatus
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.db.models.policy import ExceptionScope
from netsecops.services.assessment import AssessmentService
from netsecops.services.inventory import InventoryService
from netsecops.services.policies import PolicyService
from netsecops.services.snapshots import SnapshotService
from tests.conftest import make_group, make_user

FIXTURES = Path(__file__).parent / "fixtures"
HARDENED = (FIXTURES / "cisco/ios/17.9/hardened_switch.cfg").read_text(encoding="utf-8")
WEAK = (FIXTURES / "cisco/ios/15.2/weak_switch.cfg").read_text(encoding="utf-8")

CIS_PACK = "cis-cisco-ios-l1"


async def find_finding(session: AsyncSession, device: Device, check_id: str) -> Finding | None:
    """The finding a check raised on a device, if it raised one."""
    from netsecops.services.assessment import finding_fingerprint

    return (
        await session.execute(
            select(Finding).where(
                Finding.device_id == device.id,
                Finding.fingerprint == finding_fingerprint(check_id),
            )
        )
    ).scalar_one_or_none()


async def require_finding(session: AsyncSession, device: Device, check_id: str) -> Finding:
    found = await find_finding(session, device, check_id)
    assert found is not None, f"no finding was raised for {check_id}"
    return found


@pytest.fixture
async def analyst(session: AsyncSession) -> Principal:
    user = await make_user(session, username="phase3_analyst", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
async def device(session: AsyncSession, analyst: Principal) -> Device:
    return await InventoryService(session).create_device(
        mgmt_ip="198.51.100.31",
        actor=analyst,
        hostname="core-sw-01",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )


class TestPhase3Acceptance:
    async def test_the_whole_chain(
        self,
        session: AsyncSession,
        analyst: Principal,
        device: Device,
        vault: SecretVault,
    ) -> None:
        policies = PolicyService(session)
        snapshots = SnapshotService(session, vault=vault)
        assessments = AssessmentService(session)

        # ── 1. the shipped CIS policy installs ───────────────────────────
        installed = await policies.seed_packs()
        cis = next(p for p in installed if p.source == CIS_PACK)

        assert cis.frameworks == ["cis"]
        assert len(cis.entries) >= 40
        assert cis.is_default, "the first installed pack should become the default"

        # Seeding twice must not duplicate or overwrite.
        assert await policies.seed_packs() == []

        # ── 2. assign it to the device's group ───────────────────────────
        group = await make_group(session, name="phase3-core")
        await InventoryService(session).update_device(device, actor=analyst, group_ids=[group.id])
        await policies.assign(cis, group.id, actor=analyst)

        assert (await assessments.policy_for_device(device)).id == cis.id

        # ── 3. assess the weak configuration ─────────────────────────────
        weak_snapshot = await snapshots.create_snapshot(device, config_text=WEAK)
        outcome = await assessments.assess(device, weak_snapshot)

        assert outcome.policy_id == cis.id
        assert len(outcome.results) == len(cis.entries)
        assert outcome.findings_opened > 10, "the weak fixture should fail many controls"

        # ── 4. the findings cite the operator's own configuration ────────
        findings = (
            (
                await session.execute(
                    select(Finding).where(
                        Finding.device_id == device.id, Finding.kind == FindingKind.CONFIG.value
                    )
                )
            )
            .scalars()
            .all()
        )
        assert findings

        telnet = next(f for f in findings if f.check_id == "telnet-disabled")
        assert telnet.severity == Severity.CRITICAL.value
        assert telnet.status == FindingStatus.NEW.value
        assert telnet.remediation, "a finding without remediation is a complaint"

        # This is the acceptance criterion's "with evidence and line provenance".
        lines = telnet.evidence["lines"]
        assert lines, "the finding carries no evidence"
        assert lines[0]["line_start"] is not None
        assert lines[0]["excerpt"]

        # And the cited line is really in the configuration it claims to come from.
        cited = WEAK.splitlines()[lines[0]["line_start"] - 1]
        assert lines[0]["excerpt"].strip() in cited.strip()

        # ── 5. every outcome is recorded, not just the failures ──────────
        results = await assessments.results_for_snapshot(weak_snapshot.id)
        assert len(results) == len(cis.entries)
        assert {r.outcome for r in results} >= {Outcome.FAIL.value, Outcome.PASS.value}

        # ── 6. the risk score is explainable, not just asserted ──────────
        assert outcome.risk is not None
        assert 0 < outcome.risk.score <= 100
        components = outcome.risk.to_components()
        assert components["weighted_total"] > 0
        assert components["compliance_percent"] is not None
        assert components["coverage_percent"] is not None

        # ── 7. hardening the device resolves the findings ────────────────
        good_snapshot = await snapshots.create_snapshot(device, config_text=HARDENED)
        after = await assessments.assess(device, good_snapshot)

        assert after.findings_resolved > 0
        await session.refresh(telnet)
        assert telnet.status == FindingStatus.RESOLVED.value
        assert telnet.resolved_at is not None

        # The risk score moved in the right direction, which is the point of having one.
        assert after.risk is not None
        assert after.risk.score < outcome.risk.score

        # ── 8. the audit chain survived all of it ────────────────────────
        await session.flush()
        assert (await policies.audit.verify_chain()).valid

    async def test_a_regression_reopens_rather_than_duplicating(
        self,
        session: AsyncSession,
        analyst: Principal,
        device: Device,
        vault: SecretVault,
    ) -> None:
        """FR-FIND-01. Turning Telnet back on must reopen the original finding, so its
        history shows a regression rather than presenting as a first sighting."""
        snapshots = SnapshotService(session, vault=vault)
        assessments = AssessmentService(session)
        await PolicyService(session).seed_packs()

        first = await snapshots.create_snapshot(device, config_text=WEAK)
        await assessments.assess(device, first)

        telnet = await require_finding(session, device, "telnet-disabled")
        original_id, first_seen = telnet.id, telnet.first_seen_at

        good = await snapshots.create_snapshot(device, config_text=HARDENED)
        await assessments.assess(device, good)
        await session.refresh(telnet)
        assert telnet.status == FindingStatus.RESOLVED.value

        # It comes back.
        regressed = await snapshots.create_snapshot(
            device, config_text=WEAK.replace("hostname core-sw-01", "hostname core-sw-01 ")
        )
        await assessments.assess(device, regressed)
        await session.refresh(telnet)

        assert telnet.id == original_id
        assert telnet.status == FindingStatus.REOPENED.value
        assert telnet.resolved_at is None
        assert telnet.first_seen_at == first_seen, "first_seen must record the original sighting"
        # Opened once, then seen again on the regression. The run where it passed does
        # not increment — occurrences counts sightings of the problem, not assessments.
        assert telnet.occurrences == 2

    async def test_an_exception_suppresses_the_finding_but_not_the_result(
        self,
        session: AsyncSession,
        analyst: Principal,
        device: Device,
        vault: SecretVault,
    ) -> None:
        """FR-CHK-07. The check still ran and its outcome is still stored — hiding that
        would make the compliance figure a fiction."""
        policies = PolicyService(session)
        snapshots = SnapshotService(session, vault=vault)
        assessments = AssessmentService(session)
        await policies.seed_packs()

        await policies.create_exception(
            check_id="telnet-disabled",
            scope=ExceptionScope.DEVICE,
            device_id=device.id,
            justification="Migration to SSH completes on 30 June; CAB approved NET-4821.",
            approver="change-board",
            expires_at=datetime.now(UTC) + timedelta(days=30),
            actor=analyst,
        )

        snapshot = await snapshots.create_snapshot(device, config_text=WEAK)
        outcome = await assessments.assess(device, snapshot)

        assert outcome.findings_suppressed >= 1

        # No finding...
        assert await find_finding(session, device, "telnet-disabled") is None

        # ...but the result is there, recording that the check ran and failed.
        result = next(
            r
            for r in await assessments.results_for_snapshot(snapshot.id)
            if r.check_id == "telnet-disabled"
        )
        assert result.outcome == Outcome.FAIL.value
        assert result.suppressed_by_id is not None

    async def test_an_expired_exception_stops_suppressing(
        self,
        session: AsyncSession,
        analyst: Principal,
        device: Device,
        vault: SecretVault,
    ) -> None:
        """The expiry is the whole point of the record. An exception that outlives its
        date without reopening the finding is an undocumented decision."""
        policies = PolicyService(session)
        snapshots = SnapshotService(session, vault=vault)
        assessments = AssessmentService(session)
        await policies.seed_packs()

        exception = await policies.create_exception(
            check_id="telnet-disabled",
            scope=ExceptionScope.DEVICE,
            device_id=device.id,
            justification="Short-lived acceptance for the migration window.",
            expires_at=datetime.now(UTC) + timedelta(days=1),
            actor=analyst,
        )

        # Move the clock past the expiry by editing the row, which is what the passage
        # of time does. is_active computes against the clock, so no sweep is needed.
        exception.expires_at = datetime.now(UTC) - timedelta(hours=1)
        await session.flush()
        assert exception.is_active is False

        snapshot = await snapshots.create_snapshot(device, config_text=WEAK)
        outcome = await assessments.assess(device, snapshot)

        assert outcome.findings_suppressed == 0
        assert await find_finding(session, device, "telnet-disabled") is not None

        # The housekeeping pass makes the state visible rather than causing it.
        assert await assessments.expire_exceptions() == 1
        await session.refresh(exception)
        assert exception.status == "expired"

    async def test_a_partial_collection_is_assessed_honestly(
        self,
        session: AsyncSession,
        analyst: Principal,
        device: Device,
        vault: SecretVault,
    ) -> None:
        """FR-COL-08. A configuration that omits SSH settings must report those checks
        Not Evaluated — never as passes, which would make a half-read device look
        better than a fully assessed one."""
        snapshots = SnapshotService(session, vault=vault)
        assessments = AssessmentService(session)
        await PolicyService(session).seed_packs()

        snapshot = await snapshots.create_snapshot(device, config_text=WEAK)
        outcome = await assessments.assess(device, snapshot)

        not_evaluated = [r for r in outcome.results if r.outcome is Outcome.NOT_EVALUATED]
        assert not_evaluated, "the weak fixture omits enough that something must be unevaluable"
        assert all(r.reason for r in not_evaluated), "each must say what was missing"

        # And they are excluded from the compliance figure rather than counted as passes.
        assert outcome.risk is not None
        assert outcome.risk.coverage_percent is not None
        assert outcome.risk.coverage_percent < 100


class TestPhase3AcceptanceThroughTheApi:
    """The same criterion, driven through HTTP — which is how an auditor reaches it."""

    @pytest.fixture
    async def api_user(self, session: AsyncSession) -> User:
        return await make_user(session, username="phase3_api", roles={Role.SECURITY_ANALYST})

    async def test_policy_findings_and_compliance_are_reachable(
        self,
        client: AsyncClient,
        session: AsyncSession,
        authenticate,
        api_user: User,
        vault: SecretVault,
    ) -> None:
        authenticate(api_user)
        actor = Principal(
            id=api_user.id, username=api_user.username, roles=api_user.role_set, scope=Scope.all()
        )

        device = await InventoryService(session).create_device(
            mgmt_ip="198.51.100.32",
            actor=actor,
            hostname="core-sw-02",
            vendor=Vendor.CISCO,
            platform="cisco_ios",
            device_class=DeviceClass.SWITCH,
        )
        await PolicyService(session).seed_packs()
        snapshot = await SnapshotService(session, vault=vault).create_snapshot(
            device, config_text=WEAK
        )
        await AssessmentService(session).assess(device, snapshot)
        await session.commit()

        # The library is browsable.
        listed = await client.get("/api/v1/checks?platform=cisco_ios")
        assert listed.status_code == 200
        assert len(listed.json()) >= 60

        # The CIS policy is there, with its checks.
        policies = await client.get("/api/v1/policies")
        assert policies.status_code == 200
        cis = next(p for p in policies.json() if p["source"] == CIS_PACK)

        detail = await client.get(f"/api/v1/policies/{cis['id']}")
        assert detail.status_code == 200
        assert len(detail.json()["entries"]) >= 40

        # Findings come back worst-first, which is the only useful default order.
        findings = await client.get(f"/api/v1/findings?device_id={device.id}")
        assert findings.status_code == 200
        rows = findings.json()["data"]
        assert rows and rows[0]["severity"] == "critical"

        # A finding carries everything needed to act on it without leaving the page.
        #
        # Selected by check id, not by position. Several findings from one assessment
        # share a last_seen_at to the microsecond, so which critical sorts first is not
        # deterministic — and a test that asserts on whichever one wins that race fails
        # intermittently for a reason that has nothing to do with the code.
        telnet_row = next(r for r in rows if r["check_id"] == "telnet-disabled")
        one = await client.get(f"/api/v1/findings/{telnet_row['id']}")
        assert one.status_code == 200
        body = one.json()
        assert body["remediation"] and body["rationale"]
        assert body["references"]

        # The acceptance criterion's "line provenance", asserted on a check whose
        # evidence is a configuration line. Not every check has one — a Python check
        # reasoning over a collection may cite a stanza or nothing at all — so this
        # names the check rather than trusting the first row.
        lines = body["evidence"]["lines"]
        assert lines and lines[0]["line_start"] is not None
        assert lines[0]["excerpt"]

        # Risk and compliance are computed, not blank.
        risk = await client.get(f"/api/v1/devices/{device.id}/risk")
        assert risk.status_code == 200
        assert risk.json()["score"] is not None
        assert risk.json()["compliance_percent"] is not None

        compliance = await client.get("/api/v1/compliance/cis")
        assert compliance.status_code == 200
        assert compliance.json()["controls"], "no CIS controls were reported"

    async def test_a_finding_cannot_be_resolved_by_hand(
        self,
        client: AsyncClient,
        session: AsyncSession,
        authenticate,
        api_user: User,
        vault: SecretVault,
    ) -> None:
        """Resolved means "the check passed on a later run". Letting someone set it
        directly would make the status a claim rather than a measurement — and would
        hide a real problem behind a click."""
        authenticate(api_user)
        actor = Principal(
            id=api_user.id, username=api_user.username, roles=api_user.role_set, scope=Scope.all()
        )
        device = await InventoryService(session).create_device(
            mgmt_ip="198.51.100.33", actor=actor, vendor=Vendor.CISCO, platform="cisco_ios"
        )
        await PolicyService(session).seed_packs()
        snapshot = await SnapshotService(session, vault=vault).create_snapshot(
            device, config_text=WEAK
        )
        await AssessmentService(session).assess(device, snapshot)
        await session.commit()

        rows = (await client.get(f"/api/v1/findings?device_id={device.id}")).json()["data"]

        refused = await client.patch(
            f"/api/v1/findings/{rows[0]['id']}", json={"status": "resolved"}
        )
        assert refused.status_code == 422
        assert "risk accepted" in refused.json()["detail"].lower()

        # Risk-accepting it is allowed, and audited.
        accepted = await client.patch(
            f"/api/v1/findings/{rows[0]['id']}", json={"status": "risk_accepted"}
        )
        assert accepted.status_code == 200

        actions = (await session.execute(select(AuditLog.action))).scalars().all()
        assert "finding.status_changed" in actions
