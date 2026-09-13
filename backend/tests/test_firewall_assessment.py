"""Rulebase analysis becoming stored findings (FR-FW-02 … FR-FW-05, FR-FIND-01).

The `firewall` package is tested elsewhere on what it concludes. This file is about what
happens to those conclusions, and the two things most likely to be quietly wrong are
both about *identity over time*:

**Fingerprints must survive a renumber.** Inserting one rule at the top of a rulebase
renumbers every rule below it. If the finding identity contained the order, a single
insert would close every finding on the device and open an identical set — destroying
the first-seen dates that are the only reason to track a finding rather than re-derive
it. `test_a_renumbered_rulebase_keeps_its_findings` is the assertion that matters most
here.

**Closure by absence has to stay conditional.** For a config check, absence means
nothing — the check may simply not have run, so its finding stays open. Rulebase analysis
re-derives everything from the whole rulebase every time, so absence *is* evidence and
closure is correct. But only when the analysis actually ran: a snapshot with no rulebase
is not a clean rulebase, and must resolve nothing.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.crypto import SecretVault
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, Finding
from netsecops.db.models.collection import FindingKind, FindingStatus, Snapshot
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.services.firewall_assessment import (
    MAX_FINDINGS_PER_KIND,
    FirewallAssessmentService,
)
from netsecops.services.inventory import InventoryService
from tests.conftest import make_user


@pytest.fixture
async def analyst(session: AsyncSession) -> Principal:
    user = await make_user(session, username="fw_analyst", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
async def device(session: AsyncSession, analyst: Principal) -> Device:
    return await InventoryService(session).create_device(
        mgmt_ip="198.51.100.77",
        actor=analyst,
        hostname="edge-fw-01",
        vendor=Vendor.PALOALTO,
        platform="panos",
        device_class=DeviceClass.FIREWALL,
    )


def rule(
    order: int,
    name: str,
    *,
    src: str = "any",
    dst: str = "any",
    service: str = "any",
    action: str = "allow",
    src_zone: str = "untrust",
    dst_zone: str = "dmz",
    **extra: Any,
) -> dict[str, Any]:
    return {
        "order": order,
        "name": name,
        "enabled": True,
        "src": [src],
        "dst": [dst],
        "services": [service],
        "action": action,
        "src_zones": [src_zone],
        "dst_zones": [dst_zone],
        **extra,
    }


def ncm(rules: list[dict[str, Any]], **firewall: Any) -> dict[str, Any]:
    return {
        "device": {"hostname": "edge-fw-01", "vendor": "paloalto", "platform": "panos"},
        "firewall": {"security_rules": rules, "zones": ["untrust", "dmz"], **firewall},
    }


async def snapshot_with(session: AsyncSession, device: Device, payload: dict[str, Any]) -> Snapshot:
    """A snapshot carrying a specific NCM, without going through a collection."""
    # Hashed from the payload so two snapshots in one test are distinct rows rather than
    # colliding on the uniqueness the snapshot service relies on.
    digest = sha256(repr(payload).encode()).hexdigest()
    row = Snapshot(
        org_id=device.org_id,
        device_id=device.id,
        ncm=payload,
        config_redacted="",
        config_hash=digest,
        normalized_hash=digest,
    )
    session.add(row)
    await session.flush()
    return row


async def firewall_findings(session: AsyncSession, device: Device) -> list[Finding]:
    return list(
        (
            await session.execute(
                select(Finding).where(
                    Finding.device_id == device.id,
                    Finding.kind == FindingKind.FIREWALL.value,
                )
            )
        )
        .scalars()
        .all()
    )


#: A shadowed rule: #2 denies RDP everywhere, #3 tries to allow it from a partner range.
SHADOWED = [
    rule(1, "Block inbound RDP", service="tcp/3389", action="deny"),
    rule(2, "Partner RDP to web", src="198.51.100.0/24", dst="10.20.0.10", service="tcp/3389"),
]


class TestFindingsAreCreated:
    async def test_a_shadowed_rule_becomes_a_finding(
        self, session: AsyncSession, device: Device
    ) -> None:
        snapshot = await snapshot_with(session, device, ncm(SHADOWED))
        outcome = await FirewallAssessmentService(session).assess(device, snapshot)

        assert outcome.analysed is True
        assert outcome.rules_analysed == 2

        findings = await firewall_findings(session, device)
        shadowed = [f for f in findings if "shadowed" in f.fingerprint]

        assert len(shadowed) == 1
        assert shadowed[0].kind == FindingKind.FIREWALL.value
        assert shadowed[0].status == FindingStatus.NEW.value
        assert "Partner RDP to web" in shadowed[0].title
        assert shadowed[0].check_id is None, "a rulebase finding comes from no check"

    async def test_a_shadowed_finding_carries_actionable_remediation(
        self, session: AsyncSession, device: Device
    ) -> None:
        """The finding tells an operator a rule is dead. Without saying what to do about
        it, the two possible fixes — move it up, or delete it — mean opposite things for
        the traffic."""
        snapshot = await snapshot_with(session, device, ncm(SHADOWED))
        await FirewallAssessmentService(session).assess(device, snapshot)

        shadowed = next(
            f for f in await firewall_findings(session, device) if "shadowed" in f.fingerprint
        )
        assert shadowed.remediation
        assert "move this rule above" in shadowed.remediation

    async def test_the_evidence_names_both_rules(
        self, session: AsyncSession, device: Device
    ) -> None:
        """Either rule can be changed to fix the problem, so both are recorded — and the
        order is recorded in the evidence, where it is useful, rather than in the
        fingerprint, where it would be destructive."""
        snapshot = await snapshot_with(session, device, ncm(SHADOWED))
        await FirewallAssessmentService(session).assess(device, snapshot)

        shadowed = next(
            f for f in await firewall_findings(session, device) if "shadowed" in f.fingerprint
        )
        assert shadowed.evidence["subject_rule"] == "Partner RDP to web"
        assert shadowed.evidence["cause_rule"] == "Block inbound RDP"
        assert shadowed.evidence["cause_order"] == 1

    async def test_policy_findings_are_stored(self, session: AsyncSession, device: Device) -> None:
        snapshot = await snapshot_with(session, device, ncm([rule(1, "Permit everything")]))
        await FirewallAssessmentService(session).assess(device, snapshot)

        findings = await firewall_findings(session, device)
        assert any("any_any_any" in f.fingerprint for f in findings)
        assert any(f.severity == "critical" for f in findings)

    async def test_hygiene_findings_are_stored(self, session: AsyncSession, device: Device) -> None:
        payload = ncm(
            [rule(1, "Web", dst="web-01", service="tcp/443")],
            address_objects=[
                {"name": "web-01", "type": "host", "value": "10.20.0.10"},
                {"name": "web-01-copy", "type": "host", "value": "10.20.0.10"},
            ],
        )
        snapshot = await snapshot_with(session, device, payload)
        await FirewallAssessmentService(session).assess(device, snapshot)

        findings = await firewall_findings(session, device)
        assert any("duplicate_object" in f.fingerprint for f in findings)

    async def test_nat_findings_are_stored(self, session: AsyncSession, device: Device) -> None:
        payload = ncm(
            [rule(1, "Inbound RDP", dst="10.20.0.11", service="tcp/3389")],
            nat_rules=[
                {
                    "order": 1,
                    "name": "Publish RDP",
                    "translated": "10.20.0.11:3389",
                    "direction": "destination",
                }
            ],
        )
        snapshot = await snapshot_with(session, device, payload)
        outcome = await FirewallAssessmentService(session).assess(device, snapshot)

        assert outcome.exposure_analysed is True, "the zone names should be recognised"
        findings = await firewall_findings(session, device)
        exposed = [f for f in findings if "exposed_insecure_service" in f.fingerprint]

        assert len(exposed) == 1
        assert exposed[0].severity == "critical"
        assert "RDP" in exposed[0].description

    async def test_correlations_are_counted_but_not_stored(
        self, session: AsyncSession, device: Device
    ) -> None:
        """A partial overlap with different actions is a fact about ordering, not a
        defect. A row for each would drown the shadowing findings that do matter."""
        rules = [
            rule(1, "Deny a", src="10.0.0.0/24", dst="192.168.0.0/16", action="deny"),
            rule(2, "Allow b", src="10.0.0.0/16", dst="192.168.1.0/24"),
        ]
        snapshot = await snapshot_with(session, device, ncm(rules))
        outcome = await FirewallAssessmentService(session).assess(device, snapshot)

        assert outcome.counts.get("correlated") == 1
        assert not [
            f for f in await firewall_findings(session, device) if "correlated" in f.fingerprint
        ]


class TestIdentityOverTime:
    async def test_a_renumbered_rulebase_keeps_its_findings(
        self, session: AsyncSession, device: Device
    ) -> None:
        """The assertion this module's fingerprint design exists for.

        Inserting a rule at the top renumbers everything below it. A fingerprint built
        from the rule order would close every finding and open an identical set, and the
        first-seen date — the only thing that makes a tracked finding more useful than a
        re-derived one — would reset on every insert.
        """
        service = FirewallAssessmentService(session)

        first = await snapshot_with(session, device, ncm(SHADOWED))
        await service.assess(device, first)
        original = next(
            f for f in await firewall_findings(session, device) if "shadowed" in f.fingerprint
        )
        original_id, first_seen = original.id, original.first_seen_at

        renumbered = [
            rule(1, "New rule at the top", src="10.99.0.0/24", dst="10.98.0.0/24", service="tcp/1"),
            rule(2, "Block inbound RDP", service="tcp/3389", action="deny"),
            rule(
                3,
                "Partner RDP to web",
                src="198.51.100.0/24",
                dst="10.20.0.10",
                service="tcp/3389",
            ),
        ]
        second = await snapshot_with(session, device, ncm(renumbered))
        outcome = await service.assess(device, second)

        still = next(
            f for f in await firewall_findings(session, device) if "shadowed" in f.fingerprint
        )
        assert still.id == original_id, "the renumber opened a new finding"
        assert still.first_seen_at == first_seen
        assert still.occurrences == 2
        assert outcome.findings_resolved == 0

    async def test_a_fixed_rulebase_resolves_its_findings(
        self, session: AsyncSession, device: Device
    ) -> None:
        """Closure by absence, which is correct here because every relationship is
        re-derived from the whole rulebase on each snapshot."""
        service = FirewallAssessmentService(session)

        first = await snapshot_with(session, device, ncm(SHADOWED))
        await service.assess(device, first)

        # The operator moved the permit above the deny, so nothing is shadowed.
        fixed = [
            rule(
                1,
                "Partner RDP to web",
                src="198.51.100.0/24",
                dst="10.20.0.10",
                service="tcp/3389",
            ),
            rule(2, "Block inbound RDP", service="tcp/3389", action="deny"),
        ]
        second = await snapshot_with(session, device, ncm(fixed))
        outcome = await service.assess(device, second)

        assert outcome.findings_resolved >= 1
        shadowed = [
            f for f in await firewall_findings(session, device) if "shadowed" in f.fingerprint
        ]
        assert shadowed[0].status == FindingStatus.RESOLVED.value
        assert shadowed[0].resolved_at is not None

    async def test_a_returning_problem_reopens_rather_than_duplicating(
        self, session: AsyncSession, device: Device
    ) -> None:
        """Reopened, not New: the history has to show this is a regression."""
        service = FirewallAssessmentService(session)

        await service.assess(device, await snapshot_with(session, device, ncm(SHADOWED)))
        fixed = [
            rule(
                1,
                "Partner RDP to web",
                src="198.51.100.0/24",
                dst="10.20.0.10",
                service="tcp/3389",
            ),
            rule(2, "Block inbound RDP", service="tcp/3389", action="deny"),
        ]
        await service.assess(device, await snapshot_with(session, device, ncm(fixed)))
        outcome = await service.assess(device, await snapshot_with(session, device, ncm(SHADOWED)))

        shadowed = [
            f for f in await firewall_findings(session, device) if "shadowed" in f.fingerprint
        ]
        assert len(shadowed) == 1, "the regression created a second finding"
        assert shadowed[0].status == FindingStatus.REOPENED.value
        assert shadowed[0].resolved_at is None
        assert outcome.findings_opened == 1

    async def test_a_renamed_rule_is_a_new_finding(
        self, session: AsyncSession, device: Device
    ) -> None:
        """The accepted cost of name-based identity, asserted so it is a known trade
        rather than a surprise. Renaming a rule is rare; renumbering happens on every
        insert, and only one of the two could be made stable."""
        service = FirewallAssessmentService(session)
        await service.assess(device, await snapshot_with(session, device, ncm(SHADOWED)))

        renamed = [
            rule(1, "Block inbound RDP", service="tcp/3389", action="deny"),
            rule(
                2,
                "Partner RDP to web servers",
                src="198.51.100.0/24",
                dst="10.20.0.10",
                service="tcp/3389",
            ),
        ]
        await service.assess(device, await snapshot_with(session, device, ncm(renamed)))

        shadowed = [
            f for f in await firewall_findings(session, device) if "shadowed" in f.fingerprint
        ]
        assert len(shadowed) == 2
        assert {f.status for f in shadowed} == {
            FindingStatus.NEW.value,
            FindingStatus.RESOLVED.value,
        }


class TestNoRulebaseIsNotACleanRulebase:
    """The honesty requirement, and the easiest thing here to get quietly wrong."""

    async def test_a_switch_with_no_rulebase_produces_nothing(
        self, session: AsyncSession, device: Device
    ) -> None:
        snapshot = await snapshot_with(session, device, {"device": {}, "firewall": {}})
        outcome = await FirewallAssessmentService(session).assess(device, snapshot)

        assert outcome.analysed is False
        assert outcome.findings_opened == 0
        assert await firewall_findings(session, device) == []

    async def test_an_empty_rulebase_resolves_nothing(
        self, session: AsyncSession, device: Device
    ) -> None:
        """The important half. A failed parse and a switch both produce an empty
        firewall block, and closing every open finding on the strength of that would
        report a device as fixed because we stopped being able to read it.
        """
        service = FirewallAssessmentService(session)
        await service.assess(device, await snapshot_with(session, device, ncm(SHADOWED)))

        empty = await snapshot_with(session, device, {"device": {}, "firewall": {}})
        outcome = await service.assess(device, empty)

        assert outcome.analysed is False
        assert outcome.findings_resolved == 0

        shadowed = [
            f for f in await firewall_findings(session, device) if "shadowed" in f.fingerprint
        ]
        assert shadowed[0].status == FindingStatus.NEW.value, "still open, because we did not look"

    async def test_a_missing_ncm_does_not_raise(
        self, session: AsyncSession, device: Device
    ) -> None:
        snapshot = await snapshot_with(session, device, {})
        outcome = await FirewallAssessmentService(session).assess(device, snapshot)
        assert outcome.analysed is False


class TestVolume:
    async def test_findings_are_capped_per_kind_with_a_summary(
        self, session: AsyncSession, device: Device
    ) -> None:
        """A large rulebase can yield thousands of redundancies. Writing a row for each
        makes the findings list unreadable and buries everything else on the device."""
        # Many narrow permits above one broad permit: each narrow rule is redundant.
        rules = [
            rule(i, f"Narrow {i}", src=f"10.0.{i}.0/24", dst="10.20.0.0/24", service="tcp/443")
            for i in range(1, MAX_FINDINGS_PER_KIND + 20)
        ]
        rules.append(
            rule(
                len(rules) + 1,
                "Broad permit",
                src="10.0.0.0/8",
                dst="10.20.0.0/24",
                service="tcp/443",
            )
        )

        snapshot = await snapshot_with(session, device, ncm(rules))
        await FirewallAssessmentService(session).assess(device, snapshot)

        findings = await firewall_findings(session, device)
        redundant = [f for f in findings if f.fingerprint.startswith("firewall:redundant:")]
        assert len(redundant) == MAX_FINDINGS_PER_KIND

        # One summary per truncated kind — `no_profiles` also exceeds the cap here, and
        # each kind needs its own count rather than one merged number.
        summary = [f for f in findings if f.fingerprint == "firewall:truncated:redundant"]
        assert len(summary) == 1
        assert "redundant" in summary[0].title
        # The count is truthful even though the rows are not exhaustive.
        assert str(MAX_FINDINGS_PER_KIND + 19) in summary[0].title

    async def test_the_counts_are_complete_even_when_the_rows_are_not(
        self, session: AsyncSession, device: Device
    ) -> None:
        rules = [
            rule(i, f"Narrow {i}", src=f"10.0.{i}.0/24", dst="10.20.0.0/24", service="tcp/443")
            for i in range(1, MAX_FINDINGS_PER_KIND + 20)
        ]
        rules.append(
            rule(
                len(rules) + 1,
                "Broad permit",
                src="10.0.0.0/8",
                dst="10.20.0.0/24",
                service="tcp/443",
            )
        )
        snapshot = await snapshot_with(session, device, ncm(rules))
        outcome = await FirewallAssessmentService(session).assess(device, snapshot)

        assert outcome.counts["redundant"] == MAX_FINDINGS_PER_KIND + 19


class TestWiredIntoTheAssessment:
    async def test_assess_runs_the_rulebase_analysis(
        self, session: AsyncSession, device: Device, vault: SecretVault
    ) -> None:
        """The wiring, without which none of this reaches the product."""
        from netsecops.services.assessment import AssessmentService

        snapshot = await snapshot_with(session, device, ncm(SHADOWED))
        outcome = await AssessmentService(session).assess(device, snapshot)

        assert outcome.firewall is not None
        assert outcome.firewall.analysed is True
        assert outcome.firewall.findings_opened > 0
        assert any("shadowed" in f.fingerprint for f in await firewall_findings(session, device))

    async def test_a_broken_rulebase_does_not_cost_the_config_assessment(
        self, session: AsyncSession, device: Device, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A rulebase is attacker-influenced data of unbounded size. A surprise in the
        analysis must not take the device's configuration checks down with it — those
        are the findings that exist today and would silently stop being produced."""
        from netsecops.services import assessment as assessment_module
        from netsecops.services.assessment import AssessmentService

        async def explode(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("rulebase analysis blew up")

        monkeypatch.setattr(assessment_module.FirewallAssessmentService, "assess", explode)

        snapshot = await snapshot_with(session, device, ncm(SHADOWED))
        outcome = await AssessmentService(session).assess(device, snapshot)

        assert outcome.firewall is None
        # The configuration assessment still happened and still scored the device.
        assert outcome.risk is not None
        assert outcome.results
