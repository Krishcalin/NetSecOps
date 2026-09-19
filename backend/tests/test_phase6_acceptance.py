"""Phase 6 acceptance (SRS §12).

    known-vulnerable fixture versions produce expected CVEs with correct confidence

Written as one continuous path, because the criterion is that the chain connects:
import a feed bundle → collect a device whose version is known to be in an affected
range → assess it → get a vulnerability finding naming the right CVE at the right
confidence → upgrade the device → watch the finding resolve itself.

Every link has unit tests elsewhere. This asserts they join up, and that the two
questions an operator actually asks — *am I affected* and *what do I upgrade to* — both
come out of the far end.

**The confidences are asserted individually and deliberately.** "Produces expected CVEs"
would be satisfied by a system that flagged everything, so the criterion is only
meaningfully met if the devices that are *not* affected come back not affected, and the
ones nobody could rule on come back unevaluated rather than either.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.crypto import SecretVault
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, Finding
from netsecops.db.models.collection import FindingKind, FindingSeverity, FindingStatus, Snapshot
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.db.models.vulnerability import VulnAdvisory, VulnMatch
from netsecops.services.feeds import FeedImportService
from netsecops.services.inventory import InventoryService
from netsecops.services.snapshots import SnapshotService
from netsecops.services.vuln_assessment import (
    VulnAssessmentService,
    eol_fingerprint,
    vuln_fingerprint,
)
from netsecops.vuln.matcher import Confidence
from tests.conftest import make_user

FIXTURES = Path(__file__).parent / "fixtures"
FEEDS = FIXTURES / "feeds"
OPERATIONAL = FIXTURES / "operational"

ASA_CONFIG = (FIXTURES / "cisco/asa/9.18/edge_firewall.cfg").read_text(encoding="utf-8")
ASA_SHOW_VERSION = (OPERATIONAL / "cisco_asa/show_version_asa5525.txt").read_text(encoding="utf-8")

NVD_BUNDLE = (FEEDS / "nvd" / "cisco_asa_cves.json").read_bytes()
EOL_BUNDLE = (FEEDS / "eol" / "cisco_asa.json").read_bytes()

#: The ASA fixture reports 9.18(2) from its configuration. CVE-2024-20353 names
#: `>=9.18.0 <9.18.4` as affected, so this device is inside the range — checked against
#: the fixture by hand, not read off a run of the matcher.
AFFECTED_CVE = "CVE-2024-20353"
#: Both advisories in the bundle that cover 9.18(2). The second states its scope as
#: `<=9.18.3`, an inclusive upper bound — unreadable until `VersionConstraint` gained
#: `last_affected`, so this test expected one finding for as long as it was unreadable.
AFFECTED_CVES = [AFFECTED_CVE, "CVE-2024-20359"]
#: The release that closes it, per the same NVD record.
FIXED_VERSION = "9.18.4"


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="phase6_analyst", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def onboard(session: AsyncSession, actor: Principal, *, ip: str, hostname: str) -> Device:
    return await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=actor,
        hostname=hostname,
        vendor=Vendor.CISCO,
        platform="cisco_asa",
        device_class=DeviceClass.FIREWALL,
    )


async def collect(
    session: AsyncSession, vault: SecretVault, device: Device, *, version: str = "9.18(2)"
) -> Snapshot:
    """Store a snapshot the way a real collection would, artefacts and all.

    The version is substituted into the *configuration*, not into the `show version`
    artefact. An ASA states its own image version on the third line of its running
    config, and the artefact supplies only the chassis model and serial — so editing the
    artefact changes nothing about which advisories match. Worth stating because the
    first version of this test did exactly that and quietly kept asserting against an
    unchanged 9.18(2).
    """
    config = ASA_CONFIG.replace("ASA Version 9.18(2)", f"ASA Version {version}")
    return await SnapshotService(session, vault=vault).create_snapshot(
        device,
        config_text=config,
        platform="cisco_asa",
        supporting={"show version": ASA_SHOW_VERSION},
    )


class TestPhase6Acceptance:
    async def test_the_whole_chain(
        self, session: AsyncSession, actor: Principal, vault: SecretVault
    ) -> None:
        feeds = FeedImportService(session)
        assessments = VulnAssessmentService(session)

        # ── 1. import a feed bundle, integrity checked ───────────────────
        imported = await feeds.import_bundle(
            NVD_BUNDLE,
            feed="nvd",
            actor=actor,
            expected_sha256=sha256(NVD_BUNDLE).hexdigest(),
        )
        assert imported.advisories == 4
        assert imported.sync.status == "succeeded"

        # ── 2. a device whose version is in a known-affected range ───────
        device = await onboard(session, actor, ip="198.51.100.40", hostname="edge-fw-01")
        snapshot = await collect(session, vault, device)
        assert snapshot.ncm["device"]["version"] == "9.18(2)"

        # ── 3. assess ────────────────────────────────────────────────────
        outcome = await assessments.assess_device(device)

        # ── 4. the expected CVEs, at the expected confidence ─────────────
        confirmed = [m for m in outcome.matches if m.confidence is Confidence.CONFIRMED]
        assert sorted(m.advisory_id for m in confirmed) == sorted(AFFECTED_CVES), (
            "9.18(2) is inside >=9.18.0 <9.18.4, and also inside the <=9.18.3 bound that "
            "CVE-2024-20359 states — an inclusive bound the engine could not read until "
            "`last_affected` existed, so this expected one finding where there are two"
        )

        # ── 5. and a finding somebody can act on ─────────────────────────
        finding = (
            await session.execute(
                select(Finding).where(
                    Finding.device_id == device.id,
                    Finding.fingerprint == vuln_fingerprint("nvd", AFFECTED_CVE),
                )
            )
        ).scalar_one()

        assert finding.kind == FindingKind.VULN.value
        assert finding.status == FindingStatus.NEW.value
        assert finding.severity == FindingSeverity.HIGH.value, "CVSS 8.6 is High"
        assert AFFECTED_CVE in finding.title
        assert finding.description, "FR-VUL-03 requires an explanation"
        assert "9.18(2)" in finding.description

        # ── 6. what to upgrade to (FR-VUL-10) ────────────────────────────
        # Scoped to the advisory rather than to "the confirmed one": 9.18(2) is inside
        # two ranges in this bundle, so there is no single confirmed match any more.
        match_row = (
            await session.execute(
                select(VulnMatch)
                .join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id)
                .where(
                    VulnMatch.device_id == device.id,
                    VulnMatch.confidence == Confidence.CONFIRMED.value,
                    VulnAdvisory.advisory_id == AFFECTED_CVE,
                )
            )
        ).scalar_one()
        assert match_row.snapshot_id == snapshot.id, (
            "a verdict must name the configuration it was computed against"
        )

        # ── 7. upgrade the device; the finding closes itself ─────────────
        await collect(session, vault, device, version=FIXED_VERSION)
        after = await assessments.assess_device(device)

        assert after.findings_resolved >= 1
        await session.refresh(finding)
        assert finding.status == FindingStatus.RESOLVED.value
        assert finding.resolved_at is not None


class TestTheCriterionIsNotMetByFlaggingEverything:
    """ "Produces expected CVEs" is satisfied by a system that flags all of them.

    The criterion only means something if the negatives are right too.
    """

    async def test_a_patched_device_is_not_flagged(
        self, session: AsyncSession, actor: Principal, vault: SecretVault
    ) -> None:
        await FeedImportService(session).import_bundle(NVD_BUNDLE, feed="nvd", actor=actor)
        device = await onboard(session, actor, ip="198.51.100.41", hostname="patched-fw")
        await collect(session, vault, device, version=FIXED_VERSION)

        outcome = await VulnAssessmentService(session).assess_device(device)

        assert outcome.confirmed == 0
        findings = (
            (
                await session.execute(
                    select(Finding).where(
                        Finding.device_id == device.id, Finding.kind == FindingKind.VULN.value
                    )
                )
            )
            .scalars()
            .all()
        )
        assert findings == []

    async def test_a_device_with_no_readable_version_is_unevaluated_not_clean(
        self, session: AsyncSession, actor: Principal, vault: SecretVault
    ) -> None:
        """The distinction the whole phase is built around.

        No `show version` artefact means the ASA's own config line still gives 9.18(2)
        — so to make the version genuinely unreadable the snapshot carries a version
        this system cannot parse. That device is not patched; it is unassessable, and
        must be reported as a coverage gap rather than filed with the clean ones.
        """
        await FeedImportService(session).import_bundle(NVD_BUNDLE, feed="nvd", actor=actor)
        device = await onboard(session, actor, ip="198.51.100.42", hostname="opaque-fw")
        snapshot = await collect(session, vault, device)
        snapshot.ncm = {**snapshot.ncm, "device": {**snapshot.ncm["device"], "version": "unknown"}}
        await session.flush()

        outcome = await VulnAssessmentService(session).assess_device(device)

        assert outcome.confirmed == 0
        assert outcome.not_evaluated, "an unassessable device must be surfaced"

    async def test_an_uncollected_device_is_unevaluated(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        device = await onboard(session, actor, ip="198.51.100.43", hostname="never-collected")

        outcome = await VulnAssessmentService(session).assess_device(device)

        assert outcome.matches == []
        assert "Nothing has been collected" in outcome.not_evaluated[0]


class TestBecomingUnassessableDoesNotCureADevice:
    async def test_a_finding_stays_open_when_the_version_stops_being_readable(
        self, session: AsyncSession, actor: Principal, vault: SecretVault
    ) -> None:
        """The rule that governs resolution, tested at the level it matters.

        "No confirmed match this run" happens both when a device is patched and when it
        stops being readable. They are indistinguishable in the data and opposite in
        meaning. Resolving on the second would mean an estate that lost its
        `show version` collection reports itself progressively cured — every device
        going quiet at once, and the findings list emptying to applause.
        """
        await FeedImportService(session).import_bundle(NVD_BUNDLE, feed="nvd", actor=actor)
        device = await onboard(session, actor, ip="198.51.100.44", hostname="going-dark")
        await collect(session, vault, device)

        assessments = VulnAssessmentService(session)
        await assessments.assess_device(device)

        finding = (
            await session.execute(
                select(Finding).where(
                    Finding.device_id == device.id,
                    Finding.fingerprint == vuln_fingerprint("nvd", AFFECTED_CVE),
                )
            )
        ).scalar_one()
        assert FindingStatus(finding.status).is_active

        # The device goes dark: same box, same exposure, unreadable version.
        snapshot = (
            await session.execute(
                select(Snapshot)
                .where(Snapshot.device_id == device.id)
                .order_by(Snapshot.created_at.desc())
                .limit(1)
            )
        ).scalar_one()
        snapshot.ncm = {**snapshot.ncm, "device": {**snapshot.ncm["device"], "version": "unknown"}}
        await session.flush()

        await assessments.assess_device(device)
        await session.refresh(finding)

        assert FindingStatus(finding.status).is_active, "an unreadable device is not a patched one"
        assert finding.status != FindingStatus.RESOLVED.value


class TestEndOfLife:
    async def test_an_unsupported_release_raises_a_finding(
        self, session: AsyncSession, actor: Principal, vault: SecretVault
    ) -> None:
        """FR-VUL-05, through the same chain.

        The ASA fixture is on 9.18, whose security maintenance ended 2025-11-30 in the
        bundle — so as of any run after that date this is an end-of-support device.
        """
        await FeedImportService(session).import_bundle(
            EOL_BUNDLE, feed="endoflife.date", actor=actor, vendor="cisco", product="asa"
        )
        device = await onboard(session, actor, ip="198.51.100.45", hostname="old-fw")
        await collect(session, vault, device)

        outcome = await VulnAssessmentService(session).assess_device(device)

        assert outcome.lifecycle is not None
        finding = (
            await session.execute(
                select(Finding).where(
                    Finding.device_id == device.id, Finding.fingerprint == eol_fingerprint("9.18")
                )
            )
        ).scalar_one()

        assert "9.18" in finding.title
        assert finding.severity == FindingSeverity.HIGH.value

    async def test_with_no_eol_data_the_lifecycle_is_unknown_not_supported(
        self, session: AsyncSession, actor: Principal, vault: SecretVault
    ) -> None:
        device = await onboard(session, actor, ip="198.51.100.46", hostname="no-eol-data")
        await collect(session, vault, device)

        outcome = await VulnAssessmentService(session).assess_device(device)

        assert outcome.lifecycle.value == "unknown"
        assert any("lifecycle" in note for note in outcome.not_evaluated)


class TestMatchesAreAnAuditTrail:
    async def test_every_advisory_weighed_leaves_a_row(
        self, session: AsyncSession, actor: Principal, vault: SecretVault
    ) -> None:
        """Including the ones that did not apply.

        "We checked and it does not apply" and "we never looked" are different answers,
        and only one of them should let somebody sleep. A match table holding only hits
        cannot tell them apart.
        """
        await FeedImportService(session).import_bundle(NVD_BUNDLE, feed="nvd", actor=actor)
        device = await onboard(session, actor, ip="198.51.100.47", hostname="audited-fw")
        await collect(session, vault, device)

        await VulnAssessmentService(session).assess_device(device)

        rows = (
            (await session.execute(select(VulnMatch).where(VulnMatch.device_id == device.id)))
            .scalars()
            .all()
        )
        assert len(rows) == 4, "one per advisory in the bundle, whatever the verdict"
        assert {row.confidence for row in rows} != {Confidence.CONFIRMED.value}

    async def test_reassessing_updates_rather_than_duplicates(
        self, session: AsyncSession, actor: Principal, vault: SecretVault
    ) -> None:
        await FeedImportService(session).import_bundle(NVD_BUNDLE, feed="nvd", actor=actor)
        device = await onboard(session, actor, ip="198.51.100.48", hostname="rerun-fw")
        await collect(session, vault, device)

        assessments = VulnAssessmentService(session)
        await assessments.assess_device(device)
        await assessments.assess_device(device)

        rows = (
            (await session.execute(select(VulnMatch).where(VulnMatch.device_id == device.id)))
            .scalars()
            .all()
        )
        assert len(rows) == 4

        finding = (
            await session.execute(
                select(Finding).where(
                    Finding.device_id == device.id,
                    Finding.fingerprint == vuln_fingerprint("nvd", AFFECTED_CVE),
                )
            )
        ).scalar_one()
        assert finding.occurrences == 2, "seen twice, not opened twice"
