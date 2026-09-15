"""Vulnerability feed ingestion (FR-VUL-07, FR-VUL-08).

C-7 requires the whole product to run air-gapped with feeds imported by hand, so the
bundle path is the primary one and these tests treat it that way.

The integrity check carries the most weight here. An operator carries these files in on
removable media, through at least one machine outside the security boundary, and a
bundle is a list of statements about which of their devices are exploitable. One that
has been altered can hide a CVE affecting the whole estate, and nothing downstream would
look wrong — no error, no gap, just a shorter list.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ValidationProblem
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.vulnerability import EolRecordRow, VulnAdvisory, VulnCve
from netsecops.services.feeds import (
    BundleKind,
    FeedImportService,
    SyncStatus,
    detect_kind,
    digest,
)
from tests.conftest import make_user

FIXTURES = Path(__file__).parent / "fixtures" / "feeds"

CSAF = (FIXTURES / "csaf" / "pan-sa-2024-0012.json").read_bytes()
NVD = (FIXTURES / "nvd" / "cisco_asa_cves.json").read_bytes()
EOL = (FIXTURES / "eol" / "cisco_asa.json").read_bytes()


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="feed_admin", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
def feeds(session: AsyncSession) -> FeedImportService:
    return FeedImportService(session)


# ══════════════════════════ format detection ═════════════════════════════════


class TestDetection:
    def test_a_csaf_document(self) -> None:
        assert detect_kind(json.loads(CSAF)) is BundleKind.CSAF

    def test_an_nvd_feed(self) -> None:
        assert detect_kind(json.loads(NVD)) is BundleKind.NVD

    def test_an_endoflife_list(self) -> None:
        assert detect_kind(json.loads(EOL)) is BundleKind.EOL

    def test_csaf_is_checked_before_nvd(self) -> None:
        """A CSAF document also has a top-level `vulnerabilities` key.

        Checked the other way round, a vendor advisory is read as an NVD feed, finds no
        records in it, and reports a clean empty import — the bundle silently does
        nothing.
        """
        assert detect_kind({"document": {}, "vulnerabilities": []}) is BundleKind.CSAF

    @pytest.mark.parametrize("payload", [{}, {"other": 1}, "text", 42, None])
    def test_an_unrecognised_shape_is_refused(self, payload) -> None:
        with pytest.raises(ValidationProblem, match="not a bundle NetSecOps recognises"):
            detect_kind(payload)


# ═════════════════════════ the integrity check ═══════════════════════════════


class TestIntegrity:
    async def test_a_matching_digest_imports(self, feeds, actor, session) -> None:
        result = await feeds.import_bundle(
            CSAF, feed="paloalto", actor=actor, expected_sha256=digest(CSAF)
        )

        assert result.status is SyncStatus.SUCCEEDED
        assert result.advisories == 1

    async def test_a_mismatched_digest_imports_nothing(self, feeds, actor, session) -> None:
        """Refused before anything is written, not rolled back after.

        A bundle that does not match its digest is not a bundle to import most of.
        """
        with pytest.raises(ValidationProblem, match="SHA-256"):
            await feeds.import_bundle(CSAF, feed="paloalto", actor=actor, expected_sha256="0" * 64)

        stored = (await session.execute(select(VulnAdvisory))).scalars().all()
        assert stored == [], "nothing may reach the database on a digest mismatch"

    async def test_the_failure_is_still_recorded(self, feeds, actor, session) -> None:
        """FR-VUL-07 asks for error surfacing.

        "When did this last work?" is asked the morning somebody notices the
        vulnerability page looks thin, and a table of successes cannot answer it.
        """
        with pytest.raises(ValidationProblem):
            await feeds.import_bundle(CSAF, feed="paloalto", actor=actor, expected_sha256="0" * 64)

        sync = await feeds.last_sync("paloalto")
        assert sync is not None
        assert sync.status == SyncStatus.FAILED.value
        assert sync.error_message and "SHA-256" in sync.error_message
        assert sync.finished_at is not None

    async def test_the_digest_is_recorded_even_without_an_expected_one(self, feeds, actor) -> None:
        """So a later import can be compared against what was accepted before."""
        result = await feeds.import_bundle(CSAF, feed="paloalto", actor=actor)

        assert result.sync.bundle_sha256 == digest(CSAF)

    async def test_an_unreadable_bundle_fails_cleanly(self, feeds, actor) -> None:
        with pytest.raises(ValidationProblem, match="not readable JSON"):
            await feeds.import_bundle(b"\xff\xfe not json", feed="paloalto", actor=actor)


# ════════════════════════════ what gets stored ═══════════════════════════════


class TestCsafImport:
    async def test_the_advisory_is_stored(self, feeds, actor, session) -> None:
        await feeds.import_bundle(CSAF, feed="paloalto", actor=actor)

        row = (await session.execute(select(VulnAdvisory))).scalar_one()
        assert row.advisory_id == "PAN-SA-2024-0012"
        assert row.cve_ids == ["CVE-2024-0012"]
        assert len(row.affected) == 4

    async def test_the_unparsed_notes_survive_storage(self, feeds, actor, session) -> None:
        """The reason an advisory can raise a finding but never clear a device.

        Dropped on the way in, every re-imported advisory looks fully understood, and
        the matcher starts confidently clearing devices it should decline to rule on.
        """
        await feeds.import_bundle(CSAF, feed="paloalto", actor=actor)

        row = (await session.execute(select(VulnAdvisory))).scalar_one()
        assert row.notes_unparsed, "the fixture has an undefined product id"
        assert any("CSAFPID-0999" in note for note in row.notes_unparsed)

    async def test_an_unparsed_constraint_keeps_its_kind_and_text(
        self, feeds, actor, session
    ) -> None:
        await feeds.import_bundle(CSAF, feed="paloalto", actor=actor)

        row = (await session.execute(select(VulnAdvisory))).scalar_one()
        unparsed = [e for e in row.affected if e["constraint"]["kind"] == "unparsed"]

        assert unparsed, "the prose range must round-trip as unparsed"
        assert any("9.1 maintenance release" in e["constraint"]["raw"] for e in unparsed)

    async def test_reimporting_replaces_rather_than_duplicates(self, feeds, actor, session) -> None:
        await feeds.import_bundle(CSAF, feed="paloalto", actor=actor)
        await feeds.import_bundle(CSAF, feed="paloalto", actor=actor)

        rows = (await session.execute(select(VulnAdvisory))).scalars().all()
        assert len(rows) == 1, "identity is (source, advisory_id), not a new row per sync"


class TestNvdImport:
    async def test_advisories_and_cves_are_both_stored(self, feeds, actor, session) -> None:
        result = await feeds.import_bundle(NVD, feed="nvd", actor=actor)

        assert result.advisories == 4
        assert result.cves == 4
        assert len((await session.execute(select(VulnCve))).scalars().all()) == 4

    async def test_cvss_lands_in_the_right_column(self, feeds, actor, session) -> None:
        await feeds.import_bundle(NVD, feed="nvd", actor=actor)

        row = (
            await session.execute(select(VulnCve).where(VulnCve.cve_id == "CVE-2024-20353"))
        ).scalar_one()
        assert row.cvss31 is not None
        assert row.cvss31["base_score"] == 8.6
        assert row.cvss31["vector"].startswith("CVSS:3.1/")

    async def test_epss_and_kev_stay_null(self, feeds, actor, session) -> None:
        """They come from other feeds. Writing a default here turns "never imported"
        into "checked, and it is not exploited" — which is a claim nobody made."""
        await feeds.import_bundle(NVD, feed="nvd", actor=actor)

        row = (
            await session.execute(select(VulnCve).where(VulnCve.cve_id == "CVE-2024-20353"))
        ).scalar_one()
        assert row.epss is None
        assert row.kev is None


class TestEolImport:
    async def test_cycles_are_stored(self, feeds, actor, session) -> None:
        result = await feeds.import_bundle(
            EOL, feed="endoflife.date", actor=actor, vendor="cisco", product="asa"
        )

        assert result.eol_records == 5
        rows = (await session.execute(select(EolRecordRow))).scalars().all()
        assert {row.cycle for row in rows} == {"9.20", "9.18", "9.16", "9.12", "9.8"}

    async def test_an_undated_ending_survives_storage(self, feeds, actor, session) -> None:
        await feeds.import_bundle(
            EOL, feed="endoflife.date", actor=actor, vendor="cisco", product="asa"
        )

        row = (
            await session.execute(select(EolRecordRow).where(EolRecordRow.cycle == "9.12"))
        ).scalar_one()
        assert row.life_ended_undated is True
        assert row.life_ends is None

    async def test_the_vendor_must_be_supplied(self, feeds, actor) -> None:
        """An EoL bundle lists cycles and does not say whose.

        Filing Cisco's lifecycle dates under Fortinet would report a supported estate as
        dead, so this is required rather than inferred from the feed name.
        """
        with pytest.raises(ValidationProblem, match="does not say whose"):
            await feeds.import_bundle(EOL, feed="endoflife.date", actor=actor)

    async def test_reimporting_updates_in_place(self, feeds, actor, session) -> None:
        await feeds.import_bundle(
            EOL, feed="endoflife.date", actor=actor, vendor="cisco", product="asa"
        )
        await feeds.import_bundle(
            EOL, feed="endoflife.date", actor=actor, vendor="cisco", product="asa"
        )

        rows = (await session.execute(select(EolRecordRow))).scalars().all()
        assert len(rows) == 5


# ═══════════════════════ sync status and honesty ═════════════════════════════


class TestSyncRecord:
    async def test_a_clean_import_is_succeeded(self, feeds, actor) -> None:
        result = await feeds.import_bundle(NVD, feed="nvd", actor=actor)

        assert result.sync.status == SyncStatus.SUCCEEDED.value
        assert result.sync.records_rejected == 0
        assert result.sync.finished_at is not None

    async def test_rejected_records_make_the_sync_partial(self, feeds, actor) -> None:
        """Nine thousand of ten thousand is not success.

        Reporting it as clean hides a thousand blind spots — devices that will report no
        vulnerabilities because the records naming them never arrived.
        """
        payload = json.dumps(
            {"vulnerabilities": [{"cve": {"id": "CVE-1"}}, {"cve": {}}, {"not": "a record"}]}
        ).encode()

        result = await feeds.import_bundle(payload, feed="nvd", actor=actor)

        assert result.rejected == 2
        assert result.status is SyncStatus.PARTIAL

    async def test_history_is_newest_first(self, feeds, actor) -> None:
        await feeds.import_bundle(CSAF, feed="paloalto", actor=actor)
        await feeds.import_bundle(NVD, feed="nvd", actor=actor)

        history = await feeds.history()
        assert [entry.feed for entry in history[:2]] == ["nvd", "paloalto"]

    async def test_last_sync_finds_a_failure_too(self, feeds, actor) -> None:
        await feeds.import_bundle(CSAF, feed="paloalto", actor=actor)
        with pytest.raises(ValidationProblem):
            await feeds.import_bundle(CSAF, feed="paloalto", actor=actor, expected_sha256="0" * 64)

        assert (await feeds.last_sync("paloalto")).status == SyncStatus.FAILED.value

    async def test_every_import_is_audited(self, feeds, actor, session) -> None:
        from netsecops.db.models import AuditLog

        await feeds.import_bundle(CSAF, feed="paloalto", actor=actor)

        entries = (
            (await session.execute(select(AuditLog).where(AuditLog.action == "feed.synced")))
            .scalars()
            .all()
        )
        assert len(entries) == 1
        assert entries[0].details["sha256"] == digest(CSAF)


# ════════════════════ the round trip the matcher depends on ══════════════════


class TestStoredAdvisoriesStillMatch:
    async def test_an_imported_advisory_produces_the_same_verdict(
        self, feeds, actor, session
    ) -> None:
        """Storage must not change an answer.

        Everything the matcher reasons from — the constraint kind, the raw range text,
        the unparsed notes — goes through JSONB and comes back. If any of it is lost on
        the way, verdicts computed after a restart differ from those computed before,
        and nobody would notice until a device was cleared that should not have been.
        """
        from netsecops.ncm.models import NormalisedConfig
        from netsecops.vuln.advisory import (
            Advisory,
            AffectedProduct,
            ConstraintKind,
            VersionConstraint,
        )
        from netsecops.vuln.matcher import Confidence, match

        await feeds.import_bundle(NVD, feed="nvd", actor=actor)
        row = (
            await session.execute(
                select(VulnAdvisory).where(VulnAdvisory.advisory_id == "CVE-2024-20353")
            )
        ).scalar_one()

        rebuilt = Advisory(
            source=row.source,
            advisory_id=row.advisory_id,
            cve_ids=list(row.cve_ids),
            notes_unparsed=list(row.notes_unparsed),
            affected=[
                AffectedProduct(
                    vendor=entry["vendor"],
                    product=entry["product"],
                    cpe=entry["cpe"],
                    product_id=entry["product_id"],
                    constraint=VersionConstraint(
                        kind=ConstraintKind(entry["constraint"]["kind"]),
                        raw=entry["constraint"]["raw"],
                        introduced=entry["constraint"]["introduced"],
                        fixed=entry["constraint"]["fixed"],
                        version=entry["constraint"]["version"],
                    ),
                )
                for entry in row.affected
            ],
        )

        ncm = NormalisedConfig()
        ncm.device.vendor = "cisco"
        ncm.device.platform = "cisco_asa"
        ncm.device.version = "9.18(2)"

        assert match(ncm, rebuilt).confidence is Confidence.CONFIRMED
