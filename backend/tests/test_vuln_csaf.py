"""CSAF 2.0 ingestion (FR-VUL-02).

The fixture is deliberately imperfect, because real vendor advisories are. It carries a
clean two-sided range, a one-sided range, a range written as prose, a product_id that the
product tree never defines, and a product under investigation. Four of those five are
things a naive parser drops silently, and each dropped statement is a vulnerable device
reporting clean.

The tests are organised around what the parser must refuse to conclude rather than around
its functions.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netsecops.vuln.advisory import ConstraintKind
from netsecops.vuln.csaf import parse_csaf, parse_version_spec

FIXTURES = Path(__file__).parent / "fixtures" / "feeds" / "csaf"


@pytest.fixture
def pan_advisory():
    payload = json.loads((FIXTURES / "pan-sa-2024-0012.json").read_text(encoding="utf-8"))
    advisory = parse_csaf(payload)
    assert advisory is not None
    return advisory


# ═════════════════════════════ version specs ═════════════════════════════════


class TestVersionSpecs:
    def test_a_two_sided_range(self) -> None:
        spec = parse_version_spec(">=11.0.0 <11.0.3")

        assert spec.kind is ConstraintKind.RANGE
        assert spec.introduced == "11.0.0"
        assert spec.fixed == "11.0.3"

    def test_a_one_sided_upper_bound(self) -> None:
        spec = parse_version_spec("<10.2.9")

        assert spec.kind is ConstraintKind.RANGE
        assert spec.introduced is None
        assert spec.fixed == "10.2.9"

    def test_a_one_sided_lower_bound(self) -> None:
        spec = parse_version_spec(">=10.2.0")

        assert spec.kind is ConstraintKind.RANGE
        assert spec.introduced == "10.2.0"
        assert spec.fixed is None

    def test_a_bare_version_is_exact(self) -> None:
        spec = parse_version_spec("15.2(7)E3")

        assert spec.kind is ConstraintKind.EXACT
        assert spec.version == "15.2(7)E3"

    @pytest.mark.parametrize(
        "raw",
        [
            "all versions prior to the 9.1 maintenance release",
            "11.0.0 - 11.0.2",
            "<=10.2.8",
            ">10.2.0 <10.2.9",
            "every supported release",
            "",
        ],
    )
    def test_what_cannot_be_read_keeps_its_text(self, raw: str) -> None:
        """Unparsed, never approximated.

        The inclusive and exclusive cases here are the subtle ones. `<=10.2.8` means
        10.2.8 is affected, so the fix is in some later release this model cannot name;
        storing 10.2.8 as the fixed version would report every device on 10.2.8 as
        patched. An off-by-one release is a real device left exposed.
        """
        spec = parse_version_spec(raw)

        assert spec.kind is ConstraintKind.UNPARSED
        assert spec.interpretable is False
        assert spec.raw == (raw.strip() or raw)

    def test_an_inclusive_upper_bound_is_not_stored_as_a_fix(self) -> None:
        spec = parse_version_spec(">=10.2.0 <=10.2.8")

        assert spec.fixed is None, "10.2.8 is affected, so it is not the fixed release"


# ════════════════════════════ document parsing ═══════════════════════════════


class TestAdvisoryMetadata:
    def test_the_identity_and_dates(self, pan_advisory) -> None:
        assert pan_advisory.advisory_id == "PAN-SA-2024-0012"
        assert pan_advisory.source == "Palo Alto Networks"
        assert pan_advisory.cve_ids == ["CVE-2024-0012"]
        assert pan_advisory.cwe_ids == ["CWE-306"]
        assert pan_advisory.published is not None
        assert pan_advisory.modified is not None
        assert pan_advisory.modified > pan_advisory.published

    def test_the_references_and_remediations(self, pan_advisory) -> None:
        assert "https://nvd.nist.gov/vuln/detail/CVE-2024-0012" in pan_advisory.references
        assert len(pan_advisory.remediations) == 2
        assert any("Upgrade to PAN-OS 11.0.3" in text for text in pan_advisory.remediations)

    def test_the_newest_cvss_version_is_the_primary_score(self, pan_advisory) -> None:
        """A document publishing both v3.1 and v4.0 is stating v4.0 as current."""
        primary = pan_advisory.primary_score

        assert primary is not None
        assert primary.version == "4.0"
        assert primary.base_score == 9.8
        assert primary.vector is not None, "a base score without its vector cannot be re-derived"

    def test_both_scores_are_kept(self, pan_advisory) -> None:
        assert {score.version for score in pan_advisory.scores} == {"3.1", "4.0"}


class TestProductTreeResolution:
    def test_vendor_and_product_context_descends_to_the_leaves(self, pan_advisory) -> None:
        """A version number read without its ancestors is attached to nothing."""
        entry = next(p for p in pan_advisory.affected if p.product_id == "CSAFPID-0001")

        assert entry.vendor == "Palo Alto Networks"
        assert entry.product == "PAN-OS"
        assert entry.constraint.introduced == "11.0.0"
        assert entry.constraint.fixed == "11.0.3"

    def test_a_vendor_supplied_cpe_is_kept(self, pan_advisory) -> None:
        """The vendor's own identifier beats this system's guess at one."""
        entry = next(p for p in pan_advisory.affected if p.product_id == "CSAFPID-0001")

        assert entry.cpe == "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*"

    def test_a_leaf_without_a_cpe_is_still_identifiable(self, pan_advisory) -> None:
        entry = next(p for p in pan_advisory.affected if p.product_id == "CSAFPID-0002")

        assert entry.cpe is None
        assert entry.identifiable, "vendor and product are enough to match on"

    def test_the_fixed_release_is_recorded_separately(self, pan_advisory) -> None:
        """FR-VUL-10 needs to know what to upgrade *to*, not only what is broken."""
        assert [p.product_id for p in pan_advisory.fixed] == ["CSAFPID-0100"]
        assert pan_advisory.fixed[0].constraint.kind is ConstraintKind.EXACT
        assert pan_advisory.fixed[0].constraint.version == "11.0.3"


class TestWhatTheParserRefusesToDrop:
    """Each of these is a statement a naive parser loses, and each loss hides a
    vulnerability rather than creating a false one."""

    def test_a_prose_range_survives_as_unparsed(self, pan_advisory) -> None:
        entry = next(p for p in pan_advisory.affected if p.product_id == "CSAFPID-0003")

        assert entry.constraint.kind is ConstraintKind.UNPARSED
        assert "9.1 maintenance release" in entry.constraint.raw, (
            "the operator must be able to read what the vendor actually wrote"
        )
        assert entry.product == "PAN-OS", "the product is known even when the range is not"

    def test_a_product_id_the_tree_never_defines_is_kept(self, pan_advisory) -> None:
        """Vendors really do publish these.

        The statement "CSAFPID-0999 is affected" was made. Dropping it because the tree
        is incomplete turns a declared vulnerability into silence.
        """
        entry = next(p for p in pan_advisory.affected if p.product_id == "CSAFPID-0999")

        assert entry.constraint.kind is ConstraintKind.UNPARSED
        assert entry.identifiable is False
        assert any("CSAFPID-0999" in note for note in pan_advisory.notes_unparsed)

    def test_under_investigation_is_recorded_as_an_open_question(self, pan_advisory) -> None:
        """Explicitly-unknown and explicitly-not-affected are different claims."""
        assert any("under investigation" in note for note in pan_advisory.notes_unparsed)

    def test_the_advisory_knows_it_is_only_partly_understood(self, pan_advisory) -> None:
        """The flag the matcher reads before it dares conclude "not affected".

        This document has two unreadable statements, so it can rule a device *in* but
        never *out*.
        """
        assert pan_advisory.uninterpretable == 2
        assert pan_advisory.fully_interpreted is False

    def test_the_readable_statements_are_still_usable(self, pan_advisory) -> None:
        """Partial understanding must not poison the parts that were understood."""
        usable = [p for p in pan_advisory.affected if p.constraint.interpretable]

        assert len(usable) == 2
        assert all(p.product == "PAN-OS" for p in usable)


class TestMalformedDocuments:
    def test_a_non_csaf_payload_is_rejected(self) -> None:
        assert parse_csaf({"not": "csaf"}) is None
        assert parse_csaf([]) is None  # type: ignore[arg-type]

    def test_an_advisory_with_no_tracking_id_is_rejected(self) -> None:
        """Without an identifier every sync would store a fresh copy of it."""
        assert parse_csaf({"document": {"title": "no id", "tracking": {}}}) is None

    def test_a_document_with_no_vulnerabilities_says_so(self) -> None:
        advisory = parse_csaf({"document": {"tracking": {"id": "X-1"}, "publisher": {"name": "V"}}})

        assert advisory is not None
        assert advisory.affected == []
        assert advisory.fully_interpreted is False, "an empty advisory is not a clean one"

    def test_the_source_can_be_overridden(self) -> None:
        """Feed ingestion knows which feed it fetched from; the document may not say."""
        advisory = parse_csaf({"document": {"tracking": {"id": "X-1"}}}, source="fortinet-psirt")

        assert advisory is not None
        assert advisory.source == "fortinet-psirt"
