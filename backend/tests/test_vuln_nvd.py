"""NVD JSON 2.0 ingestion (FR-VUL-01, FR-VUL-04).

The fixture is four real-shaped records chosen for the constructs that produce wrong
verdicts rather than errors: a clean two-range CVE, one bounded with
`versionEndIncluding`, one with an AND configuration and a `vulnerable: false` platform
entry, and one NVD has rejected.

Each of the last three is silently mishandled by the obvious implementation, and each
mishandling points the same way — towards telling somebody a device is fine.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netsecops.ncm.models import NormalisedConfig
from netsecops.vuln.advisory import ConstraintKind
from netsecops.vuln.matcher import Confidence, match
from netsecops.vuln.nvd import parse_nvd_feed

FIXTURES = Path(__file__).parent / "fixtures" / "feeds" / "nvd"


@pytest.fixture
def advisories():
    payload = json.loads((FIXTURES / "cisco_asa_cves.json").read_text(encoding="utf-8"))
    return {advisory.advisory_id: advisory for advisory in parse_nvd_feed(payload)}


def asa(version: str) -> NormalisedConfig:
    ncm = NormalisedConfig()
    ncm.device.vendor = "cisco"
    ncm.device.platform = "cisco_asa"
    ncm.device.version = version
    return ncm


# ═══════════════════════════ the ordinary record ═════════════════════════════


class TestACleanCve:
    def test_the_metadata(self, advisories) -> None:
        advisory = advisories["CVE-2024-20353"]

        assert advisory.cve_ids == ["CVE-2024-20353"]
        assert advisory.cwe_ids == ["CWE-835"]
        assert advisory.source == "nvd"
        assert advisory.published is not None
        assert "denial of service" in (advisory.description or "")
        assert advisory.references, "the vendor advisory link must survive"

    def test_the_score_keeps_its_vector(self, advisories) -> None:
        score = advisories["CVE-2024-20353"].primary_score

        assert score is not None
        assert score.version == "3.1"
        assert score.base_score == 8.6
        assert score.severity == "HIGH"
        assert score.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"

    def test_both_version_ranges_are_read(self, advisories) -> None:
        advisory = advisories["CVE-2024-20353"]
        ranges = {
            (entry.constraint.introduced, entry.constraint.fixed) for entry in advisory.affected
        }

        assert ranges == {("9.12.0", "9.12.4.67"), ("9.18.0", "9.18.4")}
        assert advisory.fully_interpreted, "nothing in this record is ambiguous"

    def test_it_matches_a_device_inside_a_range(self, advisories) -> None:
        result = match(asa("9.18(2)"), advisories["CVE-2024-20353"])

        assert result.confidence is Confidence.CONFIRMED

    def test_it_clears_a_device_on_the_fixed_release(self, advisories) -> None:
        result = match(asa("9.18(4)"), advisories["CVE-2024-20353"])

        assert result.confidence is Confidence.NOT_AFFECTED


# ═════════════════ the constructs that produce wrong verdicts ════════════════


class TestVersionEndIncluding:
    """The bound NVD uses wherever a vendor never shipped a fix.

    `versionEndIncluding: 9.18.3` means 9.18.3 **is** affected. Storing it as the fixed
    release — the obvious mapping, since both are upper bounds — reports every device on
    9.18.3 as patched, which is precisely the population most at risk.
    """

    def test_it_is_not_stored_as_a_fixed_release(self, advisories) -> None:
        entry = advisories["CVE-2024-20359"].affected[0]

        assert entry.constraint.fixed is None
        assert entry.constraint.kind is ConstraintKind.UNPARSED
        assert "<=9.18.3" in entry.constraint.raw, "the operator must see the real bound"

    def test_a_device_on_that_version_is_not_cleared(self, advisories) -> None:
        result = match(asa("9.18(3)"), advisories["CVE-2024-20359"])

        assert result.confidence is not Confidence.NOT_AFFECTED
        assert result.confidence is Confidence.NOT_EVALUATED

    def test_the_advisory_knows_it_is_not_fully_interpreted(self, advisories) -> None:
        assert advisories["CVE-2024-20359"].fully_interpreted is False


class TestCompoundAndPlatformEntries:
    """A CVE that applies only to one product *running on* another."""

    def test_a_vulnerable_false_entry_is_not_an_affected_product(self, advisories) -> None:
        """NVD uses these for "runs on" context.

        Reading them as affected attaches the CVE to every platform a vulnerable
        application was ever packaged with — here, to ASA 9.18.4, which is the fixed
        release of an unrelated CVE two records up.
        """
        advisory = advisories["CVE-2024-99001"]
        products = {entry.product for entry in advisory.affected}

        assert products == {"identity_services_engine"}
        assert "adaptive_security_appliance_software" not in products

    def test_an_and_configuration_is_recorded_as_not_fully_modelled(self, advisories) -> None:
        """ "Affected when X *and* Y" cannot be answered by matching either half."""
        advisory = advisories["CVE-2024-99001"]

        assert advisory.fully_interpreted is False
        assert any("compound (AND)" in note for note in advisory.notes_unparsed)

    def test_an_asa_is_not_cleared_by_a_cve_it_only_appears_in_as_a_platform(
        self, advisories
    ) -> None:
        """The ASA is named in the record, but only as what ISE runs on.

        It must not be reported affected — and, because the record is not fully
        understood, must not be confidently cleared either.
        """
        result = match(asa("9.18(4)"), advisories["CVE-2024-99001"])

        assert result.confidence is not Confidence.CONFIRMED


class TestRejectedRecords:
    def test_a_rejected_cve_matches_nothing(self, advisories) -> None:
        """Withdrawn by its CNA. Its wildcard applicability would otherwise match every
        ASA in the estate."""
        advisory = advisories["CVE-2024-99002"]

        assert advisory.affected == []
        assert "Withdrawn" in (advisory.description or "")

    def test_a_rejected_cve_does_not_raise_a_finding(self, advisories) -> None:
        result = match(asa("9.18(2)"), advisories["CVE-2024-99002"])

        assert result.confidence is Confidence.NOT_AFFECTED


# ═══════════════════════════ shape and robustness ════════════════════════════


class TestFeedHandling:
    def test_every_record_becomes_one_advisory(self, advisories) -> None:
        assert len(advisories) == 4

    def test_placeholder_cwes_are_dropped(self, advisories) -> None:
        """`CWE-noinfo` is NVD saying it assigned none; it is not a weakness id."""
        assert advisories["CVE-2024-20359"].cwe_ids == []

    @pytest.mark.parametrize("payload", [None, [], "", {"no": "vulnerabilities"}, 42])
    def test_a_malformed_payload_yields_nothing_rather_than_raising(self, payload) -> None:
        """This is the first thing to touch bytes fetched from NVD.

        A feed that returned an error page must not abort a sync that also carried
        thousands of good records.
        """
        assert parse_nvd_feed(payload) == []

    def test_a_record_with_no_id_is_skipped(self) -> None:
        assert parse_nvd_feed({"vulnerabilities": [{"cve": {"descriptions": []}}]}) == []

    def test_a_record_with_no_configurations_says_so(self) -> None:
        """Silence here would be indistinguishable from "affects nothing"."""
        advisories = parse_nvd_feed(
            {
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2024-00000", "vulnStatus": "Awaiting Analysis"}}
                ]
            }
        )

        assert len(advisories) == 1
        assert advisories[0].fully_interpreted is False
        assert any("no applicability data" in note for note in advisories[0].notes_unparsed)

    def test_a_negated_node_is_not_read_as_a_plain_list(self) -> None:
        """Negation inverts the verdict exactly, so the node is not used for matching."""
        advisories = parse_nvd_feed(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-00001",
                            "configurations": [
                                {
                                    "nodes": [
                                        {
                                            "negate": True,
                                            "cpeMatch": [
                                                {
                                                    "vulnerable": True,
                                                    "criteria": "cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*",
                                                }
                                            ],
                                        }
                                    ]
                                }
                            ],
                        }
                    }
                ]
            }
        )

        assert advisories[0].affected == []
        assert any("negated" in note for note in advisories[0].notes_unparsed)
