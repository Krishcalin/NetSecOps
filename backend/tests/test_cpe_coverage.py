"""Checking the CPE product names against imported advisories (FR-VUL-02).

`vuln/cpe.py` maps each platform to the CPE vendor and product the dictionary is
*expected* to use. Those names were written from documentation and never confirmed;
`unverified_products()` has existed since Phase 6 as the list of what needed confirming,
with no caller, because confirming appeared to need the NVD CPE dictionary.

It does not. Every imported NVD advisory carries the CPE strings NVD itself uses, so the
corpus already in the database is the dictionary.

**Why a wrong name is worth this much care.** It fails silently. There is no error, no
unparsed record and no warning — the device simply matches no advisory, which on the
vulnerability page is indistinguishable from a device that has none. It is the one defect
in the matcher that makes an estate look *safer* than it is.

**What counts as a contradiction is the whole design, and it took three attempts.**
"Advisories exist for this vendor and none names our product" flags any product the
corpus does not happen to cover — against this repository's own fixtures it called four
Cisco names wrong when the corpus holds two advisories. Adding a string-similarity
threshold was no better: `ios_xe` and `ios_xr` score 0.8 and are different operating
systems, so a corpus with one would condemn the other.

A contradiction now requires the same name under different **punctuation** — the one
difference that is never a different product. Everything else is no-evidence, with the
vendor's real product names listed beside it for a human to read.

That is the difference between a report someone acts on and one they learn to ignore.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.db.models.vulnerability import VulnAdvisory
from netsecops.services.cpe_coverage import Corroboration, CpeCoverageService
from netsecops.vuln.cpe import PRODUCTS, unverified_products


async def advisory(
    session: AsyncSession, *, advisory_id: str, affected: list[dict[str, object]]
) -> VulnAdvisory:
    row = VulnAdvisory(
        org_id=1,
        advisory_id=advisory_id,
        source="nvd",
        title=advisory_id,
        cve_ids=[],
        affected=affected,
    )
    session.add(row)
    await session.flush()
    return row


def entry(coverage, platform: str):
    return next(item for item in coverage.products if item.platform == platform)


class TestTheListItselfIsStillWorthChecking:
    def test_every_product_in_the_table_is_offered_for_verification(self) -> None:
        """`unverified_products()` and the coverage report must cover the same set — a
        platform added to one and not the other is a name nobody ever checks."""
        assert set(unverified_products()) == set(PRODUCTS)


class TestWithNoAdvisories:
    async def test_nothing_is_contradicted(self, session: AsyncSession) -> None:
        """An empty corpus proves nothing. Reporting every name as wrong would be the
        loudest possible way of saying "no data"."""
        coverage = await CpeCoverageService(session).build()

        assert coverage.contradicted == []
        assert all(item.status is Corroboration.NO_EVIDENCE for item in coverage.products)

    async def test_it_says_why_it_could_not_check(self, session: AsyncSession) -> None:
        coverage = await CpeCoverageService(session).build()

        assert any("No advisories have been imported" in note for note in coverage.limitations)


class TestCorroboration:
    async def test_a_name_an_advisory_uses_is_corroborated(self, session: AsyncSession) -> None:
        await advisory(
            session,
            advisory_id="CVE-2024-20353",
            affected=[
                {"cpe": "cpe:2.3:o:cisco:adaptive_security_appliance_software:9.18:*:*:*:*:*:*:*"}
            ],
        )

        coverage = await CpeCoverageService(session).build()

        assert entry(coverage, "cisco_asa").status is Corroboration.CORROBORATED

    async def test_the_cpe_part_does_not_have_to_agree(self, session: AsyncSession) -> None:
        """Our table records ISE as an application; NVD files the same product under `o`
        often enough that requiring the part to match would produce false contradictions.
        Vendor and product agreeing is the claim being checked."""
        await advisory(
            session,
            advisory_id="CVE-2024-ISE",
            affected=[{"cpe": "cpe:2.3:o:cisco:identity_services_engine:3.1:*:*:*:*:*:*:*"}],
        )

        coverage = await CpeCoverageService(session).build()

        assert entry(coverage, "cisco_ise").status is Corroboration.CORROBORATED

    async def test_a_csaf_advisory_without_a_cpe_still_counts_as_evidence(
        self, session: AsyncSession
    ) -> None:
        """A CSAF advisory names the vendor and product in prose and carries no CPE.
        Ignoring it would report every CSAF-only vendor as having no evidence."""
        await advisory(
            session,
            advisory_id="PAN-SA-2024-0012",
            affected=[{"vendor": "paloaltonetworks", "product": "pan-os"}],
        )

        coverage = await CpeCoverageService(session).build()

        assert entry(coverage, "panos").status is Corroboration.CORROBORATED


class TestContradiction:
    async def test_a_near_miss_on_punctuation_is_contradicted(self, session: AsyncSession) -> None:
        """**The finding this exists to produce.**

        Our table says `nx-os`; the corpus says `nx_os`. One of the two is wrong, and the
        wrong one matches no advisory at all while reporting the device as clean.
        """
        await advisory(
            session,
            advisory_id="CVE-2024-NXOS",
            affected=[{"cpe": "cpe:2.3:o:cisco:nx_os:9.3:*:*:*:*:*:*:*"}],
        )

        coverage = await CpeCoverageService(session).build()

        nxos = entry(coverage, "cisco_nxos")
        assert nxos.status is Corroboration.CONTRADICTED
        assert nxos.closest_match == "nx_os"
        assert nxos in coverage.contradicted

    async def test_an_unrelated_product_for_the_same_vendor_is_not_a_contradiction(
        self, session: AsyncSession
    ) -> None:
        """The mistake the first version of this check made.

        Cisco publishes for hundreds of products. A corpus holding one IOS-XR advisory
        says nothing about whether our ASA name is right, and reporting it as wrong sends
        an operator chasing a defect that is not there — after which they stop reading the
        report at all.
        """
        await advisory(
            session,
            advisory_id="CVE-2024-OTHER",
            affected=[{"cpe": "cpe:2.3:o:cisco:ios_xr:7.5:*:*:*:*:*:*:*"}],
        )

        coverage = await CpeCoverageService(session).build()

        assert entry(coverage, "cisco_asa").status is Corroboration.NO_EVIDENCE
        assert coverage.contradicted == []

    async def test_a_sibling_product_in_the_same_family_is_not_a_contradiction(
        self, session: AsyncSession
    ) -> None:
        """Why string similarity was rejected, pinned so it cannot come back.

        `ios_xe` and `ios_xr` score 0.8 against each other and are different operating
        systems. Vendors name whole families this way — `ios`, `ios_xe`, `ios_xr`,
        `nx-os` — so similarity cannot tell a misspelling from a sibling, and a corpus
        holding one of them must not condemn the others.
        """
        await advisory(
            session,
            advisory_id="CVE-2024-XR",
            affected=[{"cpe": "cpe:2.3:o:cisco:ios_xr:7.5:*:*:*:*:*:*:*"}],
        )

        coverage = await CpeCoverageService(session).build()

        assert entry(coverage, "cisco_iosxe").status is Corroboration.NO_EVIDENCE
        assert entry(coverage, "cisco_ios").status is Corroboration.NO_EVIDENCE

    async def test_it_still_offers_the_names_the_corpus_carries(
        self, session: AsyncSession
    ) -> None:
        """Even without a contradiction, the candidates are worth showing — they are what
        turns "unconfirmed" into something a human can check by eye."""
        await advisory(
            session,
            advisory_id="CVE-2024-OTHER",
            affected=[{"cpe": "cpe:2.3:o:cisco:ios_xr:7.5:*:*:*:*:*:*:*"}],
        )

        coverage = await CpeCoverageService(session).build()

        assert "ios_xr" in entry(coverage, "cisco_asa").vendor_products_seen

    async def test_another_vendors_advisories_say_nothing(self, session: AsyncSession) -> None:
        await advisory(
            session,
            advisory_id="CVE-2024-OTHER",
            affected=[{"cpe": "cpe:2.3:o:cisco:ios_xr:7.5:*:*:*:*:*:*:*"}],
        )

        coverage = await CpeCoverageService(session).build()

        assert entry(coverage, "fortios").status is Corroboration.NO_EVIDENCE

    async def test_the_no_evidence_gap_is_reported_as_a_corpus_gap(
        self, session: AsyncSession
    ) -> None:
        await advisory(
            session,
            advisory_id="CVE-2024-OTHER",
            affected=[{"cpe": "cpe:2.3:o:cisco:ios_xr:7.5:*:*:*:*:*:*:*"}],
        )

        coverage = await CpeCoverageService(session).build()

        assert any("gap in the corpus, not a fault" in note for note in coverage.limitations)


class TestUnreadableInput:
    async def test_a_malformed_cpe_does_not_abort_the_check(self, session: AsyncSession) -> None:
        """Advisories carry malformed identifiers. One must not take the report with it."""
        await advisory(
            session,
            advisory_id="CVE-2024-BAD",
            affected=[
                {"cpe": "not-a-cpe"},
                {"cpe": "cpe:2.3:o:cisco:adaptive_security_appliance_software:9.18:*:*:*:*:*:*:*"},
            ],
        )

        coverage = await CpeCoverageService(session).build()

        assert entry(coverage, "cisco_asa").status is Corroboration.CORROBORATED

    @pytest.mark.parametrize("affected", [[], [{"cpe": None}], [{"vendor": "cisco"}]])
    async def test_an_advisory_naming_nothing_usable_is_simply_no_evidence(
        self, session: AsyncSession, affected: list[dict[str, object]]
    ) -> None:
        await advisory(session, advisory_id="CVE-2024-EMPTY", affected=affected)

        coverage = await CpeCoverageService(session).build()

        assert coverage.contradicted == []
