"""Every advertised compliance framework has checks behind it (FR-CHK-05).

`References` declared `cert_in` and `cea`, the compliance view offered both as pivots
and the frontend carried labels for them — and not one of the 103 shipped checks used
either. `GET /compliance/cert_in` returned an empty framework, which renders as a
compliance view with nothing in it rather than as "this framework is not mapped".

That is the same class of defect the check library already guards against elsewhere: a
declaration that looks like coverage and is not. `test_check_library.py` catches a check
whose NCM path no parser populates; this catches a framework whose checks do not exist.
"""

from __future__ import annotations

from collections import Counter

import pytest

from netsecops.checks.loader import get_registry
from netsecops.checks.schema import References

#: Frameworks the product offers as a compliance pivot. Adding one here without mapping
#: any checks fails the build, which is the point.
ADVERTISED = (
    "cis",
    "nist_800_53",
    "pci_dss",
    "iso_27001",
    "cert_in",
    "cea",
    "hipaa",
    "nerc_cip",
    "nist_800_41",
)


@pytest.fixture(scope="module")
def registry():
    return get_registry()


class TestNoFrameworkIsAdvertisedAndEmpty:
    @pytest.mark.parametrize("framework", ADVERTISED)
    def test_every_advertised_framework_has_checks(self, registry, framework: str) -> None:
        mapped = registry.by_framework(framework)

        assert mapped, (
            f"`{framework}` is offered as a compliance pivot with no check mapped to it. "
            "An empty framework renders as a compliance view with nothing in it, which "
            "reads as a clean result rather than as an unmapped framework. Either map "
            "checks to it or remove it from the schema and the UI."
        )

    def test_the_schema_declares_exactly_what_is_advertised(self) -> None:
        """A field added to `References` and to nothing else is a framework that will
        silently never appear."""
        declared = set(References.frameworks_declared())

        assert declared == set(ADVERTISED), (
            "The frameworks declared on References have drifted from the list this "
            f"test asserts. Declared: {sorted(declared)}; advertised: {sorted(ADVERTISED)}."
        )

    async def test_the_api_serves_every_advertised_framework(
        self, client, analyst, authenticate
    ) -> None:
        """The other half of the same defect, from the other end.

        The console used to hard-code its own list of four, so `cert_in` and `cea` were
        mapped, tested and invisible. A mapping the product has and does not offer is,
        to a user, indistinguishable from one it does not have — so the list is served
        from the registry and this asserts the two agree.
        """
        authenticate(analyst)

        rows = (await client.get("/api/v1/compliance/frameworks")).json()

        assert {r["key"] for r in rows} == set(ADVERTISED)
        # The count travels with the key: 13 mapped checks and 103 support very
        # different claims, and a picker that lists them identically invites the
        # stronger claim to be made from the weaker mapping.
        counts = {r["key"]: r["checks"] for r in rows}
        assert counts["cert_in"] > 0
        assert counts["nist_800_53"] > counts["cert_in"]


class TestTheIndianFrameworksAreMappedDeliberately:
    """CERT-In and CEA are prose directives, not numbered control catalogues.

    The identifiers name the subject rather than inventing a clause number — see
    docs/compliance-india.md. These tests pin the shape so a later contributor does not
    "tidy" them into invented numbering.
    """

    def test_cert_in_maps_only_what_a_configuration_can_evidence(self, registry) -> None:
        """Five of the seven Directions are incident reporting, points of contact and
        KYC obligations. None is satisfiable by a running-config, and mapping them would
        inflate a compliance percentage with checks that cannot fail for the right
        reason."""
        subjects = Counter()
        for check in registry.by_framework("cert_in"):
            subjects.update(check.references.cert_in)

        assert set(subjects) == {"Clock Synchronisation", "Log Retention"}

    def test_cert_in_covers_the_clock_and_the_logs(self, registry) -> None:
        ids = {check.id for check in registry.by_framework("cert_in")}

        assert "ntp-server-configured" in ids
        assert "syslog-server-configured" in ids

    def test_cea_is_organised_by_subject_area(self, registry) -> None:
        subjects = Counter()
        for check in registry.by_framework("cea"):
            subjects.update(check.references.cea)

        assert set(subjects) == {
            "Access Control",
            "Cryptography",
            "Logging and Monitoring",
            "Network Security",
            "Remote Access",
            "Secure Configuration",
            "Wireless Security",
        }

    def test_every_check_carries_a_cea_subject(self, registry) -> None:
        """CEA's guidelines address secure configuration of ICT assets broadly, so the
        pivot discriminates by *subject* rather than by which checks are in scope."""
        unmapped = [check.id for check in registry.definitions() if not check.references.cea]

        assert not unmapped, f"checks with no CEA subject: {sorted(unmapped)[:10]}"

    def test_no_invented_clause_numbers(self, registry) -> None:
        """Neither published document numbers its requirements in a form that can be
        cited like `AC-4`. A bare number here would be fabricated precision."""
        for check in registry.definitions():
            for value in list(check.references.cert_in) + list(check.references.cea):
                assert not value.strip().rstrip(".").replace(".", "").isdigit(), (
                    f"{check.id} cites `{value}` as a clause number. CERT-In Directions "
                    "and the CEA guidelines are prose; cite the subject instead."
                )


class TestTheThreeNewFrameworksAreCitedFromASource:
    """HIPAA, NERC CIP and NIST 800-41, added to match AlgoSec's advertised set.

    Each is pinned to the vocabulary its published source actually uses, so a later
    contributor cannot enlarge a framework by inventing an identifier. See
    docs/compliance-frameworks.md for how each mapping was arrived at, and for why
    FISMA, SOX and IAVA were considered and deliberately not advertised.
    """

    #: HIPAA Security Rule, Technical Safeguards — the only standards a device
    #: configuration can evidence. Real § numbers from 45 CFR 164.312.
    HIPAA_SAFEGUARDS = frozenset(
        {
            "164.312(a)(1)",
            "164.312(a)(2)(iii)",
            "164.312(b)",
            "164.312(d)",
            "164.312(e)(1)",
        }
    )

    #: NERC CIP requirements a running-config can evidence: the electronic security
    #: perimeter and the system-security-management sub-requirements.
    NERC_REQUIREMENTS = frozenset(
        {
            "CIP-005-7 R1",
            "CIP-007-6 R1",
            "CIP-007-6 R4",
            "CIP-007-6 R5",
        }
    )

    #: NIST SP 800-41r1 is prose, so — like cert_in and cea — it is cited by subject.
    NIST_800_41_SUBJECTS = frozenset(
        {"Firewall Management", "Firewall Logging", "Firewall Policy"}
    )

    def test_hipaa_cites_only_real_technical_safeguards(self, registry) -> None:
        for check in registry.by_framework("hipaa"):
            for value in check.references.hipaa:
                assert value in self.HIPAA_SAFEGUARDS, (
                    f"{check.id} cites HIPAA `{value}`, which is not one of the technical "
                    f"safeguards a configuration can evidence: {sorted(self.HIPAA_SAFEGUARDS)}."
                )

    def test_nerc_cip_cites_only_config_evidenceable_requirements(self, registry) -> None:
        for check in registry.by_framework("nerc_cip"):
            for value in check.references.nerc_cip:
                assert value in self.NERC_REQUIREMENTS, (
                    f"{check.id} cites NERC `{value}`, outside the requirements a config "
                    f"can evidence: {sorted(self.NERC_REQUIREMENTS)}."
                )

    def test_nist_800_41_is_cited_by_subject_never_a_number(self, registry) -> None:
        for check in registry.by_framework("nist_800_41"):
            for value in check.references.nist_800_41:
                assert value in self.NIST_800_41_SUBJECTS, (
                    f"{check.id} cites 800-41 `{value}`. 800-41r1 is prose; cite one of "
                    f"{sorted(self.NIST_800_41_SUBJECTS)} — never a clause number."
                )
                assert not value.strip().rstrip(".").replace(".", "").isdigit()
