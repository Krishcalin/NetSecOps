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
ADVERTISED = ("cis", "nist_800_53", "pci_dss", "iso_27001", "cert_in", "cea")


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
