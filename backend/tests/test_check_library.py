"""The shipped check library, audited against real parser output (FR-CHK-01, FR-CHK-03).

A check definition can be perfectly valid YAML, load without complaint, and still be
incapable of ever producing a verdict — because the NCM path it names is one no parser
populates for the platforms it claims to apply to. Nothing about that is visible: the
check appears in the policy, runs on every device, and reports *Not Evaluated* or, worse,
a confident failure, forever.

Two failure modes, and they differ in how bad they are:

**`missing: not_evaluated` plus an unresolvable path** is a dead check. Honest, but it
occupies a line in the policy and a row in every result set while telling nobody
anything. `cisco-ssh-key-2048` was one of these: it named
`management.services.ssh.host_key_bits`, which only the NX-OS parser populates, while
its applicability listed IOS alone.

**`missing: fail` plus an unresolvable path is a false finding**, which is much worse —
it reports a problem that is not there, on every device, with full confidence.
`fortios-remote-auth-configured` was one: it named `aaa_servers`, which is not an NCM
path at all (the field is `aaa.servers`), so a FortiGate with RADIUS properly configured
was reported as having no central authentication.

A path counts as resolvable if *any* fixture for an applicable platform resolves it. That
is deliberate: a feature absent from a deliberately weak configuration is the finding, not
a parser gap, so requiring every fixture to resolve every path would flag exactly the
checks that are working.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import jmespath
import pytest

from netsecops.checks.loader import get_registry
from netsecops.checks.schema import CheckDefinition
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser, supported_platforms

FIXTURES = Path(__file__).parent / "fixtures"

#: Every fixture in the corpus, by the platform whose parser reads it. Directory-driven
#: so a new vendor fixture is covered the moment it is added, rather than when somebody
#: remembers to list it here.
CORPUS: dict[str, list[Path]] = {
    "cisco_ios": sorted((FIXTURES / "cisco/ios").rglob("*.cfg")),
    "cisco_nxos": sorted((FIXTURES / "cisco/nxos").rglob("*.cfg")),
    "cisco_asa": sorted((FIXTURES / "cisco/asa").rglob("*.cfg")),
    # AireOS is a command list rather than a configuration file, hence `.txt`.
    "cisco_wlc_aireos": sorted((FIXTURES / "cisco/wlc").rglob("*.txt")),
    # ISE is read as a bundle of API responses, like the Check Point management server.
    "cisco_ise": sorted((FIXTURES / "cisco/ise").rglob("*.json")),
    # AAA servers: two API bundles and two Unix configuration files (FR-AAA-03/04).
    "fortiauthenticator": sorted((FIXTURES / "fortinet/fortiauthenticator").rglob("*.json")),
    "freeradius": sorted((FIXTURES / "linux/freeradius").rglob("*.json")),
    "tac_plus": sorted((FIXTURES / "linux/tacplus").rglob("*.conf")),
    "fortios": sorted((FIXTURES / "fortinet/fortios").rglob("*.cfg")),
    "panos": sorted((FIXTURES / "paloalto/panos").rglob("*.xml")),
    "checkpoint_mgmt": sorted((FIXTURES / "checkpoint/mgmt").rglob("*.json")),
    "checkpoint_gaia": sorted((FIXTURES / "checkpoint/gaia").rglob("*.txt")),
}


@pytest.fixture(scope="module")
def ncms() -> dict[str, list[dict[str, Any]]]:
    """Every fixture parsed once, grouped by platform."""
    return {
        platform: [
            get_parser(platform)
            .parse(ParseContext(text=p.read_text(encoding="utf-8")))
            .to_storage()
            for p in paths
        ]
        for platform, paths in CORPUS.items()
        if paths
    }


def ncm_checks() -> list[CheckDefinition]:
    return [
        definition
        for definition in get_registry().definitions()
        if getattr(definition.logic, "type", None) == "ncm"
        and getattr(definition.logic, "expression", None)
    ]


class TestTheCorpusCoversEveryPlatform:
    def test_every_platform_with_a_parser_has_a_fixture(self) -> None:
        """Without one, none of the audits below can say anything about that platform —
        they would pass by having nothing to check.

        Aliases are exempt: a platform whose parser is shared with another is covered by
        that platform's corpus, and a second identical fixture would only be a second
        thing to keep in step.
        """
        from netsecops.parsers.registry import PARSERS

        canonical = {}
        for platform, parser in PARSERS.items():
            canonical.setdefault(parser, platform)

        missing = [
            platform
            for platform, parser in PARSERS.items()
            if canonical[parser] == platform and not CORPUS.get(platform)
        ]
        assert not missing, f"no fixture for {missing}; the library audit cannot see them"

    def test_the_iosxe_alias_needs_no_fixture_of_its_own(self) -> None:
        """IOS-XE shares the IOS parser and syntax, so the IOS corpus covers it."""
        assert "cisco_iosxe" not in CORPUS
        assert get_parser("cisco_iosxe").__class__ is get_parser("cisco_ios").__class__


class TestEveryExpressionResolves:
    @pytest.mark.parametrize("definition", ncm_checks(), ids=lambda d: d.id)
    def test_the_expression_resolves_on_at_least_one_fixture(
        self, definition: CheckDefinition, ncms: dict[str, list[dict[str, Any]]]
    ) -> None:
        platforms = definition.applicability.platforms or list(ncms)
        candidates = [p for p in platforms if ncms.get(p)]
        if not candidates:
            pytest.skip(f"no fixture for any of {platforms}")

        expression = definition.logic.expression
        for platform in candidates:
            for ncm in ncms[platform]:
                if jmespath.search(expression, ncm) is not None:
                    return

        policy = definition.logic.missing
        consequence = (
            "every device it applies to will be reported as FAILING this check, which is "
            "a false finding"
            if policy == "fail"
            else "it can never produce a verdict and is dead weight in every policy"
        )
        pytest.fail(
            f"{definition.id} selects {expression!r}, which no parser populates for "
            f"{candidates}. Its missing policy is '{policy}', so {consequence}. Either "
            f"the path is wrong, the applicability names the wrong platforms, or the "
            f"parser does not yet capture the value."
        )

    @pytest.mark.parametrize("definition", ncm_checks(), ids=lambda d: d.id)
    def test_the_expression_is_valid_jmespath(self, definition: CheckDefinition) -> None:
        """Caught at load time by the schema too, but a compile error here names the
        check rather than failing the whole registry."""
        jmespath.compile(definition.logic.expression)


class TestApplicabilityIsMeaningful:
    @pytest.mark.parametrize("definition", get_registry().definitions(), ids=lambda d: d.id)
    def test_every_named_platform_exists(self, definition: CheckDefinition) -> None:
        """A typo in a platform name makes a check apply to nothing, and looks exactly
        like a check that passes everywhere."""
        known = set(supported_platforms())
        unknown = [p for p in definition.applicability.platforms if p not in known]
        assert not unknown, f"{definition.id} names unknown platform(s) {unknown}"

    @pytest.mark.parametrize("definition", get_registry().definitions(), ids=lambda d: d.id)
    def test_a_vendor_scoped_check_names_that_vendors_platforms(
        self, definition: CheckDefinition
    ) -> None:
        """Naming a vendor and then a different vendor's platform means the check applies
        to nothing at all, because the two conditions are combined with AND."""
        vendors = {v.lower() for v in definition.applicability.vendors}
        if not vendors or not definition.applicability.platforms:
            return

        prefixes = {
            "cisco": ("cisco_",),
            "fortinet": ("fortios",),
            "paloalto": ("panos",),
            "checkpoint": ("checkpoint_",),
        }
        expected = tuple(p for v in vendors for p in prefixes.get(v, ()))
        if not expected:
            return

        mismatched = [p for p in definition.applicability.platforms if not p.startswith(expected)]
        assert not mismatched, (
            f"{definition.id} declares vendor(s) {sorted(vendors)} but platform(s) "
            f"{mismatched}; the two are ANDed, so the check applies to nothing."
        )


class TestTheLibraryAsAWhole:
    def test_check_ids_are_unique(self) -> None:
        ids = [d.id for d in get_registry().definitions()]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        assert not duplicates, f"duplicate check ids: {duplicates}"

    def test_every_check_has_a_rationale_and_remediation(self) -> None:
        """A finding without either is a demand with no argument behind it. The
        rationale is what persuades someone to make the change, and the remediation is
        what tells them how — a check missing them produces work nobody can action."""
        thin = [
            d.id
            for d in get_registry().definitions()
            if len((d.rationale or "").split()) < 20 or not (d.remediation or "").strip()
        ]
        assert not thin, f"checks with a thin rationale or no remediation: {thin}"

    def test_every_check_carries_a_framework_reference(self) -> None:
        """The mappings are what make the report answerable to an auditor. A check with
        none still runs, but cannot appear in any compliance view."""
        unmapped = [
            d.id
            for d in get_registry().definitions()
            if not any(
                getattr(d.references, field, None)
                for field in ("cis", "nist_800_53", "pci_dss", "iso_27001", "cwe")
            )
        ]
        assert not unmapped, f"checks with no framework mapping: {unmapped}"

    @pytest.mark.parametrize(
        ("platform", "vendor", "device_class", "minimum"),
        [
            ("cisco_ios", "cisco", "switch", 60),
            ("cisco_nxos", "cisco", "switch", 35),
            ("cisco_asa", "cisco", "firewall", 28),
            ("fortios", "fortinet", "firewall", 34),
            ("panos", "paloalto", "firewall", 34),
            ("checkpoint_mgmt", "checkpoint", "firewall", 30),
            ("checkpoint_gaia", "checkpoint", "firewall", 32),
        ],
    )
    def test_each_platform_has_a_worthwhile_number_of_checks(
        self, platform: str, vendor: str, device_class: str, minimum: int
    ) -> None:
        """A platform NetSecOps claims to assess must be assessed by more than a handful
        of checks, or a clean report says nothing.

        The vendor is stated rather than derived from the platform name. Deriving it —
        splitting `panos` on an underscore that is not there — silently produced
        `vendor="panos"`, which matches no check's `vendors: [paloalto]`, so every
        vendor-scoped check was excluded and this assertion passed by counting only the
        common pack. A test that measures the wrong thing and passes is worse than none.
        """
        from netsecops.checks.engine import DeviceContext, applies_to

        context = DeviceContext(
            platform=platform,
            device_class=device_class,
            vendor=vendor,
            hostname="audit",
        )
        applicable = [d for d in get_registry().definitions() if applies_to(d, context, {}) is None]
        assert len(applicable) >= minimum, f"only {len(applicable)} checks apply to {platform}"

    def test_the_library_meets_the_phase_4_target(self) -> None:
        """SRS §12 Phase 4 asks for at least 90 checks across the vendor set."""
        assert len(get_registry().definitions()) >= 90, (
            f"the library ships {len(get_registry().definitions())} checks"
        )
