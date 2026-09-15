"""CPE 2.3 construction (FR-VUL-01).

A CPE is the join key between a device and the NVD, and every way of getting it wrong
fails silently. A misspelled product, an unescaped parenthesis, a wildcard version — none
of them raises. They produce a device that reports no vulnerabilities, which is
indistinguishable on screen from a device that is fully patched.

So the tests here are mostly about the two refusals rather than the happy path: no CPE
without a mapped product, and no CPE without a version.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser
from netsecops.vuln.cpe import (
    PRODUCTS,
    Cpe,
    Part,
    hardware_cpe,
    quote,
    software_cpe,
    unverified_products,
)

FIXTURES = Path(__file__).parent / "fixtures"
OPERATIONAL = FIXTURES / "operational"


def ncm_for(platform: str, config: str, supporting: dict[str, str] | None = None):
    text = (FIXTURES / config).read_text(encoding="utf-8")
    return get_parser(platform).parse(ParseContext(text=text, supporting=supporting or {}))


def device_ncm(*, vendor=None, platform=None, version=None, model=None) -> NormalisedConfig:
    """A bare NCM carrying only what a CPE is built from."""
    ncm = NormalisedConfig()
    ncm.device.vendor = vendor
    ncm.device.platform = platform
    ncm.device.version = version
    ncm.device.model = model
    return ncm


# ═══════════════════════════════ quoting ═════════════════════════════════════


class TestQuoting:
    """The binding rules. Each of these appears in a real device version string."""

    def test_parentheses_are_escaped(self) -> None:
        """`15.2(7)E3` is an entirely ordinary Cisco version.

        Unescaped, the parentheses make the identifier unparseable to anything reading
        it back, and the device silently matches nothing.
        """
        assert quote("15.2(7)E3") == r"15.2\(7\)e3"

    def test_dots_and_hyphens_stand_for_themselves(self) -> None:
        """Every version has dots and half the products have hyphens.

        Escaping these would be just as wrong as failing to escape parentheses — NVD
        publishes `cisco:nx-os`, not `cisco:nx\\-os`.
        """
        assert quote("nx-os") == "nx-os"
        assert quote("11.0.3") == "11.0.3"

    def test_case_is_normalised(self) -> None:
        """Matching is case-insensitive in the spec and case-sensitive in every
        implementation that compares strings."""
        assert quote("R81.20") == "r81.20"

    def test_whitespace_becomes_underscores(self) -> None:
        """A CPE component cannot contain a space, and `Nexus9000 C93180YC-EX` does."""
        assert quote("Nexus9000 C93180YC-EX") == "nexus9000_c93180yc-ex"

    def test_underscores_survive(self) -> None:
        assert quote("ios_xe") == "ios_xe"

    @pytest.mark.parametrize("character", ["(", ")", ":", "/", "?", "*", "!", "#", "%", "+"])
    def test_every_other_punctuation_mark_is_escaped(self, character: str) -> None:
        assert quote(f"a{character}b") == f"a\\{character}b"


# ═══════════════════════════ software identifiers ════════════════════════════


class TestSoftwareCpe:
    def test_a_cisco_ios_switch(self) -> None:
        ncm = device_ncm(vendor="cisco", platform="cisco_ios", version="15.2(7)E3")
        cpe = software_cpe(ncm)

        assert cpe is not None
        assert cpe.to_string() == r"cpe:2.3:o:cisco:ios:15.2\(7\)e3:*:*:*:*:*:*:*"

    @pytest.mark.parametrize(
        ("platform", "version", "expected"),
        [
            ("cisco_iosxe", "17.9.4a", "cpe:2.3:o:cisco:ios_xe:17.9.4a:*:*:*:*:*:*:*"),
            ("cisco_nxos", "10.3(4a)", r"cpe:2.3:o:cisco:nx-os:10.3\(4a\):*:*:*:*:*:*:*"),
            (
                "cisco_asa",
                "9.18(2)",
                r"cpe:2.3:o:cisco:adaptive_security_appliance_software:9.18\(2\):*:*:*:*:*:*:*",
            ),
            ("panos", "11.0.3-h1", "cpe:2.3:o:paloaltonetworks:pan-os:11.0.3-h1:*:*:*:*:*:*:*"),
            ("fortios", "7.2.5", "cpe:2.3:o:fortinet:fortios:7.2.5:*:*:*:*:*:*:*"),
            ("checkpoint_gaia", "R81.20", "cpe:2.3:o:checkpoint:gaia_os:r81.20:*:*:*:*:*:*:*"),
        ],
    )
    def test_each_operating_system(self, platform: str, version: str, expected: str) -> None:
        cpe = software_cpe(device_ncm(platform=platform, version=version))

        assert cpe is not None
        assert cpe.to_string() == expected

    def test_an_aaa_server_is_an_application_not_an_operating_system(self) -> None:
        """ISE runs on an OS; the CVEs are against the product.

        Emitting part `o` here would compare it against operating-system advisories and
        miss every ISE advisory there is.
        """
        cpe = software_cpe(device_ncm(platform="cisco_ise", version="3.2.0.542"))

        assert cpe is not None
        assert cpe.part is Part.APPLICATION
        assert cpe.to_string().startswith("cpe:2.3:a:cisco:identity_services_engine:")


class TestSoftwareCpeRefusals:
    """The two cases where a CPE could be produced and must not be."""

    def test_no_version_means_no_cpe(self) -> None:
        """A wildcard version would match every advisory ever written for the product.

        A PAN-OS firewall whose `show system info` did not run would go from "version
        unknown" to "affected by every PAN-OS CVE in the database" — the single most
        damaging output this module could produce.
        """
        assert software_cpe(device_ncm(platform="panos", version=None)) is None
        assert software_cpe(device_ncm(platform="panos", version="   ")) is None

    def test_an_unmapped_platform_yields_nothing(self) -> None:
        """Not a guess. A wrong product name matches nothing and looks like a pass."""
        assert software_cpe(device_ncm(platform="juniper_junos", version="21.4R3")) is None

    def test_no_platform_yields_nothing(self) -> None:
        assert software_cpe(device_ncm(version="15.2(7)E3")) is None

    def test_a_wildcard_never_appears_in_the_version_component(self) -> None:
        """Belt and braces on the refusal above, stated as a property.

        Whatever route a CPE is built by, the version component must name a version.
        """
        for platform in PRODUCTS:
            cpe = software_cpe(device_ncm(platform=platform, version="1.2.3"))
            assert cpe is not None
            assert cpe.to_string().split(":")[5] != "*"


# ═══════════════════════════ hardware identifiers ════════════════════════════


class TestHardwareCpe:
    def test_a_catalyst_switch(self) -> None:
        cpe = hardware_cpe(device_ncm(vendor="cisco", model="WS-C2960X-48FPD-L"))

        assert cpe is not None
        assert cpe.to_string() == "cpe:2.3:h:cisco:ws-c2960x-48fpd-l:-:*:*:*:*:*:*:*"

    def test_the_version_component_is_na_rather_than_any(self) -> None:
        """A chassis has no software version.

        `-` says "not applicable"; `*` says "any version", which is a different and
        wrong claim — it would match hardware entries qualified by a version.
        """
        cpe = hardware_cpe(device_ncm(vendor="cisco", model="WS-C2960X-48FPD-L"))

        assert cpe is not None
        assert cpe.to_string().split(":")[5] == "-"

    def test_the_vendor_is_mapped_to_its_cpe_spelling(self) -> None:
        """The inventory says `paloalto`; the dictionary says `paloaltonetworks`."""
        cpe = hardware_cpe(device_ncm(vendor="paloalto", model="PA-3220"))

        assert cpe is not None
        assert cpe.to_string() == "cpe:2.3:h:paloaltonetworks:pa-3220:-:*:*:*:*:*:*:*"

    def test_no_model_means_no_hardware_cpe(self) -> None:
        assert hardware_cpe(device_ncm(vendor="cisco", model=None)) is None

    def test_an_unmapped_vendor_means_no_hardware_cpe(self) -> None:
        assert hardware_cpe(device_ncm(vendor="juniper", model="EX4300")) is None


# ══════════════════ built from what the parsers actually produce ═════════════


class TestAgainstRealFixtures:
    """The identifiers that come out of the real parse path.

    Every test above constructs an NCM by hand. These prove the whole chain — fixture,
    parser, supporting artefact, CPE — so that a change to any link shows up here.
    """

    def test_a_collected_ios_switch(self) -> None:
        ncm = ncm_for(
            "cisco_ios",
            "cisco/ios/15.2/weak_switch.cfg",
            {"show version": (OPERATIONAL / "cisco_ios/show_version_c2960x.txt").read_text()},
        )

        assert str(software_cpe(ncm)) == r"cpe:2.3:o:cisco:ios:15.2\(7\)e3:*:*:*:*:*:*:*"
        assert str(hardware_cpe(ncm)) == "cpe:2.3:h:cisco:ws-c2960x-48fpd-l:-:*:*:*:*:*:*:*"

    def test_an_uploaded_ios_switch_yields_a_coarser_identifier_and_no_hardware(self) -> None:
        """The difference the operational artefact makes, stated as a CPE.

        Without `show version` the identifier is `15.2` — a release train containing
        dozens of rebuilds — and there is no hardware CPE at all, because a running
        configuration never names the chassis.
        """
        ncm = ncm_for("cisco_ios", "cisco/ios/15.2/weak_switch.cfg")

        assert str(software_cpe(ncm)) == "cpe:2.3:o:cisco:ios:15.2:*:*:*:*:*:*:*"
        assert hardware_cpe(ncm) is None

    def test_a_collected_panos_firewall(self) -> None:
        request = "GET /api/?type=op&cmd=<show><system><info></info></system></show>"
        ncm = ncm_for(
            "panos",
            "paloalto/panos/11.0/perimeter_fw.xml",
            {request: (OPERATIONAL / "panos/show_system_info.xml").read_text()},
        )

        assert str(software_cpe(ncm)) == "cpe:2.3:o:paloaltonetworks:pan-os:11.0.3-h1:*:*:*:*:*:*:*"
        assert str(hardware_cpe(ncm)) == "cpe:2.3:h:paloaltonetworks:pa-3220:-:*:*:*:*:*:*:*"

    def test_an_uncollected_panos_firewall_has_no_software_cpe(self) -> None:
        """The refusal, reached through the real parser rather than a hand-built NCM."""
        ncm = ncm_for("panos", "paloalto/panos/11.0/perimeter_fw.xml")

        assert software_cpe(ncm) is None

    def test_a_collected_nexus_switch(self) -> None:
        ncm = ncm_for(
            "cisco_nxos",
            "cisco/nxos/10.3/dc_switch.cfg",
            {"show version": (OPERATIONAL / "cisco_nxos/show_version_n9k.txt").read_text()},
        )

        assert str(software_cpe(ncm)) == r"cpe:2.3:o:cisco:nx-os:10.3\(4a\):*:*:*:*:*:*:*"
        # The chassis string contains a space, which a CPE component cannot.
        assert str(hardware_cpe(ncm)) == "cpe:2.3:h:cisco:nexus9000_c93180yc-ex:-:*:*:*:*:*:*:*"


# ══════════════════════════ the standing obligation ══════════════════════════


class TestProductNamesAreVerifiedWhenFeedsLand:
    def test_every_parsed_platform_has_a_product_mapping_or_is_known_absent(self) -> None:
        """A platform NetSecOps parses but cannot name in CPE terms is unassessable.

        Not a failure — some genuinely have no dictionary entry — but it must be a
        deliberate, visible omission rather than one nobody noticed. Adding a parser
        without considering its CPE name will fail here.
        """
        from netsecops.parsers.registry import PARSERS

        missing = set(PARSERS) - set(PRODUCTS)

        assert missing == set(), (
            f"platforms with no CPE product mapping: {sorted(missing)}. Add them to "
            "PRODUCTS, or record here why they have no dictionary entry."
        )

    def test_the_provisional_names_are_listed_for_checking(self) -> None:
        """These strings are written from the naming convention and have NOT been
        checked against a real NVD dictionary — there is none in the repository.

        `unverified_products()` is what the feed-ingestion slice calls to do that, and
        this test is the record that it is still owed. When the dictionary lands, any
        name below that has no match is a device silently reporting zero
        vulnerabilities.
        """
        names = unverified_products()

        assert names["cisco_ios"] == "cisco:ios"
        assert names["cisco_iosxe"] == "cisco:ios_xe"
        assert names["panos"] == "paloaltonetworks:pan-os"
        assert len(names) == len(PRODUCTS)


class TestCpeRoundTrip:
    def test_the_string_has_exactly_thirteen_components(self) -> None:
        """A CPE 2.3 formatted string is `cpe:2.3:` plus eleven components.

        Escaped colons inside a component do not count, which is the point of quoting
        them — a product name containing a bare colon would shift every field after it.
        """
        cpe = Cpe(part=Part.OS, vendor="cisco", product="ios", version="15.2(7)E3")
        raw = cpe.to_string()

        assert raw.count(":") - raw.count("\\:") == 12
        assert raw.split(":")[:2] == ["cpe", "2.3"]
