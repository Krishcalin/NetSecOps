"""Version, model and serial from operational state (FR-VUL-01, FR-PARSE-04).

A CPE is built from vendor, platform, version and hardware model, and on most platforms
none of the last three is in the running configuration. They come from `show version`,
`show system info` or `show version all` — commands every collection profile already
issued, whose output the runner stored as an artefact and then **discarded before
parsing**. Until this was wired up the version-extraction code in the Cisco, PAN-OS and
Gaia parsers was unreachable in production, and every CVE match would have had nothing
to match against.

The separation between `text` and `supporting` is the part worth protecting. `show
version` reports an uptime that is different every time it is asked. Appending it to the
configuration — the obvious shortcut — would change the config hash on every collection
and report the whole estate as drifting, burying real changes in noise. The last test
here pins that.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.crypto import SecretVault
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser
from netsecops.services.inventory import InventoryService
from netsecops.services.snapshots import SnapshotService
from tests.conftest import make_user

FIXTURES = Path(__file__).parent / "fixtures"
OPERATIONAL = FIXTURES / "operational"


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="artifacts_analyst", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


def read(relative: str) -> str:
    return (FIXTURES / relative).read_text(encoding="utf-8")


def parse(platform: str, config: str, supporting: dict[str, str] | None = None):
    return get_parser(platform).parse(ParseContext(text=read(config), supporting=supporting or {}))


# ════════════════════════════ the artefact channel ═══════════════════════════


class TestParseContextArtifacts:
    def test_a_command_that_ran_is_returned(self) -> None:
        context = ParseContext(text="", supporting={"show version": "Version 15.2(7)E3"})

        assert context.artifact("show version") == "Version 15.2(7)E3"

    def test_a_command_that_did_not_run_is_none(self) -> None:
        assert ParseContext(text="").artifact("show version") is None

    def test_an_empty_response_counts_as_absent(self) -> None:
        """A command that ran and returned nothing told us nothing.

        Returning `""` would let a parser record an empty version, which reads
        downstream as a device whose version is known to be blank.
        """
        context = ParseContext(text="", supporting={"show version": "   \n  "})

        assert context.artifact("show version") is None

    def test_the_first_command_that_answered_wins(self) -> None:
        """The same fact has different command names across platforms and releases."""
        context = ParseContext(text="", supporting={"fw ver": "R81.20"})

        assert context.artifact("show version all", "fw ver") == "R81.20"


# ═══════════════════════════ per-platform extraction ═════════════════════════


class TestCiscoIos:
    CONFIG = "cisco/ios/15.2/weak_switch.cfg"

    def test_the_image_version_comes_from_show_version(self) -> None:
        """Not `15.2`. The train and rebuild are the whole question for a CVE.

        The configuration's own `version 15.2` line is the config-syntax version and is
        what this device reported before the artefact was wired through — indistinguishable
        from every other 15.2 image ever shipped.
        """
        ncm = parse(
            "cisco_ios",
            self.CONFIG,
            {"show version": (OPERATIONAL / "cisco_ios/show_version_c2960x.txt").read_text()},
        )

        assert ncm.device.version == "15.2(7)E3"

    def test_model_and_serial_are_read(self) -> None:
        ncm = parse(
            "cisco_ios",
            self.CONFIG,
            {"show version": (OPERATIONAL / "cisco_ios/show_version_c2960x.txt").read_text()},
        )

        assert ncm.device.model == "WS-C2960X-48FPD-L"
        assert ncm.device.serials == ["FOC1932X0GT"]

    def test_without_the_artefact_it_falls_back_to_the_config_directive(self) -> None:
        """An uploaded configuration (FR-COL-11) has nothing else.

        The coarse value is recorded rather than left None, because a major-release
        match is still worth something — but it is `15.2`, and the matcher has to treat
        it as the imprecise identifier it is.
        """
        ncm = parse("cisco_ios", self.CONFIG)

        assert ncm.device.version == "15.2"
        assert ncm.device.model is None, "nothing may be invented for a model"
        assert ncm.device.serials == []


class TestCiscoNxos:
    CONFIG = "cisco/nxos/10.3/dc_switch.cfg"

    def test_the_configuration_already_carries_the_image_version(self) -> None:
        """NX-OS differs from IOS: its running-config opens with the real image version."""
        assert parse("cisco_nxos", self.CONFIG).device.version == "10.3(4a)"

    def test_the_chassis_and_serial_come_from_show_version(self) -> None:
        ncm = parse(
            "cisco_nxos",
            self.CONFIG,
            {"show version": (OPERATIONAL / "cisco_nxos/show_version_n9k.txt").read_text()},
        )

        assert ncm.device.model == "Nexus9000 C93180YC-EX"
        assert ncm.device.serials == ["FDO21120U5D"]
        assert ncm.device.version == "10.3(4a)", "the artefact must not disturb it"


class TestCiscoAsa:
    CONFIG = "cisco/asa/9.18/edge_firewall.cfg"

    def test_the_appliance_model_and_serial(self) -> None:
        ncm = parse(
            "cisco_asa",
            self.CONFIG,
            {"show version": (OPERATIONAL / "cisco_asa/show_version_asa5525.txt").read_text()},
        )

        assert ncm.device.version == "9.18(2)"
        assert ncm.device.model == "ASA5525"
        assert ncm.device.serials == ["JMX1935L0GT"]


class TestPanos:
    CONFIG = "paloalto/panos/11.0/perimeter_fw.xml"
    REQUEST = "GET /api/?type=op&cmd=<show><system><info></info></system></show>"

    def test_a_panos_device_has_no_version_without_the_artefact(self) -> None:
        """Stated rather than assumed: this is the platform the gap was worst on.

        None, not a guess — the matcher reports "unknown version" and declines to rule.
        """
        assert parse("panos", self.CONFIG).device.version is None

    def test_the_version_model_and_serial_come_from_show_system_info(self) -> None:
        ncm = parse(
            "panos",
            self.CONFIG,
            {self.REQUEST: (OPERATIONAL / "panos/show_system_info.xml").read_text()},
        )

        assert ncm.device.version == "11.0.3-h1", "the hotfix suffix is part of the version"
        assert ncm.device.model == "PA-3220"
        assert ncm.device.serials == ["013201004215"]

    def test_a_plugin_version_is_not_mistaken_for_the_software_version(self) -> None:
        """The fixture carries a `dlp` plugin at 4.0.1 inside `<plugin_versions>`.

        Matching `<sw-version>` as a substring, or taking the first version-shaped
        element, picks up whichever the vendor happened to order first — and a CVE
        matched against a plugin's version number is a finding about nothing.
        """
        ncm = parse(
            "panos",
            self.CONFIG,
            {self.REQUEST: (OPERATIONAL / "panos/show_system_info.xml").read_text()},
        )

        assert ncm.device.version != "4.0.1"

    def test_malformed_xml_leaves_the_version_unknown(self) -> None:
        ncm = parse("panos", self.CONFIG, {self.REQUEST: "<response><result"})

        assert ncm.device.version is None


class TestCheckPointGaia:
    CONFIG = "checkpoint/gaia/R81.20/cp_gw_edge_01.txt"

    def test_no_version_without_the_artefact(self) -> None:
        assert parse("checkpoint_gaia", self.CONFIG).device.version is None

    def test_the_gaia_version_comes_from_show_version_all(self) -> None:
        ncm = parse(
            "checkpoint_gaia",
            self.CONFIG,
            {
                "show version all": (
                    OPERATIONAL / "checkpoint_gaia/show_version_all.txt"
                ).read_text()
            },
        )

        assert ncm.device.version == "R81.20"

    def test_fw_ver_is_the_fallback_when_show_version_did_not_run(self) -> None:
        ncm = parse(
            "checkpoint_gaia",
            self.CONFIG,
            {"fw ver": "This is Check Point's software version R81.20 - Build 631"},
        )

        assert ncm.device.version == "R81.20"

    def test_the_os_version_wins_over_the_firewall_module(self) -> None:
        """A gateway can run a Gaia OS and a firewall module at different versions.

        Advisories are written against the OS, so when both answered the OS is taken —
        merging them, or letting whichever parsed last win, would produce a version that
        matches the wrong advisory set.
        """
        ncm = parse(
            "checkpoint_gaia",
            self.CONFIG,
            {
                "show version all": "Product version Check Point Gaia R81.20\nOS build 631",
                "fw ver": "This is Check Point's software version R80.40 - Build 294",
            },
        )

        assert ncm.device.version == "R81.20"


# ══════════════════ the invariant this change could have broken ══════════════


class TestOperationalStateStaysOutOfTheConfiguration:
    def test_the_parsed_configuration_is_unchanged_by_the_artefact(self) -> None:
        """Supporting output must not change what the configuration parse reports.

        `show version` reports an uptime that differs on every collection. If it reached
        the configuration text, the config hash would change every run, every device in
        the estate would report drift, and real changes would be lost in the noise
        (FR-DRIFT-01).

        It also catches the subtler direction, which is what it caught when first
        written: with the artefact present the parser no longer needed the config's own
        `version 15.2` line, stopped consuming it, and reported a line it understands
        perfectly well as unparsed. `raw_unparsed` means "we could not read this", so
        that would have understated coverage for exactly the devices that were parsed
        most completely.
        """
        without = parse("cisco_ios", TestCiscoIos.CONFIG)
        with_artefact = parse(
            "cisco_ios",
            TestCiscoIos.CONFIG,
            {"show version": (OPERATIONAL / "cisco_ios/show_version_c2960x.txt").read_text()},
        )

        assert with_artefact.raw_unparsed == without.raw_unparsed, (
            "the same configuration must report the same unparsed remainder, with or "
            "without a supporting artefact"
        )

    @pytest.mark.parametrize(
        ("platform", "config"),
        [
            ("cisco_ios", TestCiscoIos.CONFIG),
            ("cisco_nxos", TestCiscoNxos.CONFIG),
            ("cisco_asa", TestCiscoAsa.CONFIG),
        ],
    )
    def test_an_uptime_never_reaches_the_ncm(self, platform: str, config: str) -> None:
        """Nothing that changes between two identical collections may be stored.

        A volatile value in the NCM is not merely untidy: the NCM is what checks read,
        so it would make a check's evidence differ run to run for a device nobody
        touched.
        """
        supporting = {"show version": "uptime is 51 weeks, 2 days, 14 hours, 9 minutes"}
        ncm = parse(platform, config, supporting)

        assert ncm.device.uptime_s is None
        assert "51 weeks" not in ncm.model_dump_json()

    async def test_two_collections_differing_only_in_uptime_are_one_snapshot(
        self, session: AsyncSession, actor: Principal, vault: SecretVault
    ) -> None:
        """The invariant at the level it actually matters: the database.

        The parser-boundary test above proves artefact text does not reach the parsed
        configuration. This proves the consequence — that a device collected twice, whose
        configuration did not change and whose uptime necessarily did, still
        de-duplicates to a single snapshot and raises no drift (FR-DRIFT-01).

        Had `show version` been appended to the configuration instead of carried beside
        it, this would produce two snapshots and a drift finding on every collection, for
        every device in the estate, forever.
        """
        device = await InventoryService(session).create_device(
            mgmt_ip="198.51.100.77",
            actor=actor,
            hostname="uptime-sw-01",
            vendor=Vendor.CISCO,
            platform="cisco_ios",
            device_class=DeviceClass.SWITCH,
        )
        snapshots = SnapshotService(session, vault=vault)
        config = read(TestCiscoIos.CONFIG)
        version_output = (OPERATIONAL / "cisco_ios/show_version_c2960x.txt").read_text()

        first = await snapshots.create_snapshot(
            device,
            config_text=config,
            supporting={"show version": version_output},
        )
        second = await snapshots.create_snapshot(
            device,
            config_text=config,
            supporting={
                "show version": version_output.replace(
                    "uptime is 51 weeks, 2 days, 14 hours, 9 minutes",
                    "uptime is 51 weeks, 2 days, 14 hours, 24 minutes",
                )
            },
        )

        assert second.id == first.id, "a changed uptime is not a configuration change"
        assert not (await snapshots.detect_drift(device, second)).changed

        # And the version still arrived, so this is not passing because nothing was read.
        assert first.ncm["device"]["version"] == "15.2(7)E3"
