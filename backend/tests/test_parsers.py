"""Parser tests against the fixture corpus (FR-PARSE-01 … FR-PARSE-05).

Three kinds of assertion live here, and they answer different questions:

1. **Corpus-wide invariants** run over every fixture. They catch the failures that are
   catastrophic and easy to miss — a parser that leaks a secret into the NCM, one that
   raises on an unfamiliar stanza, one whose provenance points at the wrong line.
2. **Per-fixture expectations** pin down what each configuration actually says. These
   are what make the parsers useful rather than merely non-crashing.
3. **Coverage** asserts the parsers understand ≥90% of each fixture, so a regression
   that quietly stops parsing half a configuration fails here rather than silently
   turning checks into "Not evaluated".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from netsecops.core.redaction import REDACTED
from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import NoParserError, get_parser, supported_platforms

FIXTURES = Path(__file__).parent / "fixtures"

#: Secrets that appear in the fixtures. Every one must be absent from the NCM, from
#: provenance excerpts and from raw_unparsed — the three places parser output escapes.
#:
#: ``test_every_planted_secret_is_actually_planted`` asserts each of these really does
#: occur in the corpus. Without that guard a typo or an edited fixture would leave an
#: entry matching nothing, and the leak tests would pass by checking for a string that
#: was never there — the most comfortable kind of false assurance.
PLANTED_SECRETS = (
    # Cisco IOS — hardened
    "S3cr3tVtpPass",
    "Ro-Community-9f3a",
    "$9$abcdefghijklmnop",
    "$9$EnableSecretHashHere00",
    "08351F1B4A0C0A0E",
    "071B24475D0A1601",
    # Cisco IOS — weak
    "Admin123",
    "070C285F4D06",
    "cisco123",
    "T4c4csK3y!Secret",
    "R4d1usK3y!Secret",
    "VtpP4ssw0rd",
    # Cisco NX-OS
    "$5$abcdefgh$ijklmnopqrstuvwxyz",
    "$5$qwertyui$opasdfghjklzxcvbnm",
    "0x1234abcd",
    "0xdeadbeef",
    "RoCommunity9f3a",
    "RwCommunity7b21",
    "abc123def456",
    # Cisco ASA
    "$sha512$5000$abcdefgh$ijklmnop",
    "$sha512$5000$qrstuvwx$yzabcdef",
)


@dataclass(frozen=True)
class Fixture:
    platform: str
    path: Path

    @property
    def id(self) -> str:
        return f"{self.platform}:{self.path.parent.name}/{self.path.name}"

    def text(self) -> str:
        return self.path.read_text(encoding="utf-8")

    def parse(self) -> NormalisedConfig:
        return get_parser(self.platform).parse(ParseContext(text=self.text(), command="show run"))


CORPUS = [
    Fixture("cisco_ios", FIXTURES / "cisco/ios/17.9/hardened_switch.cfg"),
    Fixture("cisco_ios", FIXTURES / "cisco/ios/15.2/weak_switch.cfg"),
    Fixture("cisco_nxos", FIXTURES / "cisco/nxos/10.3/dc_switch.cfg"),
    Fixture("cisco_nxos", FIXTURES / "cisco/nxos/9.3/edge_n3k.cfg"),
    Fixture("cisco_asa", FIXTURES / "cisco/asa/9.18/edge_firewall.cfg"),
]

HARDENED_IOS, WEAK_IOS, DC_NXOS, EDGE_NXOS, ASA = CORPUS


def meaningful_lines(text: str) -> list[str]:
    """Configuration lines a parser is expected to account for.

    Blank lines and comments are excluded: they carry no configuration, and counting
    them would inflate coverage without the parser understanding anything more.
    """
    return [
        line
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("!") and line.strip() not in {"end", "exit"}
    ]


class TestTheCorpusItself:
    @pytest.mark.parametrize("secret", PLANTED_SECRETS)
    def test_every_planted_secret_is_actually_planted(self, secret: str) -> None:
        """A leak test that searches for a string no fixture contains proves nothing."""
        assert any(secret in fixture.text() for fixture in CORPUS), (
            f"{secret!r} appears in no fixture, so every test asserting it does not "
            "leak is vacuous. Remove it, or plant it."
        )

    def test_every_fixture_lives_under_vendor_platform_version(self) -> None:
        """FR-PARSE-05 prescribes the layout, and Phase 4 adds three more vendors to
        it — a corpus that drifted from the convention now would be worse then."""
        for fixture in CORPUS:
            version_dir, platform_dir, vendor_dir = (
                fixture.path.parent,
                fixture.path.parent.parent,
                fixture.path.parent.parent.parent,
            )
            assert vendor_dir.parent.name == "fixtures", (
                f"{fixture.path} is not at fixtures/<vendor>/<platform>/<version>/"
            )
            assert platform_dir.name and version_dir.name[0].isdigit()


# ────────────────────────── corpus-wide invariants ──────────────────────────


@pytest.mark.parametrize("fixture", CORPUS, ids=lambda f: f.id)
class TestEveryFixture:
    def test_parses_without_raising(self, fixture: Fixture) -> None:
        """FR-PARSE-03. A parser that raises takes the whole collection with it."""
        ncm = fixture.parse()
        assert ncm.ncm_version == "1.0"

    def test_coverage_is_at_least_90_percent(self, fixture: Fixture) -> None:
        """Phase 2 acceptance criterion."""
        ncm = fixture.parse()
        total = len(meaningful_lines(fixture.text()))
        understood = total - len(ncm.raw_unparsed)
        coverage = 100 * understood / total

        assert coverage >= 90, (
            f"{fixture.id}: parser understood only {coverage:.1f}% of "
            f"{total} configuration lines. Unparsed:\n  " + "\n  ".join(ncm.raw_unparsed[:25])
        )

    def test_no_secret_reaches_the_ncm(self, fixture: Fixture) -> None:
        """FR-COL-13 and C-2.

        The NCM is written to the database as JSONB, returned by the API and copied
        into findings. A secret that reaches it has effectively been published.
        """
        serialised = fixture.parse().model_dump_json()
        leaked = [secret for secret in PLANTED_SECRETS if secret in serialised]
        assert not leaked, f"{fixture.id}: these secrets survived into the NCM: {leaked}"

    def test_provenance_points_at_real_lines(self, fixture: Fixture) -> None:
        """FR-PARSE-04. Provenance that points nowhere is worse than none at all —
        a finding would cite a line the operator cannot find."""
        ncm = fixture.parse()
        line_count = len(fixture.text().splitlines())
        assert ncm.provenance.entries, f"{fixture.id}: recorded no provenance at all"

        for path, entry in ncm.provenance.entries.items():
            assert entry.line_start is not None
            assert 1 <= entry.line_start <= line_count, (
                f"{fixture.id}: provenance for {path} points at line "
                f"{entry.line_start}, outside 1..{line_count}"
            )
            assert entry.line_end is None or entry.line_end >= entry.line_start

    def test_provenance_excerpts_are_redacted(self, fixture: Fixture) -> None:
        """An excerpt is copied into findings and tickets, so it must never carry
        the secret its own line contained."""
        ncm = fixture.parse()
        for path, entry in ncm.provenance.entries.items():
            if not entry.excerpt:
                continue
            leaked = [secret for secret in PLANTED_SECRETS if secret in entry.excerpt]
            assert not leaked, f"{fixture.id}: excerpt for {path} leaks {leaked}"

    def test_unparsed_lines_are_redacted(self, fixture: Fixture) -> None:
        """The unparsed list is the one place raw configuration is kept verbatim.
        It is also returned by the API, so it goes through redaction too."""
        ncm = fixture.parse()
        joined = "\n".join(ncm.raw_unparsed)
        leaked = [secret for secret in PLANTED_SECRETS if secret in joined]
        assert not leaked, f"{fixture.id}: raw_unparsed leaks {leaked}"

    def test_parsing_is_deterministic(self, fixture: Fixture) -> None:
        """Two parses of one file must agree, or snapshot hashing is meaningless and
        every collection would look like drift."""
        assert fixture.parse().model_dump_json() == fixture.parse().model_dump_json()

    def test_hostname_is_extracted(self, fixture: Fixture) -> None:
        ncm = fixture.parse()
        assert ncm.device.hostname, f"{fixture.id}: no hostname parsed"


# ──────────────────────────── tolerance (FR-PARSE-03) ────────────────────────


class TestTolerance:
    @pytest.mark.parametrize("platform", sorted(supported_platforms()))
    def test_garbage_does_not_raise(self, platform: str) -> None:
        """Vendor syntax drifts between releases; a parser that fell over on the first
        surprise would be useless in the field."""
        nonsense = "\n".join(
            [
                "hostname surprise",
                "quantum-entangle interface Gi1/0/1 with Gi1/0/2",
                "    unindented-child-of-nothing",
                "!" * 200,
                "\x00\x01 binary garbage",
                "interface",  # truncated stanza
            ]
        )
        ncm = get_parser(platform).parse(ParseContext(text=nonsense))
        assert ncm.raw_unparsed, "unrecognised lines must be retained, not dropped"

    @pytest.mark.parametrize("platform", sorted(supported_platforms()))
    def test_empty_input_does_not_raise(self, platform: str) -> None:
        ncm = get_parser(platform).parse(ParseContext(text=""))
        assert ncm.device.hostname is None

    def test_unknown_platform_raises(self) -> None:
        """A device we cannot interpret must not be silently reported as clean."""
        with pytest.raises(NoParserError, match="No configuration parser"):
            get_parser("acme_router_9000")

    def test_truncated_configuration_still_parses_what_arrived(self) -> None:
        """A collection cut short mid-transfer should yield what did arrive."""
        text = FIXTURES.joinpath("cisco/ios/17.9/hardened_switch.cfg").read_text(encoding="utf-8")
        ncm = get_parser("cisco_ios").parse(ParseContext(text=text[: len(text) // 2]))
        assert ncm.device.hostname


# ──────────────────── absent is not false (the NCM discipline) ───────────────


class TestAbsentIsNotFalse:
    def test_unmentioned_service_is_none_not_false(self) -> None:
        """Blurring "not found" with "found, and off" produces confident, wrong
        findings: a check would report Telnet as disabled on a configuration that
        never mentioned it."""
        ncm = get_parser("cisco_ios").parse(ParseContext(text="hostname bare\n"))
        assert ncm.management.services.telnet.enabled is None
        assert ncm.management.services.http.enabled is None

    def test_explicitly_disabled_service_is_false(self) -> None:
        ncm = get_parser("cisco_ios").parse(
            ParseContext(text="hostname sw1\nno ip http server\nno ip http secure-server\n")
        )
        assert ncm.management.services.http.enabled is False
        assert ncm.management.services.https.enabled is False


# ─────────────────────────── per-fixture expectations ────────────────────────


class TestHardenedIosSwitch:
    @pytest.fixture
    def ncm(self) -> NormalisedConfig:
        return HARDENED_IOS.parse()

    def test_identity(self, ncm: NormalisedConfig) -> None:
        assert ncm.device.hostname == "core-sw-01"
        assert ncm.device.version == "17.9"
        assert ncm.device.vendor == "cisco"

    def test_telnet_is_off_and_ssh_is_v2(self, ncm: NormalisedConfig) -> None:
        assert ncm.management.services.ssh.enabled is True
        assert ncm.management.services.ssh.version == 2
        assert ncm.management.services.telnet.enabled is False

    def test_aaa_is_centralised_with_local_fallback(self, ncm: NormalisedConfig) -> None:
        assert ncm.aaa.new_model is True
        assert ncm.aaa.local_fallback is True
        assert {server.type for server in ncm.aaa.servers} <= {"tacacs", "radius"}
        assert ncm.aaa.servers, "no AAA servers parsed"
        assert all(server.key_configured for server in ncm.aaa.servers)

    def test_snmp_v3_only(self, ncm: NormalisedConfig) -> None:
        assert ncm.snmp.v3_users, "no SNMPv3 users parsed"
        assert all(user.level == "authPriv" for user in ncm.snmp.v3_users)

    def test_syslog_and_ntp_are_configured(self, ncm: NormalisedConfig) -> None:
        assert ncm.logging.syslog_servers
        assert ncm.ntp.servers
        assert ncm.ntp.authenticated is True

    def test_interface_security_is_captured(self, ncm: NormalisedConfig) -> None:
        access_ports = [i for i in ncm.interfaces if i.mode == "access"]
        assert access_ports, "no access ports parsed"
        assert any(i.security.port_security is True for i in access_ports)
        assert any(i.security.bpduguard is True for i in access_ports)

    def test_no_plaintext_user_passwords(self, ncm: NormalisedConfig) -> None:
        assert ncm.users, "no local users parsed"
        assert all(not user.weak_hash for user in ncm.users)


class TestWeakIosSwitch:
    """The fixture that should light up like a Christmas tree in Phase 3."""

    @pytest.fixture
    def ncm(self) -> NormalisedConfig:
        return WEAK_IOS.parse()

    def test_telnet_is_enabled(self, ncm: NormalisedConfig) -> None:
        assert ncm.management.services.telnet.enabled is True

    def test_weak_password_hashing_is_detected(self, ncm: NormalisedConfig) -> None:
        assert any(user.weak_hash for user in ncm.users), (
            "a type-7 or type-5 secret must be flagged as a weak hash"
        )

    def test_snmp_v2c_communities_are_recorded_but_masked(self, ncm: NormalisedConfig) -> None:
        assert ncm.snmp.v1v2c_communities, "no v2c communities parsed"
        for community in ncm.snmp.v1v2c_communities:
            assert "RoCommunity9f3a" not in (community.name_masked or "")
            assert "RwCommunity7b21" not in (community.name_masked or "")

    def test_writable_community_is_identified(self, ncm: NormalisedConfig) -> None:
        """Losing the read/write distinction would downgrade a critical finding."""
        assert any(c.rw for c in ncm.snmp.v1v2c_communities)

    def test_http_server_is_enabled(self, ncm: NormalisedConfig) -> None:
        assert ncm.management.services.http.enabled is True

    def test_differs_from_the_hardened_switch(self) -> None:
        hardened, weak = HARDENED_IOS.parse(), WEAK_IOS.parse()
        assert hardened.management.services.telnet.enabled is not (
            weak.management.services.telnet.enabled
        )


class TestNxosSwitch:
    @pytest.fixture
    def ncm(self) -> NormalisedConfig:
        return DC_NXOS.parse()

    def test_identity(self, ncm: NormalisedConfig) -> None:
        assert ncm.device.hostname
        assert ncm.device.version and ncm.device.version.startswith("10.3")

    def test_features_are_captured(self, ncm: NormalisedConfig) -> None:
        """NX-OS gates most behaviour on feature flags; a check that ignored them
        would assess capabilities the device does not have enabled."""
        assert ncm.features.extra, "no NX-OS features parsed"

    def test_snmp_v3_priv_records_the_algorithm_not_the_key(self, ncm: NormalisedConfig) -> None:
        """NX-OS writes `priv 0x<key>`; an earlier version of this parser captured the
        key material into the field meant for the algorithm name."""
        for user in ncm.snmp.v3_users:
            assert not (user.priv or "").startswith("0x")
            assert not (user.auth or "").startswith("0x")

    def test_local_accounts_are_parsed_without_their_hashes(self, ncm: NormalisedConfig) -> None:
        assert ncm.users
        for user in ncm.users:
            assert "$9$" not in (user.secret_type or "")


class TestWeakNxosSwitch:
    """The NX-OS counterpart of the weak IOS switch."""

    @pytest.fixture
    def ncm(self) -> NormalisedConfig:
        return EDGE_NXOS.parse()

    def test_telnet_feature_is_detected(self, ncm: NormalisedConfig) -> None:
        """`feature telnet` is how a Nexus turns Telnet on; missing it would report a
        device with Telnet listening as having no Telnet at all."""
        assert ncm.management.services.telnet.enabled is True

    def test_password_strength_check_enabled_is_recorded(self, ncm: NormalisedConfig) -> None:
        assert ncm.management.password_policy.complexity_required is True

    def test_plaintext_password_is_flagged_as_weak(self, ncm: NormalisedConfig) -> None:
        weak = [user for user in ncm.users if user.weak_hash]
        assert weak, "a `password 0` account must be flagged as a weak hash"

    def test_banner_is_captured(self, ncm: NormalisedConfig) -> None:
        assert ncm.management.banners.motd

    def test_snmp_user_without_priv_is_authnopriv(self, ncm: NormalisedConfig) -> None:
        """Collapsing authNoPriv into authPriv would report an unencrypted SNMPv3
        session as encrypted."""
        assert any(user.level == "authNoPriv" for user in ncm.snmp.v3_users)

    def test_ntp_authenticate_is_recorded(self, ncm: NormalisedConfig) -> None:
        assert ncm.ntp.authenticated is True

    def test_writable_community_bound_to_an_admin_group_is_rw(self, ncm: NormalisedConfig) -> None:
        """NX-OS expresses write access as group membership, not an `rw` keyword."""
        assert any(community.rw for community in ncm.snmp.v1v2c_communities)

    def test_default_community_is_identified(self, ncm: NormalisedConfig) -> None:
        assert any(community.is_default for community in ncm.snmp.v1v2c_communities)


class TestLegacyIosConstructs:
    """Syntax a 15.2-era switch still uses, which the hardened 17.9 fixture lacks."""

    @pytest.fixture
    def ncm(self) -> NormalisedConfig:
        return WEAK_IOS.parse()

    def test_one_line_aaa_servers_are_parsed(self, ncm: NormalisedConfig) -> None:
        """`tacacs-server host` predates `aaa group server` and is still everywhere."""
        kinds = {server.type for server in ncm.aaa.servers}
        assert kinds == {"tacacs", "radius"}
        assert all(server.key_configured for server in ncm.aaa.servers)

    def test_numbered_acls_are_grouped_by_number(self, ncm: NormalisedConfig) -> None:
        """Numbered ACLs are flat lines, not a hierarchy; entries sharing a number are
        one ACL, and treating each line as its own would make every rule look isolated."""
        numbered = {acl.name: acl for acl in ncm.acls if acl.type == "numbered"}
        assert "10" in numbered
        assert len(numbered["10"].entries) == 2
        assert any(entry.log for entry in numbered["10"].entries)

    def test_vtp_password_is_recorded_as_set_not_as_a_value(self, ncm: NormalisedConfig) -> None:
        assert ncm.l2.vtp_password_set is True
        assert "VtpP4ssw0rd" not in ncm.model_dump_json()

    def test_banner_is_captured(self, ncm: NormalisedConfig) -> None:
        assert ncm.management.banners.motd


class TestShowVersionPrefix:
    def test_show_version_output_supplies_the_precise_version(self) -> None:
        """The collection profile issues `show version` alongside the configuration.
        Its version string carries the maintenance letter the config line omits, and
        Phase 6 needs that precision to match a CVE rather than a whole train."""
        text = (
            "Cisco IOS Software, C2960X Software, Version 15.2(7)E3, RELEASE SOFTWARE\n"
            "hostname sw1\n"
            "version 15.2\n"
        )
        ncm = get_parser("cisco_ios").parse(ParseContext(text=text))
        assert ncm.device.version == "15.2(7)E3"


class TestSectionFailureIsContained:
    def test_one_failing_section_does_not_lose_the_others(self, monkeypatch) -> None:
        """A parser is a long list of independent sections. If an unforeseen input
        breaks one, the other twenty must still produce their part of the NCM —
        otherwise a single odd stanza costs the entire assessment."""
        parser = get_parser("cisco_ios")

        def explode(*_args: object, **_kwargs: object) -> None:
            raise ValueError("simulated section failure")

        monkeypatch.setattr(parser, "_parse_snmp", explode)
        ncm = parser.parse(ParseContext(text=HARDENED_IOS.text()))

        assert ncm.device.hostname == "core-sw-01"
        assert ncm.snmp.v3_users == []


class TestMalformedStanzas:
    """Lines a device should never emit, but sometimes does.

    These exercise the guards that skip an unusable line instead of raising. Each one
    is a line seen in the wild from a truncated transfer or a half-applied change.
    """

    @pytest.mark.parametrize(
        "text",
        [
            "username\n",
            "snmp-server community\n",
            "snmp-server user\n",
            "aaa authentication login\n",
            "access-list 10\n",
            "logging host\n",
            "ntp server\n",
            "interface\n",
            "ip access-list extended\n",
        ],
        ids=lambda t: t.strip().replace(" ", "_") or "blank",
    )
    def test_ios_truncated_line_is_skipped_not_fatal(self, text: str) -> None:
        ncm = get_parser("cisco_ios").parse(ParseContext(text=f"hostname sw1\n{text}"))
        assert ncm.device.hostname == "sw1"

    @pytest.mark.parametrize(
        "text",
        [
            "username\n",
            "snmp-server community\n",
            "snmp-server user\n",
            "aaa authentication login\n",
            "logging server\n",
            "ntp server\n",
            "tacacs-server host\n",
            "interface\n",
        ],
        ids=lambda t: t.strip().replace(" ", "_") or "blank",
    )
    def test_nxos_truncated_line_is_skipped_not_fatal(self, text: str) -> None:
        ncm = get_parser("cisco_nxos").parse(ParseContext(text=f"hostname sw1\n{text}"))
        assert ncm.device.hostname == "sw1"

    @pytest.mark.parametrize(
        "text",
        [
            "username\n",
            "access-list\n",
            "object network\n",
            "interface\n",
            "aaa-server\n",
        ],
        ids=lambda t: t.strip().replace(" ", "_") or "blank",
    )
    def test_asa_truncated_line_is_skipped_not_fatal(self, text: str) -> None:
        ncm = get_parser("cisco_asa").parse(ParseContext(text=f"hostname fw1\n{text}"))
        assert ncm.device.hostname == "fw1"


class TestAsaFirewall:
    @pytest.fixture
    def ncm(self) -> NormalisedConfig:
        return ASA.parse()

    def test_identity(self, ncm: NormalisedConfig) -> None:
        assert ncm.device.hostname
        assert ncm.device.version and ncm.device.version.startswith("9.18")

    def test_interfaces_carry_security_levels(self, ncm: NormalisedConfig) -> None:
        assert ncm.interfaces
        assert any(i.description or i.name for i in ncm.interfaces)

    def test_access_lists_are_parsed(self, ncm: NormalisedConfig) -> None:
        assert ncm.acls, "no ACLs parsed from an ASA configuration"
        assert any(acl.entries for acl in ncm.acls)

    def test_ssh_restrictions_are_captured(self, ncm: NormalisedConfig) -> None:
        assert ncm.management.services.ssh.enabled is True


# ─────────────────────────────── redaction ───────────────────────────────────


class TestRedactionOfFixtures:
    @pytest.mark.parametrize("fixture", CORPUS, ids=lambda f: f.id)
    def test_redacted_config_keeps_structure_but_loses_secrets(self, fixture: Fixture) -> None:
        """A redacted configuration must still be readable as configuration — an
        operator reviewing a diff needs the line, just not the secret."""
        from netsecops.core.redaction import redact_config

        original = fixture.text()
        redacted = redact_config(original)

        assert len(redacted.splitlines()) == len(original.splitlines()), (
            "redaction must not add or remove lines, or line numbers in provenance "
            "would stop matching the text they point at"
        )
        for secret in PLANTED_SECRETS:
            assert secret not in redacted, f"{fixture.id}: {secret!r} survived redaction"

    @pytest.mark.parametrize("fixture", CORPUS, ids=lambda f: f.id)
    def test_redaction_is_idempotent(self, fixture: Fixture) -> None:
        """Redacting twice must not replace the placeholders themselves, or the
        fingerprint that makes a placeholder traceable would be destroyed."""
        from netsecops.core.redaction import redact_config

        once = redact_config(fixture.text())
        assert redact_config(once) == once

    @pytest.mark.parametrize("fixture", CORPUS, ids=lambda f: f.id)
    def test_something_was_actually_redacted(self, fixture: Fixture) -> None:
        """Guards against a redaction rule silently ceasing to match: a fixture with
        no placeholders at all would otherwise pass every test above."""
        from netsecops.core.redaction import redact_config

        assert REDACTED in redact_config(fixture.text())


# ─────────────────────────── line-number discipline ──────────────────────────


class TestLineNumbers:
    def test_provenance_is_one_based(self) -> None:
        """ciscoconfparse2 counts from zero; operators count from one. An off-by-one
        here sends every finding to the wrong line."""
        text = "hostname sw1\nno ip http server\n"
        ncm = get_parser("cisco_ios").parse(ParseContext(text=text))
        entry = ncm.provenance.entries.get("device.hostname")

        assert entry is not None
        assert entry.line_start == 1

    def test_excerpt_matches_the_line_it_names(self) -> None:
        text = "!\n!\nhostname sw1\n"
        ncm = get_parser("cisco_ios").parse(ParseContext(text=text))
        entry = ncm.provenance.entries["device.hostname"]

        assert entry.line_start == 3
        assert "hostname sw1" in (entry.excerpt or "")

    @pytest.mark.parametrize("fixture", CORPUS, ids=lambda f: f.id)
    def test_unparsed_entries_carry_their_line_number(self, fixture: Fixture) -> None:
        ncm = fixture.parse()
        for entry in ncm.raw_unparsed:
            assert re.match(r"^\d+: ", entry), (
                f"unparsed entry {entry!r} has no line number, so an operator cannot "
                "find it in their own configuration"
            )
