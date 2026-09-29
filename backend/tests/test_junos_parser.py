"""Juniper Junos — SRX, MX and EX (SRS §1.3, FR-PARSE-01 … FR-PARSE-05).

Juniper was the largest single vendor gap against AlgoSec: they onboard SRX, Netscreen,
M/E routers and Junos Space, and we had no policy, no profile and no parser.

**Junos has two configuration formats and they are the same configuration.** The default
is a brace hierarchy; `| display set` prints flat statements. Both arrive in practice —
the flat form because the profile asks for it, the brace form because that is what
`show configuration` returns and what somebody uploading offline will paste. Reading
only one would produce an empty NCM from a perfectly good capture, which is
indistinguishable from a device with nothing configured. So the normaliser is tested as
hard as the parser, and the same fixture is asserted through both formats.

Three properties of the conversion carry most of this file:

* **Line numbers survive it.** A finding cites where its evidence came from, and after
  flattening that is the line which *terminated* the statement, not the one that opened
  the block three levels above.
* **`inactive:` is not a comment.** Junos keeps a deactivated statement in the file.
  Dropping the marker reports a disabled thing as enabled; dropping the line loses that
  somebody left it there. It propagates to everything inside the block.
* **A closing brace must remove exactly what its opening brace pushed.** `security-zone
  trust {` pushes two tokens, so a stack that pops one token per brace silently
  mis-parents every statement after the first nested block.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsecops.adapters.policies import get_policy
from netsecops.adapters.profiles import PROFILES
from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.juniper.junos import to_set_statements
from netsecops.parsers.registry import get_parser

FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "juniper"
    / "junos"
    / "21.4"
    / "srx_show_configuration.txt"
)


def parse(text: str, **supporting: str) -> NormalisedConfig:
    return get_parser("juniper_junos").parse(ParseContext(text=text, supporting=supporting))


@pytest.fixture(scope="module")
def braces() -> NormalisedConfig:
    return parse(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def flat() -> NormalisedConfig:
    """The same configuration, converted to `display set` form and parsed again.

    This is the test that the two formats are one configuration rather than two
    parsers' worth of behaviour.
    """
    statements = to_set_statements(FIXTURE.read_text(encoding="utf-8").splitlines())
    text = "\n".join(
        ("inactive: " if inactive else "") + "set " + " ".join(tokens)
        for _, tokens, inactive in statements
    )
    return parse(text)


# ──────────────────── the platform is wired up ──────────────────────────


class TestThePlatformIsWired:
    def test_it_has_a_policy_a_profile_and_a_parser(self) -> None:
        from netsecops.parsers.registry import PARSERS

        assert get_policy("juniper_junos") is not None
        assert "juniper_junos" in PROFILES
        assert "juniper_junos" in PARSERS

    def test_the_profile_asks_for_the_flat_form(self) -> None:
        # Both formats parse, but the flat one is what a finding's provenance wants:
        # its lines map one-to-one onto statements.
        issued = list(PROFILES["juniper_junos"].all_commands())
        assert issued[0] == "show configuration | display set"

    def test_every_command_it_issues_is_approved(self) -> None:
        policy = get_policy("juniper_junos")
        for command in PROFILES["juniper_junos"].all_commands():
            assert policy.match(command) is not None, command


# ───────────────────────── the normaliser ───────────────────────────────


class TestTheBraceToSetConversion:
    def test_a_nested_statement_gets_its_whole_path(self) -> None:
        text = "system {\n    services {\n        ssh {\n            root-login deny;\n        }\n    }\n}\n"
        statements = to_set_statements(text.splitlines())
        assert [tokens for _, tokens, _ in statements] == [
            ["system", "services", "ssh", "root-login", "deny"]
        ]

    def test_the_line_number_is_the_one_that_terminated_the_statement(self) -> None:
        # Not the line that opened the block. A finding that cites `system {` sends the
        # reader four lines above the thing it is talking about.
        text = "system {\n    services {\n        telnet;\n    }\n}\n"
        statements = to_set_statements(text.splitlines())
        assert statements[0][0] == 3

    def test_a_closing_brace_removes_exactly_what_was_pushed(self) -> None:
        # `security-zone trust {` pushes two tokens. A stack that pops one per brace
        # leaves `trust` on it and mis-parents everything that follows.
        text = (
            "security {\n"
            "    zones {\n"
            "        security-zone trust {\n"
            "            description a;\n"
            "        }\n"
            "        security-zone untrust {\n"
            "            description b;\n"
            "        }\n"
            "    }\n"
            "    policies {\n"
            "        default-policy deny-all;\n"
            "    }\n"
            "}\n"
        )
        statements = [tokens for _, tokens, _ in to_set_statements(text.splitlines())]
        assert statements[-1] == ["security", "policies", "default-policy", "deny-all"]

    def test_inactive_propagates_into_the_block(self) -> None:
        text = "inactive: system {\n    services {\n        telnet;\n    }\n}\n"
        statements = to_set_statements(text.splitlines())
        assert statements[0][2] is True

    def test_a_set_form_capture_passes_straight_through(self) -> None:
        statements = to_set_statements(["set system host-name srx-01"])
        assert statements == [(1, ["system", "host-name", "srx-01"], False)]

    def test_a_quoted_value_stays_one_token(self) -> None:
        # `description "Uplink to core"` is two tokens. Split naively it becomes four
        # and the dispatch that reads `description <value>` matches nothing.
        statements = to_set_statements(['set interfaces ge-0/0/0 description "Uplink to core"'])
        assert statements[0][1][-1] == '"Uplink to core"'

    def test_comments_and_the_version_banner_are_not_statements(self) -> None:
        text = "## Last commit: 2026-09-14\nversion 21.4R3;\nsystem {\n    host-name a;\n}\n"
        statements = [tokens for _, tokens, _ in to_set_statements(text.splitlines())]
        assert ["system", "host-name", "a"] in statements
        assert not any(t[:1] == ["##"] for t in statements)

    def test_output_that_is_not_junos_is_a_parse_failure(self) -> None:
        assert parse("Building configuration...\n").parse_failed is True


# ─────────────────── both formats agree, field by field ─────────────────


class TestBothFormatsReadTheSameDevice:
    def test_hostname(self, braces: NormalisedConfig, flat: NormalisedConfig) -> None:
        assert braces.device.hostname == flat.device.hostname == "srx-edge-01"

    def test_the_same_interfaces(self, braces: NormalisedConfig, flat: NormalisedConfig) -> None:
        assert {i.name for i in braces.interfaces} == {i.name for i in flat.interfaces}

    def test_the_same_rules(self, braces: NormalisedConfig, flat: NormalisedConfig) -> None:
        assert [r.name for r in braces.firewall.security_rules] == [
            r.name for r in flat.firewall.security_rules
        ]

    def test_the_same_routes(self, braces: NormalisedConfig, flat: NormalisedConfig) -> None:
        assert {r.destination for r in braces.routing.routes} == {
            r.destination for r in flat.routing.routes
        }


# ────────────────────── the management plane ────────────────────────────


class TestTheManagementPlane:
    def test_ssh_on_telnet_off(self, braces: NormalisedConfig) -> None:
        # Junos enables a service by the presence of its stanza, so absence *is* the
        # answer here — a parsed configuration with no `telnet` statement is a device
        # with telnet off, and False is honest rather than assumed.
        assert braces.management.services.ssh.enabled is True
        assert braces.management.services.telnet.enabled is False

    def test_http_off_https_on(self, braces: NormalisedConfig) -> None:
        assert braces.management.services.http.enabled is False
        assert braces.management.services.https.enabled is True

    def test_ssh_protocol_version_is_a_number(self, braces: NormalisedConfig) -> None:
        # Junos writes `v2`; the NCM stores 2, as every other platform does.
        assert braces.management.services.ssh.version == 2

    def test_root_login_is_kept(self, braces: NormalisedConfig) -> None:
        assert braces.management.management_acls["ssh-root-login"] == "deny"

    def test_the_login_banner(self, braces: NormalisedConfig) -> None:
        assert "Authorised access only" in (braces.management.banners.login or "")

    def test_idle_timeout_is_seconds(self, braces: NormalisedConfig) -> None:
        # Junos writes minutes. Stored verbatim it reads as a ten-second timeout and
        # passes a check that should fail.
        assert braces.management.session.exec_timeout_s == 600

    def test_users_and_their_class(self, braces: NormalisedConfig) -> None:
        assert {(u.name, u.role) for u in braces.users} == {
            ("netops", "super-user"),
            ("auditor", "read-only"),
        }


class TestSnmpAndAaa:
    def test_read_only_and_read_write_communities_are_distinguished(
        self, braces: NormalisedConfig
    ) -> None:
        by_rw = {c.rw: c for c in braces.snmp.v1v2c_communities}
        assert by_rw[False].is_default is True
        assert by_rw[True].is_default is False

    def test_the_community_string_is_never_stored(self, braces: NormalisedConfig) -> None:
        assert all("public" not in c.name_masked for c in braces.snmp.v1v2c_communities)

    def test_radius_server_and_its_secret(self, braces: NormalisedConfig) -> None:
        radius = [s for s in braces.aaa.servers if s.type == "radius"]
        assert [s.host for s in radius] == ["10.10.0.30"]
        assert radius[0].key_configured is True

    def test_local_fallback_is_read_from_the_authentication_order(
        self, braces: NormalisedConfig
    ) -> None:
        # `authentication-order [ radius password ]` — whether `password` appears after
        # the server is exactly the local-fallback question, and it is the difference
        # between a lockout and a bypass.
        assert braces.aaa.local_fallback is True

    def test_both_syslog_hosts(self, braces: NormalisedConfig) -> None:
        assert [s.host for s in braces.logging.syslog_servers] == ["10.10.0.20", "10.10.0.21"]

    def test_ntp_servers_and_the_preferred_one(self, braces: NormalisedConfig) -> None:
        assert [s.host for s in braces.ntp.servers] == ["10.10.0.10", "10.10.0.11"]
        assert braces.ntp.servers[0].prefer is True


# ──────────────────────── interfaces and routes ─────────────────────────


class TestInterfaces:
    def test_a_unit_is_its_own_interface(self, braces: NormalisedConfig) -> None:
        # `ge-0/0/0.0` is what a zone binds and what a route egresses. Collapsing units
        # into their physical parent makes both joins fail.
        names = {i.name for i in braces.interfaces}
        assert "ge-0/0/0.0" in names

    def test_addresses_keep_their_prefix_length(self, braces: NormalisedConfig) -> None:
        uplink = next(i for i in braces.interfaces if i.name == "ge-0/0/0.0")
        assert uplink.ip_addresses == ["10.10.10.2/30"]

    def test_the_out_of_band_port_is_flagged_as_management(self, braces: NormalisedConfig) -> None:
        # fxp0 is Junos's management port by convention on every platform that has one,
        # and every "is management separated" check reads the interface list.
        fxp = next(i for i in braces.interfaces if i.name.startswith("fxp0"))
        assert fxp.is_management is True

    def test_a_deactivated_interface_is_down_not_absent(self, braces: NormalisedConfig) -> None:
        # `inactive: ge-0/0/7` is still in the configuration. Reported as up it is a
        # live interface nobody is watching; dropped entirely, nobody learns it is
        # still configured.
        decommissioned = [i for i in braces.interfaces if i.name.startswith("ge-0/0/7")]
        assert decommissioned
        assert all(i.admin_up is False for i in decommissioned)


class TestRouting:
    def test_static_routes(self, braces: NormalisedConfig) -> None:
        by_destination = {r.destination: r for r in braces.routing.routes}
        assert by_destination["0.0.0.0/0"].next_hop == "10.10.10.1"
        assert by_destination["172.16.0.0/12"].next_hop == "192.0.2.254"

    def test_a_discard_route_has_no_next_hop(self, braces: NormalisedConfig) -> None:
        # Stored with a next hop it becomes an edge to a device that does not exist,
        # and the topology walk follows it.
        discard = next(r for r in braces.routing.routes if r.destination == "10.99.0.0/16")
        assert discard.next_hop is None


# ──────────────────────────── the SRX bits ──────────────────────────────


class TestTheAddressBook:
    """Not optional, and `test_silent_emptiness` is what proved it.

    A policy matching `destination-address dmz-web` resolves that name against the
    address objects. With none parsed it resolves to the empty set, and a rule whose
    destination is empty can never match a packet — nothing errors, nothing is logged,
    the rule is simply skipped every time. The first draft of this parser read policies
    and not the book, and the sweep caught it.
    """

    def test_addresses(self, braces: NormalisedConfig) -> None:
        by_name = {o.name: o for o in braces.firewall.address_objects}
        assert by_name["dmz-web"].value == "192.0.2.10/32"
        assert by_name["dmz-api"].value == "192.0.2.11/32"

    def test_an_address_set_accumulates_its_members(self, braces: NormalisedConfig) -> None:
        # Junos writes one `address` line per member, so a reader that assigns rather
        # than appends keeps only the last and reports a group of one.
        group = next(g for g in braces.firewall.address_groups if g.name == "dmz-services")
        assert group.members == ["dmz-web", "dmz-api"]

    def test_a_rule_referring_to_an_object_is_not_inert(self, braces: NormalisedConfig) -> None:
        legacy = next(r for r in braces.firewall.security_rules if r.name == "legacy-inbound")
        assert legacy.dst == ["dmz-web"]
        assert any(o.name == "dmz-web" for o in braces.firewall.address_objects)


class TestSecurityPolicies:
    def test_zones(self, braces: NormalisedConfig) -> None:
        assert set(braces.firewall.zones) == {"trust", "untrust"}

    def test_a_policy_carries_its_zones_and_match_criteria(self, braces: NormalisedConfig) -> None:
        allow = next(r for r in braces.firewall.security_rules if r.name == "allow-web")
        assert (allow.src_zones, allow.dst_zones) == (["trust"], ["untrust"])
        assert allow.applications == ["junos-http", "junos-https"]
        assert allow.action == "allow"

    def test_permit_becomes_allow(self, braces: NormalisedConfig) -> None:
        # The NCM's vocabulary is `allow`, and the rulebase analysis keys off it. A rule
        # left as Junos's `permit` is a rule no shadowing check ever evaluates.
        assert {r.action for r in braces.firewall.security_rules} <= {"allow", "deny", "reject"}

    def test_a_policy_with_no_action_defaults_to_deny(self) -> None:
        # Junos has no implicit permit. A policy whose `then` we failed to read must not
        # become an allow — that is the one direction where a parser bug opens a hole.
        text = (
            "security {\n    policies {\n        from-zone a to-zone b {\n"
            "            policy p {\n                match {\n"
            "                    source-address any;\n                }\n"
            "            }\n        }\n    }\n}\n"
        )
        ncm = parse(text)
        assert ncm.firewall.security_rules[0].action == "deny"

    def test_a_deactivated_policy_is_disabled_not_missing(self, braces: NormalisedConfig) -> None:
        # It is still in the configuration and will come back the moment somebody
        # activates it. Dropped, nobody reviews it; reported as enabled, it is a rule
        # the rulebase analysis thinks is live.
        legacy = next(r for r in braces.firewall.security_rules if r.name == "legacy-inbound")
        assert legacy.enabled is False

    def test_logging_on_a_rule(self, braces: NormalisedConfig) -> None:
        allow = next(r for r in braces.firewall.security_rules if r.name == "allow-web")
        assert allow.log_end is True

    def test_a_router_without_a_security_hierarchy_is_not_an_error(self) -> None:
        # An MX or EX has no `security` stanza. Empty is the correct answer, and it must
        # not be a parse failure.
        ncm = parse("system {\n    host-name mx-core-01;\n}\n")
        assert ncm.firewall.security_rules == []
        assert ncm.parse_failed is False


# ─────────────────────── version, for CVE matching ──────────────────────


class TestVersionFromSupportingOutput:
    def test_version_and_model(self) -> None:
        # Not in the configuration on any Junos platform, so without the supporting
        # artefact no CVE can be matched (FR-VUL-01).
        show_version = "Hostname: srx-edge-01\nModel: srx345\nJunos: 21.4R3-S4.9\n"
        ncm = parse("system {\n    host-name srx-edge-01;\n}\n", **{"show version": show_version})
        assert ncm.device.version == "21.4R3-S4.9"
        assert ncm.device.model == "srx345"

    def test_the_chassis_serial(self) -> None:
        hardware = "Item             Version  Part number  Serial number     Description\nChassis                                JN123456AB        SRX345\n"
        ncm = parse(
            "system {\n    host-name a;\n}\n", **{"show chassis hardware": hardware}
        )
        assert ncm.device.serials == ["JN123456AB"]

    def test_no_supporting_output_leaves_the_version_unknown(
        self, braces: NormalisedConfig
    ) -> None:
        # None, not a guess. A CVE matched against an invented version is worse than
        # one not matched at all.
        assert braces.device.version is None
