"""F5 BIG-IP, read through tmsh (SRS §1.3, FR-PARSE-01 … FR-PARSE-05).

`tmsh list` prints a brace tree that **looks like Junos and is not**: there are no
statement terminators, so brace depth is the only structure, and a parser cannot tell a
setting from a block header without checking whether the line ends in `{`. That is why
this platform has its own reader rather than sharing the Junos one, and most of the
format tests below are about the three shapes that break a naive depth tracker.

**The inversion is the thing most likely to be got wrong.** F5 states TLS as what a
profile will *not* speak — `no-tlsv1`, `no-sslv3` — so the accepted versions are the
complement of the options list. A reader that treats the options as the enabled set
reports a profile offering a version called "no-tlsv1", and misses that TLS 1.0 is on.
It decides whether a listener looks hardened or exposed, so it has its own class.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsecops.adapters.policies import get_policy
from netsecops.adapters.profiles import PROFILES
from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.f5.bigip import parse_blocks
from netsecops.parsers.registry import get_parser

FIXTURE = Path(__file__).parent / "fixtures" / "f5" / "bigip" / "17.1" / "tmsh_list.txt"


def parse(text: str, **supporting: str) -> NormalisedConfig:
    return get_parser("f5_bigip").parse(ParseContext(text=text, supporting=supporting))


@pytest.fixture(scope="module")
def ncm() -> NormalisedConfig:
    return parse(FIXTURE.read_text(encoding="utf-8"))


def listener(ncm: NormalisedConfig, name: str):
    return next(v for v in ncm.load_balancer.virtual_servers if v.id == name).services[0]


# ──────────────────── the platform is wired up ──────────────────────────


class TestThePlatformIsWired:
    def test_policy_profile_and_parser(self) -> None:
        from netsecops.parsers.registry import PARSERS

        assert get_policy("f5_bigip") is not None
        assert "f5_bigip" in PROFILES
        assert "f5_bigip" in PARSERS

    def test_every_command_it_issues_is_approved(self) -> None:
        policy = get_policy("f5_bigip")
        for command in PROFILES["f5_bigip"].all_commands():
            assert policy.match(command) is not None, command

    def test_only_tmsh_read_verbs_are_approved(self) -> None:
        # tmsh separates cleanly: `list` and `show` read; `create`, `modify` and
        # `delete` write. A policy built from the two read verbs cannot express a write.
        patterns = [rule.pattern for rule in get_policy("f5_bigip").commands]
        assert all(p.startswith(("tmsh -q list", "tmsh -q show")) for p in patterns), patterns

    def test_the_advanced_shell_is_not_used(self) -> None:
        # `cat /config/bigip.conf` returns the same text and needs bash, which is the
        # one privilege a read-only BIG-IP account should not have.
        patterns = [rule.pattern for rule in get_policy("f5_bigip").commands]
        assert not any("cat " in p or "bash" in p for p in patterns)


# ────────────────────────── the brace tree ──────────────────────────────


class TestTheFormat:
    def test_a_header_carries_type_and_name(self) -> None:
        # The type and the name arrive together and nothing else identifies the object,
        # so the header has to be kept whole rather than reduced to a name.
        blocks = parse_blocks(
            ["ltm virtual /Common/vs {", "    destination 1.1.1.1:80", "}"]
        )
        assert blocks[0].header == ["ltm", "virtual", "/Common/vs"]
        assert blocks[0].value("destination") == "1.1.1.1:80"

    def test_an_inline_empty_block_does_not_swallow_the_file(self) -> None:
        # `/Common/http { }` appears in every `profiles` stanza. Treated as an
        # unterminated header it consumes everything after it.
        text = "ltm virtual /Common/vs {\n    profiles {\n        /Common/http { }\n    }\n    pool /Common/p\n}\n"
        blocks = parse_blocks(text.splitlines())
        assert len(blocks) == 1
        assert blocks[0].value("pool") == "/Common/p"

    def test_a_brace_delimited_list_is_values_not_a_block(self) -> None:
        # `options { a b c }` is a list. Read as a block its values vanish.
        blocks = parse_blocks(["ltm profile client-ssl /Common/p {", "    options { a b c }", "}"])
        assert blocks[0].values("options") == ["a", "b", "c"]

    def test_a_nested_object_becomes_a_child(self) -> None:
        text = "ltm pool /Common/p {\n    members {\n        /Common/10.0.0.1:80 {\n            address 10.0.0.1\n        }\n    }\n}\n"
        blocks = parse_blocks(text.splitlines())
        members = blocks[0].child("members")
        assert members is not None
        assert members.children[0].value("address") == "10.0.0.1"

    def test_output_that_is_not_tmsh_is_a_parse_failure(self) -> None:
        assert parse("Building configuration...\n").parse_failed is True

    def test_an_unbalanced_brace_does_not_raise(self) -> None:
        # Truncated output is ordinary. It must degrade, not throw.
        assert parse("ltm virtual /Common/vs {\n    pool /Common/p\n").parse_failed is False


# ─────────────────── the TLS inversion, on its own ──────────────────────


class TestTlsIsStatedAsWhatIsDisabled:
    def test_a_hardened_profile_accepts_only_modern_versions(self, ncm: NormalisedConfig) -> None:
        # `options { … no-sslv3 no-tlsv1 no-tlsv1.1 }` leaves 1.2 and 1.3.
        assert listener(ncm, "vs_web_https").tls_versions == ["TLSv1.2", "TLSv1.3"]

    def test_a_profile_disabling_only_sslv3_still_offers_tls_1_0(
        self, ncm: NormalisedConfig
    ) -> None:
        # The finding, and the one a naive reader inverts into a clean result.
        assert "TLSv1.0" in listener(ncm, "vs_legacy_https").tls_versions

    def test_no_option_name_ever_reaches_the_version_list(self, ncm: NormalisedConfig) -> None:
        # Reading the options as the enabled set produces versions called "no-tlsv1"
        # and "dont-insert-empty-fragments", which match no check and no CVE condition.
        for server in ncm.load_balancer.virtual_servers:
            for service in server.services:
                assert all(not v.startswith("no-") for v in service.tls_versions)

    def test_the_profile_is_named_so_a_finding_can_point_at_it(
        self, ncm: NormalisedConfig
    ) -> None:
        assert listener(ncm, "vs_legacy_https").ssl_policy == "clientssl-legacy"


# ────────────────────── what it publishes ───────────────────────────────


class TestVirtualServers:
    def test_every_virtual_server(self, ncm: NormalisedConfig) -> None:
        assert {v.id for v in ncm.load_balancer.virtual_servers} == {
            "vs_web_https",
            "vs_legacy_https",
            "vs_retired",
        }

    def test_the_destination_splits_into_address_and_port(self, ncm: NormalisedConfig) -> None:
        # `/Common/203.0.113.10:443` is partition, address and port in one token.
        web = next(v for v in ncm.load_balancer.virtual_servers if v.id == "vs_web_https")
        assert web.address == "203.0.113.10"
        assert web.services[0].port == 443

    def test_a_disabled_virtual_server(self, ncm: NormalisedConfig) -> None:
        # BIG-IP disables by the *presence* of a bare `disabled` line, so its absence
        # means enabled rather than unknown.
        retired = next(v for v in ncm.load_balancer.virtual_servers if v.id == "vs_retired")
        assert retired.enabled is False

    def test_an_enabled_one_says_so(self, ncm: NormalisedConfig) -> None:
        web = next(v for v in ncm.load_balancer.virtual_servers if v.id == "vs_web_https")
        assert web.enabled is True

    def test_the_pool_reference_is_stripped_of_its_partition(self, ncm: NormalisedConfig) -> None:
        # `/Common/pool_web` and `pool_web` are the same pool. Compared unstripped,
        # every virtual-server-to-pool join misses.
        assert listener(ncm, "vs_web_https").group == "pool_web"
        assert any(g.id == "pool_web" for g in ncm.load_balancer.groups)


class TestPools:
    def test_members_and_their_addresses(self, ncm: NormalisedConfig) -> None:
        by_address = {s.address: s for s in ncm.load_balancer.real_servers}
        assert by_address["10.20.0.11"].port == 8443

    def test_a_member_taken_out_of_rotation(self, ncm: NormalisedConfig) -> None:
        # `session user-disabled` is an administrative decision. `state` reports health,
        # which is a different question and not a configuration fact.
        by_address = {s.address: s for s in ncm.load_balancer.real_servers}
        assert by_address["10.20.0.11"].enabled is True
        assert by_address["10.20.0.12"].enabled is False

    def test_the_monitor_is_the_health_check(self, ncm: NormalisedConfig) -> None:
        pool = next(g for g in ncm.load_balancer.groups if g.id == "pool_web")
        assert pool.health_check == "/Common/https"
        assert pool.members == ["10.20.0.11:8443", "10.20.0.12:8443"]


# ───────────────────────── the platform ─────────────────────────────────


class TestTheManagementPlane:
    def test_hostname(self, ncm: NormalisedConfig) -> None:
        assert ncm.device.hostname == "bigip-edge-01.corp.example.net"

    def test_ssh_timeout_is_already_seconds(self, ncm: NormalisedConfig) -> None:
        # Unlike Junos and Alteon, BIG-IP writes seconds. Multiplying by sixty here
        # would report a fifteen-minute timeout as fifteen hours.
        assert ncm.management.session.exec_timeout_s == 900

    def test_the_login_banner(self, ncm: NormalisedConfig) -> None:
        assert ncm.management.banners.login == "Authorised access only."

    def test_the_gui_ciphers_are_a_list(self, ncm: NormalisedConfig) -> None:
        # Colon-separated on F5, and a check comparing against a weak-cipher set needs
        # them split.
        assert "ECDHE-RSA-AES256-GCM-SHA384" in ncm.management.services.https.ciphers

    def test_users_and_their_roles(self, ncm: NormalisedConfig) -> None:
        # The role lives two levels down under `partition-access`, not beside the name.
        assert {(u.name, u.role) for u in ncm.users} == {("admin", "admin"), ("auditor", "guest")}


class TestSnmpTimeAndLogging:
    def test_read_only_and_read_write_communities(self, ncm: NormalisedConfig) -> None:
        # F5 omits `access` when read-only, so absence is the answer rather than a gap.
        by_rw = {c.rw: c for c in ncm.snmp.v1v2c_communities}
        assert by_rw[False].is_default is True
        assert by_rw[True].is_default is False

    def test_the_community_string_is_never_stored(self, ncm: NormalisedConfig) -> None:
        assert all("public" not in c.name_masked for c in ncm.snmp.v1v2c_communities)

    def test_ntp_servers_come_out_of_a_brace_list(self, ncm: NormalisedConfig) -> None:
        assert [s.host for s in ncm.ntp.servers] == ["10.10.0.10", "10.10.0.11"]

    def test_both_syslog_servers_with_ports(self, ncm: NormalisedConfig) -> None:
        assert [(s.host, s.port) for s in ncm.logging.syslog_servers] == [
            ("10.10.0.20", 514),
            ("10.10.0.21", 514),
        ]


class TestNetwork:
    def test_self_ips_become_interfaces(self, ncm: NormalisedConfig) -> None:
        # The topology graph matches a route's next hop against an interface address.
        # A self IP stored anywhere else joins nothing and the BIG-IP sits alone.
        by_name = {i.name: i for i in ncm.interfaces}
        assert by_name["self-external"].ip_addresses == ["203.0.113.2/24"]
        assert by_name["self-internal"].description == "internal"

    def test_the_default_route(self, ncm: NormalisedConfig) -> None:
        # F5 spells it `network default`, which is not a prefix any lookup matches.
        default = next(r for r in ncm.routing.routes if r.destination == "0.0.0.0/0")
        assert default.next_hop == "203.0.113.1"

    def test_a_specific_route_keeps_its_prefix(self, ncm: NormalisedConfig) -> None:
        assert any(
            r.destination == "10.0.0.0/8" and r.next_hop == "10.20.0.1" for r in ncm.routing.routes
        )


class TestVersionFromSupportingOutput:
    def test_version_and_serial(self) -> None:
        version = "Sys::Version\nMain Package\n  Product     BIG-IP\n  Version     17.1.1.3\n  Build       0.0.5\n"
        hardware = "Platform\n  Name                  BIG-IP i5800\n  Chassis Serial        f5-abcd-efgh\n"
        ncm = parse(
            "sys global-settings {\n    hostname a\n}\n",
            **{"tmsh -q show sys version": version, "tmsh -q show sys hardware": hardware},
        )
        assert ncm.device.version == "17.1.1.3"
        assert ncm.device.serials == ["f5-abcd-efgh"]

    def test_without_it_the_version_is_unknown(self, ncm: NormalisedConfig) -> None:
        # None, not a guess. A CVE matched against an invented version is worse than
        # one not matched at all.
        assert ncm.device.version is None
