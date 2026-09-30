"""Arista EOS (SRS §1.3, FR-PARSE-01 … FR-PARSE-05).

EOS is IOS-like enough to share `CiscoStyleParser` and different enough not to share
`CiscoIosParser`. **Every one of the differences is silent if missed**, which is the
whole argument for a separate parser and the shape of most of this file: pointed at EOS,
the IOS patterns match nothing and report a switch with no addresses and no routes,
which is indistinguishable from a switch that was never collected.

The four that matter:

* addresses and routes are CIDR, not dotted-mask;
* `management ssh` and `management api http-commands` replace `line vty` and
  `ip http server`;
* a username carries a **role**, which is what actually governs;
* eAPI is running only when the block says `no shutdown` — the block's presence is not
  the answer, which is the opposite of how Junos services read.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsecops.adapters.policies import get_policy
from netsecops.adapters.profiles import PROFILES
from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURE = (
    Path(__file__).parent / "fixtures" / "arista" / "eos" / "4.29" / "show_running_config.txt"
)


def parse(text: str, **supporting: str) -> NormalisedConfig:
    return get_parser("arista_eos").parse(ParseContext(text=text, supporting=supporting))


@pytest.fixture(scope="module")
def ncm() -> NormalisedConfig:
    return parse(FIXTURE.read_text(encoding="utf-8"))


# ──────────────────── the platform is wired up ──────────────────────────


class TestThePlatformIsWired:
    def test_policy_profile_and_parser(self) -> None:
        from netsecops.parsers.registry import PARSERS

        assert get_policy("arista_eos") is not None
        assert "arista_eos" in PROFILES
        assert "arista_eos" in PARSERS

    def test_every_command_it_issues_is_approved(self) -> None:
        policy = get_policy("arista_eos")
        for command in PROFILES["arista_eos"].all_commands():
            assert policy.match(command) is not None, command

    def test_it_does_not_reuse_the_cisco_ios_parser(self) -> None:
        # The point of the whole module. Sharing `CiscoIosParser` would read nothing
        # from a CIDR address or a CIDR route, and report it as a clean device.
        from netsecops.parsers.cisco.ios import CiscoIosParser
        from netsecops.parsers.registry import PARSERS

        assert PARSERS["arista_eos"] is not CiscoIosParser


# ───────────────── the differences from IOS, one by one ─────────────────


class TestWhatIosWouldGetWrong:
    def test_cidr_interface_addresses(self, ncm: NormalisedConfig) -> None:
        # `ip address 10.10.10.2/30`, not `10.10.10.2 255.255.255.252`. The IOS pattern
        # requires the dotted mask and matches nothing here.
        uplink = next(i for i in ncm.interfaces if i.name == "Ethernet1")
        assert uplink.ip_addresses == ["10.10.10.2/30"]

    def test_cidr_static_routes(self, ncm: NormalisedConfig) -> None:
        # `ip route 0.0.0.0/0 10.10.10.1`, not `ip route 0.0.0.0 0.0.0.0 10.10.10.1`.
        by_destination = {r.destination: r for r in ncm.routing.routes}
        assert by_destination["0.0.0.0/0"].next_hop == "10.10.10.1"
        assert by_destination["10.30.0.0/16"].next_hop == "10.10.10.5"

    def test_a_username_carries_a_role(self, ncm: NormalisedConfig) -> None:
        # The role is the authorisation on EOS; the privilege number is IOS
        # compatibility. Reading only the number reports `auditor` as an ordinary user
        # and says nothing about what it may do.
        by_name = {u.name: u for u in ncm.users}
        assert by_name["admin"].role == "network-admin"
        assert by_name["auditor"].role == "network-operator"
        assert by_name["auditor"].privilege == 1

    def test_a_user_with_no_password_is_recorded_as_such(self, ncm: NormalisedConfig) -> None:
        by_name = {u.name: u for u in ncm.users}
        assert by_name["auditor"].secret_type == "none"

    def test_ssh_is_read_from_the_management_block(self, ncm: NormalisedConfig) -> None:
        # `management ssh` exists on every EOS switch, so its presence is not the
        # answer — SSH is off only when the block says `shutdown`.
        assert ncm.management.services.ssh.enabled is True

    def test_the_idle_timeout_is_minutes(self, ncm: NormalisedConfig) -> None:
        # EOS writes minutes, BIG-IP writes seconds. Stored verbatim this is a
        # fifteen-second timeout and passes a check that should fail.
        assert ncm.management.session.exec_timeout_s == 900


class TestTheApiBlock:
    """eAPI running is usually the finding, and the block's presence is not it."""

    def test_no_shutdown_means_it_is_running(self, ncm: NormalisedConfig) -> None:
        assert ncm.management.services.https.enabled is True
        assert ncm.features.https_server is True

    def test_protocol_https_alone_does_not_enable_plaintext(self, ncm: NormalisedConfig) -> None:
        assert ncm.management.services.http.enabled is False
        assert ncm.features.http_server is False

    def test_a_shut_api_block_is_not_running(self) -> None:
        # The case that separates "configured" from "listening". An IOS-style reader
        # keyed on the block's presence reports this switch as exposing its API.
        text = (
            "hostname sw1\n"
            "!\n"
            "management api http-commands\n"
            "   protocol https\n"
            "   shutdown\n"
            "!\n"
        )
        ncm = parse(text)
        assert ncm.management.services.https.enabled is False

    def test_an_absent_block_means_not_configured(self) -> None:
        # A real answer and the secure one, not a gap.
        ncm = parse("hostname sw1\n!\ninterface Ethernet1\n   shutdown\n!\n")
        assert ncm.features.https_server is False
        assert ncm.features.http_server is False

    def test_plaintext_http_is_visible_when_it_is_on(self) -> None:
        text = "hostname sw1\n!\nmanagement api http-commands\n   protocol http\n   no shutdown\n!\n"
        ncm = parse(text)
        assert ncm.management.services.http.enabled is True


# ─────────────────────── the ordinary hardening ─────────────────────────


class TestTheManagementPlane:
    def test_hostname_and_domain(self, ncm: NormalisedConfig) -> None:
        assert ncm.device.hostname == "arista-leaf-01"
        assert ncm.device.domain_name == "corp.example.net"

    def test_the_login_banner(self, ncm: NormalisedConfig) -> None:
        assert "Authorised access only" in (ncm.management.banners.login or "")

    def test_telnet_is_off_when_no_block_configures_it(self, ncm: NormalisedConfig) -> None:
        assert ncm.management.services.telnet.enabled is False

    def test_read_only_and_read_write_communities(self, ncm: NormalisedConfig) -> None:
        # EOS omits the access word when read-only, so absence is the answer.
        by_rw = {c.rw: c for c in ncm.snmp.v1v2c_communities}
        assert by_rw[False].is_default is True
        assert by_rw[True].is_default is False

    def test_the_community_string_is_never_stored(self, ncm: NormalisedConfig) -> None:
        assert all("public" not in c.name_masked for c in ncm.snmp.v1v2c_communities)

    def test_radius_and_local_fallback(self, ncm: NormalisedConfig) -> None:
        assert [s.host for s in ncm.aaa.servers] == ["10.10.0.30"]
        assert ncm.aaa.servers[0].key_configured is True
        # `group radius local` — whether `local` follows the server is the difference
        # between a lockout and a bypass.
        assert ncm.aaa.local_fallback is True

    def test_ntp_and_syslog(self, ncm: NormalisedConfig) -> None:
        assert [s.host for s in ncm.ntp.servers] == ["10.10.0.10", "10.10.0.11"]
        assert ncm.ntp.servers[0].prefer is True
        assert [s.host for s in ncm.logging.syslog_servers] == ["10.10.0.20", "10.10.0.21"]


class TestInterfacesAndRoutes:
    def test_a_shut_interface_is_down(self, ncm: NormalisedConfig) -> None:
        shut = next(i for i in ncm.interfaces if i.name == "Ethernet47")
        assert shut.admin_up is False

    def test_an_up_interface_says_so(self, ncm: NormalisedConfig) -> None:
        assert next(i for i in ncm.interfaces if i.name == "Ethernet1").admin_up is True

    def test_no_switchport_marks_a_routed_port(self, ncm: NormalisedConfig) -> None:
        # The difference between an address that routes and one that does not.
        assert next(i for i in ncm.interfaces if i.name == "Ethernet1").mode == "routed"
        assert next(i for i in ncm.interfaces if i.name == "Vlan10").mode is None

    def test_the_management_port_is_flagged(self, ncm: NormalisedConfig) -> None:
        assert next(i for i in ncm.interfaces if i.name == "Management1").is_management is True

    def test_a_null_route_has_no_next_hop(self, ncm: NormalisedConfig) -> None:
        # `ip route 10.99.0.0/16 Null0` — EOS accepts an interface where IOS wants an
        # address. Stored as a next hop it becomes an edge to a device that does not
        # exist, and the path walk follows it.
        discard = next(r for r in ncm.routing.routes if r.destination == "10.99.0.0/16")
        assert discard.next_hop is None
        assert discard.interface == "Null0"

    def test_a_route_with_both_interface_and_gateway_keeps_the_gateway(self) -> None:
        # `ip route <prefix> <intf> <gw>` — EOS accepts both an egress interface and a
        # next-hop gateway. Capturing only the first token drops the gateway and the path
        # walk then treats the route as directly-attached instead of forwarding to the
        # real next hop, truncating or misrouting the walk.
        ncm = parse(
            "hostname sw1\n"
            "!\n"
            "ip route 0.0.0.0/0 Ethernet1 10.1.1.1\n"
            "ip route 10.20.0.0/24 Vlan10 192.168.1.254 tag 5\n"
        )
        by_destination = {r.destination: r for r in ncm.routing.routes}

        default = by_destination["0.0.0.0/0"]
        assert default.interface == "Ethernet1"
        assert default.next_hop == "10.1.1.1"

        tagged = by_destination["10.20.0.0/24"]
        assert tagged.interface == "Vlan10"
        assert tagged.next_hop == "192.168.1.254"

    def test_a_gateway_only_route_still_has_no_interface(self) -> None:
        # The added optional gateway group must not steal a trailing administrative
        # distance or `name`/`tag` keyword and turn a plain next-hop route into an
        # interface route.
        ncm = parse("hostname sw1\n!\nip route 10.40.0.0/16 10.10.10.9 200\n")
        route = next(r for r in ncm.routing.routes if r.destination == "10.40.0.0/16")
        assert route.next_hop == "10.10.10.9"
        assert route.interface is None


class TestVersionAndRobustness:
    def test_version_model_and_serial_from_one_command(self) -> None:
        # EOS puts all three in one response, which is why this platform's allow-list
        # is a third the length of Cisco's.
        output = (
            "Arista DCS-7050SX3-48YC8-F\n"
            "Hardware version: 11.01\n"
            "Serial number: JPE12345678\n"
            "Software image version: 4.29.2F\n"
        )
        ncm = parse("hostname sw1\n", **{"show version": output})
        assert ncm.device.version == "4.29.2F"
        assert ncm.device.model == "DCS-7050SX3-48YC8-F"
        assert ncm.device.serials == ["JPE12345678"]

    def test_without_it_the_version_is_unknown(self, ncm: NormalisedConfig) -> None:
        assert ncm.device.version is None

    def test_output_that_is_not_eos_is_a_parse_failure(self) -> None:
        assert parse("Building configuration...\n").parse_failed is True

    def test_unread_stanzas_are_reported(self, ncm: NormalisedConfig) -> None:
        # `spanning-tree mode mstp` and the AAA authorization line are not modelled.
        # They must be visible rather than dropped — that list is the coverage figure's
        # evidence.
        assert ncm.raw_unparsed
