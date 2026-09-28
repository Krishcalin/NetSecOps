"""Radware Alteon ADC configuration (SRS §1.3.1, FR-PARSE-01 … FR-PARSE-05).

Alteon has had a read-only allow-list since the device families were scoped, and no
profile and no parser — because nothing in public documentation showed the *shape* of
its configuration, and a parser written against guessed field names does not fail. It
reports "not configured" for ever, which is indistinguishable from a hardened appliance.

That is what these tests are shaped around. The fixture is a verified published
`/cfg/dump` extended with the management stanzas from Radware's command reference, and
almost every assertion below is about the difference between *absent* and *off*.

**The format is a menu tree with no closing token.** A block is a path line and the
indented settings under it, running until the next path. Three things about it broke the
first draft and each has a test:

* `/c` and `/cfg` are the same tree, and a capture may use either.
* `/c/sys/access/sshd/ena` is a complete command — the state is the last path segment,
  and the block has no body at all.
* `/c/slb/virt 10/service 80 http` carries its port and type as path arguments, and
  `/c/slb/virt 10/service 80 http/pip` is a sub-object of that service rather than a
  second listener on the same port.

**This parser has never been run against a real appliance**, which is recorded here as
well as in the module. The `Number of…` style cross-check that guards the C9800's AP
list has no equivalent in this dump, so the honest mitigation is that unread stanzas
land in `raw_unparsed` and are counted rather than dropped.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsecops.adapters.policies import get_policy
from netsecops.adapters.profiles import PROFILES
from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURE = Path(__file__).parent / "fixtures" / "radware" / "alteon" / "32.6" / "cc.txt"


@pytest.fixture(scope="module")
def ncm() -> NormalisedConfig:
    parser = get_parser("radware_alteon")
    return parser.parse(ParseContext(text=FIXTURE.read_text(encoding="utf-8")))


# ─────────────────────── the commands are issued ────────────────────────


class TestTheProfileExists:
    """Alteon had an allow-list and no profile, so nothing was ever sent to one."""

    def test_the_platform_has_a_profile(self) -> None:
        assert "radware_alteon" in PROFILES

    def test_it_prefers_the_redacting_dump(self) -> None:
        # `cc` is Radware's "configuration dump without keys and certificates" — the
        # appliance redacts before the data leaves it. `/cfg/dump` is approved too and
        # is deliberately not what we ask for first.
        issued = list(PROFILES["radware_alteon"].all_commands())
        assert issued[0] == "cc"

    def test_every_command_it_issues_is_approved(self) -> None:
        policy = get_policy("radware_alteon")
        for command in PROFILES["radware_alteon"].all_commands():
            assert policy.match(command) is not None, command


# ──────────────────────────── the format ────────────────────────────────


class TestTheMenuFormat:
    def test_both_spellings_of_the_tree(self) -> None:
        # The CLI accepts `/c`, `/cfg/dump` emits `/cfg`. Matching one reads nothing at
        # all on captures that use the other — silently, because an Alteon with no
        # recognised stanza looks exactly like one that was never collected.
        parser = get_parser("radware_alteon")
        for prefix in ("/c", "/cfg"):
            ncm = parser.parse(ParseContext(text=f"{prefix}/sys/ssnmp\n\tname \"sw1\"\n"))
            assert ncm.device.hostname == "sw1", prefix

    def test_a_path_can_be_a_complete_command(self, ncm: NormalisedConfig) -> None:
        # `/c/sys/access/sshd/ena` has no indented body; the state is the last segment.
        assert ncm.management.services.ssh.enabled is True

    def test_output_that_is_not_alteon_is_a_parse_failure(self) -> None:
        # Not "an Alteon with nothing configured". The coverage arithmetic cannot tell
        # those apart, and a green "99% parsed" pill over an empty NCM is the worst
        # outcome available.
        ncm = get_parser("radware_alteon").parse(ParseContext(text="Building configuration...\n"))
        assert ncm.parse_failed is True

    def test_an_empty_capture_does_not_raise(self) -> None:
        assert get_parser("radware_alteon").parse(ParseContext(text="")).parse_failed is True


# ─────────────────────── the management plane ───────────────────────────


class TestTheManagementPlane:
    """The reason to do this platform at all.

    None of these fields are Alteon-specific: filling them is what makes the existing
    check library — written against the NCM, not against a vendor — apply to an ADC.
    """

    def test_hostname(self, ncm: NormalisedConfig) -> None:
        assert ncm.device.hostname == "lb-core-01"

    def test_telnet_off_is_recorded_as_off_not_as_absent(self, ncm: NormalisedConfig) -> None:
        # The distinction the whole NCM rests on. `None` makes a check report Not
        # Evaluated; `False` makes it pass. Blurring them produces a confident wrong
        # answer in whichever direction happens to be convenient.
        assert ncm.management.services.telnet.enabled is False

    def test_http_off_and_https_on(self, ncm: NormalisedConfig) -> None:
        assert ncm.management.services.http.enabled is False
        assert ncm.management.services.https.enabled is True

    def test_the_feature_flags_follow(self, ncm: NormalisedConfig) -> None:
        # FR-VUL-03 is feature-aware: a CVE that only affects devices serving HTTP must
        # not be reported against one that has it off.
        assert (ncm.features.http_server, ncm.features.https_server) == (False, True)

    def test_a_service_nobody_mentioned_stays_unknown(self, ncm: NormalisedConfig) -> None:
        # SNMP access is not in this dump. Reporting it as disabled would be inventing
        # a fact, and the check should say Not Evaluated.
        assert ncm.management.services.snmp.enabled is None

    def test_idle_timeout_is_stored_in_seconds(self, ncm: NormalisedConfig) -> None:
        # Alteon writes `idle 15` in minutes; the NCM stores seconds everywhere, so a
        # verbatim 15 would read as a fifteen-*second* timeout and pass a check that
        # should fail.
        assert ncm.management.session.exec_timeout_s == 900


class TestSnmp:
    def test_read_and_write_communities_are_distinguished(self, ncm: NormalisedConfig) -> None:
        # Which one a default string sits on *is* the finding: `public` read-only is an
        # information leak; `public` read-write is a device somebody else administers.
        by_rw = {c.rw: c for c in ncm.snmp.v1v2c_communities}
        assert by_rw[False].is_default is True
        assert by_rw[True].is_default is False

    def test_the_community_string_is_never_stored(self, ncm: NormalisedConfig) -> None:
        # The NCM records enough to compare against known defaults and no more. A
        # snapshot is read by more people than the device is.
        assert all("public" not in c.name_masked for c in ncm.snmp.v1v2c_communities)
        assert all("Str0ngW!" not in c.name_masked for c in ncm.snmp.v1v2c_communities)


class TestTimeAndLogging:
    def test_both_ntp_servers(self, ncm: NormalisedConfig) -> None:
        assert [s.host for s in ncm.ntp.servers] == ["10.136.1.10", "10.136.1.11"]

    def test_the_primary_is_marked_as_preferred(self, ncm: NormalisedConfig) -> None:
        assert ncm.ntp.servers[0].prefer is True

    def test_both_syslog_hosts(self, ncm: NormalisedConfig) -> None:
        # `host` and `host2` are separate keys, not a list. Reading only the first
        # reports a device with one collector as though redundancy were absent.
        assert [s.host for s in ncm.logging.syslog_servers] == ["10.136.1.20", "10.136.1.21"]


class TestAaaAndUsers:
    def test_radius_servers(self, ncm: NormalisedConfig) -> None:
        radius = [s for s in ncm.aaa.servers if s.type == "radius"]
        assert [s.host for s in radius] == ["10.136.1.30", "10.136.1.31"]

    def test_the_shared_secret_is_recorded_as_present_not_stored(
        self, ncm: NormalisedConfig
    ) -> None:
        assert all(s.key_configured is True for s in ncm.aaa.servers)

    def test_local_users_and_their_class_of_service(self, ncm: NormalisedConfig) -> None:
        # `cos` is kept as Alteon's own word. Mapping `oper` onto a privilege number
        # would invent a scale the platform does not have.
        assert {(u.name, u.role) for u in ncm.users} == {("netops", "oper"), ("auditor", "user")}


# ───────────────────────────── layer 3 ──────────────────────────────────


class TestLayerThree:
    def test_the_management_port_is_flagged_as_management(self, ncm: NormalisedConfig) -> None:
        # Every check that asks "is management on its own network" reads the interface
        # list. An address stored anywhere else is invisible to all of them.
        mgmt = next(i for i in ncm.interfaces if i.is_management)
        assert mgmt.ip_addresses == ["10.136.1.100/255.255.255.0"]

    def test_data_interfaces_carry_their_vlan(self, ncm: NormalisedConfig) -> None:
        one = next(i for i in ncm.interfaces if i.name == "if1")
        assert (one.vlan, one.admin_up) == (85, True)

    def test_an_ipv6_interface_is_not_dropped(self, ncm: NormalisedConfig) -> None:
        two = next(i for i in ncm.interfaces if i.name == "if2")
        assert two.ip_addresses == ["fc00:85:0:0:0:0:0:100/64"]

    def test_the_gateway_becomes_a_default_route(self, ncm: NormalisedConfig) -> None:
        # Recorded as a route so the device joins the topology graph like anything else.
        # The graph matches a next hop to an interface address; a gateway stored under
        # its own name joins nothing and the ADC sits alone on the map.
        assert any(
            r.destination == "0.0.0.0/0" and r.next_hop == "10.136.85.254"
            for r in ncm.routing.routes
        )

    def test_the_management_gateway_is_a_route_too(self, ncm: NormalisedConfig) -> None:
        assert any(r.next_hop == "10.136.1.254" and r.interface == "mgmt" for r in ncm.routing.routes)


# ────────────────────── server load balancing ───────────────────────────


class TestLoadBalancing:
    """What an ADC publishes, which no other NCM section can hold.

    An interface address says where the device is. A VIP says what it offers.
    """

    def test_slb_is_on(self, ncm: NormalisedConfig) -> None:
        assert ncm.load_balancer.enabled is True

    def test_every_virtual_server(self, ncm: NormalisedConfig) -> None:
        assert {v.id: v.address for v in ncm.load_balancer.virtual_servers} == {
            "10": "10.136.85.10",
            "20": "10.136.85.20",
        }

    def test_a_vip_carries_each_of_its_listeners(self, ncm: NormalisedConfig) -> None:
        # Two services on one VIP. A reader that keyed by virtual server alone would
        # report the HTTPS one and lose the cleartext listener beside it, which is the
        # one worth finding.
        ten = next(v for v in ncm.load_balancer.virtual_servers if v.id == "10")
        assert {(s.port, s.service) for s in ten.services} == {(80, "http"), (443, "https")}

    def test_a_service_sub_object_is_not_a_second_listener(self, ncm: NormalisedConfig) -> None:
        # `/c/slb/virt 10/service 80 http/pip` configures proxy IP *on* the service.
        # Read as a listener it doubles the published surface of every VIP using one.
        ten = next(v for v in ncm.load_balancer.virtual_servers if v.id == "10")
        assert len(ten.services) == 2

    def test_the_ssl_policy_is_carried(self, ncm: NormalisedConfig) -> None:
        ten = next(v for v in ncm.load_balancer.virtual_servers if v.id == "10")
        https = next(s for s in ten.services if s.port == 443)
        assert https.ssl_policy == "strict-tls12"

    def test_a_cleartext_listener_is_visible(self, ncm: NormalisedConfig) -> None:
        # The reason `service` keeps the vendor's own word rather than being normalised
        # into a boolean: the question is which listener is cleartext, not whether any is.
        twenty = next(v for v in ncm.load_balancer.virtual_servers if v.id == "20")
        assert [(s.port, s.service) for s in twenty.services] == [(23, "telnet")]

    def test_real_servers_and_their_state(self, ncm: NormalisedConfig) -> None:
        # A disabled real server left in the configuration is hygiene, and it is only
        # hygiene if `dis` is read as False rather than as absent.
        by_id = {r.id: r for r in ncm.load_balancer.real_servers}
        assert by_id["1"].enabled is True
        assert by_id["3"].enabled is False
        assert by_id["3"].address == "10.136.85.3"

    def test_a_group_lists_every_member(self, ncm: NormalisedConfig) -> None:
        # `add` repeats once per member, so reading "the first `add`" gives a group of
        # one and makes a balanced service look like a single point of failure.
        group = ncm.load_balancer.groups[0]
        assert group.members == ["1", "2", "3"]
        assert group.health_check == "tcp"

    def test_slb_is_inferred_on_when_the_dump_omits_it(self) -> None:
        # Inferred upward only: a dump that says `off` is believed. A device covered in
        # VIPs whose feature flag reads "we could not tell" is plainly wrong.
        text = "/c/slb/virt 10\n\tena\n\tvip 10.0.0.1\n"
        ncm = get_parser("radware_alteon").parse(ParseContext(text=text))
        assert ncm.load_balancer.enabled is True


# ──────────────────────────── honesty ───────────────────────────────────


class TestWhatItDoesNotRead:
    def test_unread_stanzas_are_reported_rather_than_dropped(self, ncm: NormalisedConfig) -> None:
        # Persistence, proxy IP and port roles are not modelled. They must appear in
        # `raw_unparsed` — that list is the coverage figure's evidence, and the only
        # mitigation available for a parser that has never met the hardware.
        unparsed = "\n".join(ncm.raw_unparsed)
        assert "persist" in unparsed

    def test_coverage_is_not_claimed_to_be_total(self, ncm: NormalisedConfig) -> None:
        assert ncm.raw_unparsed, "a parser that claims to read everything is not being honest"

    def test_the_vendor_and_platform_are_stamped(self, ncm: NormalisedConfig) -> None:
        assert (ncm.device.vendor, ncm.device.platform) == ("radware", "radware_alteon")
