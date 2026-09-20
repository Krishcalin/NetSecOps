"""Cisco ACE parsing and the IOS/NX-OS rulebase (FR-PARSE-02, FR-FW-01).

An IOS or NX-OS access list is the device's security policy, and until this existed the
parsers recorded the action, a `log` flag and the raw line — so the relationship
analysis, the per-rule hygiene checks and the NAT join were all blind to the two
platforms that make up a third of the check library.

The bulk of these tests are about the wildcard mask, because it is the one construct
here that fails *silently*. `10.1.1.0 0.0.0.255` is a /24; read as a netmask it is a /8,
and read as a second address it is nonsense. Either mistake produces a rule whose scope
is wrong by orders of magnitude and whose subsequent analysis is confidently incorrect —
there is no error, just a different rulebase than the one on the device.

The second theme is refusal. A discontiguous mask, a `neq` operator, an unreadable port
name: each is something the model cannot express, and each is marked rather than
approximated. A rule excluded from analysis and flagged is recoverable; a rule analysed
as a different rule is not.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from netsecops.firewall.analysis import analyse
from netsecops.firewall.model import resolve_rulebase
from netsecops.parsers.base import ParseContext
from netsecops.parsers.cisco.acl import UNREADABLE, parse_ace, wildcard_to_cidr
from netsecops.parsers.registry import get_parser

FIXTURES = Path(__file__).parent / "fixtures"


class TestWildcardMasks:
    @pytest.mark.parametrize(
        ("address", "wildcard", "expected"),
        [
            ("10.1.1.0", "0.0.0.255", "10.1.1.0/24"),
            ("10.0.0.0", "0.255.255.255", "10.0.0.0/8"),
            ("192.168.1.0", "0.0.0.127", "192.168.1.0/25"),
            ("172.16.0.0", "0.0.255.255", "172.16.0.0/16"),
            ("10.1.1.1", "0.0.0.0", "10.1.1.1/32"),
            ("0.0.0.0", "255.255.255.255", "0.0.0.0/0"),
        ],
    )
    def test_contiguous_masks_convert(self, address: str, wildcard: str, expected: str) -> None:
        assert wildcard_to_cidr(address, wildcard) == expected

    def test_a_wildcard_is_not_a_netmask(self) -> None:
        """The mistake this function exists to prevent, stated directly.

        `0.0.0.255` is a /24. Read as a netmask it would be a /8 — 16 million addresses
        instead of 254, and every overlap conclusion drawn from it wrong.
        """
        assert wildcard_to_cidr("10.1.1.0", "0.0.0.255") == "10.1.1.0/24"
        assert wildcard_to_cidr("10.1.1.0", "0.0.0.255") != "10.0.0.0/8"

    @pytest.mark.parametrize("wildcard", ["0.0.0.254", "0.0.255.0", "0.1.0.255", "0.0.0.85"])
    def test_discontiguous_masks_are_refused(self, wildcard: str) -> None:
        """`0.0.0.254` matches every even final octet. No prefix describes that.

        Returning an approximation would produce a rule that looks precise and is not.
        """
        assert wildcard_to_cidr("10.1.1.0", wildcard) is None

    def test_rubbish_is_refused(self) -> None:
        assert wildcard_to_cidr("not-an-address", "0.0.0.255") is None
        assert wildcard_to_cidr("10.1.1.0", "not-a-mask") is None


class TestExtendedAces:
    def test_a_wildcard_source_and_a_host_destination(self) -> None:
        ace = parse_ace("permit tcp 10.1.1.0 0.0.0.255 host 10.2.2.5 eq 443")

        assert ace is not None
        assert ace.action == "permit"
        assert ace.protocol == "tcp"
        assert ace.source == "10.1.1.0/24"
        assert ace.destination == "10.2.2.5"
        assert ace.services == ["tcp/443"]
        assert ace.partial is False

    def test_any_to_any(self) -> None:
        ace = parse_ace("permit ip any any")

        assert ace is not None
        assert (ace.source, ace.destination) == ("any", "any")
        # `ip` on IOS means every protocol, which the resolver spells `any`.
        assert ace.services == ["any"]

    def test_a_named_port_resolves(self) -> None:
        ace = parse_ace("deny tcp any host 192.168.1.1 eq www log")

        assert ace is not None
        assert ace.services == ["tcp/80"]
        assert ace.log is True
        assert ace.action == "deny"

    def test_a_port_range(self) -> None:
        ace = parse_ace("permit tcp 10.0.0.0 0.255.255.255 any range 1024 65535")

        assert ace is not None
        assert ace.source == "10.0.0.0/8"
        assert ace.services == ["tcp/1024-65535"]

    def test_several_ports_after_eq(self) -> None:
        """IOS accepts `eq www 443 8080` on one line, and dropping the tail would
        understate the rule."""
        ace = parse_ace("permit tcp any any eq www 443 8080")

        assert ace is not None
        assert ace.services == ["tcp/80", "tcp/443", "tcp/8080"]

    def test_lt_and_gt_become_ranges(self) -> None:
        assert parse_ace("permit tcp any any lt 1024").services == ["tcp/1-1023"]
        assert parse_ace("permit tcp any any gt 1023").services == ["tcp/1024-65535"]

    def test_an_nxos_prefix_needs_no_conversion(self) -> None:
        ace = parse_ace("10 permit tcp 10.1.1.0/24 any eq 22")

        assert ace is not None
        assert ace.sequence == 10
        assert ace.source == "10.1.1.0/24"
        assert ace.services == ["tcp/22"]

    def test_object_groups_are_kept_as_names(self) -> None:
        """Resolved against the NCM's address groups like any other vendor's objects."""
        ace = parse_ace("permit tcp object-group SRC-HOSTS object-group WEB-SERVERS eq 443")

        assert ace is not None
        assert ace.source == "SRC-HOSTS"
        assert ace.destination == "WEB-SERVERS"

    def test_established_is_recorded_but_does_not_narrow_the_scope(self) -> None:
        """A TCP flag match narrows which packets match, not which addresses or ports.

        Treating the rule as covering the whole space can only over-report an overlap,
        never hide one — the same conservative direction the resolver takes for PAN-OS
        `application-default`.
        """
        ace = parse_ace("permit tcp any any established")

        assert ace is not None
        assert "established" in ace.flags
        assert ace.partial is False
        assert ace.services == ["tcp"]


class TestStandardAces:
    def test_a_standard_entry_has_no_destination(self) -> None:
        ace = parse_ace("permit 10.1.1.0 0.0.0.255")

        assert ace is not None
        assert ace.source == "10.1.1.0/24"
        assert ace.destination == "any"
        assert ace.services == ["any"]

    def test_a_standard_host_entry(self) -> None:
        ace = parse_ace("permit host 10.1.1.1")

        assert ace is not None
        assert ace.source == "10.1.1.1"

    def test_permit_any(self) -> None:
        ace = parse_ace("permit any")

        assert ace is not None
        assert ace.source == "any"


class TestWhatIsRefused:
    def test_a_remark_is_not_a_rule(self) -> None:
        assert parse_ace("remark Permit inbound HTTPS") is None

    def test_a_blank_line_is_not_a_rule(self) -> None:
        assert parse_ace("   ") is None

    def test_a_discontiguous_source_marks_the_entry_partial(self) -> None:
        ace = parse_ace("permit tcp 10.1.1.0 0.0.0.254 any eq 443")

        assert ace is not None
        assert ace.source == UNREADABLE
        assert ace.partial is True

    def test_neq_is_refused_rather_than_expanded(self) -> None:
        """ "Every port except 22" is representable as intervals but not as a `tcp/…`
        literal, and writing two ranges would make the rule look precise while losing
        what it actually says."""
        ace = parse_ace("permit tcp any any neq 22")

        assert ace is not None
        assert ace.partial is True

    def test_neq_still_consumes_its_operand(self) -> None:
        """If the port were left unconsumed it would be read as the next address."""
        ace = parse_ace("permit tcp any neq 22 host 10.0.0.1")

        assert ace is not None
        assert ace.destination == "10.0.0.1"

    def test_an_unknown_port_name_is_refused(self) -> None:
        ace = parse_ace("permit tcp any any eq some-vendor-service")

        assert ace is not None
        assert ace.partial is True


class TestBindingsAreNormalised:
    """Where an access list is enforced, in a shape something can act on.

    `Acl.applied_to` kept the device's own words, which differ per platform and cannot
    be compared: `access-group INSIDE-IN in interface inside` against
    `GigabitEthernet0/1 in`. The path walk needs to know which list governs a hop, so
    the binding is parsed once, here, rather than re-guessed by every consumer.
    """

    ASA = """
hostname edge-fw
!
interface GigabitEthernet0/1
 nameif inside
 ip address 10.0.1.2 255.255.255.252
!
access-list INSIDE-IN extended permit ip 10.10.0.0 255.255.255.0 any
access-list INSIDE-IN extended deny ip any any
access-list DETACHED extended deny ip any any
access-list GLOBAL-POLICY extended permit ip any any
!
access-group INSIDE-IN in interface inside
access-group GLOBAL-POLICY global
!
: end
"""

    IOS = """
hostname edge-router
!
ip access-list extended TRANSIT-IN
 permit ip 10.10.0.0 0.0.0.255 any
!
ip access-list extended VTY-ONLY
 permit tcp 10.100.0.0 0.0.255.255 any eq 22
!
interface GigabitEthernet0/1
 ip address 10.10.0.1 255.255.255.0
 ip access-group TRANSIT-IN in
!
end
"""

    def test_an_asa_binding_records_the_nameif_and_direction(self) -> None:
        ncm = get_parser("cisco_asa").parse(ParseContext(text=self.ASA))

        bindings = ncm.firewall.rulebase_bindings
        assert [(b.interface, b.direction) for b in bindings["INSIDE-IN"]] == [("inside", "in")]

    def test_an_asa_global_binding_names_no_interface(self) -> None:
        """`access-group NAME global` applies on every interface, and the path walk has
        to treat it as governing whichever hop it is asked about."""
        ncm = get_parser("cisco_asa").parse(ParseContext(text=self.ASA))

        bindings = ncm.firewall.rulebase_bindings["GLOBAL-POLICY"]
        assert [(b.interface, b.direction) for b in bindings] == [(None, "in")]

    def test_an_unbound_list_is_marked_as_filtering_nothing(self) -> None:
        ncm = get_parser("cisco_asa").parse(ParseContext(text=self.ASA))

        by_rulebase = {rule.rulebase: rule.applied for rule in ncm.firewall.security_rules}
        assert by_rulebase["INSIDE-IN"] is True
        assert by_rulebase["DETACHED"] is False

    def test_an_ios_binding_records_the_interface_name(self) -> None:
        """IOS has no zones, so the interface name is the only key available."""
        ncm = get_parser("cisco_ios").parse(ParseContext(text=self.IOS))

        bindings = ncm.firewall.rulebase_bindings
        assert [(b.interface, b.direction) for b in bindings["TRANSIT-IN"]] == [
            ("GigabitEthernet0/1", "in")
        ]
        assert "VTY-ONLY" not in bindings

    def test_the_raw_lines_are_still_kept(self) -> None:
        """`applied_to` is evidence — what the device actually said — and the parsed
        form is for acting on. Losing the first would make a binding unciteable."""
        ncm = get_parser("cisco_asa").parse(ParseContext(text=self.ASA))

        acl = next(acl for acl in ncm.acls if acl.name == "INSIDE-IN")
        assert acl.applied_to == ["access-group INSIDE-IN in interface inside"]


class TestTheAsaSpeaksTheResolversVocabulary:
    """The ASA parser emitted its own service dialect, and nothing read it.

    `permit ip …` became the service `ip` and `permit tcp … eq 443 log` became
    `tcp/eq 443 log`. Neither resolves, so both landed in the rule's `unresolved` list
    and stopped the rule matching anything — which meant **no ASA rule ever matched in a
    path walk**, and every access list fell through to its implicit deny.
    """

    CONFIG = """
hostname edge-fw
!
access-list L extended permit ip 10.10.0.0 255.255.255.0 any
access-list L extended permit tcp any host 10.20.0.10 eq 443 log
access-list L extended permit udp any any range 16384 32767
access-list L extended permit tcp any any neq 22
access-list L extended deny ip any any log
!
access-group L in interface inside
!
: end
"""

    def rules(self):
        ncm = get_parser("cisco_asa").parse(ParseContext(text=self.CONFIG))
        # Through the dump, because that is how the stored snapshot reaches the resolver
        # and the path walk — never as the live model object.
        return resolve_rulebase(ncm.firewall.model_dump(mode="json"))[0]

    def test_permit_ip_resolves_to_every_protocol(self) -> None:
        rule = self.rules()[0]

        assert rule.unresolved == ()
        assert rule.services.is_any

    def test_a_port_operator_resolves_and_the_log_keyword_does_not_leak_in(self) -> None:
        rule = self.rules()[1]

        assert rule.unresolved == ()
        assert not rule.services.is_any
        assert rule.services.by_protocol[6].covers_value(443)
        assert not rule.services.by_protocol[6].covers_value(444)

    def test_a_range_operator_resolves(self) -> None:
        rule = self.rules()[2]

        assert rule.unresolved == ()
        assert rule.services.by_protocol[17].covers_value(20000)
        assert not rule.services.by_protocol[17].covers_value(80)

    def test_neq_is_refused_rather_than_widened(self) -> None:
        """ "Every port except 22" is not expressible as a `tcp/…` literal, and writing
        two ranges would make the rule look precise while losing the distinction. The
        same refusal the IOS reader already makes, because it is the same reader."""
        rule = self.rules()[3]

        assert rule.unresolved != ()

    def test_a_host_keyword_is_grammar_and_not_part_of_the_address(self) -> None:
        """`host 10.20.0.10` was passed to the resolver whole, which cannot look it up.

        Same consequence as the service dialect and found the same way: the entry landed
        in `unresolved`, stopped matching, and its access list fell through to the
        implicit deny. The IOS reader has always stripped the keyword.
        """
        rule = self.rules()[1]

        assert rule.unresolved == ()
        assert rule.destination.v4.covers_value(int(ipaddress.ip_address("10.20.0.10")))
        assert not rule.destination.v4.covers_value(int(ipaddress.ip_address("10.20.0.11")))

    def test_an_object_group_is_referenced_by_name(self) -> None:
        config = """
hostname edge-fw
!
object-group network GRP-ADMINS
 network-object host 10.100.5.50
!
access-list L extended permit tcp object-group GRP-ADMINS any eq 22
!
access-group L in interface inside
!
: end
"""
        ncm = get_parser("cisco_asa").parse(ParseContext(text=config))
        rule = resolve_rulebase(ncm.firewall.model_dump(mode="json"))[0][0]

        assert rule.unresolved == ()
        assert rule.source.v4.covers_value(int(ipaddress.ip_address("10.100.5.50")))

    def test_every_rule_in_a_real_acl_now_resolves_its_service(self) -> None:
        """The property that actually failed: one unresolved entry is a rule that never
        matches, and an access list whose entries never match reports the path blocked
        by its implicit deny."""
        resolvable = [rule for rule in self.rules() if rule.unresolved == ()]

        assert len(resolvable) == 4, "only the deliberate `neq` entry may be unresolved"


class TestTheIosRulebase:
    """The end of the exercise: IOS ACLs reaching the analysis engine."""

    def parse_ios(self, config: str):
        return get_parser("cisco_ios").parse(ParseContext(text=config))

    CONFIG = """
hostname edge-router
!
ip access-list extended OUTSIDE-IN
 remark Permit inbound HTTPS to the web server
 permit tcp any host 10.20.0.10 eq 443 log
 deny ip any any log
!
ip access-list extended INSIDE-OUT
 permit ip 10.10.0.0 0.0.0.255 any
 deny ip any any log
!
interface GigabitEthernet0/0
 ip address 203.0.113.2 255.255.255.0
 ip access-group OUTSIDE-IN in
!
interface GigabitEthernet0/1
 ip address 10.10.0.1 255.255.255.0
 ip access-group INSIDE-OUT in
!
end
"""

    def test_acl_entries_become_security_rules(self) -> None:
        ncm = self.parse_ios(self.CONFIG)

        assert len(ncm.firewall.security_rules) == 4
        assert {rule.name for rule in ncm.firewall.security_rules} == {
            "OUTSIDE-IN",
            "INSIDE-OUT",
        }

    def test_the_remark_did_not_become_a_rule(self) -> None:
        ncm = self.parse_ios(self.CONFIG)

        assert all("remark" not in (rule.name or "") for rule in ncm.firewall.security_rules)
        assert len([r for r in ncm.firewall.security_rules if r.name == "OUTSIDE-IN"]) == 2

    def test_the_wildcard_source_survives_into_the_rulebase(self) -> None:
        ncm = self.parse_ios(self.CONFIG)

        inside = next(r for r in ncm.firewall.security_rules if r.name == "INSIDE-OUT")
        assert inside.src == ["10.10.0.0/24"]

    def test_each_acl_is_its_own_enforcement_context(self) -> None:
        """Without this, INSIDE-OUT's `deny ip any any` shadows OUTSIDE-IN's permit."""
        ncm = self.parse_ios(self.CONFIG)

        assert all(rule.rulebase == rule.name for rule in ncm.firewall.security_rules)

    def test_no_cross_acl_shadowing_is_reported(self) -> None:
        ncm = self.parse_ios(self.CONFIG)
        rules, _ = resolve_rulebase(ncm.firewall.model_dump())
        result = analyse(rules)

        cross = [rel for rel in result.relationships if rel.earlier.rulebase != rel.later.rulebase]
        assert cross == []

    def test_a_real_shadow_inside_one_acl_is_reported(self) -> None:
        """The engine must actually work on this platform, not merely not misfire."""
        config = """
hostname edge-router
!
ip access-list extended SHADOWED
 permit ip any any
 permit tcp 10.1.1.0 0.0.0.255 host 10.2.2.5 eq 443
!
end
"""
        ncm = self.parse_ios(config)
        rules, _ = resolve_rulebase(ncm.firewall.model_dump())
        result = analyse(rules)

        assert result.total_by_kind, "the IOS rulebase reached the analysis engine"

    def test_the_acl_binding_is_recorded(self) -> None:
        ncm = self.parse_ios(self.CONFIG)

        outside = next(acl for acl in ncm.acls if acl.name == "OUTSIDE-IN")
        assert outside.applied_to == ["GigabitEthernet0/0 in"]

    def test_the_acl_entry_keeps_its_parsed_fields(self) -> None:
        ncm = self.parse_ios(self.CONFIG)

        outside = next(acl for acl in ncm.acls if acl.name == "OUTSIDE-IN")
        permit = outside.entries[0]
        assert permit.protocol == "tcp"
        assert permit.destination == "10.20.0.10"
        assert permit.ports == "tcp/443"
        assert permit.log is True

    def test_a_numbered_acl_also_reaches_the_rulebase(self) -> None:
        config = """
hostname edge-router
!
access-list 101 permit tcp 10.1.1.0 0.0.0.255 any eq 22
access-list 101 deny ip any any log
!
end
"""
        ncm = self.parse_ios(config)

        assert len(ncm.firewall.security_rules) == 2
        assert ncm.firewall.security_rules[0].src == ["10.1.1.0/24"]
        assert ncm.firewall.security_rules[0].rulebase == "101"

    def test_an_unreadable_entry_is_excluded_rather_than_guessed(self) -> None:
        """A discontiguous mask must take the rule out of overlap analysis."""
        config = """
hostname edge-router
!
ip access-list extended ODDBALL
 permit tcp 10.1.1.0 0.0.0.254 any eq 443
!
end
"""
        ncm = self.parse_ios(config)
        rules, _ = resolve_rulebase(ncm.firewall.model_dump())

        assert rules[0].unresolved, "the rule must be flagged as not fully understood"


class TestTheNxosRulebase:
    def test_nxos_aces_become_security_rules(self) -> None:
        config = """
hostname nexus-01
!
ip access-list MGMT-IN
  10 permit tcp 10.10.0.0/24 any eq 22
  20 deny ip any any log
!
interface Ethernet1/1
  ip access-group MGMT-IN in
!
"""
        ncm = get_parser("cisco_nxos").parse(ParseContext(text=config))

        assert len(ncm.firewall.security_rules) == 2
        first = ncm.firewall.security_rules[0]
        assert first.src == ["10.10.0.0/24"]
        assert first.services == ["tcp/22"]
        assert first.rulebase == "MGMT-IN"
        assert ncm.acls[0].entries[0].sequence == 10
