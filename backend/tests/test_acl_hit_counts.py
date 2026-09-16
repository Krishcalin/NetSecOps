"""ACL hit counts from `show access-list` (FR-FW-03).

Hit counts are not in an ASA running configuration. The collection profile has always
asked for them — `show access-list` is listed there with the purpose "ACL hit counts —
absent from the configuration" — and the parser then discarded the artefact, so every
ASA rule carried `hit_count = None` and the two unused-rule checks in
`firewall/policy.py` could never fire on the platform.

The tests below are mostly about the ways attribution goes *wrong*, because this is the
input to advice that deletes firewall rules. A rule wrongly reported as never hit is the
error that takes down production, so every ambiguity here has to resolve to None rather
than to a number.
"""

from __future__ import annotations

from pathlib import Path

from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURES = Path(__file__).parent / "fixtures"
ASA_CONFIG = FIXTURES / "cisco" / "asa" / "9.18" / "edge_firewall.cfg"
SHOW_ACCESS_LIST = FIXTURES / "operational" / "cisco_asa" / "show_access_list.txt"


def parse_asa(show_output: str | None = None) -> NormalisedConfig:
    supporting = {"show access-list": show_output} if show_output is not None else {}
    return get_parser("cisco_asa").parse(
        ParseContext(text=ASA_CONFIG.read_text(encoding="utf-8"), supporting=supporting)
    )


def rules_for(ncm: NormalisedConfig, acl: str) -> list:
    return [rule for rule in ncm.firewall.security_rules if rule.name == acl]


class TestHitCountsAreAttached:
    def test_counts_land_on_the_right_rules(self) -> None:
        ncm = parse_asa(SHOW_ACCESS_LIST.read_text(encoding="utf-8"))

        outside = rules_for(ncm, "OUTSIDE-IN")
        assert [rule.hit_count for rule in outside] == [1423, 88211]

    def test_a_remark_does_not_shift_the_pairing(self) -> None:
        """OUTSIDE-IN's first configured line is a remark, so its first ACE is line 2.

        Pairing on the line number would attribute the deny-any-any count to the
        permit rule and leave the deny unknown.
        """
        ncm = parse_asa(SHOW_ACCESS_LIST.read_text(encoding="utf-8"))

        permit, deny = rules_for(ncm, "OUTSIDE-IN")
        assert permit.action == "allow"
        assert permit.hit_count == 1423
        assert deny.action == "deny"
        assert deny.hit_count == 88211

    def test_object_group_children_are_summed_into_the_parent_rule(self) -> None:
        """One configured ACE, three show lines: a parent with no count and two children.

        The configured rule was matched whenever either child was, so it has been hit
        twelve times — not zero, which is what reading the parent alone would report.
        """
        ncm = parse_asa(SHOW_ACCESS_LIST.read_text(encoding="utf-8"))

        _, object_group_rule, _ = rules_for(ncm, "INSIDE-OUT")
        assert "GRP-ADMIN-HOSTS" in object_group_rule.src[0]
        assert object_group_rule.hit_count == 12

    def test_zero_is_recorded_as_zero_not_as_unknown(self) -> None:
        """A genuine zero is the finding; it must survive as 0 and not become None."""
        ncm = parse_asa(SHOW_ACCESS_LIST.read_text(encoding="utf-8"))

        permit, _ = rules_for(ncm, "DMZ-IN")
        assert permit.hit_count == 0

    def test_last_hit_stays_unknown(self) -> None:
        """`show access-list` reports no timestamp, so idle-age must stay unanswerable."""
        ncm = parse_asa(SHOW_ACCESS_LIST.read_text(encoding="utf-8"))

        assert all(rule.last_hit is None for rule in ncm.firewall.security_rules)


class TestAmbiguityResolvesToUnknown:
    def test_no_artefact_leaves_every_count_unknown(self) -> None:
        ncm = parse_asa()

        assert ncm.firewall.security_rules
        assert all(rule.hit_count is None for rule in ncm.firewall.security_rules)

    def test_an_acl_the_device_did_not_report_is_left_alone(self) -> None:
        show_output = "\n".join(
            line
            for line in SHOW_ACCESS_LIST.read_text(encoding="utf-8").splitlines()
            if "DMZ-IN" not in line
        )

        ncm = parse_asa(show_output)

        assert [rule.hit_count for rule in rules_for(ncm, "DMZ-IN")] == [None, None]
        # The ACLs the device did report are unaffected by the one it did not.
        assert [rule.hit_count for rule in rules_for(ncm, "OUTSIDE-IN")] == [1423, 88211]

    def test_a_differing_entry_count_abandons_that_acl(self) -> None:
        """The device enforcing more entries than we parsed means one of us is wrong.

        Which one is not knowable from here, and pairing the lists anyway would shift
        every count after the divergence onto the wrong rule.
        """
        extra = (
            "access-list DMZ-IN line 3 extended permit udp any any eq 53 (hitcnt=900) 0xabcd0001"
        )
        show_output = SHOW_ACCESS_LIST.read_text(encoding="utf-8") + extra + "\n"

        ncm = parse_asa(show_output)

        assert [rule.hit_count for rule in rules_for(ncm, "DMZ-IN")] == [None, None]

    def test_a_disagreeing_action_abandons_that_acl(self) -> None:
        """Same length, different content: the lists have drifted out of step.

        Flipping DMZ-IN's first entry to a deny makes the pairing inconsistent with the
        configuration, and the whole ACL is abandoned rather than half-attributed.
        """
        show_output = SHOW_ACCESS_LIST.read_text(encoding="utf-8").replace(
            "access-list DMZ-IN line 1 extended permit tcp",
            "access-list DMZ-IN line 1 extended deny tcp",
        )

        ncm = parse_asa(show_output)

        assert [rule.hit_count for rule in rules_for(ncm, "DMZ-IN")] == [None, None]
        assert [rule.hit_count for rule in rules_for(ncm, "INSIDE-OUT")] == [90412, 12, 4001]

    def test_summary_and_preamble_lines_are_not_mistaken_for_entries(self) -> None:
        """`; 3 elements; name hash:` and the cached-flows preamble are not ACEs."""
        ncm = parse_asa(SHOW_ACCESS_LIST.read_text(encoding="utf-8"))

        # Three rules parsed, three counts attributed — no phantom fourth entry, which
        # would have tripped the length guard and abandoned the ACL instead.
        assert [rule.hit_count for rule in rules_for(ncm, "INSIDE-OUT")] == [90412, 12, 4001]

    def test_unparseable_output_is_survivable(self) -> None:
        ncm = parse_asa("% Invalid input detected at '^' marker.")

        assert all(rule.hit_count is None for rule in ncm.firewall.security_rules)


class TestTheUnusedRuleChecksNowFire:
    def test_a_never_hit_rule_is_reported(self) -> None:
        """The point of the exercise: `never_hit` was unreachable on ASA before this."""
        from netsecops.firewall.model import resolve_rulebase
        from netsecops.firewall.policy import RuleIssue, examine

        ncm = parse_asa(SHOW_ACCESS_LIST.read_text(encoding="utf-8"))
        rules, _ = resolve_rulebase(ncm.firewall.model_dump())
        report = examine(rules)

        never_hit = {
            finding.rule_order
            for finding in report.findings
            if finding.issue is RuleIssue.NEVER_HIT
        }
        zero_hit = [rule.order for rule in ncm.firewall.security_rules if rule.hit_count == 0]

        assert zero_hit, "the fixture must contain a hitcnt=0 rule for this to mean anything"
        assert set(zero_hit) <= never_hit

    def test_without_the_artefact_no_rule_is_called_never_hit(self) -> None:
        """The contrast that shows the checks were dead, not merely quiet."""
        from netsecops.firewall.model import resolve_rulebase
        from netsecops.firewall.policy import RuleIssue, examine

        rules, _ = resolve_rulebase(parse_asa().firewall.model_dump())
        report = examine(rules)

        assert not [f for f in report.findings if f.issue is RuleIssue.NEVER_HIT]


# ═══════════════════════════════════ PAN-OS ══════════════════════════════════
#
# PAN-OS keys its counters by rule name, and rule names are unique within a rulebase,
# so there is no ordinal pairing to get wrong here. The collection profile previously
# asked for `show counter global` under the description "Rule hit counts" — a command
# that returns global dataplane counters and nothing per-rule. Nothing read it.

PANOS_CONFIG = FIXTURES / "paloalto" / "panos" / "11.0" / "perimeter_fw.xml"
RULE_HIT_COUNT = FIXTURES / "operational" / "panos" / "show_rule_hit_count.xml"


def parse_panos(hit_output: str | None = None) -> NormalisedConfig:
    from netsecops.parsers.paloalto.panos import PanOsParser

    supporting = {PanOsParser.RULE_HIT_COUNT: hit_output} if hit_output is not None else {}
    return get_parser("panos").parse(
        ParseContext(text=PANOS_CONFIG.read_text(encoding="utf-8"), supporting=supporting)
    )


def panos_rule(ncm: NormalisedConfig, name: str):
    return next(rule for rule in ncm.firewall.security_rules if rule.name == name)


class TestPanOsHitCounts:
    def test_counts_are_matched_by_rule_name(self) -> None:
        ncm = parse_panos(RULE_HIT_COUNT.read_text(encoding="utf-8"))

        assert panos_rule(ncm, "Inbound web").hit_count == 1904772
        assert panos_rule(ncm, "Partner RDP to web").hit_count == 17

    def test_last_hit_is_iso_8601_so_the_idle_clock_can_read_it(self) -> None:
        from netsecops.firewall.policy import _days_since

        ncm = parse_panos(RULE_HIT_COUNT.read_text(encoding="utf-8"))

        last_hit = panos_rule(ncm, "Partner RDP to web").last_hit
        assert last_hit is not None
        assert last_hit.startswith("2023-09-16")
        assert _days_since(last_hit) is not None

    def test_a_never_hit_rule_has_no_idle_age(self) -> None:
        """`last-hit-timestamp` of 0 means never matched, not matched in 1970.

        Converting it literally would report an idle age of ~20,000 days and raise a
        stale-rule finding on evidence that only says the rule has never been used —
        which `hit_count == 0` already reports, correctly.
        """
        ncm = parse_panos(RULE_HIT_COUNT.read_text(encoding="utf-8"))

        rule = panos_rule(ncm, "Old migration rule")
        assert rule.hit_count == 0
        assert rule.last_hit is None

    def test_a_rule_the_counters_omitted_stays_unknown(self) -> None:
        """Absent from the response is not the same as never hit."""
        ncm = parse_panos(RULE_HIT_COUNT.read_text(encoding="utf-8"))

        rule = panos_rule(ncm, "Permit all internal to dmz")
        assert rule.hit_count is None
        assert rule.last_hit is None

    def test_no_artefact_leaves_every_count_unknown(self) -> None:
        ncm = parse_panos()

        assert ncm.firewall.security_rules
        assert all(rule.hit_count is None for rule in ncm.firewall.security_rules)

    def test_an_unexpected_response_shape_degrades_to_unknown(self) -> None:
        """The shape is written from documentation, not a captured device response.

        If a real device answers differently the counts must simply not appear, never
        appear wrong — so a response the parser does not recognise leaves every rule
        exactly where it was before the command was added.
        """
        ncm = parse_panos(
            "<response status='success'><result><something-else/></result></response>"
        )

        assert all(rule.hit_count is None for rule in ncm.firewall.security_rules)

    def test_malformed_xml_is_survivable(self) -> None:
        ncm = parse_panos("<response status='error'")

        assert ncm.firewall.security_rules
        assert all(rule.hit_count is None for rule in ncm.firewall.security_rules)

    def test_the_profile_and_the_parser_ask_for_the_same_command(self) -> None:
        """The artefact is keyed by command string, so a drift here silently kills it."""
        from netsecops.adapters.profiles import get_profile
        from netsecops.parsers.paloalto.panos import PanOsParser

        commands = {command.command for command in get_profile("panos").commands}
        assert PanOsParser.RULE_HIT_COUNT in commands

    def test_the_old_mislabelled_counter_command_is_gone(self) -> None:
        from netsecops.adapters.profiles import get_profile

        commands = " ".join(command.command for command in get_profile("panos").commands)
        assert "<counter><global>" not in commands
