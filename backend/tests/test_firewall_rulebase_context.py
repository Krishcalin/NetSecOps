"""Rules are only compared within their own enforcement context (FR-FW-02).

The relationship analysis walks every pair of rules in evaluation order. On PAN-OS,
FortiOS and Check Point that is correct: there is one ordered policy and every rule is
evaluated against every packet the firewall handles.

On ASA, IOS and NX-OS it is not. The policy is a set of named ACLs bound to different
interfaces, and an entry in OUTSIDE-IN is never applied to a packet that an entry in
INSIDE-OUT sees. Comparing them produced *shadowed* findings about a conflict that
cannot occur — and the remedy a shadowing finding implies is deleting the later rule,
which on a real device is live.

`SecurityRule.rulebase` names the context. Rules only pair with others sharing it.
"""

from __future__ import annotations

from netsecops.firewall.analysis import Relationship, analyse
from netsecops.firewall.model import resolve_rulebase


def rule(order: int, *, rulebase: str | None, action: str, src: str, dst: str) -> dict:
    return {
        "order": order,
        "name": f"rule-{order}",
        "rulebase": rulebase,
        "enabled": True,
        "action": action,
        "src": [src],
        "dst": [dst],
        "services": ["tcp/22"],
    }


def analysed(raw: list[dict]):
    rules, _ = resolve_rulebase({"security_rules": raw})
    return analyse(rules)


class TestSeparateAclsAreNotCompared:
    def test_a_shadow_across_two_acls_is_not_reported(self) -> None:
        """The false positive, stated as a test.

        Rule 2 is strictly inside rule 1 with the opposite action — textbook shadowing
        if they shared an ACL. They do not.
        """
        result = analysed(
            [
                rule(1, rulebase="OUTSIDE-IN", action="allow", src="any", dst="any"),
                rule(
                    2, rulebase="INSIDE-OUT", action="deny", src="10.10.0.5/32", dst="10.20.0.0/24"
                ),
            ]
        )

        assert result.total_by_kind == {}
        assert result.pairs_compared == 0

    def test_the_same_pair_inside_one_acl_is_still_reported(self) -> None:
        """The partition must not silence a real finding, only a meaningless one."""
        result = analysed(
            [
                rule(1, rulebase="OUTSIDE-IN", action="allow", src="any", dst="any"),
                rule(
                    2, rulebase="OUTSIDE-IN", action="deny", src="10.10.0.5/32", dst="10.20.0.0/24"
                ),
            ]
        )

        assert result.total_by_kind.get(Relationship.SHADOWED) == 1

    def test_three_acls_each_analyse_independently(self) -> None:
        result = analysed(
            [
                rule(1, rulebase="A", action="allow", src="any", dst="any"),
                rule(2, rulebase="A", action="deny", src="10.0.0.1/32", dst="any"),
                rule(3, rulebase="B", action="allow", src="any", dst="any"),
                rule(4, rulebase="B", action="deny", src="10.0.0.2/32", dst="any"),
                rule(5, rulebase="C", action="deny", src="10.0.0.3/32", dst="any"),
            ]
        )

        # One shadow inside A, one inside B, none across them and none in C.
        assert result.total_by_kind.get(Relationship.SHADOWED) == 2


class TestSinglePolicyPlatformsAreUnaffected:
    def test_rules_with_no_context_are_all_compared(self) -> None:
        """PAN-OS, FortiOS and Check Point leave `rulebase` None on every rule."""
        result = analysed(
            [
                rule(1, rulebase=None, action="allow", src="any", dst="any"),
                rule(2, rulebase=None, action="deny", src="10.10.0.5/32", dst="10.20.0.0/24"),
            ]
        )

        assert result.total_by_kind.get(Relationship.SHADOWED) == 1

    def test_a_missing_key_behaves_as_no_context(self) -> None:
        """Every rulebase parsed before this field existed omits it entirely."""
        raw = [
            rule(1, rulebase=None, action="allow", src="any", dst="any"),
            rule(2, rulebase=None, action="deny", src="10.10.0.5/32", dst="10.20.0.0/24"),
        ]
        for entry in raw:
            del entry["rulebase"]

        rules, _ = resolve_rulebase({"security_rules": raw})

        assert all(r.rulebase is None for r in rules)
        assert analyse(rules).total_by_kind.get(Relationship.SHADOWED) == 1

    def test_a_context_and_no_context_do_not_mix(self) -> None:
        """Half-populated data must not silently pair across the boundary."""
        result = analysed(
            [
                rule(1, rulebase=None, action="allow", src="any", dst="any"),
                rule(
                    2, rulebase="OUTSIDE-IN", action="deny", src="10.10.0.5/32", dst="10.20.0.0/24"
                ),
            ]
        )

        assert result.pairs_compared == 0


class TestTheAsaParserSetsTheContext:
    def test_each_acl_becomes_its_own_context(self) -> None:
        from pathlib import Path

        from netsecops.parsers.base import ParseContext
        from netsecops.parsers.registry import get_parser

        config = Path(__file__).parent / "fixtures" / "cisco" / "asa" / "9.18" / "edge_firewall.cfg"
        ncm = get_parser("cisco_asa").parse(ParseContext(text=config.read_text(encoding="utf-8")))

        contexts = {rule.rulebase for rule in ncm.firewall.security_rules}
        assert contexts == {"OUTSIDE-IN", "INSIDE-OUT", "DMZ-IN"}
        # And the context matches the ACL the entry was written under.
        assert all(rule.rulebase == rule.name for rule in ncm.firewall.security_rules)

    def test_the_fixture_no_longer_reports_cross_acl_shadowing(self) -> None:
        """Every ACL here ends in `deny ip any any`, which would shadow the first
        entry of every ACL below it if the lists were treated as one policy."""
        from pathlib import Path

        from netsecops.parsers.base import ParseContext
        from netsecops.parsers.registry import get_parser

        config = Path(__file__).parent / "fixtures" / "cisco" / "asa" / "9.18" / "edge_firewall.cfg"
        ncm = get_parser("cisco_asa").parse(ParseContext(text=config.read_text(encoding="utf-8")))
        rules, _ = resolve_rulebase(ncm.firewall.model_dump())
        result = analyse(rules)

        cross = [rel for rel in result.relationships if rel.earlier.rulebase != rel.later.rulebase]
        assert cross == []
