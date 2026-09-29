"""Dead rules and undocumented rules (FR-FW-02).

Two additions to the policy examiner, both of the kind that is easy to ship and easy to
ship wrongly. Neither describes an exposure: they describe a rulebase nobody can safely
maintain, which is the other half of what a firewall review is for.

**An unroutable rule is dead.** If the device has no route to anything a rule permits,
no forwarded packet can ever match it — usually the fossil of a decommissioned site.
Saying so is useful; saying so wrongly means telling somebody a live rule is dead, and
the obvious ways to get it wrong are all about *what the absence of a route means*. Most
of this file is those conditions.

**An undocumented rule is the one nobody dares delete.** The trap here is the mirror of
the check itself: several platforms have no comment field and several parsers do not
read the one they have, so every `comment` is None — and reporting that would be a
finding about our own coverage dressed up as one about the customer's configuration.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest

from netsecops.firewall.model import RULE_COMMENT_PLATFORMS, resolve_rulebase
from netsecops.firewall.policy import RoutedSpace, RuleIssue, examine
from netsecops.parsers.registry import PARSERS


def rulebase(**rule: Any) -> list[Any]:
    base: dict[str, Any] = {"order": 1, "name": "r1", "action": "allow"}
    base.update(rule)
    rules, _ = resolve_rulebase({"security_rules": [base]})
    return rules


def routes(*destinations: str, truncated: bool | None = False) -> RoutedSpace:
    return RoutedSpace.from_routes([{"destination": d} for d in destinations], truncated=truncated)


def issues(report: Any, issue: RuleIssue) -> list[Any]:
    return [finding for finding in report.findings if finding.issue is issue]


# ═══════════════════════ the rule the device cannot reach ════════════════════


class TestADeadRuleIsReported:
    def test_a_destination_with_no_route_to_it(self) -> None:
        report = examine(
            rulebase(dst=["192.168.99.0/24"]), routed=routes("10.0.0.0/8", "172.16.0.0/12")
        )

        found = issues(report, RuleIssue.UNROUTABLE_DESTINATION)
        assert len(found) == 1
        assert "no route" in found[0].message

    def test_a_destination_the_device_does_route_to_is_not(self) -> None:
        report = examine(rulebase(dst=["10.1.2.0/24"]), routed=routes("10.0.0.0/8"))

        assert issues(report, RuleIssue.UNROUTABLE_DESTINATION) == []

    def test_partial_coverage_counts_as_routed(self) -> None:
        """One address in range is enough for the rule to be live.

        The claim is "this can never match", so any overlap at all refutes it. Requiring
        the whole destination to be routed would report a rule covering a supernet as
        dead while it carries traffic every day.
        """
        report = examine(rulebase(dst=["10.0.0.0/8"]), routed=routes("10.1.2.0/24"))

        assert issues(report, RuleIssue.UNROUTABLE_DESTINATION) == []

    def test_a_deny_rule_is_reported_too(self) -> None:
        """Dead is dead. A deny to nowhere is as much clutter as a permit to nowhere,
        and the checks below this one skip deny rules for a reason that does not apply."""
        report = examine(
            rulebase(action="deny", dst=["192.168.99.0/24"]), routed=routes("10.0.0.0/8")
        )

        assert len(issues(report, RuleIssue.UNROUTABLE_DESTINATION)) == 1


class TestWhenTheQuestionMayNotBeAsked:
    """Every one of these produces a false "this rule is dead" if it is skipped."""

    def test_a_default_route_makes_nothing_unroutable(self) -> None:
        """The most important guard. On a device carrying 0.0.0.0/0 every destination is
        reachable, so a check that still ran would report dead rules on precisely the
        kind of device where none is."""
        space = routes("10.0.0.0/8", "0.0.0.0/0")

        assert space.usable is False
        assert (
            issues(
                examine(rulebase(dst=["192.168.99.0/24"]), routed=space),
                RuleIssue.UNROUTABLE_DESTINATION,
            )
            == []
        )

    def test_a_truncated_table_is_not_a_table(self) -> None:
        """`MAX_ROUTES_PER_DEVICE` caps what is stored. A prefix that fell off the end is
        missing evidence, not a missing route."""
        space = routes("10.0.0.0/8", truncated=True)

        assert space.usable is False
        assert (
            issues(
                examine(rulebase(dst=["192.168.99.0/24"]), routed=space),
                RuleIssue.UNROUTABLE_DESTINATION,
            )
            == []
        )

    def test_no_routes_means_not_collected(self) -> None:
        """Not a device that forwards nowhere. A switch whose table was never captured
        must produce nothing here."""
        assert routes().usable is False
        assert (
            issues(
                examine(rulebase(dst=["192.168.99.0/24"]), routed=routes()),
                RuleIssue.UNROUTABLE_DESTINATION,
            )
            == []
        )

    def test_no_routed_space_at_all_disables_the_check(self) -> None:
        """A caller that knows nothing about routing passes nothing, and gets nothing."""
        assert (
            issues(examine(rulebase(dst=["192.168.99.0/24"])), RuleIssue.UNROUTABLE_DESTINATION)
            == []
        )

    def test_a_route_that_could_not_be_read_disables_it(self) -> None:
        """A table we only partly understood cannot be used to call a rule dead."""
        space = RoutedSpace.from_routes([{"destination": "10.0.0.0/8"}, {"destination": "?!"}])

        assert space.usable is False

    def test_an_ipv6_route_does_not(self) -> None:
        """It adds no IPv4 coverage, but it is not an unreadable line either — the
        distinction is whether we failed to understand something or simply stored a
        different address family."""
        space = RoutedSpace.from_routes(
            [{"destination": "10.0.0.0/8"}, {"destination": "2001:db8::/32"}]
        )

        assert space.usable is True

    def test_a_destination_of_any_is_never_dead(self) -> None:
        report = examine(rulebase(dst=["any"]), routed=routes("10.0.0.0/8"))

        assert issues(report, RuleIssue.UNROUTABLE_DESTINATION) == []

    def test_an_unresolved_destination_is_unknown_not_dead(self) -> None:
        """The same distinction the path walk draws: a name we could not expand is an
        open question, and answering it "dead" is a guess in the confident direction."""
        firewall = {
            "address_objects": [{"name": "sg-web", "type": "security-group"}],
            "security_rules": [{"order": 1, "name": "r1", "action": "allow", "dst": ["sg-web"]}],
        }
        rules, _ = resolve_rulebase(firewall)

        report = examine(rules, routed=routes("10.0.0.0/8"))

        assert issues(report, RuleIssue.UNROUTABLE_DESTINATION) == []

    def test_a_disabled_rule_is_not_examined_for_it(self) -> None:
        """It is already reported as disabled; two findings for one dead rule is noise."""
        report = examine(
            rulebase(enabled=False, dst=["192.168.99.0/24"]), routed=routes("10.0.0.0/8")
        )

        assert issues(report, RuleIssue.UNROUTABLE_DESTINATION) == []
        assert len(issues(report, RuleIssue.DISABLED)) == 1


# ════════════════════════ the rule nobody wrote down ═════════════════════════


class TestTheUndocumentedRule:
    def test_a_rule_with_no_comment_is_reported(self) -> None:
        report = examine(rulebase(), comments_captured=True)

        assert len(issues(report, RuleIssue.NO_DOCUMENTATION)) == 1

    def test_a_rule_with_one_is_not(self) -> None:
        report = examine(rulebase(comment="Permit the payroll batch job"), comments_captured=True)

        assert issues(report, RuleIssue.NO_DOCUMENTATION) == []

    def test_whitespace_is_not_documentation(self) -> None:
        report = examine(rulebase(comment="   "), comments_captured=True)

        assert len(issues(report, RuleIssue.NO_DOCUMENTATION)) == 1

    def test_a_deny_rule_is_held_to_the_same_standard(self) -> None:
        """Deliberately above the permits gate. An undocumented deny is the rule people
        are most afraid to touch: nothing records what it was protecting."""
        report = examine(rulebase(action="deny"), comments_captured=True)

        assert len(issues(report, RuleIssue.NO_DOCUMENTATION)) == 1

    def test_nothing_is_said_where_comments_are_not_captured(self) -> None:
        """The guard that stops this being a finding about our own parser coverage.

        On a platform whose parser does not read comments every `comment` is None, and
        flagging that would file an info finding against every rule on every device —
        which is how a findings list becomes something people filter out entirely.
        """
        report = examine(rulebase(), comments_captured=False)

        assert issues(report, RuleIssue.NO_DOCUMENTATION) == []

    def test_it_is_info_severity(self) -> None:
        """A maintenance problem, not a security state. Ranked with exposures it would
        push the findings that matter this week off the top of the page."""
        from netsecops.firewall.policy import ISSUE_SEVERITY

        assert ISSUE_SEVERITY[RuleIssue.NO_DOCUMENTATION] == "info"


class TestTheCommentPlatformRegistry:
    def test_every_listed_platform_exists(self) -> None:
        """A typo here silently turns the check off for a platform that supports it."""
        assert RULE_COMMENT_PLATFORMS <= set(PARSERS)

    @pytest.mark.parametrize("platform", sorted(RULE_COMMENT_PLATFORMS))
    def test_each_listed_platform_really_captures_comments(self, platform: str) -> None:
        """The registry is a claim about the parsers, so it is checked against them —
        and against the corpus rather than the source, because a `comment=` assignment
        that never fires reads the same as one that does.

        Listing a platform whose parser does not populate `comment` reports every rule
        on it as undocumented, which is the exact false finding the registry prevents.
        Checked by parser class: `cisco_iosxe` and `cisco_c9800` are the IOS parser under
        other names, so one fixture with a `remark` in it proves all three.
        """
        import json
        from pathlib import Path

        baseline = json.loads(
            (Path(__file__).parent / "fixtures" / "parser_field_baseline.json").read_text(
                encoding="utf-8"
            )
        )
        proven = {
            PARSERS[name]
            for name, fields in baseline.items()
            if name in PARSERS and "firewall.security_rules.comment" in fields
        }

        assert PARSERS[platform] in proven, (
            f"{platform} is listed in RULE_COMMENT_PLATFORMS, but no fixture parsed by "
            f"{PARSERS[platform].__name__} produces a rule comment — so the claim that "
            "it captures them is untested. Add a comment or remark to one of its fixtures."
        )


class TestTheConsoleHasWordsForEveryIssue:
    """A finding the UI renders as `unroutable_destination` is a finding nobody reads.

    The label map is TypeScript and the issue list is Python, so nothing connected them
    and a new issue type reached the console as a raw slug — silently, because a slug
    still renders. Checked here rather than in vitest because this side is where the
    issues are declared, so this is the side that knows when one is added.
    """

    LABELS = (
        pathlib.Path(__file__).parents[2]
        / "frontend"
        / "src"
        / "features"
        / "firewall"
        / "types.ts"
    )

    @pytest.mark.parametrize("issue", sorted(RuleIssue, key=lambda i: i.value))
    def test_every_issue_has_a_label(self, issue: RuleIssue) -> None:
        if not self.LABELS.is_file():
            pytest.skip("frontend sources are not present in this checkout")

        text = self.LABELS.read_text(encoding="utf-8")
        assert f"{issue.value}:" in text, (
            f"{issue.value} has no entry in ISSUE_LABELS, so the console will print the "
            "raw key to an operator."
        )


class TestTheCiscoRemarkReachesTheRule:
    """IOS has no per-entry comment field, so `remark` is the whole of it.

    Asserted against the parser rather than the registry, because the registry test
    greps for an assignment and would pass on a remark that never reaches a rule.
    """

    IOS = (
        "hostname edge\n"
        "!\n"
        "ip access-list extended OUTSIDE-IN\n"
        " remark Allow the payroll batch job to reach the finance server\n"
        " permit tcp 10.1.0.0 0.0.0.255 host 10.20.0.10 eq 443\n"
        " permit tcp 10.1.0.0 0.0.0.255 host 10.20.0.10 eq 8443\n"
        " remark Temporary, raised under CHG0041299\n"
        " permit tcp any host 10.20.0.11 eq 22\n"
        " deny ip any any\n"
    )

    @staticmethod
    def rules_from(text: str) -> Any:
        from netsecops.parsers.base import ParseContext
        from netsecops.parsers.registry import get_parser

        ncm = get_parser("cisco_ios").parse(ParseContext(text=text, command="show run"))
        return ncm.firewall.security_rules

    def parse(self) -> Any:
        return self.rules_from(self.IOS)

    def test_the_remark_lands_on_the_entry_below_it(self) -> None:
        rules = self.parse()

        assert rules[0].comment == "Allow the payroll batch job to reach the finance server"

    def test_it_carries_to_every_entry_until_the_next_remark(self) -> None:
        """One remark above a block of entries is the common shape. Attaching it only to
        the first would report the rest of a documented ACL as undocumented."""
        rules = self.parse()

        assert rules[1].comment == "Allow the payroll batch job to reach the finance server"
        assert rules[2].comment == "Temporary, raised under CHG0041299"
        assert rules[3].comment == "Temporary, raised under CHG0041299"

    def test_the_remark_is_not_itself_a_rule(self) -> None:
        """It permits nothing. Turning a remark into a rule would put an entry with no
        addresses into the middle of a first-match evaluation."""
        rules = self.parse()

        assert len(rules) == 4
        assert not any("remark" in (rule.name or "").lower() for rule in rules)

    def test_an_entry_before_any_remark_has_no_comment(self) -> None:
        """None, and specifically not the remark that follows it — a remark describes
        what comes after, and reading it backwards would attribute the wrong change
        ticket to a rule."""
        rules = self.rules_from(
            "hostname edge\n!\nip access-list extended L\n"
            " permit ip host 10.0.0.1 any\n"
            " remark Added later\n"
            " permit ip host 10.0.0.2 any\n"
        )

        assert rules[0].comment is None
        assert rules[1].comment == "Added later"
