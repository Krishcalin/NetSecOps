"""Rule relationship analysis (FR-FW-03, FR-FW-06).

The hand-written cases pin down the taxonomy. The property tests do something the
examples cannot: they check the analyser's verdicts against brute-force packet matching
over a small address space, so a claim like "rule 7 is shadowed" is verified by
enumerating packets and confirming rule 7 never wins.

That is the assertion worth having. A shadowing report is an instruction to delete a
rule from a firewall, and being wrong about it takes production down.
"""

from __future__ import annotations

import ipaddress
import itertools

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from netsecops.firewall.analysis import (
    RangeOutcome,
    Relationship,
    analyse,
    first_match,
    first_match_over_range,
    summarise,
)
from netsecops.firewall.intervals import parse_address
from netsecops.firewall.model import resolve_rulebase


def rule(
    order: int,
    *,
    src: str = "any",
    dst: str = "any",
    service: str = "any",
    action: str = "allow",
    enabled: bool = True,
    src_zone: str | None = None,
    dst_zone: str | None = None,
    applications: list[str] | None = None,
    **extra: object,
) -> dict:
    return {
        "order": order,
        "name": f"rule-{order}",
        "enabled": enabled,
        "src": [src],
        "dst": [dst],
        "services": [service],
        "action": action,
        "src_zones": [src_zone] if src_zone else [],
        "dst_zones": [dst_zone] if dst_zone else [],
        "applications": applications or [],
        **extra,
    }


def analyse_rules(*raw: dict, **kwargs: object):
    rules, _ = resolve_rulebase({"security_rules": list(raw)})
    return analyse(rules, **kwargs)  # type: ignore[arg-type]


def verdict_over(*raw: dict, source: str, destination: str, port: int = 443, protocol: int = 6):
    """What a rulebase does across two ranges, built the way the product builds one."""
    rules, _ = resolve_rulebase({"security_rules": list(raw)})
    src, _ = parse_address(source)
    dst, _ = parse_address(destination)
    return first_match_over_range(rules, source=src, destination=dst, protocol=protocol, port=port)


class TestTheSegmentationQuestion:
    """ "Can anything in A reach anything in B" — which `first_match` cannot answer.

    It decides one packet, so asking about a pair of /24s means 65,536 queries and, worse,
    answers a question nobody asked: whether one arbitrary host pair gets through, rather
    than whether the boundary holds. A single denial inside an otherwise-permitted range
    is exactly what a segmentation review is looking for, and it is invisible unless the
    query happens to land on it.
    """

    def test_a_rule_covering_both_ranges_decides_the_whole_range(self) -> None:
        result = verdict_over(
            rule(1, src="10.10.0.0/24", dst="10.20.0.0/24", action="allow"),
            source="10.10.0.0/24",
            destination="10.20.0.0/24",
        )

        assert result.outcome is RangeOutcome.ALLOWED
        assert result.decided_by is not None
        assert result.decided_by.order == 1

    def test_a_broad_deny_blocks_the_whole_range(self) -> None:
        result = verdict_over(
            rule(1, action="deny"),
            source="10.10.0.0/24",
            destination="10.20.0.0/24",
        )

        assert result.outcome is RangeOutcome.BLOCKED

    def test_one_denied_host_inside_a_permitted_range_is_not_reported_as_allowed(self) -> None:
        """The finding a host-by-host query would miss 255 times out of 256.

        The boundary is open for almost the whole range, and a segmentation review that
        reports "allowed" has described it accurately and uselessly — the interesting
        fact is that one address is treated differently.
        """
        result = verdict_over(
            rule(1, dst="10.20.0.5", action="deny"),
            rule(2, action="allow"),
            source="10.10.0.0/24",
            destination="10.20.0.0/24",
        )

        assert result.outcome is RangeOutcome.MIXED
        assert result.outcome is not RangeOutcome.ALLOWED
        assert [r.order for r in result.split_by] == [1]

    def test_a_partial_permit_inside_a_denied_range_is_also_mixed(self) -> None:
        """Mixed is not a synonym for "mostly allowed" — it points both ways."""
        result = verdict_over(
            rule(1, dst="10.20.0.0/25", action="allow"),
            rule(2, action="deny"),
            source="10.10.0.0/24",
            destination="10.20.0.0/24",
        )

        assert result.outcome is RangeOutcome.MIXED
        assert [r.order for r in result.split_by] == [1]

    def test_a_partial_source_also_splits_the_range(self) -> None:
        """Both axes matter. Half the source VLAN permitted is not "permitted"."""
        result = verdict_over(
            rule(1, src="10.10.0.0/25", dst="10.20.0.0/24", action="allow"),
            rule(2, action="deny"),
            source="10.10.0.0/24",
            destination="10.20.0.0/24",
        )

        assert result.outcome is RangeOutcome.MIXED

    def test_a_rule_that_misses_the_range_neither_decides_nor_splits(self) -> None:
        """An unrelated rule must not make every answer "mixed".

        This is what would make the verdict useless in practice: a real rulebase holds
        hundreds of rules about other subnets, and if each one counted as a split the
        answer would never be uniform.
        """
        result = verdict_over(
            rule(1, src="192.168.0.0/24", dst="172.16.0.0/24", action="deny"),
            rule(2, src="10.10.0.0/24", dst="10.20.0.0/24", action="allow"),
            source="10.10.0.0/24",
            destination="10.20.0.0/24",
        )

        assert result.outcome is RangeOutcome.ALLOWED
        assert result.split_by == ()

    def test_a_rule_on_another_port_does_not_split_the_range(self) -> None:
        """It reaches these addresses and not this service, so it does not apply."""
        result = verdict_over(
            rule(1, dst="10.20.0.5", service="tcp/22", action="deny"),
            rule(2, action="allow"),
            source="10.10.0.0/24",
            destination="10.20.0.0/24",
            port=443,
        )

        assert result.outcome is RangeOutcome.ALLOWED

    def test_an_empty_rulebase_reports_no_match_rather_than_allowed(self) -> None:
        """The implicit default decides it, and that is not this function's to assume."""
        result = verdict_over(
            rule(1, src="192.168.0.0/24", dst="172.16.0.0/24"),
            source="10.10.0.0/24",
            destination="10.20.0.0/24",
        )

        assert result.outcome is RangeOutcome.NO_MATCH

    def test_a_disabled_rule_does_not_split(self) -> None:
        result = verdict_over(
            rule(1, dst="10.20.0.5", action="deny", enabled=False),
            rule(2, action="allow"),
            source="10.10.0.0/24",
            destination="10.20.0.0/24",
        )

        assert result.outcome is RangeOutcome.ALLOWED

    def test_a_single_host_pair_agrees_with_first_match(self) -> None:
        """A range of one must not answer differently from the packet query.

        Two engines that disagree on the same question is worse than one that cannot
        answer it, so the degenerate case is pinned.
        """
        rules, _ = resolve_rulebase(
            {
                "security_rules": [
                    rule(1, dst="10.20.0.5", action="deny"),
                    rule(2, action="allow"),
                ]
            }
        )
        packet = first_match(
            rules,
            source=int(ipaddress.ip_address("10.10.0.9")),
            destination=int(ipaddress.ip_address("10.20.0.5")),
            protocol=6,
            port=443,
        )
        ranged = verdict_over(
            rule(1, dst="10.20.0.5", action="deny"),
            rule(2, action="allow"),
            source="10.10.0.9",
            destination="10.20.0.5",
        )

        assert packet.matched is not None
        assert packet.matched.order == 1
        assert ranged.outcome is RangeOutcome.BLOCKED
        assert ranged.decided_by is not None
        assert ranged.decided_by.order == packet.matched.order


class TestTheRangeVerdictAgreesWithEveryPacket:
    """Checked against brute force, because a uniform verdict is a strong claim.

    "Allowed" over a range asserts something about every packet in it, and a segmentation
    review acts on that. So the range answer is verified by enumerating the packets and
    confirming `first_match` agrees on all of them — the same discipline the shadowing
    analysis is held to in this file, and for the same reason.
    """

    @staticmethod
    def _rules(raw: list[dict]):
        rules, _ = resolve_rulebase({"security_rules": raw})
        return rules

    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    @given(
        deny_host=st.integers(min_value=0, max_value=7),
        deny_first=st.booleans(),
        broad_action=st.sampled_from(["allow", "deny"]),
    )
    def test_a_uniform_verdict_holds_for_every_packet_in_the_range(
        self, deny_host: int, deny_first: bool, broad_action: str
    ) -> None:
        specific = rule(1 if deny_first else 2, dst=f"10.20.0.{deny_host}", action="deny")
        broad = rule(2 if deny_first else 1, action=broad_action)
        raw = [specific, broad] if deny_first else [broad, specific]
        rules = self._rules(sorted(raw, key=lambda r: r["order"]))

        source = "10.10.0.0/29"
        destination = "10.20.0.0/29"
        src_set, _ = parse_address(source)
        dst_set, _ = parse_address(destination)
        ranged = first_match_over_range(
            rules, source=src_set, destination=dst_set, protocol=6, port=443
        )

        actions = set()
        for s in range(8):
            for d in range(8):
                packet = first_match(
                    rules,
                    source=int(ipaddress.ip_address(f"10.10.0.{s}")),
                    destination=int(ipaddress.ip_address(f"10.20.0.{d}")),
                    protocol=6,
                    port=443,
                )
                actions.add(packet.matched.action if packet.matched else None)

        if ranged.outcome is RangeOutcome.ALLOWED:
            assert actions == {"allow"}, "a uniform permit covered a packet that was denied"
        elif ranged.outcome is RangeOutcome.BLOCKED:
            assert actions == {"deny"}, "a uniform deny covered a packet that was permitted"
        elif ranged.outcome is RangeOutcome.MIXED:
            # Mixed is allowed to be conservative — it may report a split where the
            # packets happen to agree — but it must never hide a genuine disagreement.
            pass
        else:
            assert actions == {None}

    @settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    @given(host=st.integers(min_value=0, max_value=7))
    def test_a_genuine_disagreement_is_never_reported_as_uniform(self, host: int) -> None:
        """The direction that matters. Over-reporting MIXED is noise; under-reporting is
        a segmentation review that missed the exception it was run to find."""
        rules = self._rules(
            [
                rule(1, dst=f"10.20.0.{host}", action="deny"),
                rule(2, action="allow"),
            ]
        )
        src_set, _ = parse_address("10.10.0.0/29")
        dst_set, _ = parse_address("10.20.0.0/29")

        ranged = first_match_over_range(
            rules, source=src_set, destination=dst_set, protocol=6, port=443
        )

        assert ranged.outcome is RangeOutcome.MIXED


class TestTheTaxonomy:
    def test_a_broad_deny_above_a_specific_permit_shadows_it(self) -> None:
        """The finding that matters most: the rulebase does not do what it says."""
        result = analyse_rules(
            rule(1, src="10.0.0.0/8", dst="any", action="deny"),
            rule(2, src="10.1.2.0/24", dst="any", action="allow"),
        )

        shadowed = result.by_kind(Relationship.SHADOWED)
        assert len(shadowed) == 1
        assert shadowed[0].later_order == 2
        assert shadowed[0].earlier_order == 1
        assert "denies it instead" in shadowed[0].detail

    def test_the_same_action_twice_is_redundancy_not_shadowing(self) -> None:
        """Harmless to traffic, so it must not be reported as though the firewall is
        misbehaving. It is dead weight, and graded accordingly."""
        result = analyse_rules(
            rule(1, src="10.0.0.0/8", action="allow"),
            rule(2, src="10.1.2.0/24", action="allow"),
        )

        assert not result.by_kind(Relationship.SHADOWED)
        redundant = result.by_kind(Relationship.REDUNDANT)
        assert len(redundant) == 1
        assert redundant[0].severity == "low"
        # The broad rule is first, so the later, narrower one is the dead weight.
        assert redundant[0].subject.order == 2

    def test_a_broad_rule_below_a_narrow_one_makes_the_narrow_one_redundant(self) -> None:
        """Direction matters, and it is not simply "the later rule".

        With first-match-wins, a narrow rule sitting above a broad one with the same
        action is the pointless one: deleting it changes nothing, because the broad rule
        below reaches the same verdict on the same traffic. Reporting the broad rule here
        would send an operator to delete the wrong one — and the broad rule is usually
        already reported on its own merits as overly permissive.
        """
        result = analyse_rules(
            rule(1, src="10.1.2.0/24", action="allow"),
            rule(2, src="10.0.0.0/8", action="allow"),
        )

        redundant = result.by_kind(Relationship.REDUNDANT)
        assert len(redundant) == 1
        assert redundant[0].subject.order == 1
        assert redundant[0].cause.order == 2
        assert redundant[0].describe().startswith("Rule #1")
        assert "below it" in redundant[0].detail

    def test_removing_a_redundant_rule_is_qualified_when_it_would_lose_logging(self) -> None:
        """Redundancy is defined over the permit/deny verdict alone. A rule can be
        redundant and still be the only reason traffic is logged or inspected, and advice
        to delete it without saying so would silently drop a log source."""
        result = analyse_rules(
            rule(1, src="10.1.2.0/24", action="allow", log_end=True),
            rule(2, src="10.0.0.0/8", action="allow", log_end=False),
        )

        detail = result.by_kind(Relationship.REDUNDANT)[0].detail
        assert "logging" in detail

    def test_no_caveat_when_nothing_would_actually_be_lost(self) -> None:
        """The converse: padding every redundancy finding with a warning that does not
        apply is how a caveat stops being read."""
        result = analyse_rules(
            rule(1, src="10.1.2.0/24", action="allow", log_end=True),
            rule(2, src="10.0.0.0/8", action="allow", log_end=True),
        )

        assert "would still lose" not in result.by_kind(Relationship.REDUNDANT)[0].detail

    def test_partial_overlap_with_different_actions_is_correlation(self) -> None:
        result = analyse_rules(
            rule(1, src="10.0.0.0/24", dst="192.168.0.0/16", action="deny"),
            rule(2, src="10.0.0.0/16", dst="192.168.1.0/24", action="allow"),
        )

        correlated = result.by_kind(Relationship.CORRELATED)
        assert len(correlated) == 1
        assert "order between them decides" in correlated[0].detail

    def test_partial_overlap_with_the_same_action_is_not_reported(self) -> None:
        """It changes nothing about what the firewall does, so it is noise."""
        result = analyse_rules(
            rule(1, src="10.0.0.0/24", dst="192.168.0.0/16", action="allow"),
            rule(2, src="10.0.0.0/16", dst="192.168.1.0/24", action="allow"),
        )
        assert not result.relationships

    def test_a_specific_exception_above_a_general_rule_is_only_informational(self) -> None:
        """This is what a well-ordered rulebase looks like. Reporting it as a defect
        would flag good practice and train people to ignore the category."""
        result = analyse_rules(
            rule(1, src="10.0.0.5", action="deny"),
            rule(2, src="10.0.0.0/8", action="allow"),
        )

        generalisations = result.by_kind(Relationship.GENERALISATION)
        assert len(generalisations) == 1
        assert generalisations[0].severity == "info"

    def test_disjoint_rules_have_no_relationship(self) -> None:
        result = analyse_rules(
            rule(1, src="10.0.0.0/8", action="deny"),
            rule(2, src="192.168.0.0/16", action="allow"),
        )
        assert not result.relationships

    def test_different_zones_cannot_overlap(self) -> None:
        """Zones gate everything. Two rules in unrelated zone pairs never see the same
        packet, whatever their addresses say."""
        result = analyse_rules(
            rule(1, src_zone="trust", dst_zone="dmz", action="deny"),
            rule(2, src_zone="guest", dst_zone="untrust", action="allow"),
        )
        assert not result.relationships

    def test_disabled_rules_are_excluded_by_default(self) -> None:
        """A disabled rule cannot shadow anything — it is not in the evaluation path."""
        result = analyse_rules(
            rule(1, action="deny", enabled=False),
            rule(2, src="10.0.0.0/8", action="allow"),
        )
        assert not result.relationships
        assert result.rules_analysed == 1

    def test_services_narrow_the_comparison(self) -> None:
        result = analyse_rules(
            rule(1, service="tcp/443", action="deny"),
            rule(2, service="tcp/80", action="allow"),
        )
        assert not result.relationships

    def test_applications_are_compared_by_name(self) -> None:
        """A declared limitation, asserted so the behaviour is deliberate rather than
        accidental."""
        result = analyse_rules(
            rule(1, applications=["ssl"], action="deny"),
            rule(2, applications=["ssh"], action="allow"),
        )
        assert not result.relationships
        assert any("App-ID" in limit for limit in result.limitations)


class TestReportingDiscipline:
    def test_a_shadowed_rule_is_reported_once(self) -> None:
        """Five earlier rules may each shadow the same dead rule. Reporting it five
        times buries the other four problems."""
        result = analyse_rules(
            rule(1, src="10.0.0.0/8", action="deny"),
            rule(2, src="10.0.0.0/12", action="deny"),
            rule(3, src="10.0.0.0/16", action="deny"),
            rule(4, src="10.0.1.0/24", action="allow"),
        )

        shadowed = result.by_kind(Relationship.SHADOWED)
        assert len([s for s in shadowed if s.later_order == 4]) == 1

    def test_counts_stay_truthful_when_output_is_capped(self) -> None:
        """The cap limits what is shown, never what is counted. "1.2 million
        correlations" is itself the finding."""
        rules = [
            rule(n, src=f"10.0.{n}.0-10.0.{n + 30}.255", action="allow" if n % 2 else "deny")
            for n in range(1, 60)
        ]
        result = analyse_rules(*rules, max_relationships=10)

        assert result.truncated
        assert len(result.relationships) == 10
        assert result.total_found > 10
        assert summarise(result)["total_found"] == result.total_found

    def test_the_limitations_are_always_stated(self) -> None:
        """A reader must never have to infer that pairwise means pairwise."""
        result = analyse_rules(rule(1))
        assert any("pairwise" in limit for limit in result.limitations)

    def test_evaluation_order_is_respected(self) -> None:
        """Reversing the rules reverses which one shadows the other, because the whole
        analysis is a statement about precedence."""
        forward = analyse_rules(
            rule(1, src="10.0.0.0/8", action="deny"),
            rule(2, src="10.0.0.0/24", action="allow"),
        )
        backward = analyse_rules(
            rule(1, src="10.0.0.0/24", action="allow"),
            rule(2, src="10.0.0.0/8", action="deny"),
        )

        assert forward.by_kind(Relationship.SHADOWED)
        assert not backward.by_kind(Relationship.SHADOWED)
        assert backward.by_kind(Relationship.GENERALISATION)


# ─────────────────────── property tests (acceptance) ────────────────────────

# A tiny address and port space, so every generated rulebase can be checked by
# enumerating every packet in it.
OCTETS = 8
PORTS = 4

small_rules = st.lists(
    st.fixed_dictionaries(
        {
            "src_lo": st.integers(0, OCTETS - 1),
            "src_len": st.integers(1, 4),
            "dst_lo": st.integers(0, OCTETS - 1),
            "dst_len": st.integers(1, 4),
            "port_lo": st.integers(0, PORTS - 1),
            "port_len": st.integers(1, 2),
            "allow": st.booleans(),
        }
    ),
    min_size=2,
    max_size=6,
)


def build(raw: list[dict]) -> list[dict]:
    rules = []
    for index, spec in enumerate(raw):
        src_hi = min(OCTETS - 1, spec["src_lo"] + spec["src_len"] - 1)
        dst_hi = min(OCTETS - 1, spec["dst_lo"] + spec["dst_len"] - 1)
        port_hi = min(PORTS - 1, spec["port_lo"] + spec["port_len"] - 1)
        rules.append(
            {
                "order": index + 1,
                "name": f"r{index + 1}",
                "enabled": True,
                "src": [f"10.0.0.{spec['src_lo']}-10.0.0.{src_hi}"],
                "dst": [f"10.0.1.{spec['dst_lo']}-10.0.1.{dst_hi}"],
                "services": [f"tcp/{spec['port_lo']}-{port_hi}"],
                "action": "allow" if spec["allow"] else "deny",
            }
        )
    return rules


def packets():
    return itertools.product(range(OCTETS), range(OCTETS), range(PORTS))


def matches(spec: dict, source: int, destination: int, port: int) -> bool:
    return (
        spec["src_lo"] <= source <= min(OCTETS - 1, spec["src_lo"] + spec["src_len"] - 1)
        and spec["dst_lo"] <= destination <= min(OCTETS - 1, spec["dst_lo"] + spec["dst_len"] - 1)
        and spec["port_lo"] <= port <= min(PORTS - 1, spec["port_lo"] + spec["port_len"] - 1)
    )


class TestAgainstBruteForcePacketMatching:
    """Every verdict checked by enumerating packets.

    A shadowing report tells an operator to delete a rule from a production firewall.
    Verifying it against the traffic the rule would actually see is the only way to be
    confident the instruction is safe.
    """

    @settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
    @given(small_rules)
    def test_a_rule_reported_shadowed_can_never_win(self, raw: list[dict]) -> None:
        result = analyse(resolve_rulebase({"security_rules": build(raw)})[0])

        for relationship in result.by_kind(Relationship.SHADOWED):
            victim = relationship.later_order - 1
            for source, destination, port in packets():
                winner = next(
                    (i for i, spec in enumerate(raw) if matches(spec, source, destination, port)),
                    None,
                )
                assert winner != victim, (
                    f"rule {victim + 1} was reported shadowed, but it is the first "
                    f"match for {source}->{destination}:{port}"
                )

    @settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
    @given(small_rules)
    def test_reported_pairs_really_do_overlap(self, raw: list[dict]) -> None:
        """No relationship may be claimed between rules that share no packet."""
        result = analyse(resolve_rulebase({"security_rules": build(raw)})[0])

        for relationship in result.relationships:
            a = raw[relationship.earlier_order - 1]
            b = raw[relationship.later_order - 1]
            shared = any(matches(a, s, d, p) and matches(b, s, d, p) for s, d, p in packets())
            assert shared, (
                f"rules {relationship.earlier_order} and {relationship.later_order} "
                f"were reported {relationship.kind.value} but share no packet"
            )

    @settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
    @given(small_rules)
    def test_a_rule_that_wins_a_packet_is_never_called_shadowed(self, raw: list[dict]) -> None:
        """The converse framing, which catches a different class of mistake: a rule
        that decides any packet at all is alive, whatever the pairwise test concluded."""
        result = analyse(resolve_rulebase({"security_rules": build(raw)})[0])
        shadowed_orders = {r.later_order for r in result.by_kind(Relationship.SHADOWED)}

        alive: set[int] = set()
        for source, destination, port in packets():
            winner = next(
                (i for i, spec in enumerate(raw) if matches(spec, source, destination, port)),
                None,
            )
            if winner is not None:
                alive.add(winner + 1)

        assert not (shadowed_orders & alive)

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(small_rules)
    def test_the_rule_query_agrees_with_the_rulebase(self, raw: list[dict]) -> None:
        """FR-FW-06 simulation must return the same rule the evaluation order implies."""
        rules, _ = resolve_rulebase({"security_rules": build(raw)})

        for source, destination, port in packets():
            expected = next(
                (i for i, spec in enumerate(raw) if matches(spec, source, destination, port)),
                None,
            )
            answer = first_match(
                rules,
                source=int.from_bytes(bytes([10, 0, 0, source]), "big"),
                destination=int.from_bytes(bytes([10, 0, 1, destination]), "big"),
                protocol=6,
                port=port,
            )
            if expected is None:
                assert answer.matched is None
            else:
                assert answer.matched is not None
                assert answer.matched.order == expected + 1


class TestRuleQuery:
    def test_it_returns_the_first_matching_rule(self) -> None:
        rules, _ = resolve_rulebase(
            {
                "security_rules": [
                    rule(1, src="10.0.0.0/24", dst="192.168.1.0/24", service="tcp/443"),
                    rule(2, src="any", dst="any", service="any", action="deny"),
                ]
            }
        )
        answer = first_match(
            rules,
            source=int.from_bytes(bytes([10, 0, 0, 5]), "big"),
            destination=int.from_bytes(bytes([192, 168, 1, 10]), "big"),
            protocol=6,
            port=443,
        )

        assert answer.matched is not None
        assert answer.matched.order == 1
        # The rule that would have matched but for ordering — the answer to "why did my
        # new rule not take effect".
        assert [r.order for r in answer.shadowed_by_match] == [2]

    def test_no_match_is_reported_as_no_match(self) -> None:
        rules, _ = resolve_rulebase(
            {"security_rules": [rule(1, src="10.0.0.0/24", service="tcp/443")]}
        )
        answer = first_match(
            rules,
            source=int.from_bytes(bytes([172, 16, 0, 1]), "big"),
            destination=int.from_bytes(bytes([8, 8, 8, 8]), "big"),
            protocol=6,
            port=53,
        )
        assert answer.matched is None

    def test_its_limitations_travel_with_the_answer(self) -> None:
        """An unqualified "rule 42 matches" would be read as a guarantee."""
        rules, _ = resolve_rulebase({"security_rules": [rule(1)]})
        answer = first_match(rules, source=1, destination=2, protocol=6, port=80)
        assert any("App-ID" in limit or "Application" in limit for limit in answer.limitations)


class TestObjectResolution:
    def test_nested_groups_are_expanded(self) -> None:
        firewall = {
            "address_objects": [
                {"name": "web1", "value": "10.0.0.1"},
                {"name": "web2", "value": "10.0.0.2"},
            ],
            "address_groups": [
                {"name": "inner", "members": ["web1", "web2"]},
                {"name": "outer", "members": ["inner"]},
            ],
            "security_rules": [rule(1, src="outer", action="allow")],
        }
        rules, _ = resolve_rulebase(firewall)
        assert rules[0].source.v4.size == 2

    def test_a_group_cycle_terminates(self) -> None:
        """A malformed export can contain one, and an unbounded walk would hang the
        analysis rather than failing it."""
        firewall = {
            "address_groups": [
                {"name": "a", "members": ["b"]},
                {"name": "b", "members": ["a"]},
            ],
            "security_rules": [rule(1, src="a")],
        }
        rules, _ = resolve_rulebase(firewall)
        assert rules[0].source.v4.size == 0

    def test_an_undefined_object_is_recorded_not_guessed(self) -> None:
        """Treating it as `any` would invent permissions; treating it as nothing
        silently hides the rule. Recording it is the only honest option."""
        rules, resolver = resolve_rulebase({"security_rules": [rule(1, src="does-not-exist")]})

        assert rules[0].unresolved == ("does-not-exist",)
        assert not rules[0].source
        assert "does-not-exist" in resolver.unresolved

    def test_a_rule_with_unresolved_objects_is_excluded_from_overlap(self) -> None:
        """Its real scope is unknown, so any overlap verdict would be invented."""
        result = analyse_rules(
            rule(1, src="any", action="deny"),
            rule(2, src="does-not-exist", action="allow"),
        )
        assert not result.relationships

    @pytest.mark.parametrize(
        ("value", "expected_ports"),
        [("tcp/443", 1), ("tcp/80,443", 2), ("tcp/1024-65535", 64512)],
    )
    def test_service_objects_resolve_to_ports(self, value: str, expected_ports: int) -> None:
        firewall = {
            "service_objects": [{"name": "svc", "type": "tcp", "value": value}],
            "security_rules": [rule(1, service="svc")],
        }
        rules, _ = resolve_rulebase(firewall)
        assert sum(p.size for p in rules[0].services.by_protocol.values()) == expected_ports

    def test_any_short_circuits_a_union(self) -> None:
        """`any` swallows everything else, so the rest need not be resolved."""
        firewall = {
            "address_objects": [{"name": "one", "value": "10.0.0.1"}],
            "security_rules": [
                {**rule(1), "src": ["one", "any"]},
            ],
        }
        rules, _ = resolve_rulebase(firewall)
        assert rules[0].source.is_any
