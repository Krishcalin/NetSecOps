"""Rule permissiveness scoring (FR-FW-07).

A score people sort a firewall review by has to be defensible line by line, so these
tests pin the scale at the prefixes operators actually recognise rather than asserting
that one rule scores higher than another. If /24 stops being 25, that is a change to
what the number means and it should require editing a test that says so.

The rules are built through `resolve_rulebase`, the same path the product uses, so the
scoring is exercised against really-resolved sets rather than hand-assembled ones.
"""

from __future__ import annotations

import pytest

from netsecops.firewall.model import resolve_rulebase
from netsecops.firewall.permissiveness import band_for, score_rule


def rule(
    *,
    src: str = "any",
    dst: str = "any",
    service: str = "any",
    action: str = "allow",
    enabled: bool = True,
    **extra: object,
) -> dict:
    return {
        "order": 1,
        "name": "scored",
        "enabled": enabled,
        "src": [src],
        "dst": [dst],
        "services": [service],
        "action": action,
        "src_zones": [],
        "dst_zones": [],
        **extra,
    }


def scored_with(firewall: dict, **kwargs: object):
    """Score one rule inside a rulebase that may also define objects for it."""
    rules, _ = resolve_rulebase({"security_rules": [rule(**kwargs)], **firewall})  # type: ignore[arg-type]
    return score_rule(rules[0])


def score(**kwargs: object):
    return scored_with({}, **kwargs)


class TestTheScale:
    """The score is the proportion of the address space's bits left wild, so it reads
    straight off a prefix length — which is the only reason an operator can sanity-check
    it without reading the implementation."""

    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            ("10.0.0.5", 0),  # /32 — as narrow as a rule gets
            ("10.0.0.0/24", 25),
            ("10.0.0.0/16", 50),
            ("10.0.0.0/8", 75),
            ("any", 100),
        ],
    )
    def test_source_breadth_tracks_the_prefix(self, source: str, expected: int) -> None:
        result = score(src=source, dst="10.0.0.5", service="tcp/443")
        assert result is not None
        assert result.source == expected

    def test_the_widest_possible_permit_scores_100(self) -> None:
        result = score()
        assert result is not None
        assert result.score == 100
        assert result.band == "critical"

    def test_a_fully_pinned_permit_scores_0(self) -> None:
        result = score(src="10.0.0.5", dst="10.0.0.6", service="tcp/443")
        assert result is not None
        assert (result.score, result.source, result.destination, result.service) == (0, 0, 0, 0)
        assert result.band == "low"

    def test_any_protocol_outscores_every_port_of_one_protocol(self) -> None:
        """`service any` and `tcp/1-65535` are different rules. Conflating them would
        make the score unable to distinguish the broadest thing a rule can say."""
        every_tcp_port = score(src="10.0.0.5", dst="10.0.0.6", service="tcp/0-65535")
        anything = score(src="10.0.0.5", dst="10.0.0.6", service="any")

        assert every_tcp_port is not None and anything is not None
        assert anything.service == 100
        assert 0 < every_tcp_port.service < 100


class TestWhatIsNotScored:
    def test_a_deny_rule_is_not_scored_at_all(self) -> None:
        """The implicit-deny catch-all matches everything and is the best rule in most
        rulebases. Scoring it 100 would put the healthiest line at the top of a list of
        the worst ones."""
        assert score(action="deny") is None
        assert score(action="drop") is None
        assert score(action="reject") is None

    def test_a_disabled_rule_is_still_scored(self) -> None:
        """Breadth is a property of what the rule says. Someone reviewing a disabled
        any-any-any before re-enabling it is exactly who needs the number."""
        result = score(enabled=False)
        assert result is not None
        assert result.score == 100


class TestNotOverstatingWhatIsKnown:
    def test_a_rule_naming_an_undefined_object_is_marked_as_a_floor(self) -> None:
        """An unresolved name resolves to nothing, so the covered set is smaller than
        the real one and every component understates. Reporting the number without
        saying so presents a lower bound as a measurement."""
        result = scored_with({}, src="group-nobody-defined", dst="10.0.0.6", service="tcp/443")

        assert result is not None
        assert result.understated is True

    def test_a_resolvable_rule_is_not_marked(self) -> None:
        result = scored_with(
            {
                "address_objects": [{"name": "web-01", "type": "host", "value": "10.0.0.6"}],
            },
            src="10.0.0.5",
            dst="web-01",
            service="tcp/443",
        )

        assert result is not None
        assert result.understated is False

    def test_v6_breadth_is_not_hidden_by_an_empty_v4(self) -> None:
        """The broader family wins, and it has to, because a v6-only rule has no v4 side
        at all. Scoring the v4 set alone — which is what `RuleRead.source_size` has
        always reported — calls a rule covering 2**96 addresses the narrowest kind there
        is. `2001:db8::/32` leaves 96 of 128 bits wild, so it scores 75.

        Note `::/0` would *not* prove this: it is deliberately read as "any" in both
        families, because vendors write it to mean any, so a v4-only implementation
        would score it 100 and look correct.
        """
        result = scored_with(
            {
                "address_objects": [
                    {"name": "v6-net", "type": "network", "value": "2001:db8::/32"},
                ],
            },
            src="10.0.0.5",
            dst="v6-net",
            service="tcp/443",
        )

        assert result is not None
        assert result.destination == 75


class TestTheComponentsTravelWithTheScore:
    def test_each_field_is_reported_separately(self) -> None:
        """ "73" tells an operator nothing to act on. Naming which field is wide tells
        them what to narrow, and lets them disagree on the evidence."""
        result = score(src="any", dst="10.0.0.0/8", service="tcp/443")

        assert result is not None
        assert (result.source, result.destination, result.service) == (100, 75, 0)
        assert result.score == round((100 + 75 + 0) / 3)


class TestBands:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (0, "low"),
            (24, "low"),
            (25, "moderate"),
            (49, "moderate"),
            (50, "high"),
            (99, "critical"),
        ],
    )
    def test_every_score_lands_in_exactly_one_band(self, value: int, expected: str) -> None:
        assert band_for(value) == expected
