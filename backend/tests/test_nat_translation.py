"""Following a NAT translation (FR-TOPO-03).

The reason this is worth its own file: a wrong translation is a wrong path verdict, and
a wrong path verdict is somebody opening a firewall. Almost every test here is about
the three outcomes staying distinguishable —

  * a rule applied, and here is what the packet became,
  * no rule matched, which says nothing and needs no caveat,
  * a rule may have applied and could not be read, which weakens everything downstream.

The middle and the last are the pair that must never be confused. Collapsing them is
the obvious simplification and it turns "we could not follow this" into "nothing
happened", which is exactly the silent-emptiness failure this codebase keeps finding.

The rule shapes are the ones the four parsers really emit, not invented ones.
"""

from __future__ import annotations

import ipaddress

from netsecops.topology.translation import translate


def addr(text: str) -> int:
    return int(ipaddress.IPv4Address(text))


def firewall(*rules: dict, objects: list[dict] | None = None) -> dict:
    return {
        "nat_rules": [{"order": i + 1, **rule} for i, rule in enumerate(rules)],
        "address_objects": objects or [],
    }


class TestDestinationNat:
    """The case that makes a path answerable at all.

    Ask whether the internet reaches a published service and the truth is that the edge
    firewall rewrites the public address to an internal one and routes it inward. A walk
    that does not translate looks the public address up in the inside table, finds
    nothing, and reports "unreachable" about a service that works.
    """

    def test_a_fortigate_vip_rewrites_the_destination(self) -> None:
        # The shape `_parse_vips` emits: literals on both sides, no ambiguity.
        result = translate(
            firewall(
                {
                    "name": "VIP-WEB",
                    "original_destination": ["203.0.113.10"],
                    "translated_destination": ["10.20.0.10"],
                }
            ),
            source=addr("198.51.100.5"),
            destination=addr("203.0.113.10"),
            port=443,
        )

        assert result.applied is True
        assert result.destination == addr("10.20.0.10")
        assert result.detail == "destination 203.0.113.10 → 10.20.0.10"

    def test_a_port_forward_rewrites_the_port_too(self) -> None:
        result = translate(
            firewall(
                {
                    "name": "VIP-WEB-8080",
                    "original_destination": ["203.0.113.10"],
                    "translated_destination": ["10.20.0.10"],
                    "translated_port": 8080,
                }
            ),
            source=addr("198.51.100.5"),
            destination=addr("203.0.113.10"),
            port=443,
        )

        assert result.applied is True
        assert result.port == 8080
        assert "port 443 → 8080" in (result.detail or "")

    def test_a_rule_for_another_address_does_not_apply(self) -> None:
        result = translate(
            firewall(
                {
                    "name": "VIP-MAIL",
                    "original_destination": ["203.0.113.20"],
                    "translated_destination": ["10.20.0.20"],
                }
            ),
            source=addr("198.51.100.5"),
            destination=addr("203.0.113.10"),
            port=443,
        )

        assert result.applied is False
        assert result.reason is None, "a rule that plainly does not match needs no caveat"

    def test_the_source_is_matched_on_as_well_as_the_destination(self) -> None:
        """A rule scoped to one source must not rewrite everybody else's traffic."""
        rules = firewall(
            {
                "name": "PARTNER-ONLY",
                "original_source": ["198.51.100.0/24"],
                "original_destination": ["203.0.113.10"],
                "translated_destination": ["10.20.0.10"],
            }
        )

        partner = translate(
            rules, source=addr("198.51.100.5"), destination=addr("203.0.113.10"), port=443
        )
        stranger = translate(
            rules, source=addr("203.0.113.99"), destination=addr("203.0.113.10"), port=443
        )

        assert partner.applied is True
        assert stranger.applied is False and stranger.reason is None


class TestFirstMatchWins:
    def test_the_first_matching_rule_is_applied_and_the_rest_are_not_consulted(self) -> None:
        """Every platform evaluates NAT first-match. Applying a later rule as well, or
        instead, would translate to an address the device never uses."""
        result = translate(
            firewall(
                {
                    "name": "FIRST",
                    "original_destination": ["203.0.113.10"],
                    "translated_destination": ["10.20.0.10"],
                },
                {
                    "name": "SECOND",
                    "original_destination": ["203.0.113.10"],
                    "translated_destination": ["10.99.99.99"],
                },
            ),
            source=addr("198.51.100.5"),
            destination=addr("203.0.113.10"),
            port=443,
        )

        assert result.rule_name == "FIRST"
        assert result.destination == addr("10.20.0.10")


class TestWhatCannotBeFollowed:
    """The outcome that must not be silently turned into "nothing happened"."""

    def test_a_pool_stops_the_translation_and_says_why(self) -> None:
        result = translate(
            firewall(
                {
                    "name": "OUTBOUND-PAT",
                    "original_source": ["10.10.0.0/24"],
                    "translation_unreadable": (
                        "the source is translated to whatever address ethernet1/1 holds, "
                        "which this rule does not state"
                    ),
                }
            ),
            source=addr("10.10.0.5"),
            destination=addr("8.8.8.8"),
            port=443,
        )

        assert result.applied is False
        assert result.unreadable is True
        assert "ethernet1/1" in (result.reason or "")

    def test_an_unresolvable_object_name_stops_it_rather_than_missing(self) -> None:
        """Check Point writes NAT entirely in object names. A name nothing defines must
        not read as "matches nothing" — that silently skips a rule that may well apply."""
        result = translate(
            firewall(
                {
                    "name": "Hide-Internal",
                    "original_source": ["Internal-Nets"],
                    "translated_source": ["Gateway-External"],
                }
            ),
            source=addr("10.10.0.5"),
            destination=addr("8.8.8.8"),
            port=443,
        )

        assert result.applied is False
        assert result.unreadable is True
        assert "object names" in (result.reason or "")

    def test_a_resolvable_object_name_is_followed(self) -> None:
        result = translate(
            firewall(
                {
                    "name": "Publish-Web",
                    "original_destination": ["Web-Public"],
                    "translated_destination": ["Web-Private"],
                },
                objects=[
                    {"name": "Web-Public", "value": "203.0.113.10"},
                    {"name": "Web-Private", "value": "10.20.0.10"},
                ],
            ),
            source=addr("198.51.100.5"),
            destination=addr("203.0.113.10"),
            port=443,
        )

        assert result.applied is True
        assert result.destination == addr("10.20.0.10")

    def test_translating_to_a_range_is_refused_not_guessed(self) -> None:
        """Which address of a pool a session gets is not something a stored
        configuration can answer, so picking the first would be an invention."""
        result = translate(
            firewall(
                {
                    "name": "POOL",
                    "original_source": ["10.10.0.0/24"],
                    "translated_source": ["203.0.113.0/28"],
                }
            ),
            source=addr("10.10.0.5"),
            destination=addr("8.8.8.8"),
            port=443,
        )

        assert result.applied is False
        assert result.unreadable is True
        assert "not a single address" in (result.reason or "")


class TestRulesWithNothingToSay:
    def test_a_device_with_no_nat_rules_returns_nothing(self) -> None:
        assert translate({}, source=1, destination=2, port=443).applied is False

    def test_a_rule_with_no_normalised_fields_is_skipped_silently(self) -> None:
        """A snapshot taken before the parsers emitted the normalised form. It carries
        nothing to match on, so this says nothing about it — the *walk* counts those
        separately, so a device whose NAT nobody could read still does not look like a
        device with no NAT."""
        result = translate(
            firewall({"name": "legacy", "original": "any", "translated": "interface"}),
            source=addr("10.10.0.5"),
            destination=addr("8.8.8.8"),
            port=443,
        )

        assert result.applied is False
        assert result.reason is None
