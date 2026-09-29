"""Rules that can neither be matched nor excluded (FR-FW-06, FR-TOPO-04).

Four of the platforms onboarded in September 2026 carry objects whose membership is not
in the configuration and never will be: an AWS security group stands for the instances
attached to it, an NSX dynamic group for whatever currently carries a tag, an Azure
service tag for prefixes Microsoft publishes, an ACI L2-only EPG for a bridge domain
with no gateway.

**Before 2026-09-29 a rule using one was treated as a rule that does not match.** Its
address set resolved to empty, `covers_value` returned False, and the query moved on to
the next rule — or, when nothing else matched, to the implicit deny. So a path query
across a cloud rulebase came back `blocked`, confidently, on the strength of never
having read the rule that decides. That is the dangerous direction: a reader concludes
an exposure is closed when nothing established that it is.

The property these tests defend is that such a rule is a *third state* — not a match,
not a miss — and that the third state reaches the operator instead of being rounded to
one of the other two.

They also defend the other half, which is what keeps the first half usable: a rule
excluded on a side that *did* resolve is still a plain miss. Without that, every query
against an AWS rulebase would return "cannot evaluate", and a caveat that fires on
everything is a caveat nobody reads.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from netsecops.firewall.analysis import first_match, first_match_over_range
from netsecops.firewall.intervals import parse_address
from netsecops.firewall.model import EXTERNALLY_RESOLVED_TYPES, resolve_rulebase
from netsecops.topology.graph import build_graph
from netsecops.topology.path import PolicyVerdict, RoutingConfidence, walk
from tests.test_topology import address, connected, node, static


def cloud_rulebase(*, src_type: str = "security-group") -> dict[str, Any]:
    """A rulebase whose deciding rule names an object nothing can expand.

    Deliberately the *first* rule: first match wins, so a rule that cannot be read ahead
    of everything else is the case where reading the rest tells you nothing.
    """
    return {
        "address_objects": [
            {"name": "sg-web", "type": src_type},
            {"name": "db-subnet", "type": "subnet", "value": "10.20.0.0/24"},
        ],
        "service_objects": [{"name": "https", "type": "tcp", "value": "443"}],
        "security_rules": [
            {
                "order": 1,
                "name": "web-to-db",
                "action": "allow",
                "src": ["sg-web"],
                "dst": ["db-subnet"],
                "services": ["https"],
            }
        ],
    }


# ════════════════════ the resolver knows why it failed ═══════════════════════


class TestTheReasonIsRecordedNotJustTheFailure:
    """ "Missing" and "not expandable" need different remedies.

    One is fixed by re-collecting the device or fixing a parser. The other is fixed by
    nothing this product can do, because the membership is held by a control plane it
    does not talk to. Telling an operator to re-collect a device that will never yield
    the answer wastes their afternoon and costs them their attention next time.

    The same distinction §3.8a draws between `partially-routed` and `unknown`.
    """

    def test_an_external_object_is_marked_as_such(self) -> None:
        rules, resolver = resolve_rulebase(cloud_rulebase())

        assert resolver.externally_resolved == {"sg-web"}
        assert rules[0].externally_resolved == ("sg-web",)

    def test_an_object_the_collection_missed_is_not(self) -> None:
        firewall = {
            "security_rules": [
                {"order": 1, "name": "r", "action": "allow", "src": ["never-defined"]}
            ]
        }
        rules, resolver = resolve_rulebase(firewall)

        assert rules[0].unresolved == ("never-defined",)
        assert resolver.externally_resolved == set(), "this one a re-collection could fix"

    def test_the_message_says_where_the_membership_lives(self) -> None:
        _, resolver = resolve_rulebase(cloud_rulebase())

        note = next(iter(resolver.unresolved))
        assert "security-group" in note
        assert "control plane" in note

    @pytest.mark.parametrize("kind", sorted(EXTERNALLY_RESOLVED_TYPES))
    def test_every_declared_type_is_handled(self, kind: str) -> None:
        """The set is the product's, not the test suite's.

        It lived only in `test_silent_emptiness.py` until 2026-09-29, which meant the
        product could not act on a distinction its own tests enforced.
        """
        rules, resolver = resolve_rulebase(cloud_rulebase(src_type=kind))

        assert resolver.externally_resolved == {"sg-web"}
        assert rules[0].externally_resolved == ("sg-web",)

    def test_which_side_of_the_rule_it_was_on_is_kept(self) -> None:
        """Without this the query cannot tell an open question from a closed one."""
        rules, _ = resolve_rulebase(cloud_rulebase())

        assert rules[0].unresolved_src == ("sg-web",)
        assert rules[0].unresolved_dst == ()
        assert rules[0].unresolved_svc == ()

    def test_the_flat_list_still_reads_the_same(self) -> None:
        """`unresolved` has consumers — the hygiene check, the API, permissiveness."""
        rules, _ = resolve_rulebase(cloud_rulebase())

        assert rules[0].unresolved == ("sg-web",)


# ═══════════════════ the query reports the third state ═══════════════════════


class TestTheQueryWillNotGuess:
    def query(self, rules, *, port: int = 443, dst: str = "10.20.0.10"):
        return first_match(
            rules,
            source=address("10.10.0.5"),
            destination=address(dst),
            protocol=6,
            port=port,
        )

    def test_the_unreadable_rule_is_reported(self) -> None:
        rules, _ = resolve_rulebase(cloud_rulebase())

        result = self.query(rules)

        assert [rule.name for rule in result.undecidable] == ["web-to-db"]
        assert not result.decided

    def test_it_is_not_reported_as_a_match(self) -> None:
        """Claiming it decided would be as unfounded as ignoring it.

        We do not know that the packet is in `sg-web`; we know only that we cannot tell.
        """
        rules, _ = resolve_rulebase(cloud_rulebase())

        assert self.query(rules).matched is None

    def test_a_rule_excluded_on_a_readable_side_is_a_plain_miss(self) -> None:
        """The tightening that keeps the caveat meaningful.

        This rule's source is just as unreadable, but its service is tcp/443 and the
        query asks about 22. Whatever `sg-web` contains, this rule cannot match — so
        there is no open question and no caveat.
        """
        rules, _ = resolve_rulebase(cloud_rulebase())

        result = self.query(rules, port=22)

        assert result.undecidable == ()
        assert result.decided, "a definite miss is still a definite answer"

    def test_likewise_for_the_destination(self) -> None:
        rules, _ = resolve_rulebase(cloud_rulebase())

        assert self.query(rules, dst="192.0.2.10").undecidable == ()

    def test_a_readable_rule_ahead_of_it_still_decides(self) -> None:
        """First match wins, so an unreadable rule *after* the answer changes nothing.

        The packet never reaches it whatever it contains, and collecting it would put a
        caveat on an answer that is not in doubt.
        """
        firewall = cloud_rulebase()
        firewall["security_rules"].insert(
            0,
            {
                "order": 0,
                "name": "deny-first",
                "action": "deny",
                "dst": ["db-subnet"],
                "services": ["https"],
            },
        )
        rules, _ = resolve_rulebase(firewall)

        result = self.query(rules)

        assert result.matched is not None and result.matched.name == "deny-first"
        assert result.undecidable == (), "it sits behind a rule that already decided"
        assert result.decided

    def test_a_range_query_reports_it_too(self) -> None:
        rules, _ = resolve_rulebase(cloud_rulebase())

        src, _ = parse_address("10.10.0.0/24")
        dst, _ = parse_address("10.20.0.0/24")

        verdict = first_match_over_range(rules, source=src, destination=dst, protocol=6, port=443)

        assert [rule.name for rule in verdict.undecidable] == ["web-to-db"]
        assert not verdict.decided


# ═════════════════ and the path answer carries it to the reader ══════════════


class TestThePathAnswerDoesNotClaimBlocked:
    """The failure this whole change exists for.

    A firewall whose deciding rule cannot be read used to produce `blocked` — the packet
    matched nothing, so the implicit deny "decided" it. An operator reads that as "this
    traffic cannot get through" and closes the ticket.
    """

    def _estate(self, firewall: dict[str, Any], downstream: dict[str, Any] | None = None):
        devices = [
            node(
                "edge-fw",
                routes=[
                    connected("10.10.0.0/24", "lan"),
                    static("10.20.0.0/24", "10.0.1.2", "dmz"),
                ],
                addresses={"lan": "10.10.0.1/24", "dmz": "10.0.1.1/30"},
                firewall=firewall,
            ),
            node(
                "dmz-sw",
                routes=[connected("10.20.0.0/24", "vlan20"), connected("10.0.1.0/30", "up")],
                addresses={"up": "10.0.1.2/30", "vlan20": "10.20.0.1/24"},
                firewall=downstream,
            ),
        ]
        return build_graph(devices)

    def result(self, firewall: dict[str, Any], downstream: dict[str, Any] | None = None):
        return walk(
            self._estate(firewall, downstream),
            source="10.10.0.5",
            destination="10.20.0.10",
            protocol="tcp",
            port=443,
        )

    def test_it_is_not_blocked(self) -> None:
        result = self.result(cloud_rulebase())

        assert result.policy is not PolicyVerdict.BLOCKED

    def test_nor_is_it_allowed(self) -> None:
        """Both directions are wrong. The honest answer is that it is not settled."""
        result = self.result(cloud_rulebase())

        assert result.policy is PolicyVerdict.PARTIALLY_ALLOWED

    def test_the_routing_axis_is_untouched(self) -> None:
        """The two axes fail independently — the path was traced perfectly well."""
        assert self.result(cloud_rulebase()).routing is RoutingConfidence.ROUTED

    def test_the_hop_says_it_could_not_answer(self) -> None:
        result = self.result(cloud_rulebase())

        hop = next(hop for hop in result.hops if hop.hostname == "edge-fw")
        assert hop.undecidable is True
        assert hop.action is None, "not a permit, and not a denial"

    def test_the_hop_is_distinguishable_from_a_router(self) -> None:
        """Both carry `action is None`; only one of them is a firewall we could not read.

        Collapsing them is how "no device on this path carries a firewall rulebase, so
        nothing inspected the traffic" gets printed over a firewall that inspected it.
        """
        result = self.result(cloud_rulebase())

        by_name = {hop.hostname: hop for hop in result.hops}
        assert by_name["edge-fw"].undecidable is True
        assert by_name["dmz-sw"].undecidable is False
        assert by_name["dmz-sw"].action is None

    def test_the_note_names_the_device_and_the_rule(self) -> None:
        result = self.result(cloud_rulebase())

        prose = " ".join(result.notes) + " ".join(
            note for hop in result.hops for note in hop.limitations
        )
        assert "edge-fw" in prose
        assert "web-to-db" in prose

    def test_the_note_says_which_remedy_applies(self) -> None:
        """An operator must not be sent to re-collect a device that cannot help."""
        result = self.result(cloud_rulebase())

        caveats = " ".join(note for hop in result.hops for note in hop.limitations)
        assert "sg-web" in caveats
        assert "no configuration contains" in caveats or "cannot be resolved" in caveats

    def test_a_readable_rulebase_still_answers_plainly(self) -> None:
        """The guard against this caveat becoming background noise."""
        readable = {"security_rules": [{"order": 1, "name": "permit-any", "action": "allow"}]}
        result = self.result(readable)

        assert result.policy is PolicyVerdict.ALLOWED
        assert not any(hop.undecidable for hop in result.hops)

    def test_a_definite_denial_on_another_device_still_stands(self) -> None:
        """A block is definitive, and that asymmetry survives this change.

        If the unreadable rule permits, the packet reaches the next device and dies
        there. If it denies, it dies sooner. Either way it does not get through, so
        `blocked` is the honest answer and hedging it would be a different lie.
        """
        downstream = {"security_rules": [{"order": 1, "name": "deny-all", "action": "deny"}]}

        result = self.result(cloud_rulebase(), downstream)

        assert result.policy is PolicyVerdict.BLOCKED

    def test_a_later_rule_on_the_same_device_does_not_rescue_the_answer(self) -> None:
        """The case I first got wrong, kept because the mistake is an easy one.

        A deny *below* the unreadable rule looks like the same situation and is not:
        first match wins, so if the unreadable rule permits, the packet is allowed here
        and the deny below it is never reached. The outcome is genuinely either — which
        is what undecidable means, and treating this as a definite block would be the
        original defect in a new place.
        """
        firewall = cloud_rulebase()
        firewall["security_rules"].append({"order": 9, "name": "deny-all", "action": "deny"})

        result = self.result(firewall)

        assert result.policy is PolicyVerdict.PARTIALLY_ALLOWED
        assert any(hop.undecidable for hop in result.hops)


class TestTheApiCarriesIt:
    """Capability with no surface is this codebase's named defect.

    `action` is None for an unreadable firewall and for a plain router alike, so without
    this field on the wire the console cannot draw the difference however carefully the
    engine computes it.
    """

    def test_the_hop_schema_has_the_flag(self) -> None:
        from netsecops.schemas.topology import HopRead

        assert "undecidable" in HopRead.model_fields

    def test_it_defaults_to_false(self) -> None:
        from netsecops.schemas.topology import HopRead

        hop = HopRead(device_id=uuid.uuid4(), hostname="rtr")
        assert hop.undecidable is False
