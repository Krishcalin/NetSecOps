"""Cisco Firepower via FMC (SRS §1.3, FR-PARSE-01 … FR-PARSE-05).

Three properties of the API carry this file, and each fails silently if missed.

**`MONITOR` is not an action, it is the absence of one.** It logs a match and continues
to the next rule. Mapped to allow the rulebase reads permissive; mapped to deny it reads
restrictive; and mapped to either, a broad monitoring rule at the top of a policy covers
the match space of everything under it and gets reported as shadowing all of them — on a
device where the suggested remedy is deleting live rules.

**Every match field is `{"objects": [...], "literals": [...]}`.** A reader that takes
only `objects` drops every inline address, producing rules whose source is empty and can
never match a packet.

**An absent match field means `any`.** FMC omits `sourceNetworks` on a rule matching
every source, so absence is the *broadest* value. Read as an empty set it turns the most
dangerous rule in a policy into one that appears to match nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netsecops.adapters.policies import get_policy
from netsecops.adapters.profiles import PROFILES
from netsecops.adapters.readonly import ReadOnlyGuard
from netsecops.firewall.model import NON_TERMINATING_ACTIONS
from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURE = Path(__file__).parent / "fixtures" / "cisco" / "fmc" / "7.2" / "bundle.json"


def parse(text: str) -> NormalisedConfig:
    return get_parser("cisco_ftd_fmc").parse(ParseContext(text=text))


@pytest.fixture(scope="module")
def ncm() -> NormalisedConfig:
    return parse(FIXTURE.read_text(encoding="utf-8"))


def rule(ncm: NormalisedConfig, name: str):
    return next(r for r in ncm.firewall.security_rules if r.name == name)


# ──────────────────── the platform is wired up ──────────────────────────


class TestThePlatformIsWired:
    def test_policy_profile_and_parser(self) -> None:
        from netsecops.parsers.registry import PARSERS

        assert get_policy("cisco_ftd_fmc") is not None
        assert "cisco_ftd_fmc" in PROFILES
        assert "cisco_ftd_fmc" in PARSERS

    def test_every_endpoint_it_issues_is_approved(self) -> None:
        guard = ReadOnlyGuard(get_policy("cisco_ftd_fmc"))
        for command in PROFILES["cisco_ftd_fmc"].all_commands():
            method, _, path = command.partition(" ")
            guard.check_request(
                method, path.replace("{domain}", "e276abec").replace("{policy}", "pol-0001")
            )

    def test_the_object_endpoints_are_collected(self) -> None:
        # Not optional. A rule names an address object; without the catalogue that name
        # resolves to the empty set and the rule can never match a packet — which is not
        # an error anybody sees, it is a rulebase that quietly analyses as inert.
        issued = " ".join(PROFILES["cisco_ftd_fmc"].all_commands())
        for objects in ("object/networks", "object/hosts", "object/networkgroups"):
            assert objects in issued


# ─────────────────── MONITOR, which decides nothing ─────────────────────


class TestMonitorIsNotADecision:
    def test_it_is_neither_permit_nor_deny(self, ncm: NormalisedConfig) -> None:
        assert rule(ncm, "monitor-everything").action == "monitor"

    def test_the_model_knows_it_does_not_terminate(self) -> None:
        # The property the shadowing analysis reads. Without it, a broad MONITOR rule
        # covers everything below it and is reported as shadowing all of it.
        assert "monitor" in NON_TERMINATING_ACTIONS

    def test_a_monitor_rule_does_not_shadow_what_follows(self, ncm: NormalisedConfig) -> None:
        from netsecops.firewall.analysis import Relationship, analyse
        from netsecops.firewall.model import resolve_rulebase

        rules, _ = resolve_rulebase(ncm.firewall.model_dump(mode="json"))
        found = analyse(rules)

        # `monitor-everything` matches every packet and is first. Counted as a decision,
        # it covers the match space of every rule after it and each is reported as
        # shadowed — advice to delete rules the device reaches exactly as intended.
        shadowed = {
            relationship.subject.name
            for relationship in found.relationships
            if relationship.kind is Relationship.SHADOWED
        }
        assert found.rules_analysed >= 4, "the rulebase must actually have been analysed"
        assert "allow-dmz-https" not in shadowed
        assert "block-rest" not in shadowed

    def test_and_the_same_rule_as_a_decision_would_shadow_them(
        self, ncm: NormalisedConfig
    ) -> None:
        """Proves the test above is not vacuous.

        The guard is only worth having if the rule it exempts would otherwise be
        reported — so the same rulebase is analysed with `monitor-everything` turned
        into an ordinary permit, and every rule after it must then come back shadowed.
        Without this, a change that stopped the analysis finding *anything* would leave
        the test above green.
        """
        from netsecops.firewall.analysis import Relationship, analyse
        from netsecops.firewall.model import resolve_rulebase

        firewall = ncm.firewall.model_dump(mode="json")
        firewall["security_rules"][0]["action"] = "allow"

        rules, _ = resolve_rulebase(firewall)
        found = analyse(rules)

        shadowed = {
            relationship.subject.name
            for relationship in found.relationships
            if relationship.kind is Relationship.SHADOWED
        }
        assert "block-rest" in shadowed

    def test_trust_permits_like_allow(self, ncm: NormalisedConfig) -> None:
        # `TRUST` passes traffic and skips inspection. For "does traffic pass" it is an
        # allow, and treating it as anything else understates what the policy permits.
        assert rule(ncm, "trust-backup").action == "allow"

    def test_block_with_reset_is_a_reject(self, ncm: NormalisedConfig) -> None:
        assert rule(ncm, "block-rest").action == "reject"

    def test_an_unknown_action_fails_closed(self) -> None:
        # An action Cisco adds after this was written. `permits` is False for anything
        # unrecognised, which is the safe direction — the rule is not reported as
        # allowing traffic on the strength of a name nobody has seen.
        body = {
            "/d/policy/accesspolicies/p/accessrules": {
                "items": [{"name": "future", "action": "QUARANTINE", "enabled": True}]
            }
        }
        ncm = parse(json.dumps(body))
        assert ncm.firewall.security_rules[0].action == "quarantine"


# ───────────────────── objects, literals and any ────────────────────────


class TestMatchFields:
    def test_objects_and_literals_are_both_read(self, ncm: NormalisedConfig) -> None:
        # `192.0.2.50` is typed into the rule rather than made an object. Dropping
        # literals empties the destination and the rule can never match.
        allow = rule(ncm, "allow-dmz-https")
        assert set(allow.dst) == {"net-dmz", "192.0.2.50"}

    def test_a_rule_with_only_literals_is_not_empty(self, ncm: NormalisedConfig) -> None:
        assert rule(ncm, "trust-backup").src == ["10.10.0.9"]

    def test_an_absent_field_means_any_not_nothing(self, ncm: NormalisedConfig) -> None:
        # The most dangerous rule in a policy is the one with no match constraints, and
        # FMC expresses that by omitting the field. Read as empty it looks harmless.
        monitor = rule(ncm, "monitor-everything")
        assert monitor.src == ["any"]
        assert monitor.dst == ["any"]
        assert monitor.services == ["any"]

    def test_zones_come_through(self, ncm: NormalisedConfig) -> None:
        allow = rule(ncm, "allow-dmz-https")
        assert (allow.src_zones, allow.dst_zones) == (["inside"], ["dmz"])

    def test_zones_are_collected_from_the_rules(self, ncm: NormalisedConfig) -> None:
        # FMC has no zone endpoint on this profile, so the zone list is whatever the
        # rules name — and `any` is not a zone.
        assert ncm.firewall.zones == ["dmz", "inside"]


class TestObjects:
    def test_network_and_host_objects(self, ncm: NormalisedConfig) -> None:
        by_name = {o.name: o for o in ncm.firewall.address_objects}
        assert by_name["net-corp"].value == "10.0.0.0/8"
        assert by_name["host-jump"].value == "10.10.0.9"

    def test_a_group_carries_objects_and_literals(self, ncm: NormalisedConfig) -> None:
        group = next(g for g in ncm.firewall.address_groups if g.name == "grp-internal")
        assert set(group.members) == {"net-corp", "host-jump", "172.16.0.0/12"}

    def test_port_objects_become_services(self, ncm: NormalisedConfig) -> None:
        by_name = {o.name: o for o in ncm.firewall.service_objects}
        assert by_name["HTTPS"].value == "TCP/443"


# ──────────────────────── the rest of the rule ──────────────────────────


class TestRuleDetail:
    def test_order_is_preserved(self, ncm: NormalisedConfig) -> None:
        assert [r.name for r in ncm.firewall.security_rules] == [
            "monitor-everything",
            "allow-dmz-https",
            "trust-backup",
            "legacy-disabled",
            "block-rest",
        ]

    def test_a_disabled_rule_is_disabled_not_missing(self, ncm: NormalisedConfig) -> None:
        assert rule(ncm, "legacy-disabled").enabled is False
        assert rule(ncm, "allow-dmz-https").enabled is True

    def test_the_rulebase_is_the_access_policy(self, ncm: NormalisedConfig) -> None:
        # Entries in different access policies are never applied to the same packet, so
        # the shadowing analysis must not compare across them.
        assert {r.rulebase for r in ncm.firewall.security_rules} == {"pol-0001"}

    def test_logging_flags(self, ncm: NormalisedConfig) -> None:
        allow = rule(ncm, "allow-dmz-https")
        assert (allow.log_start, allow.log_end) == (False, True)

    def test_inspection_profiles_are_carried(self, ncm: NormalisedConfig) -> None:
        # A rule that permits without an IPS or file policy is a different finding from
        # one that permits with both, and the difference is invisible without these.
        allow = rule(ncm, "allow-dmz-https")
        assert allow.profiles["ips"] == "Balanced Security and Connectivity"
        assert allow.profiles["file"] == "Block Malware"

    def test_a_rule_with_no_inspection_says_so(self, ncm: NormalisedConfig) -> None:
        assert rule(ncm, "trust-backup").profiles == {}


class TestTheAppliance:
    def test_the_fmc_version(self, ncm: NormalisedConfig) -> None:
        assert ncm.device.version == "7.2.5 (build 208)"

    def test_the_managed_sensor(self, ncm: NormalisedConfig) -> None:
        assert ncm.device.model == "Cisco Firepower 2130 Threat Defense"
        assert ncm.device.hostname == "ftd-edge-01.corp.example.net"


class TestRobustness:
    def test_invalid_json_is_a_parse_failure(self) -> None:
        assert parse("{not json").parse_failed is True

    def test_an_empty_bundle_is_a_parse_failure(self) -> None:
        # Nothing collected. Reporting it as an FMC with no rules would render the most
        # restrictive policy imaginable out of an empty file.
        assert parse("{}").parse_failed is True

    def test_an_endpoint_nothing_reads_is_reported(self, ncm: NormalisedConfig) -> None:
        assert any("intrusionpolicies" in line for line in ncm.raw_unparsed)

    def test_the_endpoints_it_reads_are_not_reported_as_gaps(self, ncm: NormalisedConfig) -> None:
        joined = "\n".join(ncm.raw_unparsed)
        assert "accessrules" not in joined
        assert "object/networks" not in joined
