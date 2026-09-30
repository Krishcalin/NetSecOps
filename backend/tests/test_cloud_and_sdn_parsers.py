"""NSX, ACI, AWS and Azure — the four platforms read from an export (SRS §1.3).

**None of these has a collection profile and that is the design, not a gap.** Each needs
a credential type and a transport this product does not have, and a parser wired to a
collector that does not exist is the capability-with-no-surface pattern
`test_unconsumed_capability` was written to find. They are ingested through FR-COL-11 —
somebody exports the JSON and uploads it — which is how a read-restricted cloud or
vSphere estate was always going to be assessed.

**They are all flattened into `security_rules`, and the flattening is where the lies
would be.** Every engine in this product reads that shape, so a distributed firewall, a
contract graph and two cloud security models all have to arrive as rules. Each one loses
something in the process, and the tests below are mostly about making sure what is lost
is the harmless part:

* **ACI has no order at all.** The fabric is default-deny and a contract permits; no two
  contracts precede one another.
* **AWS has no order and no deny.** Every rule in every applicable group is evaluated,
  and a security group can only permit.
* **Azure has a real order**, by priority, per direction — so precedence analysis is
  meaningful there and nowhere else here.
* **NSX has a two-level order**: policy sequence, then rule sequence within it.

Getting any of those wrong produces a confident precedence analysis about a rulebase
that does not exist.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netsecops.adapters.policies import POLICIES, get_policy
from netsecops.adapters.profiles import PROFILES
from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import PARSERS, get_parser

FIXTURES = Path(__file__).parent / "fixtures"

OFFLINE_PLATFORMS = ("vmware_nsx", "cisco_aci", "aws_vpc", "azure_nsg")


def parse(platform: str, relative: str) -> NormalisedConfig:
    text = (FIXTURES / relative).read_text(encoding="utf-8")
    return get_parser(platform).parse(ParseContext(text=text))


def parse_text(platform: str, text: str) -> NormalisedConfig:
    return get_parser(platform).parse(ParseContext(text=text))


@pytest.fixture(scope="module")
def nsx() -> NormalisedConfig:
    return parse("vmware_nsx", "vmware/nsx/4.1/export.json")


@pytest.fixture(scope="module")
def aci() -> NormalisedConfig:
    return parse("cisco_aci", "cisco/aci/5.2/export.json")


@pytest.fixture(scope="module")
def aws() -> NormalisedConfig:
    return parse("aws_vpc", "cloud/aws/2026/describe_security_groups.json")


@pytest.fixture(scope="module")
def azure() -> NormalisedConfig:
    return parse("azure_nsg", "cloud/azure/2026/nsg_list.json")


def named(ncm: NormalisedConfig, fragment: str):
    return next(r for r in ncm.firewall.security_rules if fragment in (r.name or ""))


# ───────────────── the shared position: export, not collect ─────────────


class TestTheyAreReadFromAnExport:
    @pytest.mark.parametrize("platform", OFFLINE_PLATFORMS)
    def test_each_has_a_policy_and_a_parser(self, platform: str) -> None:
        assert platform in POLICIES
        assert platform in PARSERS

    @pytest.mark.parametrize("platform", OFFLINE_PLATFORMS)
    def test_and_deliberately_no_collection_profile(self, platform: str) -> None:
        # The design. A profile implies a collector, and the collector needs a credential
        # type this product does not have — so the profile arrives in that slice, not
        # this one.
        assert platform not in PROFILES

    @pytest.mark.parametrize("platform", ("aws_vpc", "azure_nsg"))
    def test_the_cloud_allow_lists_are_empty(self, platform: str) -> None:
        # Not an omission — a statement. NetSecOps holds no cloud credential and has no
        # rule for `check_request` to match, so it cannot send these platforms anything
        # at all. That is a stronger guarantee than "we only send reads".
        policy = get_policy(platform)
        assert policy.commands == ()
        assert policy.http == ()

    @pytest.mark.parametrize("platform", ("vmware_nsx", "cisco_aci"))
    def test_the_api_allow_lists_permit_only_reads(self, platform: str) -> None:
        # These two will get a collector eventually, so their contract is written now
        # and a reviewer can read it before any code can act on it.
        policy = get_policy(platform)
        posts = [rule for rule in policy.http if rule.method == "POST"]
        assert all(rule.body_predicate == "auth_only" for rule in posts)
        assert all(rule.reason for rule in posts)

    @pytest.mark.parametrize("platform", OFFLINE_PLATFORMS)
    def test_onboarding_one_is_allowed_because_an_upload_can_assess_it(
        self, platform: str
    ) -> None:
        # `_validate_platform` refuses a platform nothing can read. A parser is now a
        # third way to be readable, because FR-COL-11 gained supporting captures — and
        # without that these four would be un-onboardable.
        from netsecops.adapters.children import INTERPRETERS

        usable = set(PROFILES) | set(INTERPRETERS) | set(PARSERS)
        assert platform in usable

    def test_the_externally_resolved_exemption_stays_narrow(self) -> None:
        """`test_silent_emptiness` exempts objects whose membership is not in the export.

        That exemption is the one thing in this slice that could hide a real defect, so
        it is bounded here: **no platform with a configuration file may use those
        types.** A Cisco or Juniper object that resolves to nothing is a parser bug, and
        must not become exempt by someone reaching for a convenient type string.
        """
        from tests.test_silent_emptiness import CASES, EXTERNALLY_RESOLVED, parse

        for relative, platform in CASES:
            if platform in OFFLINE_PLATFORMS:
                continue
            firewall = parse(relative, platform).firewall.model_dump(mode="json")
            used = {
                str(obj.get("type"))
                for kind in ("address_objects", "address_groups", "service_objects")
                for obj in firewall.get(kind) or []
            }
            assert not (used & EXTERNALLY_RESOLVED), (
                f"{relative} uses an externally-resolved object type; those are for "
                "platforms read from an export, where membership genuinely lives "
                "elsewhere"
            )

    @pytest.mark.parametrize("platform", ("aws_vpc", "azure_nsg", "vmware_nsx"))
    def test_each_export_platform_actually_sets_one(self, platform: str) -> None:
        # The other half: if a parser stopped typing these, the exemption above would
        # silently start covering nothing and this slice's own objects would fail the
        # sweep instead.
        from tests.test_silent_emptiness import EXTERNALLY_RESOLVED

        fixture = {
            "aws_vpc": "cloud/aws/2026/describe_security_groups.json",
            "azure_nsg": "cloud/azure/2026/nsg_list.json",
            "vmware_nsx": "vmware/nsx/4.1/export.json",
        }[platform]
        firewall = parse(platform, fixture).firewall.model_dump(mode="json")
        used = {
            str(obj.get("type"))
            for kind in ("address_objects", "address_groups")
            for obj in firewall.get(kind) or []
        }
        assert used & EXTERNALLY_RESOLVED

    @pytest.mark.parametrize("platform", OFFLINE_PLATFORMS)
    def test_an_empty_export_is_a_parse_failure(self, platform: str) -> None:
        # Not "a fabric with no rules". An empty file must never render as the most
        # restrictive policy imaginable.
        assert parse_text(platform, "{}").parse_failed is True

    @pytest.mark.parametrize("platform", OFFLINE_PLATFORMS)
    def test_invalid_json_is_a_parse_failure(self, platform: str) -> None:
        assert parse_text(platform, "{not json").parse_failed is True


# ──────────────────────────── VMware NSX ────────────────────────────────


class TestNsx:
    def test_the_two_level_order_is_policy_then_rule(self, nsx: NormalisedConfig) -> None:
        # `emergency` has sequence 10 and `app-tier` has 20, so emergency's rules come
        # first — even though app-tier's rules have lower numbers of their own. Sorting
        # by rule number alone interleaves the two and produces a precedence analysis
        # about a rulebase that does not exist.
        assert [r.name for r in nsx.firewall.security_rules] == [
            "observe-all",
            "quarantine",
            "web-to-db",
            "deny-app",
        ]

    def test_each_policy_is_its_own_rulebase(self, nsx: NormalisedConfig) -> None:
        # Two policies are separate ordered sections, like two ASA access lists.
        assert {r.rulebase for r in nsx.firewall.security_rules} == {"emergency", "app-tier"}

    def test_a_group_path_is_reduced_to_its_name(self, nsx: NormalisedConfig) -> None:
        # `/infra/domains/default/groups/web-servers` is how a rule refers to a group;
        # `web-servers` is how the group is catalogued. Compared unstripped every member
        # resolves to nothing.
        assert named(nsx, "web-to-db").src == ["web-servers"]
        assert any(g.name == "web-servers" for g in nsx.firewall.address_groups)

    def test_an_empty_match_list_is_any_not_nothing(self, nsx: NormalisedConfig) -> None:
        # `observe-all` has `"source_groups": []`. Read literally that is a rule which
        # can never match; NSX means every address.
        observe = named(nsx, "observe-all")
        assert observe.src == ["any"]
        assert observe.services == ["any"]

    def test_the_literal_any_is_normalised_too(self, nsx: NormalisedConfig) -> None:
        assert named(nsx, "deny-app").src == ["any"]

    def test_jump_to_application_is_non_terminating(self, nsx: NormalisedConfig) -> None:
        # Same shape as Firepower's MONITOR: it hands the packet on and decides nothing,
        # so it must not shadow what follows.
        from netsecops.firewall.model import NON_TERMINATING_ACTIONS

        assert named(nsx, "observe-all").action in NON_TERMINATING_ACTIONS

    def test_a_disabled_rule_is_disabled_not_missing(self, nsx: NormalisedConfig) -> None:
        assert named(nsx, "quarantine").enabled is False
        assert named(nsx, "web-to-db").enabled is True

    def test_a_dynamic_group_is_marked_rather_than_emptied(self, nsx: NormalisedConfig) -> None:
        # Its membership is computed by the manager from live VM state and is not in the
        # configuration. Reporting no members would say the rule matches nothing when it
        # may match hundreds of workloads.
        group = next(g for g in nsx.firewall.address_groups if g.name == "prod-tagged")
        assert group.type == "dynamic-group"
        assert group.members == []

    def test_a_mixed_static_and_dynamic_group_is_still_dynamic(self) -> None:
        """A group with static members AND a tag condition is still dynamic: its true
        membership also includes whatever carries the tag, which is not in the export.
        Typing it a plain 'group' made the static members look like the complete set, so a
        rule using it silently excluded everything the tag matches (2026-09-30 audit,
        invariant 2). It is typed dynamic-group (externally resolved); the static members
        are still recorded as a partial view."""
        bundle = {
            "policy/api/v1/infra/domains/default/groups": {
                "results": [
                    {
                        "display_name": "web-mixed",
                        "id": "web-mixed",
                        "expression": [
                            {
                                "resource_type": "IPAddressExpression",
                                "ip_addresses": ["10.0.0.5"],
                            },
                            {"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"},
                            {"resource_type": "Condition", "key": "Tag", "value": "web"},
                        ],
                    }
                ]
            }
        }
        ncm = parse_text("vmware_nsx", json.dumps(bundle))
        group = next(g for g in ncm.firewall.address_groups if g.name == "web-mixed")
        assert group.type == "dynamic-group"
        assert "10.0.0.5" in group.members

    def test_static_group_members(self, nsx: NormalisedConfig) -> None:
        group = next(g for g in nsx.firewall.address_groups if g.name == "web-servers")
        assert group.members == ["10.20.0.0/24"]

    def test_the_manager_version(self, nsx: NormalisedConfig) -> None:
        assert nsx.device.version == "4.1.2.3.0"


# ───────────────────────────── Cisco ACI ────────────────────────────────


class TestAci:
    def test_a_contract_becomes_one_rule_per_consumer_provider_pair(
        self, aci: NormalisedConfig
    ) -> None:
        # A contract on its own permits nothing. Connectivity exists where one EPG
        # consumes it and another provides it, so the rule is the pair.
        rule = named(aci, "web-to-db")
        assert (rule.src, rule.dst) == (["Web"], ["Db"])

    def test_a_contract_with_no_consumer_produces_no_rule(self, aci: NormalisedConfig) -> None:
        # `orphan-contract` is provided and consumed by nobody. It permits nothing, and
        # counting it as a rule would report connectivity the fabric does not have.
        assert not any("orphan" in (r.name or "") for r in aci.firewall.security_rules)

    def test_the_filter_supplies_the_ports(self, aci: NormalisedConfig) -> None:
        # Without the filters every rule's service set is empty and can never match.
        assert named(aci, "web-to-db").services == ["tcp/3306"]

    def test_everything_shares_one_rulebase(self, aci: NormalisedConfig) -> None:
        # ACI evaluates no sequence, so no two rules precede one another. One shared
        # rulebase keeps overlap detection working without inventing precedence.
        assert {r.rulebase for r in aci.firewall.security_rules} == {"aci-contracts"}

    def test_every_rule_permits(self, aci: NormalisedConfig) -> None:
        # The fabric is default-deny and a contract exists to permit. There is no deny
        # contract, so a parser emitting one would be inventing a construct.
        assert {r.action for r in aci.firewall.security_rules} == {"allow"}

    def test_a_bidirectional_subject_is_recorded(self, aci: NormalisedConfig) -> None:
        # `revFltPorts` permits the return traffic implicitly. Ignored, half the
        # fabric's real connectivity goes unreported.
        assert named(aci, "web-to-db").profiles["bidirectional"] == "yes"

    def test_an_epg_carries_its_bridge_domain_subnets(self, aci: NormalisedConfig) -> None:
        group = next(g for g in aci.firewall.address_groups if g.name == "Web")
        assert group.members == ["10.20.0.1/24"]

    def test_an_epg_with_no_subnet_is_marked_rather_than_empty(
        self, aci: NormalisedConfig
    ) -> None:
        # An L2-only EPG has no gateway. "No members" and "membership not knowable from
        # this export" are different facts.
        group = next(g for g in aci.firewall.address_groups if g.name == "L2Only")
        assert group.type == "epg-no-subnet"

    def test_the_tenant_is_carried(self, aci: NormalisedConfig) -> None:
        # Contracts in different tenants govern different traffic and a name alone
        # collides across them.
        assert named(aci, "web-to-db").profiles["tenant"] == "Production"

    def test_the_apic_version(self, aci: NormalisedConfig) -> None:
        assert aci.device.version == "5.2(7f)"


# ──────────────────────────────── AWS ───────────────────────────────────


class TestAws:
    def test_direction_is_carried_because_the_field_name_holds_it(
        self, aws: NormalisedConfig
    ) -> None:
        # `IpPermissions` is ingress and `IpPermissionsEgress` is egress, and the objects
        # inside them are identical. Parsed without the direction every egress rule looks
        # like an ingress one.
        directions = {r.profiles.get("direction") for r in aws.firewall.security_rules}
        assert directions == {"ingress", "egress"}

    def test_an_ingress_rule_points_at_its_own_group(self, aws: NormalisedConfig) -> None:
        ingress = next(
            r for r in aws.firewall.security_rules if r.profiles.get("direction") == "ingress"
        )
        assert ingress.dst == ["sg-0aaa1111"]

    def test_an_egress_rule_is_the_other_way_round(self, aws: NormalisedConfig) -> None:
        egress = next(
            r for r in aws.firewall.security_rules if r.profiles.get("direction") == "egress"
        )
        assert egress.src == ["sg-0aaa1111"]

    def test_protocol_minus_one_is_every_protocol_and_every_port(
        self, aws: NormalisedConfig
    ) -> None:
        # `-1` with no port fields. Read literally it is protocol minus-one on no ports,
        # which matches nothing — turning the most permissive rule AWS can express into
        # one that appears inert.
        egress = next(
            r for r in aws.firewall.security_rules if r.profiles.get("direction") == "egress"
        )
        assert egress.services == ["any"]

    def test_a_group_to_group_rule_is_not_dropped(self, aws: NormalisedConfig) -> None:
        # Reading only `IpRanges` — the obvious field — drops every group-to-group rule,
        # which is how a well-built VPC does most of its work.
        rules = [r for r in aws.firewall.security_rules if "sg-0aaa1111" in r.src]
        assert any(r.services == ["tcp/3306"] for r in rules)

    def test_ipv4_and_ipv6_sources_are_both_read(self, aws: NormalisedConfig) -> None:
        https = next(r for r in aws.firewall.security_rules if r.services == ["tcp/443"])
        assert set(https.src) == {"0.0.0.0/0", "::/0"}

    def test_the_full_port_range_is_normalised(self, aws: NormalisedConfig) -> None:
        # `0-65535` is every port, and several exports write it out in full.
        assert any(r.services == ["tcp/any"] for r in aws.firewall.security_rules)

    def test_every_rule_permits(self, aws: NormalisedConfig) -> None:
        # A security group can only permit; there is no deny form. A group with no rules
        # permits nothing rather than denying everything.
        assert {r.action for r in aws.firewall.security_rules} == {"allow"}

    def test_a_group_with_no_rules_contributes_none(self, aws: NormalisedConfig) -> None:
        assert not any(r.profiles.get("group") == "sg-0ccc3333" for r in aws.firewall.security_rules)

    def test_the_group_itself_is_an_object(self, aws: NormalisedConfig) -> None:
        # So a rule naming another group as its source resolves to something.
        assert any(g.name == "sg-0aaa1111" for g in aws.firewall.address_groups)

    def test_vpcs_become_zones(self, aws: NormalisedConfig) -> None:
        assert set(aws.firewall.zones) == {"vpc-01234567", "vpc-89abcdef"}

    def test_a_bare_list_export_is_accepted(self) -> None:
        # `aws ec2 describe-security-groups --query 'SecurityGroups'` emits one.
        body = [{"GroupId": "sg-1", "GroupName": "x", "IpPermissions": [], "IpPermissionsEgress": []}]
        assert parse_text("aws_vpc", json.dumps(body)).parse_failed is False


# ─────────────────────────────── Azure ──────────────────────────────────


class TestAzure:
    def test_rules_are_sorted_by_priority(self, azure: NormalisedConfig) -> None:
        # Azure is first-match by priority, and the analysis is a statement about
        # evaluation order — the JSON's order is whatever ARM felt like.
        inbound = [
            r for r in azure.firewall.security_rules if r.profiles.get("direction") == "inbound"
        ]
        assert [r.name for r in inbound] == [
            "allow-mgmt",
            "allow-https",
            "AllowVnetInBound",
            "DenyAllInBound",
        ]

    def test_direction_splits_the_rulebase(self, azure: NormalisedConfig) -> None:
        # Inbound and outbound are evaluated independently, so an inbound rule cannot
        # shadow an outbound one.
        assert {r.rulebase for r in azure.firewall.security_rules} == {
            "nsg-web/inbound",
            "nsg-web/outbound",
        }

    def test_the_default_rules_are_included(self, azure: NormalisedConfig) -> None:
        # The last of them is `DenyAllInBound`. Without it the NSG reads as having no
        # catch-all, and every permissiveness check that looks for one reports a finding
        # that is not true.
        names = {r.name for r in azure.firewall.security_rules}
        assert "DenyAllInBound" in names
        assert "DenyAllOutBound" in names

    def test_the_plural_field_is_read(self, azure: NormalisedConfig) -> None:
        # Azure populates exactly one of `sourceAddressPrefix` and the plural form. A
        # reader checking only the singular drops every multi-prefix rule, silently.
        mgmt = named(azure, "allow-mgmt")
        assert mgmt.src == ["10.10.0.0/24", "10.11.0.0/24"]
        assert set(mgmt.services) == {"tcp/22", "tcp/3389"}

    def test_a_star_prefix_becomes_any(self, azure: NormalisedConfig) -> None:
        assert named(azure, "allow-https").dst == ["any"]

    def test_a_service_tag_is_not_flattened_into_any(self, azure: NormalisedConfig) -> None:
        # `Internet` means everything outside the virtual network; `*` means everything.
        # Both are wide, only one is unbounded, and the difference matters on an inbound
        # rule.
        assert named(azure, "allow-https").src == ["Internet"]

    def test_access_maps_to_the_ncm_vocabulary(self, azure: NormalisedConfig) -> None:
        assert named(azure, "allow-https").action == "allow"
        assert named(azure, "deny-db-out").action == "deny"

    def test_the_priority_is_kept(self, azure: NormalisedConfig) -> None:
        assert named(azure, "allow-mgmt").profiles["priority"] == "100"

    def test_an_arm_wrapped_export_is_accepted(self) -> None:
        body = {"value": [{"name": "nsg-1", "properties": {"securityRules": []}}]}
        assert parse_text("azure_nsg", json.dumps(body)).parse_failed is False
