"""Check Point parsers (FR-PARSE-01 … FR-PARSE-05, FR-FW-01, FR-FW-03).

Check Point is the first vendor here that does not keep its security policy on the
device enforcing it. The policy lives on a management server and is read over its API;
the gateway holds only the Gaia operating system. That split is why there are two
parsers, and it is the thing most likely to be got wrong — a Gaia gateway assessed on
its own genuinely cannot answer any firewall question, and must report *Not Evaluated*
rather than passing for having no bad rules.

Four behaviours here have no equivalent in the other parsers, and each would be a
security-relevant defect if it silently regressed:

- **Negation.** `source-negate: true` means "everything except this". Ignoring the flag
  reads the rule as its exact opposite.
- **Sections.** Rules live inside `access-section` containers. Reading only the top level
  would report a 400-rule policy as having four rules.
- **`Inner Layer` is not a verdict.** It delegates to a sub-policy the response does not
  contain, so it is neither allow nor deny.
- **The port comparison forms.** A service of `>1023` must become `1024-65535` or the
  rule using it resolves to no traffic at all.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from netsecops.firewall import analyse, examine_hygiene, examine_policy, resolve_rulebase
from netsecops.firewall.analysis import Relationship
from netsecops.firewall.hygiene import HygieneIssue
from netsecops.firewall.intervals import IPV4_MAX
from netsecops.firewall.policy import RuleIssue
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURES = Path(__file__).parent / "fixtures/checkpoint"
MGMT_FIXTURE = FIXTURES / "mgmt/R81.20/corporate_policy.json"
GAIA_FIXTURE = FIXTURES / "gaia/R81.20/cp_gw_edge_01.txt"


@pytest.fixture(scope="module")
def mgmt_text() -> str:
    return MGMT_FIXTURE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def mgmt(mgmt_text: str) -> dict[str, Any]:
    return get_parser("checkpoint_mgmt").parse(ParseContext(text=mgmt_text)).to_storage()


@pytest.fixture(scope="module")
def resolved(mgmt: dict[str, Any]):
    return resolve_rulebase(mgmt["firewall"])


@pytest.fixture(scope="module")
def gaia_text() -> str:
    return GAIA_FIXTURE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def gaia(gaia_text: str) -> dict[str, Any]:
    return get_parser("checkpoint_gaia").parse(ParseContext(text=gaia_text)).to_storage()


def rules_by_name(ncm: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["name"]: r for r in ncm["firewall"]["security_rules"]}


# ══════════════════════ the Management API parser ═══════════════════════════


class TestTheRulebase:
    def test_sections_are_flattened_into_evaluation_order(self, mgmt: dict[str, Any]) -> None:
        """Sections are a console convenience with no effect on matching. A parser that
        read only the top level would find zero rules in this policy, because every rule
        is inside one — and would report the firewall as having no policy at all."""
        rules = mgmt["firewall"]["security_rules"]

        assert len(rules) == 8
        assert [r["order"] for r in rules] == list(range(1, 9))
        assert rules[0]["name"] == "Mgmt to DMZ SSH"
        assert rules[-1]["name"] == "Cleanup rule"

    def test_a_complete_rulebase_reports_nothing_withheld(self, mgmt: dict[str, Any]) -> None:
        """The fixture's `total` is 8 and eight rules parsed, so none were withheld."""
        assert mgmt["firewall"]["rules_not_retrieved"] == 0

    def test_a_truncated_rulebase_says_how_much_is_missing(self) -> None:
        """The dangerous case, and the reason this field exists.

        `show-access-rulebase` paginates and the request does not currently ask for a
        `limit`, so a large rulebase comes back as the server's default page. Fifty rules
        out of five hundred analyse cleanly — nothing shadowed, no any-any, a tidy
        cleanup rule at the end — and the report describes a seventh of a firewall
        without saying so.
        """
        bundle = {
            "show-access-rulebase": {
                "total": 500,
                "to": 2,
                "rulebase": [
                    {"type": "access-rule", "name": "First", "rule-number": 1},
                    {"type": "access-rule", "name": "Second", "rule-number": 2},
                ],
            }
        }
        ncm = (
            get_parser("checkpoint_mgmt").parse(ParseContext(text=json.dumps(bundle))).to_storage()
        )

        assert len(ncm["firewall"]["security_rules"]) == 2
        assert ncm["firewall"]["rules_not_retrieved"] == 498

    def test_a_response_with_no_total_says_nothing_rather_than_zero(self) -> None:
        """Absent is not zero.

        "No rules were withheld" and "the server did not tell us" are different facts,
        and only the first is a reason to trust the analysis. Defaulting to 0 would
        assert completeness on no evidence.
        """
        bundle = {
            "show-access-rulebase": {
                "rulebase": [{"type": "access-rule", "name": "Only", "rule-number": 1}]
            }
        }
        ncm = (
            get_parser("checkpoint_mgmt").parse(ParseContext(text=json.dumps(bundle))).to_storage()
        )

        assert ncm["firewall"]["rules_not_retrieved"] is None

    def test_an_unnamed_rule_falls_back_to_its_number(self, mgmt: dict[str, Any]) -> None:
        """Check Point rules are often unnamed. An empty name would make every finding
        read "rule ()"; the number is what the console shows."""
        assert "Rule 6" in rules_by_name(mgmt)

    def test_a_disabled_rule_is_marked_disabled(self, mgmt: dict[str, Any]) -> None:
        rules = rules_by_name(mgmt)
        assert rules["Legacy migration allow"]["enabled"] is False
        assert rules["Inbound web"]["enabled"] is True

    def test_an_absent_enabled_flag_does_not_disable_a_rule(self) -> None:
        """A rulebase fetched without `details-level: full` omits the flag. Reading that
        as disabled would drop the rule from the analysis and hide whatever it shadows —
        the failure would be silent and would make the firewall look safer than it is."""
        bundle = {
            "show-access-rulebase": {
                "rulebase": [{"type": "access-rule", "name": "Terse", "rule-number": 1}]
            }
        }
        ncm = (
            get_parser("checkpoint_mgmt").parse(ParseContext(text=json.dumps(bundle))).to_storage()
        )
        assert ncm["firewall"]["security_rules"][0]["enabled"] is True

    def test_track_none_means_unlogged_and_track_log_means_logged(
        self, mgmt: dict[str, Any]
    ) -> None:
        rules = rules_by_name(mgmt)
        assert rules["Inbound web"]["log_end"] is True
        assert rules["Rule 6"]["log_end"] is False

    def test_an_absent_track_stays_unknown(self) -> None:
        """Absent is not False. A rule with no track in the response has not been shown
        to be unlogged, and reporting it as such sends someone to change a firewall for
        no reason."""
        bundle = {
            "show-access-rulebase": {
                "rulebase": [{"type": "access-rule", "name": "Terse", "rule-number": 1}]
            }
        }
        ncm = (
            get_parser("checkpoint_mgmt").parse(ParseContext(text=json.dumps(bundle))).to_storage()
        )
        assert ncm["firewall"]["security_rules"][0]["log_end"] is None

    def test_the_any_object_is_normalised(self, mgmt: dict[str, Any]) -> None:
        """`CpmiAnyObject` named "Any" has to become the resolver's `any`, or every rule
        using it resolves to an object that does not exist."""
        assert rules_by_name(mgmt)["Block inbound RDP"]["src"] == ["any"]

    def test_hit_counts_and_last_hit_are_carried(self, mgmt: dict[str, Any]) -> None:
        rules = rules_by_name(mgmt)
        assert rules["Mgmt to DMZ SSH"]["hit_count"] == 148223
        assert rules["Mgmt to DMZ SSH"]["last_hit"].startswith("2026-09-12")
        # A rule that has never matched has a real zero, not a missing count.
        assert rules["Partner RDP to web"]["hit_count"] == 0

    def test_the_layer_becomes_a_zone(self, mgmt: dict[str, Any]) -> None:
        """Check Point layers are policy domains: rules in different layers never
        compete. Carrying the layer as a zone is what stops the analyser comparing
        them."""
        assert mgmt["firewall"]["zones"] == ["Corporate-Policy Network"]
        assert rules_by_name(mgmt)["Inbound web"]["src_zones"] == ["Corporate-Policy Network"]


class TestActionsAreNotGuessed:
    def test_accept_and_drop_are_carried_verbatim(self, mgmt: dict[str, Any]) -> None:
        rules = rules_by_name(mgmt)
        assert rules["Inbound web"]["action"] == "Accept"
        assert rules["Cleanup rule"]["action"] == "Drop"

    def test_inner_layer_is_neither_allow_nor_deny(self, mgmt: dict[str, Any], resolved) -> None:
        """`Inner Layer` delegates the decision to a sub-policy this response does not
        contain. Mapping it to allow would invent a permit nobody verified; mapping it to
        deny would hide one. It is kept verbatim, and `permits` is False — which keeps it
        out of the permit-only findings rather than producing confident nonsense."""
        assert rules_by_name(mgmt)["Rule 6"]["action"] == "Inner Layer"

        rules, _ = resolved
        delegating = next(r for r in rules if r.name == "Rule 6")
        assert delegating.permits is False

    def test_a_delegating_rule_is_not_reported_as_an_overly_broad_permit(self, resolved) -> None:
        rules, _ = resolved
        flagged = {f.rule_name for f in examine_policy(rules).by_issue(RuleIssue.ANY_ANY_ANY)}
        assert "Rule 6" not in flagged


class TestNegation:
    """`source-negate` is the Check Point equivalent of PAN-OS's inverted service flags:
    one boolean that, ignored, makes the parser report the exact opposite of the truth.
    """

    def test_a_negated_source_covers_everything_else(self, resolved) -> None:
        rules, _ = resolved
        rule = next(r for r in rules if r.name == "Quarantine egress")

        # Quarantine_Net is a /24. "Everything except" is the whole space minus 256.
        assert rule.source.v4.size == IPV4_MAX + 1 - 256

    def test_the_negated_range_itself_is_excluded(self, resolved) -> None:
        """The assertion that would fail if the flag were dropped: without negation the
        rule would cover 10.99.0.0/24 and nothing else, which is its exact opposite."""
        from ipaddress import IPv4Address

        rules, _ = resolved
        rule = next(r for r in rules if r.name == "Quarantine egress")

        assert not rule.source.v4.covers_value(int(IPv4Address("10.99.0.5")))
        assert rule.source.v4.covers_value(int(IPv4Address("10.10.0.5")))

    def test_the_flag_reaches_the_ncm(self, mgmt: dict[str, Any]) -> None:
        rules = rules_by_name(mgmt)
        assert rules["Quarantine egress"]["src_negate"] is True
        assert rules["Quarantine egress"]["dst_negate"] is False
        assert rules["Inbound web"]["src_negate"] is False


class TestObjects:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("Mgmt_Net", "10.100.0.0/24"),
            ("Web_01", "10.20.0.10"),
            ("Partner_Range", "198.51.100.10-198.51.100.20"),
        ],
    )
    def test_objects_render_in_a_parseable_form(
        self, mgmt: dict[str, Any], name: str, expected: str
    ) -> None:
        objects = {o["name"]: o for o in mgmt["firewall"]["address_objects"]}
        assert objects[name]["value"] == expected

    def test_objects_are_collected_from_every_response(self, mgmt: dict[str, Any]) -> None:
        """`Public_Web_VIP` is defined only in the NAT response's dictionary. A parser
        that read the access rulebase alone would leave the NAT rule unresolvable."""
        names = {o["name"] for o in mgmt["firewall"]["address_objects"]}
        assert "Public_Web_VIP" in names

    def test_the_same_object_in_two_responses_appears_once(self, mgmt: dict[str, Any]) -> None:
        """Deduplicated by UID rather than by name: two objects in different Check Point
        domains may legitimately share a name."""
        names = [o["name"] for o in mgmt["firewall"]["address_objects"]]
        assert len(names) == len(set(names))

    def test_groups_keep_their_members(self, mgmt: dict[str, Any]) -> None:
        groups = {g["name"]: g for g in mgmt["firewall"]["address_groups"]}
        assert groups["Web_Servers"]["members"] == ["Web_01", "Web_02"]

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("https", "tcp/443"),
            ("snmp", "udp/161"),
            # `>1023` must become a range the interval parser can read; left as-is the
            # service resolves to nothing and the rule silently covers no traffic.
            ("high-ports", "tcp/1024-65535"),
        ],
    )
    def test_service_ports_including_the_comparison_forms(
        self, mgmt: dict[str, Any], name: str, expected: str
    ) -> None:
        services = {o["name"]: o for o in mgmt["firewall"]["service_objects"]}
        assert services[name]["value"] == expected


class TestGatewaysAdministratorsAndNat:
    def test_the_gateway_supplies_identity(self, mgmt: dict[str, Any]) -> None:
        assert mgmt["device"]["hostname"] == "cp-gw-edge-01"
        assert mgmt["device"]["version"] == "R81.20"
        assert mgmt["device"]["vendor"] == "checkpoint"

    def test_interfaces_come_from_the_gateway_object(self, mgmt: dict[str, Any]) -> None:
        interfaces = {i["name"]: i for i in mgmt["interfaces"]}
        assert interfaces["eth0"]["ip_addresses"] == ["203.0.113.2"]

    def test_enabled_blades_are_recorded(self, mgmt: dict[str, Any]) -> None:
        """Which blades are licensed and on decides which checks are even applicable: a
        gateway without the anti-virus blade cannot be faulted for rules that lack an
        anti-virus profile, and must report Not Evaluated instead of Fail."""
        blades = mgmt["firewall"]["profiles"]
        assert blades["ips"] is True
        assert blades["anti-virus"] is False

    def test_administrators_and_their_profiles(self, mgmt: dict[str, Any]) -> None:
        users = {u["name"]: u for u in mgmt["users"]}
        assert users["admin"]["role"] == "Super User"
        assert users["admin"]["privilege"] == 15
        assert users["netsecops"]["role"] == "Read Only All"
        assert users["netsecops"]["privilege"] is None

    def test_nat_direction_distinguishes_publishing_from_hiding(self, mgmt: dict[str, Any]) -> None:
        """A translated destination publishes an internal host to the outside; a
        translated source does not. FR-FW-04 turns entirely on telling them apart."""
        nat = {r["name"]: r for r in mgmt["firewall"]["nat_rules"]}

        assert nat["Publish web"]["direction"] == "destination"
        assert nat["Publish web"]["translated"] == "Web_01"
        assert nat["Internal egress hide"]["direction"] == "source"


class TestMgmtParserHealth:
    def test_no_section_fails_silently(
        self, mgmt_text: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The tripwire. Every section is wrapped so one bad response cannot cost the
        rest, which means a section that fails on every device fails invisibly and its
        fields report Not Evaluated forever."""
        with caplog.at_level(logging.WARNING):
            get_parser("checkpoint_mgmt").parse(ParseContext(text=mgmt_text))

        failures = [r for r in caplog.records if "section_failed" in r.getMessage()]
        assert not failures, [r.getMessage() for r in failures]

    def test_a_response_nothing_reads_is_reported(self, mgmt: dict[str, Any]) -> None:
        """Coverage for a JSON bundle is about commands, not lines. A response the
        collector fetched and no rule here reads is exactly the gap `raw_unparsed`
        exists to make visible — line coverage would report a meaningless 100%."""
        assert mgmt["raw_unparsed"] == ["1: no rule reads the response to 'show-unicorns'"]

    def test_a_partial_collection_still_yields_what_arrived(self) -> None:
        """FR-COL-08. If `show-gateways-and-servers` failed and the rulebase call
        succeeded, the policy is still assessed and only the gateway fields report Not
        Evaluated. Keying the bundle by command is what makes that expressible."""
        bundle = {
            "show-access-rulebase": {
                "rulebase": [
                    {
                        "type": "access-rule",
                        "name": "Only rule",
                        "rule-number": 1,
                        "action": {"name": "Accept"},
                    }
                ]
            }
        }
        ncm = (
            get_parser("checkpoint_mgmt").parse(ParseContext(text=json.dumps(bundle))).to_storage()
        )

        assert len(ncm["firewall"]["security_rules"]) == 1
        assert ncm["device"]["hostname"] is None
        assert ncm["users"] == []

    def test_no_secret_reaches_the_ncm(self, mgmt: dict[str, Any]) -> None:
        """C-2. The Management API never returns password material — only the
        authentication method — so the method is what is stored."""
        serialised = json.dumps(mgmt)
        assert "check point password" in serialised.lower()
        for forbidden in ("phash", "password-hash", "sha1", "$1$", "$6$"):
            assert forbidden not in serialised

    def test_malformed_json_produces_a_snapshot_rather_than_an_exception(self) -> None:
        result = get_parser("checkpoint_mgmt").parse(ParseContext(text='{"truncated": '))

        assert result.device.vendor == "checkpoint"
        assert result.device.hostname is None
        assert result.raw_unparsed and "not valid JSON" in result.raw_unparsed[0]

    def test_a_json_array_is_rejected_rather_than_misread(self) -> None:
        """Valid JSON that is not a command bundle. Iterating it as one would raise, and
        the section wrapper would swallow it — leaving a clean-looking empty NCM."""
        result = get_parser("checkpoint_mgmt").parse(ParseContext(text="[1, 2, 3]"))
        assert result.raw_unparsed and "not a command bundle" in result.raw_unparsed[0]

    def test_an_empty_artefact_does_not_raise(self) -> None:
        assert get_parser("checkpoint_mgmt").parse(ParseContext(text="")).device.hostname is None

    def test_garbage_does_not_raise(self) -> None:
        assert (
            get_parser("checkpoint_mgmt").parse(ParseContext(text="\x00\x01nonsense")) is not None
        )


class TestTheMgmtPipeline:
    """Parse → resolve → analyse → findings, on one realistic policy."""

    def test_the_shadowed_rdp_rule_is_found(self, resolved) -> None:
        rules, _ = resolved
        shadowed = analyse(rules).by_kind(Relationship.SHADOWED)

        assert len(shadowed) == 1
        assert shadowed[0].subject.name == "Partner RDP to web"
        assert shadowed[0].cause.name == "Block inbound RDP"
        assert "drops it instead" in shadowed[0].detail

    def test_a_redundant_rule_that_is_load_bearing_says_so(self, resolved) -> None:
        """The most dangerous finding this module could produce.

        Rule #2 drops RDP everywhere, and the cleanup deny at the bottom drops
        everything, so #2 is redundant — the plain finding says it can go. But #2 is the
        only thing stopping #3 from allowing RDP in from a partner range. Acting on the
        unqualified advice would open a firewall.
        """
        rules, _ = resolved
        redundant = analyse(rules).by_kind(Relationship.REDUNDANT)

        assert len(redundant) == 1
        assert redundant[0].subject.name == "Block inbound RDP"
        assert redundant[0].subject_shadows == (3,)
        assert "Do not remove it without checking #3" in redundant[0].detail

    def test_the_cleanup_rule_does_not_generalise_the_whole_rulebase(self, resolved) -> None:
        """A final catch-all deny is broader than every rule above it by design. Left in,
        it produces one Info finding per rule — noise that scales with the policy and
        says only "you have a cleanup rule", which is good practice."""
        rules, _ = resolved
        generalisations = analyse(rules).by_kind(Relationship.GENERALISATION)

        assert not [g for g in generalisations if g.later.name == "Cleanup rule"]

    def test_rdp_from_a_partner_range_is_reported_as_insecure(self, resolved) -> None:
        rules, _ = resolved
        insecure = examine_policy(rules).by_issue(RuleIssue.INSECURE_SERVICE)

        assert insecure
        assert "RDP" in insecure[0].message

    def test_the_never_hit_rule_is_found(self, resolved) -> None:
        rules, _ = resolved
        never = {f.rule_name for f in examine_policy(rules).by_issue(RuleIssue.NEVER_HIT)}
        assert "Partner RDP to web" in never

    def test_the_duplicate_object_is_found(self, resolved) -> None:
        rules, resolver = resolved
        duplicates = examine_hygiene(resolver, rules).by_issue(HygieneIssue.DUPLICATE_OBJECT)

        assert len(duplicates) == 1
        assert "Web_01" in duplicates[0].name
        assert "Web_01_Old" in duplicates[0].name

    def test_unused_objects_are_found(self, resolved) -> None:
        rules, resolver = resolved
        unused = {
            f.name for f in examine_hygiene(resolver, rules).by_issue(HygieneIssue.UNUSED_OBJECT)
        }

        assert "Decommissioned_Net" in unused
        # Reached only through Web_Servers, so used.
        assert "Web_02" not in unused

    def test_groups_resolve_through_to_their_hosts(self, resolved) -> None:
        rules, _ = resolved
        rule = next(r for r in rules if r.name == "Inbound web")
        assert rule.destination.v4.size == 2


# ═════════════════════════════ the Gaia parser ══════════════════════════════


class TestGaiaDeviceAndInterfaces:
    def test_identity(self, gaia: dict[str, Any]) -> None:
        assert gaia["device"]["hostname"] == "cp-gw-edge-01"
        assert gaia["device"]["domain_name"] == "example.com"
        assert gaia["device"]["vendor"] == "checkpoint"
        assert gaia["device"]["platform"] == "checkpoint_gaia"

    def test_interfaces_merge_their_several_set_lines(self, gaia: dict[str, Any]) -> None:
        """Gaia states one interface across several lines, in an order that varies by
        version. Merging by name rather than matching a whole line is what survives
        that."""
        interfaces = {i["name"]: i for i in gaia["interfaces"]}

        assert set(interfaces) == {"eth0", "eth1", "eth2", "eth3"}
        assert interfaces["eth0"]["ip_addresses"] == ["203.0.113.2/24"]
        assert interfaces["eth0"]["description"] == "Internet-uplink"

    def test_a_shut_interface_is_false_and_an_unstated_one_is_none(
        self, gaia: dict[str, Any]
    ) -> None:
        interfaces = {i["name"]: i for i in gaia["interfaces"]}
        assert interfaces["eth0"]["admin_up"] is True
        assert interfaces["eth3"]["admin_up"] is False


class TestGaiaAccounts:
    def test_a_bash_shell_is_treated_as_full_privilege(self, gaia: dict[str, Any]) -> None:
        """A Gaia admin with /bin/bash bypasses clish and every restriction that goes
        with it — an expert-mode shell on a security gateway without needing the expert
        password."""
        users = {u["name"]: u for u in gaia["users"]}

        assert users["admin"]["role"] == "/bin/bash"
        assert users["admin"]["privilege"] == 15

    def test_a_restricted_shell_is_not(self, gaia: dict[str, Any]) -> None:
        users = {u["name"]: u for u in gaia["users"]}
        assert users["contractor"]["privilege"] is None

    def test_an_rba_admin_role_raises_privilege(self, gaia: dict[str, Any]) -> None:
        """`add rba user netsecops roles adminRole` grants administrative rights even to
        an account whose shell is the restricted one."""
        users = {u["name"]: u for u in gaia["users"]}

        assert users["netsecops"]["role"] == "adminRole"
        assert users["netsecops"]["privilege"] == 15

    def test_the_hash_algorithm_is_classified_without_storing_the_hash(
        self, gaia: dict[str, Any]
    ) -> None:
        users = {u["name"]: u for u in gaia["users"]}

        assert users["admin"]["secret_type"] == "md5-crypt"
        assert users["admin"]["weak_hash"] is True
        assert users["netsecops"]["secret_type"] == "sha512-crypt"
        assert users["netsecops"]["weak_hash"] is False


class TestGaiaServices:
    def test_the_snmp_community_is_masked_and_flagged_as_default(
        self, gaia: dict[str, Any]
    ) -> None:
        communities = gaia["snmp"]["v1v2c_communities"]

        assert len(communities) == 1
        assert communities[0]["is_default"] is True
        assert communities[0]["rw"] is False
        assert "PUBLIC" not in communities[0]["name_masked"]

    def test_the_snmpv3_security_level_is_read_not_inferred(self, gaia: dict[str, Any]) -> None:
        users = gaia["snmp"]["v3_users"]

        assert len(users) == 1
        assert users[0]["level"] == "authPriv"
        assert users[0]["auth"] == "SHA256"

    def test_an_unrecognised_security_level_becomes_unknown(self) -> None:
        """Never guessed: an unfamiliar spelling must report Not Evaluated rather than
        being rounded to whichever level looks closest."""
        config = "add snmp usm user odd security-level somethingElse\n"
        ncm = get_parser("checkpoint_gaia").parse(ParseContext(text=config)).to_storage()
        assert ncm["snmp"]["v3_users"][0]["level"] == "unknown"

    def test_syslog_and_audit_logging(self, gaia: dict[str, Any]) -> None:
        servers = gaia["logging"]["syslog_servers"]

        assert [s["host"] for s in servers] == ["10.100.5.10"]
        # `permanent` means the record of who changed what survives a reboot.
        assert gaia["logging"]["config_change_logging"] is True

    def test_ntp_and_timezone(self, gaia: dict[str, Any]) -> None:
        assert [s["host"] for s in gaia["ntp"]["servers"]] == ["10.100.5.40", "10.100.5.41"]
        assert "London" in gaia["ntp"]["timezone"]

    def test_management_services(self, gaia: dict[str, Any]) -> None:
        services = gaia["management"]["services"]
        assert services["ssh"]["enabled"] is True
        assert services["https"]["enabled"] is True
        assert services["snmp"]["enabled"] is True

    def test_the_timeout_is_converted_to_seconds(self, gaia: dict[str, Any]) -> None:
        assert gaia["management"]["session"]["exec_timeout_s"] == 600

    def test_the_banner_excludes_the_on_keyword(self, gaia: dict[str, Any]) -> None:
        """`set message banner on "text"` — `on` is the toggle. Including it would make
        the "banner warns about authorised use" checks match the wrong string."""
        banner = gaia["management"]["banners"]["login"]

        assert banner.startswith("Authorised users only")
        assert not banner.startswith("on")
        assert '"' not in banner

    def test_the_password_policy_is_read(self, gaia: dict[str, Any]) -> None:
        """These same assertions passed before the parser was correct.

        The parser matched `password-history-length`, `password-expiration-days` and
        `lockout-attempts`; Gaia emits `history-length`, `password-expiration` and
        `deny-on-fail failures-allowed`. The fixture was written from the parser rather
        than from a device, so the test agreed with the mistake — it asserted the right
        numbers arrived from syntax no Check Point gateway produces, and on real hardware
        all three fields were silently empty.

        The fixture now uses Gaia's syntax, verified against the R81.20 Gaia
        Administration Guide. What guards it going forward is not this test but the
        absence of a Check Point corpus being recorded as a known gap in
        `docs/parser-validation.md`.
        """
        policy = gaia["management"]["password_policy"]

        assert policy["min_length"] == 12
        assert policy["complexity_required"] is True
        assert policy["max_age_days"] == 90
        assert policy["history"] == 8
        assert policy["lockout_threshold"] == 5

    def test_lockout_being_configured_is_not_lockout_being_on(self, gaia: dict[str, Any]) -> None:
        """Gaia stores `failures-allowed` whether or not `deny-on-fail enable` is set.

        A threshold on its own says a lockout is configured, not that it applies, so the
        two are separate fields. Reporting a device as protected because a number is
        present would be the same error in a new place.
        """
        policy = gaia["management"]["password_policy"]

        assert policy["lockout_enabled"] is True
        assert policy["lockout_threshold"] == 5

    def test_dormant_account_lockout_is_not_the_failed_login_lockout(
        self, gaia: dict[str, Any]
    ) -> None:
        """`deny-on-nonuse` locks unused accounts; `deny-on-fail` locks attacked ones.

        The old parser mapped `deny-on-nonuse` onto `lockout_threshold`, reporting a
        dormant-account policy as a brute-force control — a device with dormant lockout
        and no failed-login lockout looked protected against password spraying.
        """
        policy = gaia["management"]["password_policy"]

        assert policy["dormant_lockout_days"] == 60
        assert policy["dormant_lockout_days"] != policy["lockout_threshold"]

    def test_the_password_hash_algorithm_is_recorded(self, gaia: dict[str, Any]) -> None:
        policy = gaia["management"]["password_policy"]

        assert policy["hash_algorithm"] == "SHA512"

    def test_an_expiry_of_never_is_absent_rather_than_a_large_number(self) -> None:
        """`never` is a legitimate Gaia value, and it must not read as a long maximum age.

        Coercing it to a sentinel like 99999 would make a device with no expiry policy
        pass a "maximum age under a year" check — the failure this codebase calls
        absent-is-not-false.
        """
        from netsecops.parsers.base import ParseContext
        from netsecops.parsers.registry import get_parser

        ncm = get_parser("checkpoint_gaia").parse(
            ParseContext(
                text="set password-controls password-expiration never\n",
                command="show configuration",
            )
        )

        assert ncm.management.password_policy.max_age_days is None


class TestGaiaParserHealth:
    def test_no_section_fails_silently(
        self, gaia_text: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """This caught a real one: `management.services.ssh.port` does not exist on
        SshConfig, and the AttributeError took the whole management section with it — so
        the timeout, banner, password policy and management ACL were all silently
        missing, with nothing but a log line to say so."""
        with caplog.at_level(logging.WARNING):
            get_parser("checkpoint_gaia").parse(ParseContext(text=gaia_text))

        failures = [r for r in caplog.records if "section_failed" in r.getMessage()]
        assert not failures, [r.getMessage() for r in failures]

    def test_coverage_meets_the_parser_floor(self, gaia_text: str, gaia: dict[str, Any]) -> None:
        meaningful = [
            line
            for line in gaia_text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        coverage = 100 * (len(meaningful) - len(gaia["raw_unparsed"])) / len(meaningful)
        assert coverage >= 90, f"{coverage:.1f}% — unparsed: {gaia['raw_unparsed'][:10]}"

    def test_unrecognised_settings_are_reported_rather_than_dropped(
        self, gaia: dict[str, Any]
    ) -> None:
        """The other half of coverage: lines nothing understood must be visible. These
        two are genuinely not security-relevant, and that is the point — the mechanism
        works, so a line that *did* matter would show up the same way."""
        unparsed = " ".join(gaia["raw_unparsed"])
        assert "max-path-splits" in unparsed

    def test_provenance_points_at_real_lines(self, gaia_text: str, gaia: dict[str, Any]) -> None:
        line_count = len(gaia_text.splitlines())
        entries = gaia["provenance"]["entries"]

        assert entries
        for path, entry in entries.items():
            assert 1 <= entry["line_start"] <= line_count, f"{path} points outside the file"

    def test_no_secret_reaches_the_ncm(self, gaia: dict[str, Any]) -> None:
        serialised = json.dumps(gaia)
        for secret in (
            "$1$Kx8tPqLm$0aZbYcXdWeVfUgThSiRj01",
            "$6$Nm4rQwEr$TyUiOpAsDfGhJkLzXcVbNm1234567890AbCdEf",
            "PUBLIC",
        ):
            assert secret not in serialised, f"{secret} leaked into the NCM"

    def test_a_truncated_line_does_not_raise(self) -> None:
        """Gaia truncates long lines. Losing one option is acceptable; losing the whole
        configuration is not."""
        ncm = (
            get_parser("checkpoint_gaia")
            .parse(ParseContext(text="set hostname gw\nset interface eth0 ipv4-address\n"))
            .to_storage()
        )
        assert ncm["device"]["hostname"] == "gw"

    def test_garbage_does_not_raise(self) -> None:
        nonsense = "set\nadd\n\x00binary\nset user\n"
        assert get_parser("checkpoint_gaia").parse(ParseContext(text=nonsense)) is not None

    def test_an_empty_configuration_does_not_raise(self) -> None:
        assert get_parser("checkpoint_gaia").parse(ParseContext(text="")).device.hostname is None

    def test_gaia_holds_no_security_policy(self, gaia: dict[str, Any]) -> None:
        """The structural fact about Check Point, asserted so it cannot quietly change.

        The gateway does not hold the rulebase — the management server does. Every
        firewall check against a Gaia-only snapshot must therefore report Not Evaluated,
        and an empty rulebase here is the correct answer rather than a parser gap. If a
        future change started inventing rules from `fw tab` output, this is what would
        catch it.
        """
        assert gaia["firewall"]["security_rules"] == []
        assert gaia["firewall"]["address_objects"] == []
