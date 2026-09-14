"""FortiOS parser (FR-PARSE-01 … FR-PARSE-05, FR-FW-01).

One test here matters more than the others. Every parser wraps each section in
try/except so an unfamiliar stanza cannot cost the rest (FR-PARSE-03) — which means a
section that fails *every* time fails invisibly, and the fields it would have populated
silently report Not Evaluated forever. `test_no_section_fails_silently` is the tripwire,
and it caught exactly that: `_parse_snmp` importing two helpers from the wrong module,
so no FortiGate would ever have had its SNMP configuration assessed.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from netsecops.firewall import analyse, examine_hygiene, examine_policy, resolve_rulebase
from netsecops.firewall.analysis import Relationship
from netsecops.firewall.hygiene import HygieneIssue
from netsecops.firewall.policy import RuleIssue
from netsecops.parsers.base import ParseContext
from netsecops.parsers.fortinet.blocks import read
from netsecops.parsers.registry import get_parser

FIXTURE = Path(__file__).parent / "fixtures/fortinet/fortios/7.2/edge_fortigate.cfg"


@pytest.fixture(scope="module")
def config_text() -> str:
    return FIXTURE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ncm(config_text: str) -> dict[str, Any]:
    return get_parser("fortios").parse(ParseContext(text=config_text)).to_storage()


@pytest.fixture(scope="module")
def resolved(ncm: dict[str, Any]):
    return resolve_rulebase(ncm["firewall"])


# ─────────────────────────── the block reader ───────────────────────────────


class TestBlockReader:
    def test_it_reads_nested_sections_and_entries(self) -> None:
        config = read(
            "config firewall policy\n"
            "    edit 1\n"
            '        set name "Web"\n'
            '        set srcaddr "LAN" "DMZ"\n'
            "    next\n"
            "end\n"
        )
        policy = config.section("firewall policy")

        assert policy is not None
        entry = policy.entries()[0]
        assert entry.name == "1"
        assert entry.get("name") == "Web"
        assert entry.get_all("srcaddr") == ["LAN", "DMZ"]

    def test_sections_nest_inside_entries(self) -> None:
        config = read(
            "config system ntp\n"
            "    config ntpserver\n"
            "        edit 1\n"
            '            set server "10.0.0.1"\n'
            "        next\n"
            "    end\n"
            "end\n"
        )
        ntp = config.section("system ntp")
        assert ntp is not None
        servers = ntp.child("ntpserver")
        assert servers is not None
        assert servers.entries()[0].get("server") == "10.0.0.1"

    def test_a_flag_distinguishes_absent_from_disabled(self) -> None:
        """`set status disable` and never mentioning status are different facts, and a
        check must be able to tell them apart."""
        config = read("config a\n    edit 1\n        set status disable\n    next\nend\n")
        entry = config.section("a").entries()[0]  # type: ignore[union-attr]

        assert entry.flag("status") is False
        assert entry.flag("never-mentioned") is None

    def test_a_truncated_capture_keeps_what_arrived(self) -> None:
        """A session that dropped mid-transfer leaves blocks open. Discarding them
        would lose everything above the cut as well as below it."""
        config = read('config firewall policy\n    edit 1\n        set name "Half"\n')
        policy = config.section("firewall policy")

        assert policy is not None
        assert policy.entries()[0].get("name") == "Half"

    def test_stray_lines_are_recorded_not_dropped(self) -> None:
        config = read("set orphan value\nend\n")
        assert len(config.unparsed) == 2

    def test_an_unbalanced_end_does_not_raise(self) -> None:
        assert read("end\nend\nend\n").unparsed


# ────────────────────────────── the mapping ─────────────────────────────────


class TestDeviceAndManagement:
    def test_identity(self, ncm: dict[str, Any]) -> None:
        assert ncm["device"]["hostname"] == "edge-fgt-01"
        assert ncm["device"]["version"] == "7.2.5"
        assert ncm["device"]["model"] == "FGT60F"
        assert ncm["device"]["vendor"] == "fortinet"

    def test_management_services_come_from_interface_allowaccess(self, ncm: dict[str, Any]) -> None:
        """FortiOS declares administrative access per interface, so the device's
        exposure is the union of what its interfaces permit — the `internal` interface
        allows telnet and http, and that is what makes them enabled."""
        services = ncm["management"]["services"]

        assert services["ssh"]["enabled"] is True
        assert services["telnet"]["enabled"] is True
        assert services["http"]["enabled"] is True
        assert services["snmp"]["enabled"] is True

    def test_the_timeout_is_converted_to_seconds(self, ncm: dict[str, Any]) -> None:
        """FortiOS states it in minutes; the NCM is seconds everywhere, or the
        vendor-neutral timeout checks would compare 60 against 600."""
        assert ncm["management"]["session"]["exec_timeout_s"] == 3600

    def test_the_password_policy_is_read(self, ncm: dict[str, Any]) -> None:
        policy = ncm["management"]["password_policy"]
        assert policy["min_length"] == 8
        assert policy["complexity_required"] is True
        assert policy["lockout_threshold"] == 3

    def test_administrators_are_parsed_with_their_profiles(self, ncm: dict[str, Any]) -> None:
        users = {u["name"]: u for u in ncm["users"]}
        assert set(users) == {"admin", "netsecops", "contractor"}
        # super_admin maps to privilege 15 so the vendor-neutral privilege checks apply.
        assert users["admin"]["privilege"] == 15
        assert users["netsecops"]["privilege"] is None


class TestLoggingTimeAndSnmp:
    def test_syslog_is_parsed(self, ncm: dict[str, Any]) -> None:
        servers = ncm["logging"]["syslog_servers"]
        assert [s["host"] for s in servers] == ["10.100.5.10"]
        assert ncm["logging"]["source_interface"] == "10.100.0.5"

    def test_ntp_servers_are_parsed_from_the_nested_section(self, ncm: dict[str, Any]) -> None:
        assert [s["host"] for s in ncm["ntp"]["servers"]] == ["10.100.5.40", "10.100.5.41"]
        assert ncm["ntp"]["authenticated"] is False

    def test_the_snmp_community_is_masked_and_flagged_as_default(self, ncm: dict[str, Any]) -> None:
        """The regression this file's headline test exists to prevent."""
        communities = ncm["snmp"]["v1v2c_communities"]

        assert len(communities) == 1
        assert communities[0]["is_default"] is True
        assert "public" not in communities[0]["name_masked"]

    def test_the_snmpv3_user_security_level_is_derived(self, ncm: dict[str, Any]) -> None:
        users = ncm["snmp"]["v3_users"]
        assert len(users) == 1
        assert users[0]["level"] == "authPriv"
        assert users[0]["auth"] == "sha256"


class TestTheFirewallBlock:
    def test_every_rule_is_parsed_in_order(self, ncm: dict[str, Any]) -> None:
        rules = ncm["firewall"]["security_rules"]
        assert len(rules) == 8
        assert [r["order"] for r in rules] == list(range(1, 9))
        assert rules[0]["name"] == "Mgmt to DMZ SSH"

    def test_a_disabled_rule_is_marked_disabled(self, ncm: dict[str, Any]) -> None:
        rules = {r["name"]: r for r in ncm["firewall"]["security_rules"]}
        assert rules["Legacy rule"]["enabled"] is False
        assert rules["Inbound web"]["enabled"] is True

    def test_logtraffic_maps_to_the_logging_fields(self, ncm: dict[str, Any]) -> None:
        rules = {r["name"]: r for r in ncm["firewall"]["security_rules"]}
        assert rules["Inbound web"]["log_end"] is True
        assert rules["LAN outbound any"]["log_end"] is False

    def test_security_profiles_are_collected_individually(self, ncm: dict[str, Any]) -> None:
        rules = {r["name"]: r for r in ncm["firewall"]["security_rules"]}
        profiles = rules["Inbound web"]["profiles"]

        assert profiles["ips"] == "default"
        assert profiles["antivirus"] == "default"
        assert profiles["decryption"] == "certificate-inspection"
        # An empty dict is what the no-profiles finding keys on.
        assert rules["LAN outbound any"]["profiles"] == {}

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("internal-net", "10.10.0.0/24"),
            ("dmz-web-01", "10.20.0.10"),
            ("partner-range", "198.51.100.10-198.51.100.20"),
        ],
    )
    def test_address_objects_render_in_a_parseable_form(
        self, ncm: dict[str, Any], name: str, expected: str
    ) -> None:
        """A dotted netmask has to become a prefix, or the interval parser cannot read
        it and the rule silently covers nothing."""
        objects = {o["name"]: o for o in ncm["firewall"]["address_objects"]}
        assert objects[name]["value"] == expected

    def test_service_objects_render_with_their_protocol(self, ncm: dict[str, Any]) -> None:
        services = {o["name"]: o for o in ncm["firewall"]["service_objects"]}
        assert services["HTTPS-443"]["value"] == "tcp/443"
        assert services["DNS-53"]["value"] == "udp/53"
        assert services["HIGH-PORTS"]["value"] == "tcp/1024-65535"

    def test_zones_are_collected_from_the_policies(self, ncm: dict[str, Any]) -> None:
        assert set(ncm["firewall"]["zones"]) >= {"wan1", "internal", "dmz", "mgmt"}

    def test_vips_become_nat_rules(self, ncm: dict[str, Any]) -> None:
        """A FortiGate has no separate NAT rulebase — a VIP *is* its destination NAT.

        Nothing read this section before, so the FR-FW-04 analysis saw zero NAT rules on
        every FortiGate and reported no exposure anywhere. The translations were all
        here.
        """
        nat = {r["name"]: r for r in ncm["firewall"]["nat_rules"]}

        assert set(nat) == {"web-vip", "rdp-vip", "orphan-vip"}
        assert nat["web-vip"]["original"] == "203.0.113.10"
        assert nat["web-vip"]["translated"] == "10.20.0.10:443"
        # Every VIP translates the destination. That is what a VIP is.
        assert nat["web-vip"]["direction"] == "destination"

    def test_a_vip_without_port_forwarding_keeps_the_port(self, ncm: dict[str, Any]) -> None:
        """`portforward` is off, so the VIP maps the address and leaves the port alone.
        Appending a port here would make the NAT match only that one port."""
        nat = {r["name"]: r for r in ncm["firewall"]["nat_rules"]}
        assert nat["orphan-vip"]["translated"] == "10.20.0.50"

    def test_a_vip_also_resolves_as_an_address_object(self, ncm: dict[str, Any]) -> None:
        """Policies name the VIP as their destination. Without an object of that name
        every publishing policy reports an unresolved destination and drops out of the
        overlap analysis."""
        objects = {o["name"]: o for o in ncm["firewall"]["address_objects"]}

        assert objects["web-vip"]["value"] == "203.0.113.10"
        assert objects["web-vip"]["type"] == "vip"


# ──────────────────────── parser health (the tripwire) ──────────────────────


class TestParserHealth:
    def test_no_section_fails_silently(
        self, config_text: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Each parser section is wrapped so one bad stanza cannot cost the rest. The
        cost of that is that a section which fails *every* time fails invisibly, and
        the fields it would have filled report Not Evaluated forever.

        This caught `_parse_snmp` importing from the wrong module — no FortiGate would
        ever have had its SNMP configuration assessed, and nothing would have said so.
        """
        with caplog.at_level(logging.WARNING):
            get_parser("fortios").parse(ParseContext(text=config_text))

        failures = [r for r in caplog.records if "section_failed" in r.getMessage()]
        assert not failures, [r.getMessage() for r in failures]

    def test_coverage_meets_the_parser_floor(self, config_text: str, ncm: dict[str, Any]) -> None:
        meaningful = [
            line
            for line in config_text.splitlines()
            if line.strip()
            and not line.strip().startswith("#")
            and line.strip() not in {"end", "next"}
        ]
        coverage = 100 * (len(meaningful) - len(ncm["raw_unparsed"])) / len(meaningful)
        assert coverage >= 90, f"{coverage:.1f}% — unparsed: {ncm['raw_unparsed'][:10]}"

    def test_provenance_points_at_real_lines(self, config_text: str, ncm: dict[str, Any]) -> None:
        line_count = len(config_text.splitlines())
        entries = ncm["provenance"]["entries"]

        assert entries
        for path, entry in entries.items():
            assert 1 <= entry["line_start"] <= line_count, f"{path} points outside the file"

    def test_no_secret_reaches_the_ncm(self, ncm: dict[str, Any]) -> None:
        import json

        serialised = json.dumps(ncm)
        for secret in (
            "R4d1usK3y!Secret",
            "SnmpAuthK3y!Secret",
            "SnmpPrivK3y!Secret",
            "SH2abcdefghijklmnopqrstuvwxyz0123456789",
        ):
            assert secret not in serialised, f"{secret} leaked into the NCM"

    def test_garbage_does_not_raise(self) -> None:
        nonsense = "config\nedit\nset\nnext\nend\nend\n\x00binary\n"
        assert get_parser("fortios").parse(ParseContext(text=nonsense)) is not None

    def test_an_empty_configuration_does_not_raise(self) -> None:
        assert get_parser("fortios").parse(ParseContext(text="")).device.hostname is None


# ──────────────────── the whole pipeline, end to end ────────────────────────


class TestTheFullPipeline:
    """Parse → resolve → analyse, on one real configuration.

    This is the assertion that the Phase 4 analysis actually connects to a vendor
    parser, rather than working only on hand-built dictionaries.
    """

    def test_the_shadowed_telnet_rule_is_found(self, resolved) -> None:
        rules, _ = resolved
        shadowed = analyse(rules).by_kind(Relationship.SHADOWED)

        assert len(shadowed) == 1
        assert shadowed[0].later_name == "Partner telnet to web"
        assert shadowed[0].earlier_name == "Block telnet inbound"

    def test_the_any_any_any_rule_is_critical(self, resolved) -> None:
        rules, _ = resolved
        findings = examine_policy(rules).by_issue(RuleIssue.ANY_ANY_ANY)

        assert len(findings) == 1
        assert findings[0].rule_name == "Permit everything"
        assert findings[0].severity == "critical"

    def test_the_unlogged_permit_rule_is_found(self, resolved) -> None:
        rules, _ = resolved
        unlogged = {f.rule_name for f in examine_policy(rules).by_issue(RuleIssue.NO_LOGGING)}
        assert "LAN outbound any" in unlogged

    def test_telnet_from_a_partner_range_is_reported(self, resolved) -> None:
        rules, _ = resolved
        insecure = examine_policy(rules).by_issue(RuleIssue.INSECURE_SERVICE)

        assert insecure
        assert "Telnet" in insecure[0].message

    def test_the_explicit_deny_all_is_not_reported_as_broad(self, resolved) -> None:
        """A cleanup rule is any/any/any by design. Reporting it would flag the one
        thing every rulebase should have."""
        rules, _ = resolved
        flagged = {f.rule_name for f in examine_policy(rules).findings if f.rule_name}
        assert "Implicit deny replacement" not in flagged

    def test_the_duplicate_object_is_found(self, resolved) -> None:
        rules, resolver = resolved
        duplicates = examine_hygiene(resolver, rules).by_issue(HygieneIssue.DUPLICATE_OBJECT)

        assert len(duplicates) == 1
        assert "dmz-web-01" in duplicates[0].name
        assert "dmz-web-01-dup" in duplicates[0].name

    def test_unused_objects_are_found(self, resolved) -> None:
        rules, resolver = resolved
        unused = {
            f.name for f in examine_hygiene(resolver, rules).by_issue(HygieneIssue.UNUSED_OBJECT)
        }
        assert "orphaned-object" in unused

    def test_nested_groups_resolve_through_two_levels(self, resolved) -> None:
        """`all-dmz` contains `dmz-web-servers`, which contains two hosts."""
        rules, _ = resolved
        rule = next(r for r in rules if r.name == "Mgmt to DMZ SSH")

        # 10.20.0.0/24 from dmz-net, which subsumes the two hosts.
        assert rule.destination.v4.size == 256
