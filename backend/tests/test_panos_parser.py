"""PAN-OS parser (FR-PARSE-01 … FR-PARSE-05, FR-FW-01).

PAN-OS is the first platform read as XML rather than as lines, which changes what can
go wrong. There is no ambiguity about where a stanza ends, so the line-format failure
modes disappear; in their place are three that the line parsers never had.

**The inverted service flags.** PAN-OS spells management services as `disable-telnet`,
`disable-http` and so on. A parser that read them as positive flags would report a
hardened device as wide open and an exposed one as clean, and every SEC check over
management exposure would be backwards. `TestManagementServices` exists for that one
inversion.

**Vsys isolation.** Two virtual systems are separate policy domains, so a rule in one
cannot shadow a rule in the other. Flattening them would invent relationships that
cannot exist and send someone to delete a live rule.

**XML entity expansion.** A device configuration is attacker-influenced input arriving
on a worker that has network access to the estate, so it is parsed with `defusedxml`.
`test_an_entity_expansion_is_refused` asserts that stays true.

As with FortiOS, `test_no_section_fails_silently` is the tripwire: every section is
wrapped so one bad stanza cannot cost the rest, which means a section that fails *every*
time fails invisibly and its fields report Not Evaluated forever.
"""

from __future__ import annotations

import json
import logging
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import pytest

from netsecops.firewall import analyse, examine_hygiene, examine_policy, resolve_rulebase
from netsecops.firewall.analysis import Relationship
from netsecops.firewall.hygiene import HygieneIssue
from netsecops.firewall.model import PROTOCOL_NUMBERS
from netsecops.firewall.policy import RuleIssue
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURE = Path(__file__).parent / "fixtures/paloalto/panos/11.0/perimeter_fw.xml"


@pytest.fixture(scope="module")
def config_text() -> str:
    return FIXTURE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ncm(config_text: str) -> dict[str, Any]:
    return get_parser("panos").parse(ParseContext(text=config_text)).to_storage()


@pytest.fixture(scope="module")
def resolved(ncm: dict[str, Any]):
    return resolve_rulebase(ncm["firewall"])


# ───────────────────────────── device and mgmt ──────────────────────────────


class TestDeviceIdentity:
    def test_identity(self, ncm: dict[str, Any]) -> None:
        device = ncm["device"]
        assert device["hostname"] == "perimeter-fw-01"
        assert device["domain_name"] == "example.com"
        assert device["vendor"] == "paloalto"
        assert device["platform"] == "panos"

    def test_ha_is_read(self, ncm: dict[str, Any]) -> None:
        assert ncm["device"]["ha"]["enabled"] is True

    def test_the_version_is_left_unknown_rather_than_guessed(self, ncm: dict[str, Any]) -> None:
        """The running version is not in the configuration — it comes from `show system
        info`, which the profile issues separately. Inventing one here would make the
        vulnerability matcher confidently wrong about which CVEs apply."""
        assert ncm["device"]["version"] is None


class TestManagementServices:
    """The `disable-*` inversion, which is the single easiest thing to get backwards."""

    @pytest.mark.parametrize(
        ("service", "expected"),
        [
            ("telnet", False),  # <disable-telnet>yes</disable-telnet>
            ("http", True),  # <disable-http>no</disable-http>
            ("https", True),
            ("ssh", True),
            ("snmp", True),
        ],
    )
    def test_disable_flags_are_inverted(
        self, ncm: dict[str, Any], service: str, expected: bool
    ) -> None:
        assert ncm["management"]["services"][service]["enabled"] is expected

    def test_a_service_the_config_never_mentions_is_not_reported_as_off(self) -> None:
        """Absent is not False. A configuration with no `<service>` block leaves every
        service unknown, and the checks must report Not Evaluated rather than passing a
        device nobody has actually looked at."""
        minimal = (
            "<config><devices><entry><deviceconfig><system>"
            "<hostname>bare</hostname>"
            "</system></deviceconfig></entry></devices></config>"
        )
        ncm = get_parser("panos").parse(ParseContext(text=minimal)).to_storage()
        assert ncm["management"]["services"]["telnet"]["enabled"] is None

    def test_the_idle_timeout_is_converted_to_seconds(self, ncm: dict[str, Any]) -> None:
        """PAN-OS states it in minutes; the NCM is seconds everywhere, or the
        vendor-neutral timeout check compares 60 against 600."""
        assert ncm["management"]["session"]["exec_timeout_s"] == 3600

    def test_the_permitted_ip_list_is_captured(self, ncm: dict[str, Any]) -> None:
        """This is what makes management exposure assessable: HTTP is enabled, but only
        reachable from one subnet, and a finding that ignored that would overstate."""
        assert "10.100.0.0/24" in ncm["management"]["management_acls"]["permitted-ip"]

    def test_the_login_banner_is_captured(self, ncm: dict[str, Any]) -> None:
        assert "Authorised users only" in ncm["management"]["banners"]["login"]

    def test_the_password_policy_is_read(self, ncm: dict[str, Any]) -> None:
        policy = ncm["management"]["password_policy"]
        assert policy["complexity_required"] is True
        assert policy["min_length"] == 12


class TestAccounts:
    def test_roles_and_privilege_are_mapped(self, ncm: dict[str, Any]) -> None:
        users = {u["name"]: u for u in ncm["users"]}
        assert set(users) == {"admin", "netsecops"}
        # superuser maps to 15 so the vendor-neutral privilege checks apply unchanged.
        assert users["admin"]["role"] == "superuser"
        assert users["admin"]["privilege"] == 15
        assert users["netsecops"]["role"] == "devicereader"
        assert users["netsecops"]["privilege"] is None

    def test_the_hash_algorithm_is_classified(self, ncm: dict[str, Any]) -> None:
        users = {u["name"]: u for u in ncm["users"]}
        assert users["admin"]["secret_type"] == "md5-crypt"
        assert users["admin"]["weak_hash"] is True
        assert users["netsecops"]["secret_type"] == "sha-crypt"
        assert users["netsecops"]["weak_hash"] is False

    def test_an_unrecognised_hash_is_not_called_weak(self) -> None:
        """Not recognised and known-weak are different facts. Reporting an unknown
        prefix as weak accuses a device of something unproven."""
        config = (
            "<config><mgt-config><users><entry name='x'>"
            "<phash>{SSHA}somethingunfamiliar</phash>"
            "</entry></users></mgt-config></config>"
        )
        ncm = get_parser("panos").parse(ParseContext(text=config)).to_storage()
        assert ncm["users"][0]["secret_type"] == "unknown"
        assert ncm["users"][0]["weak_hash"] is None


class TestLoggingTimeAndSnmp:
    def test_syslog_comes_from_the_shared_log_settings(self, ncm: dict[str, Any]) -> None:
        servers = ncm["logging"]["syslog_servers"]
        assert len(servers) == 1
        assert servers[0]["host"] == "10.100.5.10"
        assert servers[0]["port"] == 514
        assert servers[0]["transport"] == "TCP"

    def test_ntp_servers_are_read_from_their_named_tags(self, ncm: dict[str, Any]) -> None:
        """PAN-OS names them `primary-ntp-server` and `secondary-ntp-server` rather than
        using a list, so a parser looking for entries would find none."""
        assert [s["host"] for s in ncm["ntp"]["servers"]] == ["10.100.5.40", "10.100.5.41"]

    def test_ntp_authentication_is_answered_not_guessed(self, ncm: dict[str, Any]) -> None:
        """`<authentication-type><none/></authentication-type>` is explicit, which is
        why this can be False rather than unknown."""
        assert ncm["ntp"]["authenticated"] is False

    def test_the_timezone_is_captured(self, ncm: dict[str, Any]) -> None:
        assert ncm["ntp"]["timezone"] == "Europe/London"

    def test_the_snmp_community_is_masked_and_flagged_as_default(self, ncm: dict[str, Any]) -> None:
        communities = ncm["snmp"]["v1v2c_communities"]

        assert len(communities) == 1
        assert communities[0]["is_default"] is True
        assert communities[0]["rw"] is False
        assert "public" not in communities[0]["name_masked"]

    def test_certificates_are_parsed_with_their_validity(self, ncm: dict[str, Any]) -> None:
        certificates = ncm["certificates"]
        assert len(certificates) == 1
        assert certificates[0]["name"] == "perimeter-mgmt"
        assert certificates[0]["not_after"] == "2027/01/01 00:00:00"
        assert certificates[0]["self_signed"] is False


class TestInterfaces:
    def test_interfaces_carry_their_zone(self, ncm: dict[str, Any]) -> None:
        """The zone lives under vsys, not under the interface, so this is a join. Without
        it every rule's zones would be unmatchable against interface addressing."""
        interfaces = {i["name"]: i for i in ncm["interfaces"]}
        assert interfaces["ethernet1/1"]["zone"] == "untrust"
        assert interfaces["ethernet1/2"]["zone"] == "dmz"
        assert interfaces["ethernet1/3"]["zone"] == "trust"

    def test_addresses_are_captured(self, ncm: dict[str, Any]) -> None:
        interfaces = {i["name"]: i for i in ncm["interfaces"]}
        assert interfaces["ethernet1/1"]["ip_addresses"] == ["203.0.113.2/24"]


# ──────────────────────────── the firewall block ────────────────────────────


class TestTheFirewallBlock:
    def test_every_rule_is_parsed_in_order(self, ncm: dict[str, Any]) -> None:
        rules = ncm["firewall"]["security_rules"]
        assert len(rules) == 8
        assert [r["order"] for r in rules] == list(range(1, 9))
        assert rules[0]["name"] == "Mgmt to DMZ"

    def test_a_disabled_rule_is_marked_disabled(self, ncm: dict[str, Any]) -> None:
        rules = {r["name"]: r for r in ncm["firewall"]["security_rules"]}
        assert rules["Old migration rule"]["enabled"] is False
        assert rules["Inbound web"]["enabled"] is True

    def test_log_end_distinguishes_no_from_absent(self, ncm: dict[str, Any]) -> None:
        rules = {r["name"]: r for r in ncm["firewall"]["security_rules"]}
        assert rules["Inbound web"]["log_end"] is True
        assert rules["Outbound any"]["log_end"] is False
        # No <log-start> anywhere in the fixture: unknown, not off.
        assert rules["Inbound web"]["log_start"] is None

    def test_a_profile_group_and_individual_profiles_both_register(
        self, ncm: dict[str, Any]
    ) -> None:
        """PAN-OS allows either a group reference or a set of individual profiles, and a
        rule using a group is protected just as much as one listing them out. Reading
        only the individual form would report a well-configured rule as uninspected."""
        rules = {r["name"]: r for r in ncm["firewall"]["security_rules"]}

        assert rules["Mgmt to DMZ"]["profiles"] == {"group": "default"}
        assert rules["Inbound web"]["profiles"]["ips"] == "strict"
        assert rules["Inbound web"]["profiles"]["antivirus"] == "default"
        assert rules["Inbound web"]["profiles"]["url"] == "default"
        # An empty dict is what the no-profiles finding keys on.
        assert rules["Outbound any"]["profiles"] == {}

    def test_applications_are_kept(self, ncm: dict[str, Any]) -> None:
        """App-ID is the reason two PAN-OS rules on the same ports may not overlap, so
        the analyser needs these to avoid claiming relationships that do not exist."""
        rules = {r["name"]: r for r in ncm["firewall"]["security_rules"]}
        assert rules["Inbound web"]["applications"] == ["web-browsing", "ssl"]

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("web-01", "10.20.0.10/32"),
            ("dmz-net", "10.20.0.0/24"),
            ("partner-range", "198.51.100.10-198.51.100.20"),
        ],
    )
    def test_address_objects_render_in_a_parseable_form(
        self, ncm: dict[str, Any], name: str, expected: str
    ) -> None:
        objects = {o["name"]: o for o in ncm["firewall"]["address_objects"]}
        assert objects[name]["value"] == expected

    def test_an_fqdn_object_resolves_to_nothing_rather_than_to_everything(self) -> None:
        """An FQDN is resolved at runtime and the configuration does not say to what.
        Rendering it as an empty value makes the rule report unresolved; guessing, or
        defaulting to any, would silently claim the rule covers the whole internet."""
        config = (
            "<config><devices><entry><vsys><entry name='vsys1'><address>"
            "<entry name='partner-site'><fqdn>partner.example.com</fqdn></entry>"
            "</address></entry></vsys></entry></devices></config>"
        )
        ncm = get_parser("panos").parse(ParseContext(text=config)).to_storage()
        obj = ncm["firewall"]["address_objects"][0]
        assert obj["type"] == "fqdn"
        assert obj["value"] == ""

    def test_service_objects_render_with_their_protocol(self, ncm: dict[str, Any]) -> None:
        services = {o["name"]: o for o in ncm["firewall"]["service_objects"]}
        assert services["svc-https"]["value"] == "tcp/443"
        assert services["svc-unused"]["value"] == "udp/161"

    def test_groups_are_kept_separate_from_their_members(self, ncm: dict[str, Any]) -> None:
        groups = {g["name"]: g for g in ncm["firewall"]["address_groups"]}
        assert groups["web-servers"]["members"] == ["web-01", "web-02"]

        service_groups = {g["name"]: g for g in ncm["firewall"]["service_groups"]}
        assert service_groups["web-services"]["members"] == ["svc-https", "svc-http"]

    def test_zones_are_collected(self, ncm: dict[str, Any]) -> None:
        assert ncm["firewall"]["zones"] == ["dmz", "trust", "untrust"]

    def test_nat_rules_record_their_direction(self, ncm: dict[str, Any]) -> None:
        """Destination NAT is what exposes an internal host to the internet, and source
        NAT is not — FR-FW-04 turns on telling them apart."""
        nat = {r["name"]: r for r in ncm["firewall"]["nat_rules"]}

        assert nat["Inbound web NAT"]["direction"] == "destination"
        assert nat["Inbound web NAT"]["translated"] == "10.20.0.10:443"
        assert nat["Outbound PAT"]["direction"] == "source"
        assert nat["Outbound PAT"]["translated"] == "ethernet1/1"


MULTI_VSYS = """<config><devices><entry><vsys>
      <entry name="vsys1">
        <zone><entry name="trust"/></zone>
        <address><entry name="net"><ip-netmask>10.0.0.0/24</ip-netmask></entry></address>
        <rulebase><security><rules>
          <entry name="Allow all">
            <from><member>trust</member></from><to><member>trust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <service><member>any</member></service><action>allow</action>
          </entry>
        </rules></security></rulebase>
      </entry>
      <entry name="vsys2">
        <zone><entry name="trust"/></zone>
        <address><entry name="net"><ip-netmask>172.16.0.0/24</ip-netmask></entry></address>
        <rulebase><security><rules>
          <entry name="Allow all">
            <from><member>trust</member></from><to><member>trust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <service><member>any</member></service><action>allow</action>
          </entry>
        </rules></security></rulebase>
      </entry>
    </vsys></entry></devices></config>"""


@pytest.fixture(scope="module")
def multi() -> dict[str, Any]:
    return get_parser("panos").parse(ParseContext(text=MULTI_VSYS)).to_storage()


class TestVsysIsolation:
    """Two virtual systems are separate policy domains (SRS §C-6).

    A rule in vsys2 cannot shadow one in vsys1, however identical they look. If the
    parser flattened them, the analyser would report shadowing across the boundary and
    send an operator to delete a rule that is doing its job.
    """

    def test_names_are_qualified_when_there_is_more_than_one_vsys(
        self, multi: dict[str, Any]
    ) -> None:
        names = [r["name"] for r in multi["firewall"]["security_rules"]]
        assert names == ["vsys1/Allow all", "vsys2/Allow all"]
        assert multi["firewall"]["zones"] == ["vsys1/trust", "vsys2/trust"]

    def test_same_named_objects_in_different_vsys_stay_distinct(
        self, multi: dict[str, Any]
    ) -> None:
        """Both vsys define `net`, meaning different subnets. Collapsing them would make
        one vsys's rules cover the other's addresses."""
        objects = {o["name"]: o["value"] for o in multi["firewall"]["address_objects"]}
        assert objects["vsys1/net"] == "10.0.0.0/24"
        assert objects["vsys2/net"] == "172.16.0.0/24"

    def test_no_relationship_is_claimed_across_the_boundary(self, multi: dict[str, Any]) -> None:
        """The assertion the qualification exists for."""
        rules, _ = resolve_rulebase(multi["firewall"])
        assert analyse(rules).relationships == []

    def test_a_single_vsys_is_not_qualified(self, ncm: dict[str, Any]) -> None:
        """Qualifying the common case would make every finding read `vsys1/web-01` for
        no benefit to anyone reading it."""
        assert all("/" not in r["name"] for r in ncm["firewall"]["security_rules"])


SHARED = """<config>
  <shared>
    <address>
      <entry name="dns"><ip-netmask>8.8.8.8/32</ip-netmask></entry>
      <entry name="ntp"><ip-netmask>1.1.1.1/32</ip-netmask></entry>
    </address>
  </shared>
  <devices><entry><vsys><entry name="vsys1">
    <address><entry name="dns"><ip-netmask>10.0.0.53/32</ip-netmask></entry></address>
  </entry></vsys></entry></devices>
</config>"""


@pytest.fixture(scope="module")
def shared_ncm() -> dict[str, Any]:
    return get_parser("panos").parse(ParseContext(text=SHARED)).to_storage()


class TestSharedObjects:
    """A vsys-local name wins over a shared one, which is what the device does."""

    def test_a_shared_object_is_available(self, shared_ncm: dict[str, Any]) -> None:
        names = [o["name"] for o in shared_ncm["firewall"]["address_objects"]]
        assert "ntp" in names

    def test_the_vsys_definition_is_collected_after_the_shared_one(
        self, shared_ncm: dict[str, Any]
    ) -> None:
        """Order is the mechanism: the resolver takes the last definition of a name, so
        shared must be collected first for the local override to win."""
        values = [
            o["value"] for o in shared_ncm["firewall"]["address_objects"] if o["name"] == "dns"
        ]
        assert values[-1] == "10.0.0.53/32"

        _rules, resolver = resolve_rulebase(shared_ncm["firewall"])
        addresses, missing = resolver.resolve_addresses(["dns"])

        assert not missing
        assert addresses.v4.size == 1
        # 10.0.0.53, not 8.8.8.8: the local definition wins.
        local = int(IPv4Address("10.0.0.53"))
        assert addresses.v4.intervals == ((local, local),)


# ──────────────────────── parser health (the tripwire) ──────────────────────


class TestParserHealth:
    def test_no_section_fails_silently(
        self, config_text: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Each parser section is wrapped so one bad stanza cannot cost the rest. The
        cost is that a section which fails *every* time fails invisibly, and the fields
        it would have filled report Not Evaluated forever.

        On FortiOS this exact test caught `_parse_snmp` importing from the wrong module,
        so no FortiGate would ever have had its SNMP configuration assessed — and
        nothing would have said so.
        """
        with caplog.at_level(logging.WARNING):
            get_parser("panos").parse(ParseContext(text=config_text))

        failures = [r for r in caplog.records if "section_failed" in r.getMessage()]
        assert not failures, [r.getMessage() for r in failures]

    def test_every_section_actually_populates_something(self, ncm: dict[str, Any]) -> None:
        """The companion to the tripwire above: a section can also fail by quietly
        matching nothing, which logs no warning at all. The fixture exercises every
        section, so an empty one here means the section found nothing it was looking
        for."""
        assert ncm["device"]["hostname"]
        assert ncm["management"]["services"]["ssh"]["enabled"] is not None
        assert ncm["users"]
        assert ncm["logging"]["syslog_servers"]
        assert ncm["snmp"]["v1v2c_communities"]
        assert ncm["interfaces"]
        assert ncm["firewall"]["security_rules"]
        assert ncm["certificates"]

    def test_no_secret_reaches_the_ncm(self, ncm: dict[str, Any]) -> None:
        """C-2. The password hashes are the secrets in this fixture: the NCM keeps the
        algorithm and the weak-hash verdict, never the material itself."""
        serialised = json.dumps(ncm)
        for secret in (
            "$1$abcdefgh$ijklmnopqrstuvwxyz012345",
            "$5$qrstuvwx$yzabcdefghijklmnopqrstuv0123",
            "public",
        ):
            assert secret not in serialised, f"{secret} leaked into the NCM"

    def test_provenance_points_at_real_lines(self, config_text: str, ncm: dict[str, Any]) -> None:
        line_count = len(config_text.splitlines())
        entries = ncm["provenance"]["entries"]

        assert entries
        for path, entry in entries.items():
            assert 1 <= entry["line_start"] <= line_count, f"{path} points outside the file"

    def test_malformed_xml_produces_a_snapshot_rather_than_an_exception(self) -> None:
        """A truncated capture must still yield a snapshot whose checks all report Not
        Evaluated. Raising here would lose the collection and the audit record with it.
        """
        result = get_parser("panos").parse(ParseContext(text="<config><devices>"))

        assert result.device.vendor == "paloalto"
        assert result.device.hostname is None
        assert result.raw_unparsed and "not well-formed" in result.raw_unparsed[0]

    def test_an_entity_expansion_is_refused(self) -> None:
        """A billion-laughs payload in a device configuration would otherwise exhaust a
        worker that has network access to the whole estate. defusedxml refuses it, and
        the refusal lands in the malformed-XML path above rather than as a crash."""
        bomb = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE config [<!ENTITY a "xxxxxxxxxx">'
            '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>'
            "<config><hostname>&c;</hostname></config>"
        )
        result = get_parser("panos").parse(ParseContext(text=bomb))

        assert result.device.hostname is None
        assert result.raw_unparsed

    def test_an_external_entity_is_not_fetched(self) -> None:
        """XXE. The parser runs where it can reach both the filesystem and the estate."""
        xxe = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE config [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<config><devices><entry><deviceconfig><system>"
            "<hostname>&xxe;</hostname>"
            "</system></deviceconfig></entry></devices></config>"
        )
        result = get_parser("panos").parse(ParseContext(text=xxe))
        assert result.device.hostname is None

    def test_garbage_does_not_raise(self) -> None:
        assert get_parser("panos").parse(ParseContext(text="not xml at all\n\x00")) is not None

    def test_an_empty_configuration_does_not_raise(self) -> None:
        assert get_parser("panos").parse(ParseContext(text="")).device.hostname is None

    def test_an_api_response_wrapper_is_unwrapped(self) -> None:
        """The XML API returns `<response><result><config>…`. A parser that only
        accepted a bare `<config>` root would find nothing in a real collection and
        report a clean device."""
        wrapped = (
            '<response status="success"><result><config>'
            "<devices><entry><deviceconfig><system>"
            "<hostname>wrapped-fw</hostname>"
            "</system></deviceconfig></entry></devices>"
            "</config></result></response>"
        )
        result = get_parser("panos").parse(ParseContext(text=wrapped))
        assert result.device.hostname == "wrapped-fw"


# ──────────────────── the whole pipeline, end to end ────────────────────────


class TestTheFullPipeline:
    """Parse → resolve → analyse → findings, on one realistic configuration.

    This is what asserts the Phase 4 analysis connects to a vendor parser rather than
    working only on hand-built dictionaries.
    """

    def test_the_shadowed_rdp_rule_is_found(self, resolved) -> None:
        """#2 denies RDP from anywhere to anywhere; #3 tries to allow it from a partner
        range. #3 is dead, and an operator who believes the partner has access is wrong.
        """
        rules, _ = resolved
        shadowed = analyse(rules).by_kind(Relationship.SHADOWED)

        assert len(shadowed) == 1
        assert shadowed[0].subject.name == "Partner RDP to web"
        assert shadowed[0].cause.name == "Block inbound RDP"
        assert "denies it instead" in shadowed[0].detail

    def test_the_redundancy_names_the_narrow_rule_not_the_broad_one(self, resolved) -> None:
        """#7 permits everything trust→dmz, which makes the narrow #1 pointless — not
        the other way round. Naming #7 would send someone to delete the broad rule on a
        redundancy finding, when the broad rule is the actual problem and is already
        reported separately as any/any/any.
        """
        rules, _ = resolved
        redundant = analyse(rules).by_kind(Relationship.REDUNDANT)

        assert [(r.subject.name, r.cause.name) for r in redundant] == [
            ("Mgmt to DMZ", "Permit all internal to dmz")
        ]
        assert redundant[0].describe().startswith("Rule #1 (Mgmt to DMZ) is redundant")

    def test_the_redundancy_warns_that_removal_still_loses_inspection(self, resolved) -> None:
        """#1 is redundant on the permit/deny verdict alone, but it is the only one of
        the pair that logs and carries a profile group. Advising its removal without
        saying so would silently drop a log source and an inspection profile."""
        rules, _ = resolved
        redundant = analyse(rules).by_kind(Relationship.REDUNDANT)[0]

        assert "logging" in redundant.detail
        assert "security profiles" in redundant.detail

    def test_a_disabled_rule_is_left_out_of_the_analysis(self, resolved) -> None:
        """`Old migration rule` is any/any/any and disabled. Including it would produce
        a page of shadowing findings about a rule that does nothing."""
        rules, _ = resolved
        result = analyse(rules)

        assert result.rules_analysed == 7
        assert all(
            "Old migration rule" not in (r.earlier.name, r.later.name) for r in result.relationships
        )

    def test_the_any_any_any_rule_is_critical(self, resolved) -> None:
        rules, _ = resolved
        findings = examine_policy(rules).by_issue(RuleIssue.ANY_ANY_ANY)

        assert len(findings) == 1
        assert findings[0].rule_name == "Permit all internal to dmz"
        assert findings[0].severity == "critical"

    def test_the_cleanup_deny_is_not_reported_as_broad(self, resolved) -> None:
        """A final deny-all is any/any/any by design. Reporting it would flag the one
        thing every rulebase should have, and teach operators to ignore the finding."""
        rules, _ = resolved
        flagged = {f.rule_name for f in examine_policy(rules).findings if f.rule_name}
        assert "Cleanup deny" not in flagged

    def test_rdp_from_the_internet_is_reported_as_insecure(self, resolved) -> None:
        rules, _ = resolved
        insecure = examine_policy(rules).by_issue(RuleIssue.INSECURE_SERVICE)

        assert insecure
        assert "RDP" in insecure[0].message

    def test_unlogged_permit_rules_are_found(self, resolved) -> None:
        rules, _ = resolved
        unlogged = {f.rule_name for f in examine_policy(rules).by_issue(RuleIssue.NO_LOGGING)}

        assert "Outbound any" in unlogged
        # The rule that does log must not appear.
        assert "Inbound web" not in unlogged
        # Nor the any/any/any rule: it is reported once, as critical, and every other
        # finding about it would be a restatement of the same fact.
        assert "Permit all internal to dmz" not in unlogged

    def test_port_based_rules_on_an_app_aware_firewall_are_found(self, resolved) -> None:
        """`application: any` on PAN-OS means App-ID is switched off for that rule.

        The device can identify applications and the rule declines to ask, so anything
        willing to speak on the permitted port passes — the behaviour of the port-based
        firewall a next-generation one was bought to replace. Nothing else in the
        analysis notices: such a rule can be unshadowed, non-redundant, narrowly scoped
        and fully logged.
        """
        rules, _ = resolved
        port_based = {
            f.rule_name for f in examine_policy(rules).by_issue(RuleIssue.NO_APPLICATION_IDENTITY)
        }

        assert "Partner RDP to web" in port_based
        assert "Outbound any" in port_based
        # The rules that do name applications must not appear.
        assert "Inbound web" not in port_based
        assert "Mgmt to DMZ" not in port_based
        # Nor a disabled rule: it permits nothing, so its App-ID posture is not a
        # finding. `Old migration rule` is `application: any` and carries `disabled: yes`.
        assert "Old migration rule" not in port_based
        # Nor the any/any/any rule, which is reported once as critical — every other
        # finding about it restates the same fact.
        assert "Permit all internal to dmz" not in port_based

    def test_a_platform_without_app_id_is_not_penalised(self) -> None:
        """Empty is not `any`, and the difference decides whether this fires at all.

        An ASA access list has no application identity to express, so its rules carry an
        empty set. Treating that as "App-ID not in use" would raise the finding on every
        rule of every Cisco device in an estate, and a check that fires everywhere is one
        nobody reads.
        """
        from pathlib import Path

        asa = Path(__file__).parent / "fixtures/cisco/asa/9.18/edge_firewall.cfg"
        ncm = (
            get_parser("cisco_asa")
            .parse(
                ParseContext(text=asa.read_text(encoding="utf-8"), command="show running-config")
            )
            .to_storage()
        )
        rules, _ = resolve_rulebase(ncm["firewall"])

        assert rules, "the ASA fixture must yield rules, or this proves nothing"
        assert not examine_policy(rules).by_issue(RuleIssue.NO_APPLICATION_IDENTITY)

    def test_the_duplicate_object_is_found(self, resolved) -> None:
        """`web-01` and `web-01-copy` are both 10.20.0.10/32. Two names for one host is
        how a rulebase drifts into covering the same thing twice."""
        rules, resolver = resolved
        duplicates = examine_hygiene(resolver, rules).by_issue(HygieneIssue.DUPLICATE_OBJECT)

        assert len(duplicates) == 1
        assert "web-01" in duplicates[0].name
        assert "web-01-copy" in duplicates[0].name

    def test_unused_objects_are_found(self, resolved) -> None:
        rules, resolver = resolved
        unused = {
            f.name for f in examine_hygiene(resolver, rules).by_issue(HygieneIssue.UNUSED_OBJECT)
        }

        assert "never-used" in unused
        assert "svc-unused" in unused
        # An object reached only through a group is used, not unused.
        assert "web-02" not in unused

    def test_groups_resolve_to_their_members(self, resolved) -> None:
        rules, _ = resolved
        rule = next(r for r in rules if r.name == "Inbound web")

        # web-servers = web-01 + web-02, two /32s.
        assert rule.destination.v4.size == 2
        # web-services = tcp/443 + tcp/80, on TCP alone.
        assert list(rule.services.by_protocol) == [PROTOCOL_NUMBERS["tcp"]]
        assert rule.services.by_protocol[PROTOCOL_NUMBERS["tcp"]].size == 2
