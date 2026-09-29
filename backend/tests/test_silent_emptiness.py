"""Nothing in a shipped fixture may resolve to nothing without saying so.

The ASA rulebase matched no packet at all, for four separate reasons, and looked
completely healthy on every screen. The mechanism — an address or service resolving to an
empty set rather than raising — lives in the shared resolver, so PAN-OS, FortiOS and
Check Point were equally exposed and had never been checked.

This sweeps every device fixture in the repository and fails on anything that is
*silently* nothing. It is deliberately a test rather than a script: the property it
protects is one nothing else notices, and a script nobody runs protects nothing.

What it does not do is assert that the fixtures are *correct* — only that where the
product concludes "nothing", it is because there is nothing rather than because it could
not read something.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsecops.firewall.model import EXTERNALLY_RESOLVED_TYPES, resolve_rulebase
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURES = Path(__file__).parent / "fixtures"

#: Fixture directory → the platform its files are written for. Directories holding
#: manager inventories, operational command output and feed bundles are not device
#: configurations and are skipped.
PLATFORM_DIRS: dict[str, str] = {
    "checkpoint/gaia": "checkpoint_gaia",
    "checkpoint/mgmt": "checkpoint_mgmt",
    "cisco/asa": "cisco_asa",
    # A Catalyst 9800's configuration is IOS-XE and parses with the IOS parser, but it
    # is not a switch configuration and it is not collected like one — its profile asks
    # for the wireless show commands as well. Its own directory so the sweep exercises
    # it as the platform a device would actually be onboarded as.
    "cisco/c9800": "cisco_c9800",
    "cisco/ios": "cisco_ios",
    "cisco/ise": "cisco_ise",
    "cisco/nxos": "cisco_nxos",
    "cisco/wlc": "cisco_wlc_aireos",
    "fortinet/fortiauthenticator": "fortiauthenticator",
    "fortinet/fortios": "fortios",
    "linux/freeradius": "freeradius",
    "linux/tacplus": "tac_plus",
    "paloalto/panos": "panos",
    # An ADC, and the first platform whose configuration is a menu tree rather than a
    # stanza list. It belongs in the sweep for the ordinary reason: a parser nothing
    # exercises is one whose output could go inert without anybody finding out.
    "radware/alteon": "radware_alteon",
    # A WAF, read as a bundle of REST responses keyed by endpoint. Its bundle is a
    # configuration in the sense that matters here — it is what the checks run against.
    "barracuda/waf": "barracuda_waf",
    # SRX, MX and EX. The fixture is the brace form, which is the harder of the two
    # Junos formats and therefore the one worth sweeping.
    "juniper/junos": "juniper_junos",
    # An ADC. No rulebase of its own, so the rule sweeps skip it — but the corpus is
    # also what proves a parser has not gone inert, which applies to every platform.
    "f5/bigip": "f5_bigip",
    # EOS. In the sweep for the same reason as the rest, and with a particular edge of
    # its own: it shares a base class with the IOS parser, so a change there can go
    # inert here without any Cisco test noticing.
    "arista/eos": "arista_eos",
    # Firepower through its management centre. A bundle of REST responses, and the one
    # platform in the corpus whose rulebase carries a non-terminating action.
    "cisco/fmc": "cisco_ftd_fmc",
    # The four read from an export rather than collected. They belong in the sweep more
    # than most: each flattens a model that is not an ordered rulebase into one, and an
    # empty match set is the specific way that flattening goes wrong.
    "vmware/nsx": "vmware_nsx",
    "cisco/aci": "cisco_aci",
    "cloud/aws": "aws_vpc",
    "cloud/azure": "azure_nsg",
    # A forward proxy. It has no rulebase — SGOS policy is CPL in a separate file — so
    # the rule sweeps skip it, and the populated-NCM sweep is the one that matters here.
    "symantec/proxysg": "symantec_proxysg",
}


def device_fixtures() -> list[tuple[str, str]]:
    """Every device configuration in the repository, as (relative path, platform)."""
    found: list[tuple[str, str]] = []
    for path in sorted(FIXTURES.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(FIXTURES).as_posix()
        for prefix, platform in PLATFORM_DIRS.items():
            if relative.startswith(f"{prefix}/"):
                found.append((relative, platform))
                break
    return found


CASES = device_fixtures()


def parse(relative: str, platform: str):
    text = (FIXTURES / relative).read_text(encoding="utf-8")
    return get_parser(platform).parse(ParseContext(text=text))


class TestTheCorpusIsSwept:
    def test_there_is_something_to_sweep(self) -> None:
        """A mapping that stops matching would turn this whole file into a no-op that
        passes — the exact shape of failure it exists to catch."""
        assert len(CASES) >= 12, f"only {len(CASES)} device fixtures matched a platform"

    def test_every_platform_with_a_parser_has_a_fixture(self) -> None:
        """A platform nothing exercises is a platform whose rulebase could be inert
        without anybody finding out, which is how the ASA got here."""
        from netsecops.parsers.registry import PARSERS

        covered = {platform for _, platform in CASES}
        # `cisco_iosxe` shares the IOS parser and has no fixture of its own; the ISE and
        # FortiAuthenticator parsers read API payloads, which are covered above.
        missing = set(PARSERS) - covered - {"cisco_iosxe"}
        assert missing == set(), f"no fixture exercises: {sorted(missing)}"


class TestTheResolverRefusesRatherThanReturningNothing:
    """The backstop, tested on synthetic input because the fixtures no longer trip it.

    Sweeping the corpus proves the shipped data is clean; it cannot prove the *mechanism*
    is fixed, because a parser that emits a good value never exercises the path. These
    two assert the resolver's own behaviour: an object it cannot read is refused, not
    silently resolved to nothing.
    """

    @staticmethod
    def _rule_with(source: str, **firewall) -> object:
        base = {
            "security_rules": [
                {"order": 1, "name": "r", "action": "allow", "src": [source], "dst": ["any"]}
            ]
        }
        return resolve_rulebase({**base, **firewall})[0][0]

    def test_an_object_whose_value_cannot_be_read_is_unresolved(self) -> None:
        rule = self._rule_with(
            "OBJ",
            address_objects=[{"name": "OBJ", "type": "network", "value": "host 10.20.0.10"}],
        )

        assert rule.unresolved, "an unreadable object must not resolve to the empty set"
        assert not rule.source

    def test_a_group_whose_members_cannot_be_read_is_unresolved(self) -> None:
        rule = self._rule_with(
            "GRP",
            address_groups=[{"name": "GRP", "type": "network", "members": ["host 10.1.1.1"]}],
        )

        assert rule.unresolved

    def test_a_genuinely_empty_group_is_not_an_error(self) -> None:
        """An empty object-group is a real thing to write and legitimately stands for
        nothing. The distinction is whether there were members at all — conflating the
        two would replace a silent failure with a noisy false one."""
        rule = self._rule_with(
            "GRP", address_groups=[{"name": "GRP", "type": "network", "members": []}]
        )

        assert rule.unresolved == ()

    def test_a_readable_object_still_resolves(self) -> None:
        rule = self._rule_with(
            "OBJ",
            address_objects=[{"name": "OBJ", "type": "network", "value": "10.20.0.0/24"}],
        )

        assert rule.unresolved == ()
        assert rule.source


#: Object types whose membership is **defined outside the configuration** and never
#: appears in an export, however complete.
#:
#: This is a narrow, typed exception to the rule below, and it exists because the four
#: export-read platforms made the distinction unavoidable: an AWS security group stands
#: for the instances attached to it, an NSX dynamic group for whatever currently carries
#: a tag, an Azure service tag for ranges Microsoft publishes and changes, an ACI L2-only
#: EPG for a bridge domain with no gateway. None of them is a parser that failed to read
#: something — they are sets whose contents live somewhere this product is not looking.
#:
#: **The distinction is the point, not the exemption.** An object that resolves to
#: nothing because the parser could not read it is a defect. An object that resolves to
#: nothing because its membership is elsewhere is a limitation — and since 2026-09-29 a
#: path query crossing one reports that it cannot be evaluated, rather than silently
#: treating it as "no match" and returning the implicit deny as a confident `blocked`
#: (`test_undecidable_rules.py`).
#:
#: Imported rather than restated: while this set lived here alone, the product could not
#: act on a distinction its own test suite enforced, and a sixth type added to one copy
#: would not have reached the other.
EXTERNALLY_RESOLVED = EXTERNALLY_RESOLVED_TYPES


def externally_resolved(firewall: dict) -> set[str]:
    """Names in this rulebase whose membership is not in the configuration."""
    return {
        str(obj.get("name"))
        for kind in ("address_objects", "address_groups", "service_objects")
        for obj in firewall.get(kind) or []
        if obj.get("type") in EXTERNALLY_RESOLVED and obj.get("name")
    }


@pytest.mark.parametrize(("relative", "platform"), CASES, ids=[c[0] for c in CASES])
class TestNothingIsSilentlyEmpty:
    def test_it_parses_into_a_populated_ncm(self, relative: str, platform: str) -> None:
        """A configuration that parses to almost nothing passes every check on the
        device, which reads as a clean device rather than an unread one."""
        ncm = parse(relative, platform)

        populated = [
            name
            for name, value in ncm.model_dump(mode="json").items()
            if value not in (None, [], {}, "", 0)
        ]
        assert len(populated) > 2, f"{relative} parsed to almost nothing: {populated}"

    def test_no_rule_is_incapable_of_matching(self, relative: str, platform: str) -> None:
        """The ASA defect, generalised.

        A rule whose source, destination or service resolved to an empty set can never
        match a packet. Nothing errors and nothing is logged — the rule is simply skipped
        every time, so the access list silently behaves as though the entry were absent.
        """
        firewall = parse(relative, platform).firewall.model_dump(mode="json")
        if not firewall.get("security_rules"):
            pytest.skip("no rulebase on this platform")

        rules, _ = resolve_rulebase(firewall)
        external = externally_resolved(firewall)
        raw_rules = firewall.get("security_rules") or []

        inert: list[str] = []
        for index, rule in enumerate(rules):
            raw = raw_rules[index] if index < len(raw_rules) else {}
            sides = [
                side
                for side, value, members in (
                    ("source", rule.source, raw.get("src") or []),
                    ("destination", rule.destination, raw.get("dst") or []),
                    ("service", rule.services, raw.get("services") or []),
                )
                # Empty *and* not empty merely because every name it holds stands for a
                # set defined outside the configuration. A rule pointing at an AWS
                # security group is not a broken rule; it is one this export cannot
                # resolve, and the two must not read the same.
                if not value and not (members and all(m in external for m in members))
            ]
            if sides:
                inert.append(f"{rule.name} (empty {'+'.join(sides)})")

        assert inert == [], f"{relative}: {len(inert)}/{len(rules)} rules can never match: {inert}"

    def test_no_object_stands_for_nothing(self, relative: str, platform: str) -> None:
        """An address object the resolver cannot read used to return the empty set rather
        than an error, so every rule referencing it matched nothing while being parsed,
        ordered and analysed as though it were fine."""
        firewall = parse(relative, platform).firewall.model_dump(mode="json")
        if not firewall.get("security_rules"):
            pytest.skip("no rulebase on this platform")

        _, resolver = resolve_rulebase(firewall)
        empty: list[str] = []
        for kind in ("address_objects", "address_groups"):
            for obj in firewall.get(kind) or []:
                name = str(obj.get("name") or "")
                if not name:
                    continue
                # An object whose membership is defined outside the configuration is not
                # an object the parser failed to read. The type had to be set on purpose
                # for it to be exempt here.
                if obj.get("type") in EXTERNALLY_RESOLVED:
                    continue
                resolved, missing = resolver.resolve_addresses([name])
                if missing or (not resolved and not resolved.is_any):
                    empty.append(f"{kind[:-1]} {name}")

        assert empty == [], f"{relative}: objects standing for nothing: {empty}"
