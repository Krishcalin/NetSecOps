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

from netsecops.firewall.model import resolve_rulebase
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
    "cisco/ios": "cisco_ios",
    "cisco/ise": "cisco_ise",
    "cisco/nxos": "cisco_nxos",
    "cisco/wlc": "cisco_wlc_aireos",
    "fortinet/fortiauthenticator": "fortiauthenticator",
    "fortinet/fortios": "fortios",
    "linux/freeradius": "freeradius",
    "linux/tacplus": "tac_plus",
    "paloalto/panos": "panos",
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
        inert = [
            f"{rule.name} (empty "
            + "+".join(
                side
                for side, value in (
                    ("source", rule.source),
                    ("destination", rule.destination),
                    ("service", rule.services),
                )
                if not value
            )
            + ")"
            for rule in rules
            if not rule.source or not rule.destination or not rule.services
        ]

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
                resolved, missing = resolver.resolve_addresses([name])
                if missing or (not resolved and not resolved.is_any):
                    empty.append(f"{kind[:-1]} {name}")

        assert empty == [], f"{relative}: objects standing for nothing: {empty}"
