"""The read-only contract for a Radware Alteon (SRS §1.3.1, §8.1, §8.2).

**Alteon is the platform where the three-layer guard is weakest, and it is weakest in a
way that is invisible unless you go looking.** Every other platform in this product
writes with a verb at the start of a command — `set`, `no`, `write`, `delete` — which
is what `DENY_PATTERN` is anchored to catch. Alteon writes by navigating a menu tree:

    /cfg/dump              prints the configuration
    /cfg/sys/ssnmp/wcomm   sets the SNMP write community

One leaf apart, neither beginning with a verb. Before `/cfg/(?!dump\\b)` was added to
the deny-list, layer 3 fired on nothing an Alteon adapter could possibly send, and the
allow-list was the only control left on the one platform where a mistyped entry costs
the most. These tests hold both layers to that.

There is no collection profile for this platform yet, and that is deliberate rather
than unfinished: a profile implies a parser, and no sample of Alteon's `cc` output
exists in public documentation to write one against. Radware's command reference is
behind a support login. What can be reviewed today — what NetSecOps would be *permitted*
to send — is reviewable today.
"""

from __future__ import annotations

import pytest

from netsecops.adapters.policies import POLICIES
from netsecops.adapters.profiles import PROFILES
from netsecops.adapters.readonly import DENY_PATTERN, ReadOnlyGuard
from netsecops.core.errors import ReadOnlyViolationError
from netsecops.parsers.registry import PARSERS


@pytest.fixture
def guard() -> ReadOnlyGuard:
    return ReadOnlyGuard(POLICIES["radware_alteon"])


class TestTheDenyListReachesAlteonAtAll:
    """Layer 3. It did not, and nothing said so."""

    @pytest.mark.parametrize(
        "command",
        [
            "/cfg/sys/ssnmp/wcomm",
            "/cfg/sys/access/telnet",
            "/cfg/slb/virt 1/service 443/ssl",
            "/cfg/sys/user/uid 1",
            "/cfg/l3/if 1",
        ],
    )
    def test_a_configuration_path_is_a_write(self, command: str) -> None:
        assert DENY_PATTERN.match(command), f"{command} is not caught by the deny-list"

    def test_the_dump_leaf_is_the_one_exception(self) -> None:
        assert DENY_PATTERN.match("/cfg/dump") is None

    def test_the_exception_is_a_whole_word(self) -> None:
        """`/cfg/dumpfoo` is not `/cfg/dump`.

        A prefix exception would admit any command whose first seven characters
        happened to match, which on a menu tree is not a hypothetical shape.
        """
        assert DENY_PATTERN.match("/cfg/dumpster") is not None

    def test_the_rule_does_not_disturb_any_other_platform(self) -> None:
        # No other platform issues a command beginning `/cfg/`, which is why this could
        # be added globally rather than per-platform. If one ever does, this fails.
        for platform, policy in POLICIES.items():
            if platform == "radware_alteon":
                continue
            for rule in policy.commands:
                assert not rule.pattern.startswith("/cfg/"), (
                    f"{platform} now issues {rule.pattern}; the global /cfg/ deny rule "
                    "is no longer Alteon-only and needs revisiting"
                )


class TestTheAllowListIsLayerTwo:
    """Redundant with the above on purpose. Either alone would be enough today; the
    point of three layers is that a mistake in one is caught by another."""

    @pytest.mark.parametrize(
        "command",
        ["/cfg/dump", "cc", "/info/sys", "/info/slb", "/info/link"],
    )
    def test_the_documented_read_commands_are_permitted(
        self, guard: ReadOnlyGuard, command: str
    ) -> None:
        assert guard.check_command(command) is not None

    @pytest.mark.parametrize(
        "command",
        [
            "/cfg/sys/ssnmp/wcomm",
            "/cfg/sys/access/telnet ena",
            "/cfg/slb/virt 1",
            "/oper/slb/dis",
            "apply",
            "save",
        ],
    )
    def test_everything_else_is_refused(self, guard: ReadOnlyGuard, command: str) -> None:
        with pytest.raises(ReadOnlyViolationError):
            guard.check_command(command)

    def test_no_entry_uses_a_placeholder_under_the_configuration_tree(self) -> None:
        """The trap that would undo all of the above in one line.

        A placeholder matches `[A-Za-z0-9_.:/@=-]+`, and that charset includes `/`. So
        a single entry spelled `/cfg/<subtree>` would admit the entire configuration
        tree in one token — `/cfg/sys/ssnmp/wcomm` is one placeholder's worth of text.
        Every Alteon entry is a literal, and this is what keeps it that way.
        """
        for rule in POLICIES["radware_alteon"].commands:
            if rule.pattern.startswith("/cfg/"):
                assert "<" not in rule.pattern, (
                    f"{rule.pattern} puts a placeholder under /cfg/, which admits the "
                    "whole configuration tree"
                )

    def test_nothing_is_marked_session_only(self) -> None:
        """`session_only` waves a command past the deny-list.

        On Alteon that is the only layer standing between a typo and a write, so the
        flag is not used here at all — including for paging, whose Alteon spelling
        could not be confirmed. Output that comes back paged is a visible failure;
        an invented paging command would not be.
        """
        assert not [rule for rule in POLICIES["radware_alteon"].commands if rule.session_only]


class TestItIsNotCollectableYet:
    def test_the_platform_has_a_policy_and_no_profile(self) -> None:
        """Deliberate, and the registries permit it — `cisco_iosxr` and `fortimanager`
        are in the same state. A profile implies a parser, and there is no sample of
        `cc` output in public documentation to write one against."""
        assert "radware_alteon" in POLICIES
        assert "radware_alteon" not in PROFILES
        assert "radware_alteon" not in PARSERS
