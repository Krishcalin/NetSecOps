"""Collection profile conformance (SRS §8.1, §8.2, FR-COL-02, C-6).

The read-only guarantee rests on one claim: NetSecOps can only send commands that
appear in ``policies.py``, which is the list a customer's security reviewer reads.
Collection profiles are the code that decides what actually gets sent, so the claim is
only true if every profile entry is on that list. These tests are what make it true —
a profile that reached for an unlisted command fails the build rather than quietly
expanding the device-facing surface.
"""

from __future__ import annotations

import pytest

from netsecops.adapters.policies import get_policy
from netsecops.adapters.profiles import PROFILES, CollectionProfile, NoProfileError, get_profile
from netsecops.adapters.readonly import ReadOnlyGuard
from netsecops.parsers.registry import supported_platforms


def guard_for(platform: str) -> ReadOnlyGuard:
    return ReadOnlyGuard(get_policy(platform))


@pytest.mark.parametrize("platform", sorted(PROFILES))
class TestProfilesStayInsideThePolicy:
    def test_every_command_is_on_the_allow_list(self, platform: str) -> None:
        """The single most important assertion in this file."""
        guard = guard_for(platform)
        profile = PROFILES[platform]

        for command in profile.all_commands():
            assert guard.permits_command(command), (
                f"{platform}: the collection profile sends {command!r}, which is not "
                f"on the platform's allow-list in policies.py. Either add it there "
                f"where a reviewer will see it, or remove it from the profile."
            )

    def test_a_policy_exists_at_all(self, platform: str) -> None:
        assert get_policy(platform) is not None

    def test_exactly_one_command_yields_the_configuration(self, platform: str) -> None:
        """Two config commands would make it ambiguous which output is parsed; none
        would make the profile unable to produce a snapshot."""
        profile = PROFILES[platform]
        config_commands = [c for c in profile.commands if c.yields_config]
        assert len(config_commands) == 1, (
            f"{platform}: {len(config_commands)} commands claim to yield the "
            "configuration; exactly one must."
        )
        assert profile.config_command == config_commands[0].command

    def test_only_the_configuration_is_required(self, platform: str) -> None:
        """FR-COL-08: a supplementary command that fails must degrade the collection
        to partial, not abort it. Marking anything else required would mean a switch
        without a licensed feature produces no assessment at all."""
        required = [c for c in PROFILES[platform].commands if c.required]
        assert [c.command for c in required] == [PROFILES[platform].config_command]

    def test_every_command_explains_itself(self, platform: str) -> None:
        """The purpose text is shown beside the artefact. A blank one leaves an
        operator watching a collection unable to tell what was wanted."""
        for entry in PROFILES[platform].commands:
            assert entry.purpose.strip(), f"{platform}: {entry.command!r} has no purpose"

    def test_no_duplicate_commands(self, platform: str) -> None:
        """A duplicate is a wasted round trip against production equipment."""
        commands = [c.command for c in PROFILES[platform].commands]
        assert len(commands) == len(set(commands)), (
            f"{platform}: profile repeats {sorted({c for c in commands if commands.count(c) > 1})}"
        )

    def test_setup_commands_are_session_only(self, platform: str) -> None:
        """Setup commands are the one place a profile sends something the deny-list
        would otherwise reject. Each must be a declared session-only exception —
        paging or width — and nothing else."""
        policy = get_policy(platform)
        session_only = {rule.pattern for rule in policy.commands if rule.session_only}

        for command in PROFILES[platform].setup:
            assert command in session_only, (
                f"{platform}: setup command {command!r} is not a declared session-only "
                "exception in policies.py"
            )

    def test_the_configuration_command_comes_first(self, platform: str) -> None:
        """If a session dies part way through, the configuration is the one output
        worth having — so it is collected before anything optional."""
        assert PROFILES[platform].commands[0].yields_config


class TestProfileRegistry:
    def test_every_platform_with_a_parser_has_a_profile(self) -> None:
        """A parser with no profile can never be reached from a live collection; a
        profile with no parser collects a configuration nothing can read."""
        assert set(supported_platforms()) == set(PROFILES), (
            "parsers and collection profiles have diverged: "
            f"parsers only = {set(supported_platforms()) - set(PROFILES)}, "
            f"profiles only = {set(PROFILES) - set(supported_platforms())}"
        )

    def test_unknown_platform_raises(self) -> None:
        with pytest.raises(NoProfileError, match="No collection profile"):
            get_profile("acme_router_9000")

    def test_iosxe_shares_the_ios_profile(self) -> None:
        assert get_profile("cisco_iosxe") is get_profile("cisco_ios")

    def test_profile_without_a_config_command_is_rejected(self) -> None:
        """The error must name the platform: a profile missing its configuration
        command is a programming mistake, and a bare KeyError would not say which."""
        from netsecops.adapters.profiles import CollectionCommand
        from netsecops.core.errors import ValidationProblem

        broken = CollectionProfile(
            platform="broken",
            setup=(),
            commands=(CollectionCommand("show version", "no config here"),),
        )
        with pytest.raises(ValidationProblem, match="broken"):
            _ = broken.config_command


class TestProfilesAgainstTheDenyList:
    @pytest.mark.parametrize("platform", sorted(PROFILES))
    def test_no_profile_command_looks_like_a_write(self, platform: str) -> None:
        """Belt and braces over the allow-list check: even if an allow-list entry were
        mistakenly added, a profile command that trips the write-verb deny-list should
        fail here (SRS §8.1 item 2)."""
        from netsecops.adapters.readonly import DENY_PATTERN, normalise

        for entry in PROFILES[platform].commands:
            assert not DENY_PATTERN.match(normalise(entry.command)), (
                f"{platform}: profile command {entry.command!r} matches the write-verb deny-list"
            )
