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
from netsecops.adapters.profiles import (
    PROFILES,
    CollectionProfile,
    NoProfileError,
    Transport,
    get_profile,
)
from netsecops.adapters.readonly import ReadOnlyGuard
from netsecops.parsers.registry import supported_platforms


def guard_for(platform: str) -> ReadOnlyGuard:
    return ReadOnlyGuard(get_policy(platform))


@pytest.mark.parametrize("platform", sorted(PROFILES))
class TestProfilesStayInsideThePolicy:
    def test_every_command_is_on_the_allow_list(self, platform: str) -> None:
        """The single most important assertion in this file.

        Each entry is checked against the half of the guard that actually governs it:
        CLI commands against the command allow-list and write-verb deny-list, API calls
        against the HTTP method and path rules. Checking an API call with
        `permits_command` would appear to pass and prove nothing.
        """
        guard = guard_for(platform)
        profile = PROFILES[platform]

        if profile.transport is Transport.HTTP:
            for entry in profile.commands:
                method, path = entry.as_request()
                assert guard.permits_request(method, path), (
                    f"{platform}: the collection profile issues {method} {path}, which "
                    f"the platform's HTTP rules in policies.py do not permit."
                )
            return

        if profile.transport is Transport.RPC:
            # Everything is a POST here, so the body is the only thing that distinguishes
            # a read from a write. Checking these without one would pass vacuously and
            # prove nothing about the read-only guarantee.
            for entry in profile.commands:
                method, path = entry.as_request()
                assert guard.permits_request(method, path, body=entry.as_body()), (
                    f"{platform}: the collection profile issues {method} {path} with body "
                    f"{entry.as_body()}, which the platform's rules in policies.py do "
                    f"not permit."
                )
            return

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

    def test_http_profiles_only_ever_read(self, platform: str) -> None:
        """SRS §8.1: REST collection is GET-only.

        PAN-OS's XML API also accepts POST for reads, but a profile that used it would
        need a body predicate to prove the body is a read — so the profile sticks to
        GET, and this asserts it stays that way.
        """
        profile = PROFILES[platform]
        if profile.transport is not Transport.HTTP:
            pytest.skip("not a GET-collected API platform")

        for entry in profile.commands:
            method, _ = entry.as_request()
            assert method == "GET", (
                f"{platform}: profile entry {entry.command!r} uses {method}. Collection "
                "over an API is GET-only."
            )

    def test_rpc_profiles_only_ever_issue_read_operations(self, platform: str) -> None:
        """The RPC equivalent of the GET-only rule, and it matters more.

        On a POST-only API every request looks identical from the outside, so nothing
        about the method says whether a call reads or writes. `delete-access-rule` is the
        same shape as `show-access-rulebase`. The operation name is the entire guarantee,
        which is why it is asserted here as well as enforced by the body predicate.
        """
        profile = PROFILES[platform]
        if profile.transport is not Transport.RPC:
            pytest.skip("not an RPC-collected platform")

        for entry in profile.commands:
            command = entry.as_body()["command"]
            assert command.startswith("show-"), (
                f"{platform}: profile entry {entry.command!r} issues {command!r}, which "
                "is not a read. Collection over the Management API is show-only."
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


#: Parsers that deliberately have no collection profile, and why.
#:
#: **Each is read from an uploaded export rather than collected** (FR-COL-11). Every one
#: needs a credential type and a transport this product does not have — SigV4, OAuth
#: service principals, pagination — and a parser wired to a collector that does not
#: exist is the capability-with-no-surface pattern. Building the parser first is the
#: deliberate order: an export can be assessed today, and the collector arrives in its
#: own slice with its own credential design.
#:
#: Listed here rather than the check being relaxed, so that adding a fifth is a decision
#: somebody records rather than a divergence nobody notices.
PARSERS_READ_FROM_AN_EXPORT: dict[str, str] = {
    "vmware_nsx": "NSX Policy API needs a credential type and pagination that do not exist yet.",
    "cisco_aci": "APIC needs a token transport that does not exist yet.",
    "aws_vpc": "NetSecOps holds no AWS credential; the allow-list is empty on purpose.",
    "azure_nsg": "NetSecOps holds no Azure credential; the allow-list is empty on purpose.",
    # These two are here for a different reason, and a sharper one: both *had* profiles,
    # and both profiles were wrong. Their endpoints are templated per object — FMC by
    # domain and access policy, Barracuda by service — and the runner cannot expand a
    # path per discovered object. `key_in_bundle()` defaults to the last path segment,
    # so every service's `basic-security` would be filed under one key and all but one
    # discarded. `test_bundled_collection_shape` found it.
    "barracuda_waf": "Per-service endpoints need path expansion the collector lacks.",
    "cisco_ftd_fmc": "Per-domain and per-policy endpoints need path expansion the collector lacks.",
}


class TestProfileRegistry:
    def test_every_platform_with_a_parser_has_a_profile(self) -> None:
        """A parser with no profile can never be reached from a live collection; a
        profile with no parser collects a configuration nothing can read.

        The export-read platforms are the stated exception: they are reached through
        FR-COL-11 instead, which is a way to be read that did not exist when this check
        was written.
        """
        parsers = set(supported_platforms()) - set(PARSERS_READ_FROM_AN_EXPORT)

        assert parsers == set(PROFILES), (
            "parsers and collection profiles have diverged: "
            f"parsers only = {parsers - set(PROFILES)}, "
            f"profiles only = {set(PROFILES) - parsers}"
        )

    def test_no_export_read_declaration_is_stale(self) -> None:
        """A platform that gained a profile must lose its declaration.

        The same rule `test_unconsumed_capability` applies to its own backlog: a
        declaration that outlives the thing it explains makes the list look considered
        when it is out of date.
        """
        stale = sorted(p for p in PARSERS_READ_FROM_AN_EXPORT if p in PROFILES)

        assert stale == [], f"these now have a profile; delete the declarations: {stale}"

    def test_every_export_read_platform_actually_has_a_parser(self) -> None:
        """The other direction: a declaration for a platform nothing can read either."""
        missing = sorted(p for p in PARSERS_READ_FROM_AN_EXPORT if p not in supported_platforms())

        assert missing == [], f"declared as export-read and has no parser: {missing}"

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

        if PROFILES[platform].transport is not Transport.CLI:
            # The deny-list is a CLI construct. An API profile is constrained instead by
            # the method and path, or for RPC by the body operation — both asserted above.
            pytest.skip("API profiles are governed by method, path and body, not verbs")

        for entry in PROFILES[platform].commands:
            assert not DENY_PATTERN.match(normalise(entry.command)), (
                f"{platform}: profile command {entry.command!r} matches the write-verb deny-list"
            )
