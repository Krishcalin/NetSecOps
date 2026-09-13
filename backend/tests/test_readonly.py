"""Read-only conformance (SRS §8, TEST-03, FR-COL-04).

This is the test that backs the product's central promise. It asserts three things:

1. Every command in the shipped allow-lists is actually permitted by the guard — a
   typo in a policy would otherwise only surface against real hardware.
2. Nothing outside an allow-list gets through, including near-misses, prefix
   extensions, and injected second commands.
3. Every write verb the SRS deny-list names is refused, on every platform.

A failure here is not a flaky test. It means NetSecOps would send something to a
customer's device that it promises never to send.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from netsecops.adapters.policies import (
    CHECKPOINT_GAIA,
    CHECKPOINT_MGMT,
    CISCO_ASA,
    CISCO_IOS,
    CISCO_WLC_AIREOS,
    FORTIGATE,
    FORTIMANAGER,
    LINUX_AAA,
    PANOS,
    POLICIES,
    get_policy,
)
from netsecops.adapters.readonly import (
    DENY_PATTERN,
    CommandRule,
    HttpRule,
    PlatformPolicy,
    ReadOnlyGuard,
    normalise,
)
from netsecops.core.errors import ReadOnlyViolationError


def guard(policy: PlatformPolicy) -> ReadOnlyGuard:
    return ReadOnlyGuard(policy)


# ───────────────────── 1. the shipped policies are self-consistent ──────────


class TestShippedPoliciesAreCoherent:
    @pytest.mark.parametrize("platform", sorted(POLICIES))
    def test_every_allow_list_entry_is_permitted(self, platform: str) -> None:
        """A policy entry the guard would reject is a typo that only hardware would find."""
        policy = POLICIES[platform]
        g = guard(policy)

        for rule in policy.commands:
            command = _example_for(rule)
            assert g.permits_command(command), (
                f"{platform}: allow-list entry {rule.pattern!r} does not match its own "
                f"example {command!r} — the entry is malformed"
            )

    @pytest.mark.parametrize("platform", sorted(POLICIES))
    def test_only_session_only_entries_may_look_like_writes(self, platform: str) -> None:
        """Any entry tripping the deny-list must be a declared session-only exception."""
        for rule in POLICIES[platform].commands:
            if DENY_PATTERN.match(normalise(_example_for(rule))):
                assert rule.session_only, (
                    f"{platform}: {rule.pattern!r} matches the write-verb deny-list but "
                    "is not declared session_only. Either it is a write and must be "
                    "removed, or it needs an explicit, documented exception."
                )

    @pytest.mark.parametrize("platform", sorted(POLICIES))
    def test_session_only_exceptions_are_documented(self, platform: str) -> None:
        """Each exception must carry a note — reviewers need the reasoning, not the flag."""
        for rule in POLICIES[platform].commands:
            if rule.session_only:
                assert rule.note, (
                    f"{platform}: session-only exception {rule.pattern!r} has no note "
                    "explaining why it is safe"
                )

    def test_unknown_platform_is_a_hard_error(self) -> None:
        """A device we cannot describe is a device we must not touch."""
        with pytest.raises(KeyError, match="No read-only policy"):
            get_policy("acme_router_9000")

    def test_every_policy_declares_something(self) -> None:
        for platform, policy in POLICIES.items():
            assert policy.commands or policy.http, f"{platform} permits nothing at all"


def _example_for(rule: CommandRule) -> str:
    """Turn an allow-list entry into a concrete command by filling its placeholders."""
    command = rule.pattern
    for placeholder in ("<name>", "<id>", "<path>", "<service>", "<subject>"):
        command = command.replace(placeholder, "sample")
    return command.replace("[", "").replace("]", "")


# ───────────────────────── 2. nothing else gets through ─────────────────────


class TestAllowListIsExhaustive:
    def test_unlisted_command_is_refused(self) -> None:
        with pytest.raises(ReadOnlyViolationError, match="not on the read-only allow-list"):
            guard(CISCO_IOS).check_command("show secret-sauce")

    def test_prefix_of_a_permitted_command_is_not_enough(self) -> None:
        """Anchoring matters: a permitted prefix must not carry an arbitrary tail."""
        g = guard(CISCO_IOS)
        assert g.permits_command("show version")
        assert not g.permits_command("show version | redirect tftp://10.0.0.1/out.txt")

    def test_extra_trailing_argument_is_refused(self) -> None:
        assert not guard(CISCO_IOS).permits_command("show clock detail extra")

    def test_optional_token_is_honoured_both_ways(self) -> None:
        g = guard(CISCO_IOS)
        assert g.permits_command("show running-config")
        assert g.permits_command("show running-config all")
        assert not g.permits_command("show running-config everything")

    def test_placeholder_accepts_one_token_only(self) -> None:
        g = guard(CISCO_WLC_AIREOS)
        assert g.permits_command("show wlan 7")
        assert not g.permits_command("show wlan 7 8")

    def test_whitespace_does_not_change_the_verdict(self) -> None:
        g = guard(CISCO_IOS)
        assert g.permits_command("show    version")
        assert g.permits_command("  show version  ")

    def test_case_is_insensitive(self) -> None:
        assert guard(CISCO_IOS).permits_command("SHOW VERSION")

    def test_empty_command_is_refused(self) -> None:
        with pytest.raises(ReadOnlyViolationError, match="empty command"):
            guard(CISCO_IOS).check_command("   ")


class TestInjectionGuard:
    """A permitted prefix must never be able to carry a second command."""

    @pytest.mark.parametrize(
        "command",
        [
            "show version; configure terminal",
            "show version && reload",
            "show version || erase startup-config",
            "show version\nconfigure terminal",
            "show version\rreload",
            "show version `reload`",
            "show version $(reload)",
            "show version & reload",
            "show version > flash:out.txt",
            "show version < flash:in.txt",
        ],
    )
    def test_separators_are_refused(self, command: str) -> None:
        with pytest.raises(ReadOnlyViolationError, match="separator or substitution"):
            guard(CISCO_IOS).check_command(command)

    def test_injection_is_refused_before_the_allow_list_is_consulted(self) -> None:
        """Even a fully unlisted command with a separator reports the separator first."""
        with pytest.raises(ReadOnlyViolationError, match="separator"):
            guard(CISCO_IOS).check_command("totally-unlisted; reload")

    def test_placeholder_cannot_smuggle_a_separator(self) -> None:
        """The token charset excludes separators, so an interpolated name cannot escape."""
        g = guard(CISCO_WLC_AIREOS)
        assert not g.permits_command("show ap config general ap1;reload")

    def test_fortigate_must_not_pipe(self) -> None:
        """SRS §8.2 singles this out for FortiGate SSH."""
        g = guard(FORTIGATE)
        assert g.permits_command("get system status")
        with pytest.raises(ReadOnlyViolationError, match="must not pipe"):
            g.check_command("get system status | grep foo")

    def test_pipe_is_allowed_where_an_entry_includes_it(self) -> None:
        assert guard(CISCO_IOS).permits_command("show logging | include (Trap|Buffer|Logging to)")


# ─────────────────────── 3. write verbs are always refused ──────────────────


class TestWriteVerbsAreRefused:
    WRITE_COMMANDS: ClassVar[list[str]] = [
        "configure terminal",
        "conf t",
        "write memory",
        "wr",
        "copy running-config startup-config",
        "reload",
        "erase startup-config",
        "delete flash:config.txt",
        "format flash:",
        "install add file bootflash:image.bin",
        "upgrade fpd auto",
        "commit",
        "rollback configuration last 1",
        "clear counters",
        "debug ip packet",
        "no shutdown",
        "shutdown",
        "boot system flash:image.bin",
        "end",
        "test aaa group tacacs+ user pass",
        "ping 10.0.0.1",
        "traceroute 10.0.0.1",
    ]

    @pytest.mark.parametrize("command", WRITE_COMMANDS)
    @pytest.mark.parametrize(
        "policy",
        [CISCO_IOS, CISCO_ASA, CISCO_WLC_AIREOS, FORTIGATE, CHECKPOINT_GAIA, LINUX_AAA],
        ids=lambda p: p.platform,
    )
    def test_write_verbs_never_pass(self, policy: PlatformPolicy, command: str) -> None:
        assert not guard(policy).permits_command(command), (
            f"{policy.platform} permitted the write command {command!r}"
        )

    def test_deny_list_catches_a_mis_specified_allow_list_entry(self) -> None:
        """Defence in depth (SRS §8.1.2): the deny-list is the backstop for human error."""
        careless = PlatformPolicy(
            platform="careless",
            commands=(CommandRule("configure terminal"),),  # someone added a write
        )
        with pytest.raises(ReadOnlyViolationError, match="allow-list entry is wrong"):
            guard(careless).check_command("configure terminal")

    def test_session_only_entries_bypass_the_deny_list_deliberately(self) -> None:
        """`config paging disable` trips the deny regex but only affects the session."""
        assert guard(CISCO_WLC_AIREOS).permits_command("config paging disable")
        assert DENY_PATTERN.match("config paging disable"), (
            "precondition: this command does look like a write to the deny-list"
        )

    def test_gaia_pager_is_a_session_exception(self) -> None:
        assert guard(CHECKPOINT_GAIA).permits_command("set clienv rows 0")

    def test_fortigate_diagnose_is_narrowly_permitted(self) -> None:
        """`diagnose sys` reads; the rest of the diagnose tree does not."""
        g = guard(FORTIGATE)
        assert g.permits_command("diagnose sys top")
        assert not g.permits_command("diagnose debug enable")

    def test_config_mode_is_never_permitted_even_on_cisco(self) -> None:
        """SRS §8.1.4: enable mode yes, configuration mode never."""
        g = guard(CISCO_IOS)
        assert g.permits_command("enable")
        assert not g.permits_command("configure terminal")


# ─────────────────────────────── HTTP policy ────────────────────────────────


class TestHttpMethods:
    @pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
    def test_mutating_methods_are_never_permitted(self, method: str) -> None:
        with pytest.raises(ReadOnlyViolationError, match="never permitted"):
            guard(PANOS).check_request(method, "/api/")

    def test_get_on_a_listed_prefix_is_permitted(self) -> None:
        assert guard(FORTIGATE).permits_request("GET", "/api/v2/cmdb/firewall/policy")

    def test_get_on_an_unlisted_prefix_is_refused(self) -> None:
        assert not guard(FORTIGATE).permits_request("GET", "/api/v2/cmdb/secret/thing")

    def test_post_without_a_rule_is_refused(self) -> None:
        assert not guard(FORTIGATE).permits_request("POST", "/api/v2/cmdb/firewall/policy")


class TestCheckPointManagementApi:
    """SRS §8.1.3b — POST-only API, restricted to show-* and session calls."""

    @pytest.mark.parametrize(
        "command",
        ["show-hosts", "show-access-rulebase", "login", "logout", "keepalive"],
    )
    def test_reads_and_session_calls_are_permitted(self, command: str) -> None:
        assert guard(CHECKPOINT_MGMT).permits_request(
            "POST", "/web_api/v1.9/" + command, body={"command": command}
        )

    @pytest.mark.parametrize(
        "command",
        ["set-host", "add-host", "delete-host", "publish", "install-policy", "run-script"],
    )
    def test_writes_are_refused(self, command: str) -> None:
        assert not guard(CHECKPOINT_MGMT).permits_request(
            "POST", "/web_api/v1.9/" + command, body={"command": command}
        )

    def test_missing_body_is_refused(self) -> None:
        assert not guard(CHECKPOINT_MGMT).permits_request("POST", "/web_api/v1.9/show-hosts")


class TestFortiManagerJsonRpc:
    """SRS §8.1.3c — method must be get, or an exec limited to login/logout."""

    def test_get_is_permitted(self) -> None:
        assert guard(FORTIMANAGER).permits_request(
            "POST", "/jsonrpc", body={"method": "get", "params": [{"url": "/dvmdb/device"}]}
        )

    @pytest.mark.parametrize("method", ["set", "add", "update", "delete", "move", "clone"])
    def test_mutating_methods_are_refused(self, method: str) -> None:
        assert not guard(FORTIMANAGER).permits_request(
            "POST", "/jsonrpc", body={"method": method, "params": [{"url": "/dvmdb/device"}]}
        )

    def test_exec_is_permitted_only_for_session_management(self) -> None:
        g = guard(FORTIMANAGER)
        assert g.permits_request(
            "POST", "/jsonrpc", body={"method": "exec", "params": [{"url": "/sys/login/user"}]}
        )
        assert not g.permits_request(
            "POST", "/jsonrpc", body={"method": "exec", "params": [{"url": "/sys/reboot"}]}
        )

    def test_exec_with_a_mixed_batch_is_refused(self) -> None:
        """One forbidden url in the batch poisons the whole request."""
        assert not guard(FORTIMANAGER).permits_request(
            "POST",
            "/jsonrpc",
            body={
                "method": "exec",
                "params": [{"url": "/sys/login/user"}, {"url": "/sys/reboot"}],
            },
        )


class TestPanOsXmlApi:
    """SRS §8.1.3d — only keygen, op-show, config show/get, and read exports."""

    def test_keygen_is_permitted(self) -> None:
        assert guard(PANOS).permits_request("POST", "/api/", body={"type": "keygen"})

    def test_op_show_is_permitted(self) -> None:
        assert guard(PANOS).permits_request(
            "POST", "/api/", body={"type": "op", "cmd": "<show><system><info/></system></show>"}
        )

    def test_op_non_show_is_refused(self) -> None:
        assert not guard(PANOS).permits_request(
            "POST",
            "/api/",
            body={"type": "op", "cmd": "<request><restart><system/></restart></request>"},
        )

    def test_license_info_is_the_documented_request_exception(self) -> None:
        assert guard(PANOS).permits_request(
            "POST",
            "/api/",
            body={"type": "op", "cmd": "<request><license><info/></license></request>"},
        )

    @pytest.mark.parametrize("action", ["show", "get"])
    def test_config_reads_are_permitted(self, action: str) -> None:
        assert guard(PANOS).permits_request(
            "POST", "/api/", body={"type": "config", "action": action, "xpath": "/config"}
        )

    @pytest.mark.parametrize("action", ["set", "edit", "delete", "rename", "move"])
    def test_config_writes_are_refused(self, action: str) -> None:
        assert not guard(PANOS).permits_request(
            "POST", "/api/", body={"type": "config", "action": action, "xpath": "/config"}
        )

    def test_commit_is_refused(self) -> None:
        assert not guard(PANOS).permits_request("POST", "/api/", body={"type": "commit"})

    @pytest.mark.parametrize("category", ["configuration", "certificate"])
    def test_read_exports_are_permitted(self, category: str) -> None:
        assert guard(PANOS).permits_request(
            "POST", "/api/", body={"type": "export", "category": category}
        )

    def test_other_exports_are_refused(self) -> None:
        assert not guard(PANOS).permits_request(
            "POST", "/api/", body={"type": "export", "category": "device-state"}
        )


class TestAuditability:
    """SRS §8.1.7 — a customer must be able to read the effective allow-list."""

    @pytest.mark.parametrize("platform", sorted(POLICIES))
    def test_every_policy_describes_itself(self, platform: str) -> None:
        described = POLICIES[platform].describe()
        assert described, f"{platform} produced an empty description"
        assert all(isinstance(line, str) and line for line in described)

    def test_session_only_entries_are_flagged_in_the_description(self) -> None:
        described = "\n".join(CISCO_WLC_AIREOS.describe())
        assert "config paging disable   [session-only]" in described


class TestViolationDetail:
    """A violation must say enough to diagnose it, without leaking secrets."""

    def test_violation_names_the_platform_and_command(self) -> None:
        with pytest.raises(ReadOnlyViolationError) as exc:
            guard(CISCO_IOS).check_command("reload")

        assert exc.value.extra["platform"] == "cisco_ios"
        assert exc.value.extra["command"] == "reload"

    def test_violation_is_a_server_error_not_a_client_error(self) -> None:
        """It means NetSecOps misbehaved, not that the caller asked for something odd."""
        assert ReadOnlyViolationError().status_code >= 500


class TestHttpRuleConstruction:
    def test_body_predicate_is_optional(self) -> None:
        rule = HttpRule("GET", "/api/")
        assert rule.body_predicate is None
