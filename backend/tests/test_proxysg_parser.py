"""Symantec Blue Coat ProxySG, SGOS (SRS §1.3, FR-PARSE-01 … FR-PARSE-05).

**SGOS is a transcript, not a hierarchy.** `show configuration` emits the CLI commands
you would have typed, delimited by `!- BEGIN <section>` comments. Indentation carries no
meaning and a block ends with `exit`, so a parser that keys off depth — as the Junos and
F5 ones do — reads the whole file as one flat section and finds nothing.

**A proxy is not a firewall and this parser does not pretend.** SGOS policy is CPL, a
separate policy language in its own file that `show configuration` does not emit, so
`firewall.security_rules` stays empty. That is deliberate: a rulebase check then reports
Not Evaluated rather than finding no rules and calling the device clean.

**The consequential setting is `verify-peer`.** A ProxySG doing SSL interception holds a
CA every managed browser trusts. With `verify-peer no` it accepts an upstream
certificate it cannot validate and still hands the client one the browser trusts —
silently voiding TLS validation for every user behind it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsecops.adapters.policies import get_policy
from netsecops.adapters.profiles import PROFILES
from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "symantec"
    / "proxysg"
    / "7.3"
    / "show_configuration.txt"
)


def parse(text: str, **supporting: str) -> NormalisedConfig:
    return get_parser("symantec_proxysg").parse(ParseContext(text=text, supporting=supporting))


@pytest.fixture(scope="module")
def ncm() -> NormalisedConfig:
    return parse(FIXTURE.read_text(encoding="utf-8"))


class TestThePlatformIsWired:
    def test_policy_profile_and_parser(self) -> None:
        from netsecops.parsers.registry import PARSERS

        assert get_policy("symantec_proxysg") is not None
        assert "symantec_proxysg" in PROFILES
        assert "symantec_proxysg" in PARSERS

    def test_every_command_it_issues_is_approved(self) -> None:
        policy = get_policy("symantec_proxysg")
        for command in PROFILES["symantec_proxysg"].all_commands():
            assert policy.match(command) is not None, command

    def test_the_expanded_form_is_not_approved(self) -> None:
        # `show configuration expanded` inlines the appliance's private keys. The plain
        # form emits `...` placeholders, which is the same posture as preferring
        # Alteon's `cc` over `/cfg/dump`.
        patterns = [rule.pattern for rule in get_policy("symantec_proxysg").commands]
        assert "show configuration expanded" not in patterns


class TestTheTranscriptFormat:
    def test_sections_come_from_the_markers(self, ncm: NormalisedConfig) -> None:
        assert ncm.device.hostname == "proxy-edge-01"

    def test_output_with_no_markers_is_a_parse_failure(self) -> None:
        # Not "a proxy with nothing configured". The coverage arithmetic cannot tell
        # them apart and an empty NCM would read as a hardened appliance.
        assert parse("hostname proxy-1\nexit\n").parse_failed is True

    def test_an_empty_capture_does_not_raise(self) -> None:
        assert parse("").parse_failed is True


class TestTheManagementPlane:
    def test_ssh_on_from_its_section(self, ncm: NormalisedConfig) -> None:
        assert ncm.management.services.ssh.enabled is True

    def test_https_console_on_http_console_off(self, ncm: NormalisedConfig) -> None:
        # SGOS emits a section for anything that has been configured, so absence is a
        # real answer here rather than a gap — and a proxy reachable over plaintext
        # management is management traffic in clear on the device that terminates
        # everybody else's TLS.
        assert ncm.management.services.https.enabled is True
        assert ncm.management.services.http.enabled is False

    def test_telnet_is_off(self, ncm: NormalisedConfig) -> None:
        assert ncm.management.services.telnet.enabled is False

    def test_the_console_timeout_is_seconds(self, ncm: NormalisedConfig) -> None:
        # SGOS writes minutes.
        assert ncm.management.session.exec_timeout_s == 900

    def test_the_login_banner(self, ncm: NormalisedConfig) -> None:
        assert ncm.management.banners.login == "Authorised access only. Activity is monitored."

    def test_local_users(self, ncm: NormalisedConfig) -> None:
        assert {u.name for u in ncm.users} == {"admin", "auditor"}


class TestSnmpTimeAndLogging:
    def test_read_only_and_read_write_communities(self, ncm: NormalisedConfig) -> None:
        # SGOS writes the access before the string and omits it for read-only.
        by_rw = {c.rw: c for c in ncm.snmp.v1v2c_communities}
        assert by_rw[False].is_default is True
        assert by_rw[True].is_default is False

    def test_the_community_string_is_never_stored(self, ncm: NormalisedConfig) -> None:
        assert all("public" not in c.name_masked for c in ncm.snmp.v1v2c_communities)

    def test_both_ntp_servers(self, ncm: NormalisedConfig) -> None:
        assert [s.host for s in ncm.ntp.servers] == ["10.10.0.10", "10.10.0.11"]

    def test_both_syslog_hosts(self, ncm: NormalisedConfig) -> None:
        assert [s.host for s in ncm.logging.syslog_servers] == ["10.10.0.20", "10.10.0.21"]

    def test_the_radius_server_and_its_secret(self, ncm: NormalisedConfig) -> None:
        radius = [s for s in ncm.aaa.servers if s.type == "radius"]
        assert [s.host for s in radius] == ["10.10.0.30"]
        assert radius[0].key_configured is True


class TestSslInterception:
    """The most consequential thing on the appliance."""

    def test_it_is_recorded_as_configured(self, ncm: NormalisedConfig) -> None:
        assert ncm.firewall.profiles["ssl_interception"]["configured"] is True

    def test_verify_peer_off_is_captured(self, ncm: NormalisedConfig) -> None:
        # `verify-peer no` means the proxy accepts an upstream certificate it cannot
        # validate and still hands the client one the browser trusts.
        assert ncm.firewall.profiles["ssl_interception"]["verify_peer"] is False

    def test_the_tls_versions_it_offers(self, ncm: NormalisedConfig) -> None:
        assert ncm.firewall.profiles["ssl_interception"]["tls_versions"] == [
            "tlsv1.2",
            "tlsv1.3",
        ]

    def test_it_is_not_recorded_on_the_management_listener(self, ncm: NormalisedConfig) -> None:
        # Two different TLS configurations exist on this box. Putting the proxy's
        # client-facing settings under `management.services.https` would make every
        # management-hardening check read the wrong device's posture.
        assert ncm.management.services.https.tls_versions == []

    def test_an_appliance_not_intercepting_records_nothing(self) -> None:
        # Absent means never configured, which is not the same as disabled — and on an
        # appliance somebody half-set-up the difference matters.
        text = "!- BEGIN general\nhostname p1\n!- END general\n"
        assert "ssl_interception" not in parse(text).firewall.profiles


class TestWhatItDoesNotDo:
    def test_there_is_no_rulebase(self, ncm: NormalisedConfig) -> None:
        # SGOS policy is CPL in a separate file. An empty rulebase makes a check report
        # Not Evaluated; a fabricated one would make it report a clean device.
        assert ncm.firewall.security_rules == []

    def test_unread_sections_are_reported(self, ncm: NormalisedConfig) -> None:
        # `forwarding` is not modelled. It must be visible rather than dropped.
        assert any("upstream-proxy" in line for line in ncm.raw_unparsed)

    def test_version_and_serial_from_show_version(self) -> None:
        output = (
            "Version: SGOS 7.3.12.1\n"
            "Release id: 267023\n"
            "Appliance name: Blue Coat SG-S400\n"
            "Serial number: 1234567890\n"
        )
        ncm = parse(
            "!- BEGIN general\nhostname p1\n!- END general\n", **{"show version": output}
        )
        assert ncm.device.version == "7.3.12.1"
        assert ncm.device.serials == ["1234567890"]

    def test_without_it_the_version_is_unknown(self, ncm: NormalisedConfig) -> None:
        assert ncm.device.version is None
