"""Symantec Blue Coat ProxySG, SGOS (SRS §1.3, FR-PARSE-01 … FR-PARSE-05).

SGOS prints its configuration as a flat sequence of sections delimited by comment
markers, with the CLI path you would have walked to set each value:

    !- BEGIN general
    hostname proxy-edge-01
    !- END general
    !- BEGIN ssh-console
    ssh-console
    inline sshd-keypair ...
    exit
    !- END ssh-console

**It is not a hierarchy, it is a transcript.** The indentation carries no meaning; a
block is opened by a bare command and closed by `exit`, and the `!- BEGIN` markers are
comments that happen to be reliable. So the reader tracks an explicit command stack
rather than depth, the way the Alteon one tracks menu paths.

**A proxy is not a firewall and this parser does not pretend otherwise.** There is no
rulebase here. SGOS policy lives in CPL — a separate, Turing-complete policy language in
its own file, which `show configuration` does not emit — so `firewall.security_rules`
stays empty and a check that reads it reports Not Evaluated rather than a clean device.
What this reads is the management plane and the SSL interception posture, which is where
a proxy's own exposure lives.

**The interception setting is the finding worth having.** A ProxySG doing SSL
interception holds a private CA that every managed browser trusts. Whether it is on, and
what it does with certificate errors, is the single most consequential thing in the
file — and `show configuration` states it by the *presence* of a stanza rather than a
flag, which is the trap: absence means not configured, not disabled.
"""

from __future__ import annotations

import re

from netsecops.core.logging import get_logger
from netsecops.ncm.models import (
    AaaServer,
    LocalUser,
    NormalisedConfig,
    NtpServer,
    SnmpCommunity,
    SyslogServer,
)
from netsecops.parsers.base import (
    ConfigParser,
    ParseContext,
    ParseResult,
    is_default_community,
    mask_secret,
)

log = get_logger(__name__)

#: `!- BEGIN general` / `!- END general`. Comments, but reliable ones, and the only
#: thing in the file that names a section.
_SECTION = re.compile(r"^!-\s*(BEGIN|END)\s+(?P<name>.+?)\s*$", re.IGNORECASE)

#: Lines that carry no configuration.
_NOISE = re.compile(r"^(!|;|$)")


class SymantecProxySgParser(ConfigParser):
    vendor = "symantec"
    platform = "symantec_proxysg"

    IGNORE = re.compile(r"^(!|exit$|inline .*|end-\d+|\.\.\.$)")

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        result.ncm.device.vendor = self.vendor
        result.ncm.device.platform = self.platform

        sections = self._sections(context.lines)
        if not sections:
            result.ncm.parse_failed = True
            result.ncm.raw_unparsed = [
                "No SGOS section marker (!- BEGIN …) was found, so nothing was read."
            ]
            return result.ncm

        for handler in (
            self._general,
            self._console,
            self._snmp,
            self._time_and_logging,
            self._users_and_aaa,
            self._ssl,
        ):
            try:
                handler(sections, result)
            except Exception as exc:  # pragma: no cover - defensive, per FR-PARSE-03
                log.warning(
                    "parser.section_failed",
                    platform=self.platform,
                    section=handler.__name__,
                    error=str(exc),
                )

        self._version(result)
        result.finalise_unparsed(ignore=self.IGNORE)
        return result.ncm

    # ──────────────────────────── sections ──────────────────────────────

    @staticmethod
    def _sections(lines: list[str]) -> dict[str, list[tuple[int, str]]]:
        """Group the transcript by its `!- BEGIN`/`!- END` markers.

        A line outside any marker belongs to no section and is left for
        `finalise_unparsed` to report. Sections repeat — SGOS emits several
        `!- BEGIN policy` blocks — so their contents accumulate rather than replace.
        """
        found: dict[str, list[tuple[int, str]]] = {}
        current: str | None = None

        for number, raw in enumerate(lines, start=1):
            text = raw.strip()
            marker = _SECTION.match(text)
            if marker:
                name = marker.group("name").lower()
                current = name if marker.group(1).upper() == "BEGIN" else None
                if current:
                    found.setdefault(current, [])
                continue
            if current is None or _NOISE.match(text):
                continue
            found[current].append((number, text))

        return found

    @staticmethod
    def _value(
        sections: dict[str, list[tuple[int, str]]], section: str, pattern: str
    ) -> tuple[int, str] | None:
        compiled = re.compile(pattern)
        for line, text in sections.get(section, []):
            if found := compiled.match(text):
                return line, found.group(1)
        return None

    @staticmethod
    def _all(
        sections: dict[str, list[tuple[int, str]]], section: str, pattern: str
    ) -> list[tuple[int, str]]:
        compiled = re.compile(pattern)
        return [
            (line, found.group(1))
            for line, text in sections.get(section, [])
            if (found := compiled.match(text))
        ]

    # ──────────────────────────── the device ────────────────────────────

    def _general(self, sections: dict[str, list[tuple[int, str]]], result: ParseResult) -> None:
        ncm = result.ncm
        if found := self._value(sections, "general", r"^hostname (\S+)"):
            ncm.device.hostname = found[1]
            result.record("device.hostname", line=found[0])

    def _console(self, sections: dict[str, list[tuple[int, str]]], result: ParseResult) -> None:
        """The management services, which SGOS states by section presence.

        A section that is absent was never configured. That is a real answer on this
        platform — SGOS emits a section for anything that has been touched — so `False`
        is honest for a service with no section, and the parser having *read* sections
        at all is what makes it honest.
        """
        ncm = result.ncm

        ncm.management.services.ssh.enabled = "ssh-console" in sections
        result.record("management.services.ssh.enabled", line=1)

        # SGOS calls the plaintext management listener `http-console` and the TLS one
        # `https-console`. A proxy with the former reachable is management traffic in
        # clear on a device that terminates everybody else's TLS.
        ncm.management.services.http.enabled = "http-console" in sections
        ncm.management.services.https.enabled = "https-console" in sections
        ncm.features.http_server = ncm.management.services.http.enabled
        ncm.features.https_server = ncm.management.services.https.enabled

        ncm.management.services.telnet.enabled = "telnet-console" in sections

        if found := self._value(sections, "general", r"^console-timeout (\d+)"):
            # Minutes on SGOS.
            ncm.management.session.exec_timeout_s = int(found[1]) * 60
            result.record("management.session.exec_timeout_s", line=found[0])

        if found := self._value(sections, "general", r"^banner login \"(.*)\""):
            ncm.management.banners.login = found[1]
            result.record("management.banners.login", line=found[0])

    def _snmp(self, sections: dict[str, list[tuple[int, str]]], result: ParseResult) -> None:
        ncm = result.ncm

        for line, community in self._all(sections, "snmp", r"^community-string (?:ro |rw )?(\S+)"):
            raw = next(
                (text for number, text in sections.get("snmp", []) if number == line), ""
            )
            ncm.snmp.v1v2c_communities.append(
                SnmpCommunity(
                    name_masked=mask_secret(community),
                    is_default=is_default_community(community),
                    # SGOS writes the access before the string, and omits it for
                    # read-only — so absence is the answer rather than a gap.
                    rw=" rw " in f" {raw} ",
                )
            )
            result.record(
                f"snmp.v1v2c_communities.{len(ncm.snmp.v1v2c_communities) - 1}", line=line
            )

    def _time_and_logging(
        self, sections: dict[str, list[tuple[int, str]]], result: ParseResult
    ) -> None:
        ncm = result.ncm

        for line, host in self._all(sections, "ntp", r"^ntp-server (\S+)"):
            ncm.ntp.servers.append(NtpServer(host=host))
            result.record(f"ntp.servers.{len(ncm.ntp.servers) - 1}", line=line)

        for line, host in self._all(sections, "event-log", r"^syslog-host (\S+)"):
            ncm.logging.syslog_servers.append(SyslogServer(host=host))
            result.record(
                f"logging.syslog_servers.{len(ncm.logging.syslog_servers) - 1}", line=line
            )

    def _users_and_aaa(
        self, sections: dict[str, list[tuple[int, str]]], result: ParseResult
    ) -> None:
        ncm = result.ncm

        for line, name in self._all(sections, "security", r"^username (\S+)"):
            ncm.users.append(LocalUser(name=name))
            result.record(f"users.{len(ncm.users) - 1}", line=line)

        for section, kind in (("radius", "radius"), ("tacacs", "tacacs")):
            for line, host in self._all(sections, section, r"^(?:primary-)?host (\S+)"):
                ncm.aaa.servers.append(
                    AaaServer(
                        type=kind,
                        host=host,
                        key_configured=any(
                            text.startswith(("secret", "primary-secret"))
                            for _, text in sections.get(section, [])
                        )
                        or None,
                    )
                )
                result.record(f"aaa.servers.{len(ncm.aaa.servers) - 1}", line=line)

        if ncm.aaa.servers:
            ncm.aaa.new_model = True

    # ───────────────────────── SSL interception ─────────────────────────

    def _ssl(self, sections: dict[str, list[tuple[int, str]]], result: ParseResult) -> None:
        """The proxy's own TLS posture.

        **The consequential setting on the box.** A ProxySG doing SSL interception holds
        a CA that every managed browser trusts, and what it does with an upstream
        certificate error decides whether the whole estate's TLS validation still means
        anything.

        Recorded in `firewall.profiles`, which is a free-form map for exactly this — a
        device's own policy metadata. **Deliberately not under
        `management.services.https`**: those fields describe the appliance's own
        management listener, and putting the proxy's client-facing TLS there would make
        every management-hardening check read the wrong device's settings. Two different
        TLS configurations exist on this box and conflating them is worse than recording
        neither.
        """
        ncm = result.ncm

        present = [name for name in ("ssl", "ssl-proxy") if name in sections]
        if not present:
            # Absent means never configured, which on SGOS is a real answer — but it is
            # "no interception configured", not "interception disabled", and the two
            # differ on an appliance somebody half-set-up.
            return

        posture: dict[str, object] = {"configured": True}

        for section in present:
            if versions := [value for _, value in self._all(sections, section, r"^ssl-versions? (\S+)")]:
                posture["tls_versions"] = versions
            # `verify-peer no` means the proxy accepts an upstream certificate it cannot
            # validate and still hands the client one its browser trusts — the single
            # worst setting available on this platform, because it silently voids TLS
            # validation for every user behind it.
            for line, value in self._all(sections, section, r"^verify-peer (\S+)"):
                posture["verify_peer"] = value.lower() in {"yes", "on", "true"}
                result.record("firewall.profiles", line=line)

        ncm.firewall.profiles["ssl_interception"] = posture

    # ──────────────────────────── version ───────────────────────────────

    def _version(self, result: ParseResult) -> None:
        ncm = result.ncm
        output = result.context.artifact("show version")
        if not output:
            return

        if found := re.search(r"Version:\s*SGOS\s*(\S+)", output):
            ncm.device.version = found.group(1)
        if found := re.search(r"Serial number:\s*(\S+)", output, re.IGNORECASE):
            if found.group(1) not in ncm.device.serials:
                ncm.device.serials.append(found.group(1))
        if found := re.search(r"Appliance name:\s*(.+?)\s*$", output, re.MULTILINE):
            ncm.device.model = found.group(1)


__all__ = ["SymantecProxySgParser"]
