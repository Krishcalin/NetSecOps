"""Arista EOS (SRS §1.3, FR-PARSE-01 … FR-PARSE-05).

EOS is deliberately IOS-like — same indentation-structured running configuration, so it
shares `CiscoStyleParser` and ciscoconfparse2 rather than getting a reader of its own.
**The differences are small, few, and every one of them is silent if missed**, which is
why this is a separate parser rather than another key pointing at `CiscoIosParser`:

**Addresses and routes are CIDR.** `ip address 10.10.10.2/30`, not
`ip address 10.10.10.2 255.255.255.252`; `ip route 0.0.0.0/0 10.10.10.1`, not
`ip route 0.0.0.0 0.0.0.0 10.10.10.1`. The IOS parser's patterns require the dotted
mask, so pointed at EOS they match nothing and report a switch with no addresses and no
routes — which is exactly what a device that was never collected looks like.

**Management services live under `management` blocks.** `management ssh` and
`management api http-commands` replace `line vty` and `ip http server`. An IOS parser
looking for `ip http server` on EOS concludes the web API is off, and eAPI being on is
usually the finding.

**A username carries a role as well as a privilege level.** `role network-admin` is what
actually governs on EOS; the privilege number is kept for compatibility and is not the
authorisation.

**`no shutdown` is explicit under `management api http-commands`.** The block existing
does not mean the API is running, so the state is read from the negation rather than
from the block's presence — the opposite of how Junos services work, and the two are
easy to conflate.
"""

from __future__ import annotations

import re

from ciscoconfparse2 import CiscoConfParse

from netsecops.ncm.models import (
    AaaServer,
    Interface,
    LocalUser,
    NormalisedConfig,
    NtpServer,
    Route,
    SnmpCommunity,
    SyslogServer,
)
from netsecops.parsers.base import (
    CiscoStyleParser,
    ParseContext,
    ParseResult,
    is_default_community,
    mask_secret,
)

#: `ip address 10.10.10.2/30` — CIDR, unlike IOS.
_CIDR_ADDRESS = re.compile(r"^\s*ip address (\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})")

#: `ip route 0.0.0.0/0 10.10.10.1 [name X] [tag N]`, and the interface+gateway form
#: `ip route 0.0.0.0/0 Ethernet1 10.1.1.1 [tag N]` where the egress interface and the
#: next-hop gateway are both stated. The second group only matches a trailing address,
#: so an administrative distance (a bare number) or `name`/`tag` keywords do not capture.
_ROUTE = re.compile(
    r"^ip route (?:vrf (?P<vrf>\S+) )?(?P<destination>\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})"
    r"\s+(?P<first>\S+)"
    r"(?:\s+(?P<gateway>\d{1,3}(?:\.\d{1,3}){3}))?"
)

#: `username admin privilege 15 role network-admin secret sha512 $6$…`
_USERNAME = re.compile(
    r"^username (?P<name>\S+)"
    r"(?:\s+privilege (?P<privilege>\d+))?"
    r"(?:\s+role (?P<role>\S+))?"
    r"(?:\s+(?P<auth>secret|nopassword))?"
)

#: `snmp-server community public ro [ACL]`
_COMMUNITY = re.compile(r"^snmp-server community (?P<name>\S+)(?:\s+(?P<access>ro|rw))?")

#: EOS names its out-of-band port `Management1`, and it is the only one.
_MANAGEMENT = re.compile(r"^Management\d", re.IGNORECASE)


class AristaEosParser(CiscoStyleParser):
    vendor = "arista"
    platform = "arista_eos"
    syntax = "ios"

    IGNORE = re.compile(r"^(end|!|no aaa root|transceiver |Building configuration|Current config)")

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        result.ncm.device.vendor = self.vendor
        result.ncm.device.platform = self.platform

        parse = self.build(context)
        if not parse.find_objects(r"^(hostname|interface |username |management )"):
            # Nothing that looks like an EOS configuration. Distinguished from a sparse
            # one because the coverage arithmetic cannot tell them apart.
            result.ncm.parse_failed = True
            result.ncm.raw_unparsed = ["No EOS configuration stanza was found."]
            return result.ncm

        for handler in (
            self._device,
            self._management,
            self._users_and_aaa,
            self._snmp,
            self._time_and_logging,
            self._interfaces,
            self._routing,
        ):
            handler(parse, result)

        self._version(result)
        result.finalise_unparsed(ignore=self.IGNORE)
        return result.ncm

    # ──────────────────────────── device ────────────────────────────────

    def _device(self, parse: CiscoConfParse, result: ParseResult) -> None:
        ncm = result.ncm

        if obj := self.first(parse, r"^hostname "):
            ncm.device.hostname = self.capture(obj, r"^hostname (\S+)")
            result.record("device.hostname", line=self.line_number(obj))

        if obj := self.first(parse, r"^dns domain "):
            ncm.device.domain_name = self.capture(obj, r"^dns domain (\S+)")
            result.record("device.domain_name", line=self.line_number(obj))

        if obj := self.first(parse, r"^banner login"):
            # **Not a `family_range`.** EOS writes the banner body at column zero and
            # ends it with a bare `EOF`, so ciscoconfparse sees no children and the
            # stanza looks like a one-line statement with an empty banner — which is
            # itself a finding on most benchmarks, so getting this wrong manufactures
            # one. Read from the delimiter instead.
            start = self.line_number(obj)
            body: list[str] = []
            for offset in range(start, len(result.context.lines)):
                line = result.context.lines[offset]
                if line.strip() in {"EOF", "!"}:
                    break
                body.append(line.rstrip())

            if body:
                ncm.management.banners.login = "\n".join(body).strip()
                result.record(
                    "management.banners.login", line=start, line_end=start + len(body)
                )

    # ───────────────────────── management ───────────────────────────────

    def _management(self, parse: CiscoConfParse, result: ParseResult) -> None:
        ncm = result.ncm

        # `management ssh` — the block exists on every EOS switch, so its presence is
        # not the answer. SSH is off only when the block says `shutdown`.
        if obj := self.first(parse, r"^management ssh"):
            start, end = self.family_range(obj)
            body = [line.strip() for line in result.context.lines[start:end]]
            ncm.management.services.ssh.enabled = "shutdown" not in body
            result.record("management.services.ssh.enabled", line=start)

            for offset, line in enumerate(body, start=start + 1):
                if found := re.match(r"^idle-timeout (\d+)", line):
                    # Minutes on EOS. Stored verbatim it reads as fifteen seconds and
                    # passes a check that should fail.
                    ncm.management.session.exec_timeout_s = int(found.group(1)) * 60
                    result.record("management.session.exec_timeout_s", line=offset)
                # `server-port` is deliberately not recorded. `SshConfig` has no port
                # field, and adding one that no check reads is the capability-without-a-
                # surface pattern this codebase keeps having to remove. It belongs in
                # the commit that writes the check.

        # `management api http-commands` — eAPI. The block existing does not mean it is
        # running; `no shutdown` does. That is the opposite of how Junos services read,
        # and conflating the two reports every EOS switch as exposing its API.
        if obj := self.first(parse, r"^management api http-commands"):
            start, end = self.family_range(obj)
            body = [line.strip() for line in result.context.lines[start:end]]
            running = "no shutdown" in body

            # `protocol https` / `protocol http` say which listeners it opens. EOS
            # defaults to HTTPS when the statement is absent.
            protocols = [line for line in body if line.startswith("protocol ")]
            serves_http = any("http" in p and "https" not in p for p in protocols)
            serves_https = any("https" in p for p in protocols) or not protocols

            ncm.management.services.http.enabled = running and serves_http
            ncm.management.services.https.enabled = running and serves_https
            ncm.features.http_server = running and serves_http
            ncm.features.https_server = running and serves_https
            result.record("management.services.https.enabled", line=start)
        else:
            # Absent means eAPI is not configured at all, which is a real answer and the
            # secure one.
            ncm.features.http_server = False
            ncm.features.https_server = False

        ncm.management.services.telnet.enabled = bool(parse.find_objects(r"^management telnet"))

    # ───────────────────────── users and AAA ────────────────────────────

    def _users_and_aaa(self, parse: CiscoConfParse, result: ParseResult) -> None:
        ncm = result.ncm

        for obj in parse.find_objects(r"^username "):
            found = _USERNAME.match(obj.text.strip())
            if not found:
                continue
            ncm.users.append(
                LocalUser(
                    name=found.group("name"),
                    privilege=int(found.group("privilege")) if found.group("privilege") else None,
                    # The role is what actually governs on EOS. The privilege number is
                    # kept for IOS compatibility and is not the authorisation.
                    role=found.group("role"),
                    secret_type="none" if found.group("auth") == "nopassword" else None,
                )
            )
            result.record(f"users.{len(ncm.users) - 1}", line=self.line_number(obj))

        for obj in parse.find_objects(r"^radius-server host |^tacacs-server host "):
            text = obj.text.strip()
            kind = "radius" if text.startswith("radius") else "tacacs"
            host = self.capture(obj, r"host (\S+)")
            if not host:
                continue
            ncm.aaa.servers.append(
                AaaServer(type=kind, host=host, key_configured="key " in text)
            )
            result.record(f"aaa.servers.{len(ncm.aaa.servers) - 1}", line=self.line_number(obj))

        if ncm.aaa.servers:
            ncm.aaa.new_model = True

        # `aaa authentication login default group radius local` — whether `local`
        # follows the server is the local-fallback question, and it is the difference
        # between a lockout and a bypass.
        if obj := self.first(parse, r"^aaa authentication login default"):
            ncm.aaa.local_fallback = bool(re.search(r"\blocal\b", obj.text))
            result.record("aaa.local_fallback", line=self.line_number(obj))

    # ────────────────────────────── snmp ────────────────────────────────

    def _snmp(self, parse: CiscoConfParse, result: ParseResult) -> None:
        ncm = result.ncm

        for obj in parse.find_objects(r"^snmp-server community "):
            found = _COMMUNITY.match(obj.text.strip())
            if not found:
                continue
            name = found.group("name")
            ncm.snmp.v1v2c_communities.append(
                SnmpCommunity(
                    name_masked=mask_secret(name),
                    is_default=is_default_community(name),
                    # EOS omits the access word when read-only, so absence is the answer.
                    rw=found.group("access") == "rw",
                )
            )
            result.record(
                f"snmp.v1v2c_communities.{len(ncm.snmp.v1v2c_communities) - 1}",
                line=self.line_number(obj),
            )

    # ─────────────────────── time and logging ───────────────────────────

    def _time_and_logging(self, parse: CiscoConfParse, result: ParseResult) -> None:
        ncm = result.ncm

        for obj in parse.find_objects(r"^ntp server "):
            host = self.capture(obj, r"^ntp server (?:vrf \S+ )?(\S+)")
            if not host:
                continue
            ncm.ntp.servers.append(NtpServer(host=host, prefer="prefer" in obj.text))
            result.record(f"ntp.servers.{len(ncm.ntp.servers) - 1}", line=self.line_number(obj))

        for obj in parse.find_objects(r"^logging host "):
            host = self.capture(obj, r"^logging host (?:vrf \S+ )?(\S+)")
            if not host:
                continue
            ncm.logging.syslog_servers.append(SyslogServer(host=host))
            result.record(
                f"logging.syslog_servers.{len(ncm.logging.syslog_servers) - 1}",
                line=self.line_number(obj),
            )

    # ──────────────────────────── interfaces ────────────────────────────

    def _interfaces(self, parse: CiscoConfParse, result: ParseResult) -> None:
        ncm = result.ncm

        for obj in parse.find_objects(r"^interface \S+"):
            name = self.capture(obj, r"^interface (\S+)")
            if not name:
                continue
            start, end = self.family_range(obj)
            body = [line.strip() for line in result.context.lines[start:end]]

            addresses = [
                found.group(1) for line in body if (found := _CIDR_ADDRESS.match(" " + line))
            ]
            description = next(
                (line.split(" ", 1)[1] for line in body if line.startswith("description ")), None
            )

            ncm.interfaces.append(
                Interface(
                    name=name,
                    description=description,
                    ip_addresses=addresses,
                    admin_up="shutdown" not in body,
                    # `no switchport` is how EOS makes a port routed, and it is the
                    # difference between an address that routes and one that does not.
                    mode="routed" if "no switchport" in body else None,
                    is_management=bool(_MANAGEMENT.match(name)),
                )
            )
            result.record(f"interfaces.{len(ncm.interfaces) - 1}", line=start)

    # ───────────────────────────── routing ──────────────────────────────

    def _routing(self, parse: CiscoConfParse, result: ParseResult) -> None:
        ncm = result.ncm

        for obj in parse.find_objects(r"^ip route "):
            found = _ROUTE.match(obj.text.strip())
            if not found:
                continue
            first = found.group("first")
            gateway = found.group("gateway")
            # EOS accepts an interface where IOS would want an address, and it accepts
            # both together (`ip route <prefix> <intf> <gw>`). Read the first token as an
            # interface unless it is itself an address; the real next hop is then the
            # trailing gateway. Storing an interface name as a next hop would make an edge
            # to a device that does not exist; dropping the trailing gateway would make
            # the route read as directly-attached and lose the forwarding hop entirely.
            first_is_address = re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", first) is not None
            ncm.routing.routes.append(
                Route(
                    destination=found.group("destination"),
                    next_hop=first if first_is_address else gateway,
                    interface=None if first_is_address else first,
                    protocol="static",
                    vrf=found.group("vrf"),
                )
            )
            result.record(
                f"routing.routes.{len(ncm.routing.routes) - 1}", line=self.line_number(obj)
            )

        ncm.routing.static_routes = len(ncm.routing.routes)

    # ──────────────────────────── version ───────────────────────────────

    def _version(self, result: ParseResult) -> None:
        """EOS release, model and serial — all three from one `show version`.

        On IOS these are three separate commands; EOS puts them in one response, which
        is why this platform's allow-list is a third the length of Cisco's.
        """
        ncm = result.ncm
        output = result.context.artifact("show version")
        if not output:
            return

        if found := re.search(r"^Software image version:\s*(\S+)", output, re.MULTILINE):
            ncm.device.version = found.group(1)
        if found := re.search(r"^Arista\s+(\S+)", output, re.MULTILINE):
            ncm.device.model = found.group(1)
        if found := re.search(r"^Serial number:\s*(\S+)", output, re.MULTILINE):
            if found.group(1) not in ncm.device.serials:
                ncm.device.serials.append(found.group(1))


__all__ = ["AristaEosParser"]
