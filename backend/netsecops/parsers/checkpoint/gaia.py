"""Check Point Gaia clish parser (FR-PARSE-01 … FR-PARSE-05).

Gaia's `show configuration` emits a flat list of `set ...` commands — the same commands
that would recreate the box. There is no indentation and no block structure, so the
hierarchy is carried entirely in the token sequence:

```
set interface eth0 ipv4-address 10.0.0.1 mask-length 24
set snmp community PUBLIC read-only
set user admin shell /bin/bash
```

This parser covers the *operating system*: interfaces, administrators, SNMP, syslog,
NTP, password policy and management access. The security policy is not here — on Check
Point it lives on the management server, and `checkpoint_mgmt` reads it. A Gaia gateway
assessed on its own will therefore report every firewall check as *Not Evaluated*, which
is correct: the gateway genuinely does not hold the answer.

**Why `set` lines are parsed rather than matched whole.** Gaia interleaves options in an
order that varies by version — `mask-length` may precede or follow `ipv4-address`. A
regex per line would silently stop matching on an upgrade. Tokenising into key/value
pairs after a known prefix survives reordering, and an unfamiliar option lands in
`raw_unparsed` where it is visible.
"""

from __future__ import annotations

import re
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.ncm.models import (
    Interface,
    LocalUser,
    NormalisedConfig,
    NtpServer,
    Route,
    SnmpCommunity,
    SnmpV3User,
    SyslogServer,
)
from netsecops.parsers.base import (
    ConfigParser,
    ParseContext,
    ParseResult,
    is_default_community,
    mask_secret,
)
from netsecops.parsers.routes import connected_routes, store, to_cidr

log = get_logger(__name__)

#: Shells that mean the account has an interactive Linux login rather than clish only.
#: `/etc/cli.sh` is the restricted shell; anything else is a shell on the underlying OS.
_UNRESTRICTED_SHELLS = frozenset({"/bin/bash", "/bin/sh", "/bin/csh", "/bin/tcsh"})

#: Gaia's SNMPv3 security levels, mapped to the NCM's spelling. Anything unrecognised
#: becomes "unknown" rather than being guessed at.
_SECURITY_LEVELS: dict[str, str] = {
    "authpriv": "authPriv",
    "authnopriv": "authNoPriv",
    "noauthnopriv": "noAuthNoPriv",
}


def _tokens(line: str) -> list[str]:
    return line.strip().split()


def _pairs(tokens: list[str], start: int) -> dict[str, str]:
    """Read `key value key value ...` from `start`.

    A trailing key with no value is dropped rather than raising: Gaia truncates long
    lines, and losing one option is better than losing the whole configuration.
    """
    out: dict[str, str] = {}
    index = start
    while index + 1 < len(tokens):
        out[tokens[index]] = tokens[index + 1]
        index += 2
    return out


class CheckPointGaiaParser(ConfigParser):
    vendor = "checkpoint"
    platform = "checkpoint_gaia"

    IGNORE = re.compile(r"^(exit|end|#|Processing|Done)")

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        result.ncm.device.vendor = self.vendor
        result.ncm.device.platform = self.platform

        for section in (
            self._parse_device,
            self._parse_interfaces,
            self._parse_users,
            self._parse_snmp,
            self._parse_logging,
            self._parse_ntp,
            self._parse_management,
        ):
            try:
                section(context, result)
            except Exception as exc:
                log.warning(
                    "parser.section_failed",
                    platform=self.platform,
                    section=section.__name__,
                    error=str(exc),
                )

        result.finalise_unparsed(ignore=self.IGNORE)
        return result.ncm

    # ── helpers ─────────────────────────────────────────────────────────

    def _lines(self, context: ParseContext, *prefix: str) -> list[tuple[int, list[str]]]:
        """Every line starting with the given token sequence, with 1-based numbers."""
        width = len(prefix)
        found: list[tuple[int, list[str]]] = []
        for number, text in enumerate(context.lines, start=1):
            tokens = _tokens(text)
            if len(tokens) > width and tuple(tokens[:width]) == prefix:
                found.append((number, tokens))
        return found

    # ── device ──────────────────────────────────────────────────────────

    def _parse_device(self, context: ParseContext, result: ParseResult) -> None:
        device = result.ncm.device

        for number, tokens in self._lines(context, "set", "hostname"):
            device.hostname = tokens[2]
            result.record("device.hostname", line=number)

        for number, tokens in self._lines(context, "set", "domainname"):
            device.domain_name = tokens[2]
            result.record("device.domain_name", line=number)

        self._parse_show_version(result)

    #: `Product version Check Point Gaia R81.20`
    _PRODUCT = re.compile(r"^Product version Check Point Gaia (\S+)", re.M)
    #: `OS build 631`, which together with the product version identifies the image.
    _BUILD = re.compile(r"^OS build\s+(\S+)", re.M | re.I)
    #: `This is Check Point's software version R81.20 - Build 631` from `fw ver`.
    _FW_VER = re.compile(r"software version\s+(R[\w.]+)", re.I)

    def _parse_show_version(self, result: ParseResult) -> None:
        """Gaia version from `show version all`, falling back to `fw ver` (FR-VUL-01).

        Neither is in the Gaia configuration, so without the supporting artefact this
        device has no version at all and every Check Point advisory is unmatchable
        against it.

        The two sources are tried in order rather than merged: `show version all` names
        the Gaia OS, `fw ver` the firewall module, and on a gateway where they disagree
        the OS version is the one advisories are written against.
        """
        output = result.context.artifact("show version all")
        if output and (match := self._PRODUCT.search(output)):
            result.ncm.device.version = match.group(1)
            result.record("device.version", line=1)
        elif (fallback := result.context.artifact("fw ver")) and (
            match := self._FW_VER.search(fallback)
        ):
            result.ncm.device.version = match.group(1)
            result.record("device.version", line=1)

    # ── interfaces ──────────────────────────────────────────────────────

    def _parse_interfaces(self, context: ParseContext, result: ParseResult) -> None:
        by_name: dict[str, Interface] = {}
        lines: dict[str, int] = {}

        for number, tokens in self._lines(context, "set", "interface"):
            name = tokens[2]
            interface = by_name.setdefault(name, Interface(name=name))
            # One interface spans several `set interface` lines. Provenance points at the
            # first, but every line is consumed — otherwise the rest are reported as
            # unparsed configuration, which would make coverage look far worse than it is
            # and bury the lines that genuinely were not understood.
            lines.setdefault(name, number)
            result.consume(number)
            options = _pairs(tokens, 3)

            address = options.get("ipv4-address") or options.get("ipv6-address")
            if address:
                mask = options.get("mask-length")
                interface.ip_addresses.append(f"{address}/{mask}" if mask else address)

            if "comments" in options:
                interface.description = options["comments"]
            if "state" in options:
                # `off` is a real answer — an interface deliberately shut. Absent is not,
                # and must stay None so a check reports Not Evaluated rather than "down".
                interface.admin_up = options["state"] == "on"

        for name, interface in by_name.items():
            result.ncm.interfaces.append(interface)
            result.record(f"interfaces.{len(result.ncm.interfaces) - 1}", line=lines[name])

        self._parse_routing(context, result)

    # ── routing (FR-TOPO-01) ────────────────────────────────────────────

    def _parse_routing(self, context: ParseContext, result: ParseResult) -> None:
        """Static routes from ``set static-route`` (FR-TOPO-01).

        Gaia writes the next hop as `nexthop gateway address <ip>` or
        `nexthop gateway logical <interface>` — an address or an egress interface in the
        same grammatical slot, the same shape as IOS but spelled with keywords. It ends
        each line with `on` or `off`, and `off` means the route is configured and not
        installed: a route that exists and does not forward. Treating that as an edge
        would put a path through a link the operator has deliberately disabled.

        Called from the interface parser so the connected routes it derives see the
        interface list that has just been built.
        """
        collected: list[tuple[Route, int | None]] = []

        for number, tokens in self._lines(context, "set", "static-route"):
            if len(tokens) < 3:
                continue

            destination = to_cidr(tokens[2])
            if destination is None:
                continue

            if tokens[-1].lower() == "off":
                result.consume(number)
                continue

            next_hop: str | None = None
            interface: str | None = None
            for index, token in enumerate(tokens):
                if token.lower() == "address" and index + 1 < len(tokens):
                    next_hop = tokens[index + 1]
                elif token.lower() == "logical" and index + 1 < len(tokens):
                    interface = tokens[index + 1]

            collected.append(
                (
                    Route(
                        destination=destination,
                        next_hop=next_hop,
                        interface=interface,
                        protocol="static",
                    ),
                    number,
                )
            )

        collected.extend((route, None) for route in connected_routes(result.ncm.interfaces))

        store(result, collected)

    # ── administrators ──────────────────────────────────────────────────

    def _parse_users(self, context: ParseContext, result: ParseResult) -> None:
        by_name: dict[str, LocalUser] = {}
        lines: dict[str, int] = {}

        for number, tokens in self._lines(context, "set", "user"):
            name = tokens[2]
            user = by_name.setdefault(name, LocalUser(name=name))
            lines.setdefault(name, number)
            result.consume(number)
            options = _pairs(tokens, 3)

            if "shell" in options:
                shell = options["shell"]
                user.role = shell
                # A Gaia admin with /bin/bash bypasses clish entirely and every
                # restriction that goes with it. That is the finding this field feeds.
                user.privilege = 15 if shell in _UNRESTRICTED_SHELLS else None

            if "uid" in options and options["uid"] == "0":
                user.privilege = 15

            # `set user admin password-hash $6$...` — the hash itself never enters the
            # NCM; only which algorithm produced it (C-2).
            hashed = options.get("password-hash")
            if hashed:
                user.secret_type = _hash_type(hashed)
                user.weak_hash = _is_weak_hash(hashed)

        for name, user in by_name.items():
            result.ncm.users.append(user)
            result.record(f"users.{len(result.ncm.users) - 1}", line=lines[name])

        for number, tokens in self._lines(context, "add", "rba", "user"):
            # Role-based administration: `add rba user bob roles adminRole`
            options = _pairs(tokens, 4)
            role = options.get("roles")
            existing = by_name.get(tokens[3])
            if existing is not None and role:
                existing.role = role
                if role.lower() in {"adminrole", "admin"}:
                    existing.privilege = 15
                result.consume(number)

    # ── SNMP ────────────────────────────────────────────────────────────

    def _parse_snmp(self, context: ParseContext, result: ParseResult) -> None:
        snmp = result.ncm.snmp

        for number, tokens in self._lines(context, "set", "snmp", "community"):
            community = tokens[3]
            # `read-only` / `read-write` follows the name.
            rw = "read-write" in tokens[4:]
            snmp.v1v2c_communities.append(
                SnmpCommunity(
                    name_masked=mask_secret(community),
                    is_default=is_default_community(community),
                    rw=rw,
                )
            )
            snmp.v1v2c_enabled = True
            result.record(f"snmp.v1v2c_communities.{len(snmp.v1v2c_communities) - 1}", line=number)

        for number, tokens in self._lines(context, "set", "snmp", "agent"):
            # `set snmp agent on|off`. This is the only place a Gaia box says whether the
            # SNMP agent is running at all, so it feeds the management-exposure checks.
            # `off` is a real answer; a missing line leaves it None.
            result.ncm.management.services.snmp.enabled = tokens[3] == "on"
            result.record("management.services.snmp.enabled", line=number)

        for number, tokens in self._lines(context, "set", "snmp", "contact"):
            snmp.contact = " ".join(tokens[3:])
            result.record("snmp.contact", line=number)

        for number, tokens in self._lines(context, "set", "snmp", "location"):
            snmp.location = " ".join(tokens[3:])
            result.record("snmp.location", line=number)

        for number, tokens in self._lines(context, "add", "snmp", "usm", "user"):
            options = _pairs(tokens, 5)
            snmp.v3_users.append(
                SnmpV3User(
                    name=tokens[4],
                    # Gaia states the level directly, which is why this can be answered
                    # rather than inferred from which passwords happen to be set. An
                    # unrecognised spelling becomes "unknown", never a guessed level.
                    level=_SECURITY_LEVELS.get(
                        str(options.get("security-level", "")).lower(), "unknown"
                    ),
                    auth=options.get("authentication-protocol"),
                    priv=options.get("privacy-protocol"),
                )
            )
            result.record(f"snmp.v3_users.{len(snmp.v3_users) - 1}", line=number)

    # ── logging ─────────────────────────────────────────────────────────

    def _parse_logging(self, context: ParseContext, result: ParseResult) -> None:
        logging_ncm = result.ncm.logging

        for number, tokens in self._lines(context, "add", "syslog", "log-remote-address"):
            # The address follows the keyword directly; the key/value options start after
            # it. Reading it as a key/value pair gave `{"10.100.5.10": "level"}` and no
            # syslog server at all.
            host = tokens[3]
            options = _pairs(tokens, 4)
            logging_ncm.syslog_servers.append(
                SyslogServer(host=host, facility=options.get("level"))
            )
            result.record(
                f"logging.syslog_servers.{len(logging_ncm.syslog_servers) - 1}", line=number
            )

        for number, tokens in self._lines(context, "set", "syslog", "auditlog"):
            if len(tokens) > 3:
                # `permanent` means the audit log survives a reboot. Anything else means
                # the record of who changed what is lost on restart.
                logging_ncm.config_change_logging = tokens[3] == "permanent"
                result.record("logging.config_change_logging", line=number)

    # ── time ────────────────────────────────────────────────────────────

    def _parse_ntp(self, context: ParseContext, result: ParseResult) -> None:
        ntp = result.ncm.ntp

        for number, tokens in self._lines(context, "add", "ntp", "server"):
            # `add ntp server primary 10.0.0.1 version 4`
            host = tokens[4] if len(tokens) > 4 else None
            if not host:
                continue
            ntp.servers.append(NtpServer(host=host, authenticated=False))
            result.record(f"ntp.servers.{len(ntp.servers) - 1}", line=number)

        for number, _tokens in self._lines(context, "set", "ntp", "active"):
            # There is no NCM field for "NTP is switched on" — the servers list carries
            # that. Consumed so it does not read as unparsed configuration.
            result.consume(number)

        for number, tokens in self._lines(context, "set", "timezone"):
            ntp.timezone = " ".join(tokens[2:])
            result.record("ntp.timezone", line=number)

        if ntp.servers:
            ntp.authenticated = all(s.authenticated for s in ntp.servers)

    # ── management access ───────────────────────────────────────────────

    def _parse_management(self, context: ParseContext, result: ParseResult) -> None:
        management = result.ncm.management

        for number, tokens in self._lines(context, "set", "web"):
            options = _pairs(tokens, 2)
            if "ssl-port" in options:
                management.services.https.enabled = True
                management.services.https.port = int(options["ssl-port"])
                result.record("management.services.https.enabled", line=number)
            if "table-refresh-rate" in options:
                result.consume(number)

        for number, tokens in self._lines(context, "set", "ssh", "server"):
            options = _pairs(tokens, 3)
            if "port" in options:
                # SshConfig has no port field — SSH on a non-standard port is not a
                # finding anywhere in the library, and inventing a field for it would
                # widen the NCM for nothing. The service being *enabled* is the fact
                # worth recording.
                management.services.ssh.enabled = True
                result.record("management.services.ssh.enabled", line=number)

        for number, tokens in self._lines(context, "set", "inactivity-timeout"):
            # Gaia states it in minutes; the NCM is seconds everywhere.
            management.session.exec_timeout_s = int(tokens[2]) * 60
            result.record("management.session.exec_timeout_s", line=number)

        for number, tokens in self._lines(context, "set", "message", "banner"):
            # `set message banner on "text"` — `on` is the toggle, not part of the
            # banner. Including it would make the "banner mentions authorised use"
            # checks match on the wrong string.
            rest = tokens[3:]
            if rest and rest[0] in {"on", "off"}:
                if rest[0] == "off":
                    result.consume(number)
                    continue
                rest = rest[1:]
            text = " ".join(rest).strip().strip('"')
            if text:
                management.banners.login = text
                result.record("management.banners.login", line=number)

        self._parse_password_policy(context, result)

        for number, tokens in self._lines(context, "add", "allowed-client", "host"):
            management.management_acls["allowed-client"] = tokens[-1]
            result.record("management.management_acls", line=number)

    def _parse_password_policy(self, context: ParseContext, result: ParseResult) -> None:
        policy = result.ncm.management.password_policy

        mapping: dict[str, tuple[str, Any]] = {
            "min-password-length": ("min_length", int),
            "password-expiration-days": ("max_age_days", int),
            "password-history-length": ("history", int),
            "deny-on-nonuse-enable": ("lockout_threshold", None),
        }

        for number, tokens in self._lines(context, "set", "password-controls"):
            options = _pairs(tokens, 2)
            for key, value in options.items():
                target = mapping.get(key)
                if target is None:
                    continue
                field, caster = target
                try:
                    setattr(policy, field, caster(value) if caster else value == "true")
                except (TypeError, ValueError):
                    continue
                result.record(f"management.password_policy.{field}", line=number)

            complexity = options.get("complexity")
            if complexity is not None:
                try:
                    # Gaia grades complexity 1-4 by how many character classes are
                    # required. Anything above 1 means more than one class.
                    policy.complexity_required = int(complexity) > 1
                    result.record("management.password_policy.complexity_required", line=number)
                except ValueError:
                    pass

        for number, tokens in self._lines(context, "set", "password-controls", "lockout-attempts"):
            try:
                policy.lockout_threshold = int(tokens[3])
                result.record("management.password_policy.lockout_threshold", line=number)
            except (IndexError, ValueError):
                continue


# ────────────────────────────── helpers ─────────────────────────────────────


def _hash_type(hashed: str) -> str | None:
    if hashed.startswith("$1$"):
        return "md5-crypt"
    if hashed.startswith("$5$"):
        return "sha256-crypt"
    if hashed.startswith("$6$"):
        return "sha512-crypt"
    if hashed.startswith("$2"):
        return "bcrypt"
    return "unknown"


def _is_weak_hash(hashed: str) -> bool | None:
    kind = _hash_type(hashed)
    if kind == "unknown":
        # Unrecognised is not the same as weak; None makes the check report Not
        # Evaluated rather than accusing a device of something unproven.
        return None
    return kind == "md5-crypt"


__all__ = ["CheckPointGaiaParser"]
