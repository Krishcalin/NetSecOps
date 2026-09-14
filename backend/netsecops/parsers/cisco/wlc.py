"""Cisco WLC AireOS parser (FR-PARSE-01 … FR-PARSE-05, Phase 5 wireless).

AireOS is unlike every other platform here. `show run-config commands` emits a flat list
of `config ...` statements — the commands that would rebuild the controller — with no
indentation, no blocks and no ordering guarantee. Everything is carried in the token
sequence, and a WLAN's settings are scattered across a dozen lines that share only its
numeric id:

```
config wlan create 3 Corp-WiFi Corp-WiFi
config wlan security wpa akm 802.1x enable 3
config wlan security pmf required 3
config wlan broadcast-ssid enable 3
```

**The id is the join key, and it is the last token, not the first.** That is the single
thing most likely to be got wrong: `config wlan security wpa enable 3` and
`config wlan security wpa enable 13` differ only in a trailing token, and a parser that
matched loosely would apply one WLAN's security settings to another. Every rule here
reads the id off the end and merges into that WLAN alone.

**Security is derived, not stated.** AireOS has no single "this WLAN is WPA2-Enterprise"
line: it is the combination of which WPA version is enabled, which AKM is set, and
whether an 802.1X server is bound. :func:`_classify` assembles that, and leaves the
result `None` when the evidence is incomplete rather than guessing — a WLAN reported as
`wpa2-psk` when it is actually open is a far worse outcome than one reported as unknown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.ncm.models import (
    AaaServer,
    AccessPoint,
    Interface,
    LocalUser,
    NormalisedConfig,
    NtpServer,
    SnmpCommunity,
    SyslogServer,
    Wlan,
)
from netsecops.parsers.base import (
    ConfigParser,
    ParseContext,
    ParseResult,
    is_default_community,
    mask_secret,
)

log = get_logger(__name__)


@dataclass(slots=True)
class _WlanDraft:
    """A WLAN under construction, assembled from lines scattered through the file."""

    wlan_id: str
    ssid: str | None = None
    profile: str | None = None
    enabled: bool | None = None
    broadcast: bool | None = None
    pmf: str | None = None
    fast_transition: bool | None = None
    client_isolation: bool | None = None
    vlan: int | None = None
    radius_group: str | None = None
    #: The raw security evidence, resolved into a verdict by `_classify`.
    wpa: bool | None = None
    wpa2: bool | None = None
    wpa3: bool | None = None
    akms: set[str] = field(default_factory=set)
    wep: bool | None = None
    security_none: bool | None = None
    ciphers: set[str] = field(default_factory=set)
    line: int = 0


def _classify(draft: _WlanDraft) -> str | None:
    """Turn AireOS's scattered security settings into one NCM verdict.

    Returns None where the evidence does not support a conclusion. That matters more
    than it looks: this value drives the "no open SSIDs" and "no PSK on enterprise"
    checks, and a wrong verdict there is a finding that sends someone to change a
    production WLAN — or, worse, a pass on one that is genuinely open.
    """
    if draft.security_none:
        return "open"
    if draft.wep:
        return "wep"

    enterprise = "802.1x" in draft.akms
    psk = "psk" in draft.akms
    sae = "sae" in draft.akms
    owe = "owe" in draft.akms

    if owe:
        return "owe"
    if draft.wpa3:
        if sae:
            return "wpa3-sae"
        if enterprise:
            return "wpa3-ent"
        return "wpa3"
    if draft.wpa2:
        if enterprise:
            return "wpa2-ent"
        if psk:
            return "wpa2-psk"
        return "wpa2"
    if draft.wpa:
        # WPA1 is broken regardless of how it is keyed, so the distinction is not worth
        # drawing — the finding is the same either way.
        return "wpa1"

    if draft.security_none is False:
        # Something turned security *on* but nothing recorded which kind. Unknown is the
        # honest answer; "open" would be a serious false positive.
        return None
    return None


class CiscoWlcParser(ConfigParser):
    vendor = "cisco"
    platform = "cisco_wlc_aireos"

    IGNORE = re.compile(r"^(Cisco Controller|\(Cisco Controller\)|--More--|$)")

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        result.ncm.device.vendor = self.vendor
        result.ncm.device.platform = self.platform

        for section in (
            self._parse_device,
            self._parse_wlans,
            self._parse_aps,
            self._parse_aaa,
            self._parse_management,
            self._parse_users,
            self._parse_snmp,
            self._parse_logging,
            self._parse_time,
            self._parse_interfaces,
            self._parse_rogue,
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
        width = len(prefix)
        found: list[tuple[int, list[str]]] = []
        for number, text in enumerate(context.lines, start=1):
            tokens = text.strip().split()
            if len(tokens) >= width and tuple(t.lower() for t in tokens[:width]) == prefix:
                found.append((number, tokens))
        return found

    # ── device ──────────────────────────────────────────────────────────

    def _parse_device(self, context: ParseContext, result: ParseResult) -> None:
        device = result.ncm.device

        for number, tokens in self._lines(context, "config", "sysname"):
            device.hostname = tokens[2]
            result.record("device.hostname", line=number)

        # `show sysinfo` output, when the collection appended it.
        for number, text in enumerate(context.lines, start=1):
            stripped = text.strip()
            if match := re.match(r"^Product Version\.+\s*(\S+)", stripped):
                device.version = match.group(1)
                result.record("device.version", line=number)
            elif match := re.match(r"^System Name\.+\s*(\S+)", stripped):
                device.hostname = device.hostname or match.group(1)
                result.record("device.hostname", line=number)
            elif match := re.match(r"^Model\.+\s*(\S+)", stripped):
                device.model = match.group(1)
                result.record("device.model", line=number)

    # ── WLANs, which is the point of the platform ───────────────────────

    def _parse_wlans(self, context: ParseContext, result: ParseResult) -> None:
        drafts: dict[str, _WlanDraft] = {}

        def draft_for(wlan_id: str, line: int) -> _WlanDraft:
            existing = drafts.get(wlan_id)
            if existing is None:
                existing = _WlanDraft(wlan_id=wlan_id, line=line)
                drafts[wlan_id] = existing
            return existing

        for number, tokens in self._lines(context, "config", "wlan"):
            lowered = [t.lower() for t in tokens]
            result.consume(number)

            # `config wlan create <id> <profile> <ssid>`
            if len(tokens) >= 6 and lowered[2] == "create":
                draft = draft_for(tokens[3], number)
                draft.profile = tokens[4]
                draft.ssid = tokens[5]
                continue

            # Every other form carries the id as its *last* token. Reading it from a
            # fixed position instead would silently attach one WLAN's settings to
            # another as soon as a command gained an argument.
            wlan_id = tokens[-1]
            if not wlan_id.isdigit():
                continue
            draft = draft_for(wlan_id, number)

            match lowered[2:-1]:
                case ["enable"]:
                    draft.enabled = True
                case ["disable"]:
                    draft.enabled = False
                case ["broadcast-ssid", state]:
                    draft.broadcast = state == "enable"
                case ["security", "wpa", "enable"]:
                    draft.security_none = False
                case ["security", "wpa", "disable"]:
                    draft.wpa = draft.wpa2 = draft.wpa3 = False
                case ["security", "wpa", "wpa1", state]:
                    draft.wpa = state == "enable"
                case ["security", "wpa", "wpa2", state]:
                    draft.wpa2 = state == "enable"
                case ["security", "wpa", "wpa3", state]:
                    draft.wpa3 = state == "enable"
                case ["security", "wpa", "akm", akm, "enable"]:
                    draft.akms.add(akm)
                    draft.security_none = False
                case ["security", "wpa", "akm", akm, "disable"]:
                    draft.akms.discard(akm)
                case ["security", "wpa", "ciphers", cipher, state]:
                    if state == "enable":
                        draft.ciphers.add(cipher)
                case ["security", "pmf", mode]:
                    draft.pmf = mode
                case ["security", "wep", state]:
                    draft.wep = state == "enable"
                case ["security", "none", *_]:
                    draft.security_none = True
                case ["security", "802.1x", state]:
                    if state == "enable":
                        draft.akms.add("802.1x")
                        draft.security_none = False
                    else:
                        draft.akms.discard("802.1x")
                case ["radius_server", "auth", "add", server]:
                    draft.radius_group = server
                case ["mobility", "foreignmap", *_]:
                    pass
                case ["peer-blocking", mode]:
                    # AireOS's name for client isolation. `disable` is a real answer.
                    draft.client_isolation = mode != "disable"
                case ["interface", name]:
                    draft.radius_group = draft.radius_group or None
                    draft.vlan = _vlan_of(name)
                case ["ft", state]:
                    draft.fast_transition = state == "enable"
                case _:
                    continue

        wireless = result.ncm.wireless
        for draft in sorted(drafts.values(), key=lambda d: int(d.wlan_id)):
            if draft.ssid is None:
                # A WLAN configured but never created in this capture. Recorded with its
                # id rather than dropped, because a setting on a WLAN we cannot name is
                # still evidence something exists that we failed to read.
                draft.ssid = f"wlan-{draft.wlan_id}"

            wireless.wlans.append(
                Wlan(
                    ssid=draft.ssid,
                    enabled=draft.enabled,
                    security=_classify(draft),
                    pmf=draft.pmf,
                    fast_transition=draft.fast_transition,
                    radius_group=draft.radius_group,
                    broadcast=draft.broadcast,
                    client_isolation=draft.client_isolation,
                    vlan=draft.vlan,
                )
            )
            result.record(f"wireless.wlans.{len(wireless.wlans) - 1}", line=draft.line)

    # ── access points ───────────────────────────────────────────────────

    def _parse_aps(self, context: ParseContext, result: ParseResult) -> None:
        wireless = result.ncm.wireless

        # `config ap ...` lines are per-AP settings the NCM has no field for. Consumed
        # so they do not read as unparsed configuration, which would understate coverage.
        for number, _tokens in self._lines(context, "config", "ap"):
            result.consume(number)

        # `show ap summary` is a table, not commands. Its columns vary by release, so
        # this reads the two that have been stable: the name first and an address later.
        for number, text in enumerate(context.lines, start=1):
            match = re.match(
                r"^(\S+)\s+\d+\s+(\S+)\s+\S+\s+(\d{1,3}(?:\.\d{1,3}){3})", text.strip()
            )
            if not match:
                continue
            wireless.aps.append(
                AccessPoint(name=match.group(1), model=match.group(2), ip=match.group(3))
            )
            result.record(f"wireless.aps.{len(wireless.aps) - 1}", line=number)

    def _parse_rogue(self, context: ParseContext, result: ParseResult) -> None:
        for number, tokens in self._lines(context, "config", "rogue", "detection"):
            state = tokens[-1].lower()
            result.ncm.wireless.rogue_detection["enabled"] = state == "enable"
            result.record("wireless.rogue_detection", line=number)

        for number, tokens in self._lines(context, "config", "wps", "rogue", "detection"):
            result.ncm.wireless.rogue_detection["enabled"] = tokens[-1].lower() == "enable"
            result.record("wireless.rogue_detection", line=number)

    # ── AAA ─────────────────────────────────────────────────────────────

    def _parse_aaa(self, context: ParseContext, result: ParseResult) -> None:
        aaa = result.ncm.aaa

        # `config radius auth add <index> <ip> <port> ascii <secret>`
        for number, tokens in self._lines(context, "config", "radius", "auth", "add"):
            if len(tokens) < 6:
                continue
            aaa.servers.append(
                AaaServer(
                    type="radius",
                    host=tokens[5],
                    auth_port=_int_or_none(tokens[6] if len(tokens) > 6 else None),
                    # The secret is on this line and is never stored — only that one is
                    # present, which is what the check needs (C-2).
                    key_configured=len(tokens) > 8,
                )
            )
            result.record(f"aaa.servers.{len(aaa.servers) - 1}", line=number)

        for number, tokens in self._lines(context, "config", "radius", "acct", "add"):
            if len(tokens) < 6:
                continue
            aaa.servers.append(
                AaaServer(
                    type="radius",
                    host=tokens[5],
                    acct_port=_int_or_none(tokens[6] if len(tokens) > 6 else None),
                    key_configured=len(tokens) > 8,
                )
            )
            result.record(f"aaa.servers.{len(aaa.servers) - 1}", line=number)

        for number, tokens in self._lines(context, "config", "tacacs", "auth", "add"):
            if len(tokens) < 6:
                continue
            aaa.servers.append(
                AaaServer(
                    type="tacacs",
                    host=tokens[5],
                    auth_port=_int_or_none(tokens[6] if len(tokens) > 6 else None),
                    key_configured=len(tokens) > 8,
                )
            )
            result.record(f"aaa.servers.{len(aaa.servers) - 1}", line=number)

        # `config aaa auth mgmt <first> <second>` — the order administrators are checked
        # against. `local` first means the controller never asks the AAA server.
        for number, tokens in self._lines(context, "config", "aaa", "auth", "mgmt"):
            from netsecops.ncm.models import AaaMethodList

            methods = [t.lower() for t in tokens[4:]]
            aaa.authentication.append(AaaMethodList(name="mgmt", purpose="login", methods=methods))
            aaa.local_fallback = "local" in methods
            result.record("aaa.authentication.0", line=number)

    # ── management plane ────────────────────────────────────────────────

    def _parse_management(self, context: ParseContext, result: ParseResult) -> None:
        services = result.ncm.management.services

        for number, tokens in self._lines(context, "config", "network", "telnet"):
            services.telnet.enabled = tokens[-1].lower() == "enable"
            result.record("management.services.telnet.enabled", line=number)

        for number, tokens in self._lines(context, "config", "network", "ssh"):
            services.ssh.enabled = tokens[-1].lower() == "enable"
            result.record("management.services.ssh.enabled", line=number)

        for number, tokens in self._lines(context, "config", "network", "webmode"):
            # AireOS's name for plain HTTP administration.
            services.http.enabled = tokens[-1].lower() == "enable"
            result.record("management.services.http.enabled", line=number)

        for number, tokens in self._lines(context, "config", "network", "secureweb"):
            if len(tokens) == 4:
                services.https.enabled = tokens[-1].lower() == "enable"
                result.record("management.services.https.enabled", line=number)

        for number, tokens in self._lines(context, "config", "sessions", "timeout"):
            # AireOS states it in minutes; the NCM is seconds everywhere.
            value = _int_or_none(tokens[-1])
            if value is not None:
                result.ncm.management.session.exec_timeout_s = value * 60
                result.record("management.session.exec_timeout_s", line=number)

    def _parse_users(self, context: ParseContext, result: ParseResult) -> None:
        for number, tokens in self._lines(context, "config", "mgmtuser", "add"):
            if len(tokens) < 4:
                continue
            # `config mgmtuser add <name> <password> <role>` — the password is on this
            # line and never leaves it.
            result.ncm.users.append(
                LocalUser(
                    name=tokens[3],
                    role=tokens[5] if len(tokens) > 5 else None,
                    privilege=15 if len(tokens) > 5 and tokens[5].lower() == "read-write" else None,
                )
            )
            result.record(f"users.{len(result.ncm.users) - 1}", line=number)

    def _parse_snmp(self, context: ParseContext, result: ParseResult) -> None:
        snmp = result.ncm.snmp

        for number, tokens in self._lines(context, "config", "snmp", "community", "create"):
            community = tokens[4]
            snmp.v1v2c_communities.append(
                SnmpCommunity(
                    name_masked=mask_secret(community),
                    is_default=is_default_community(community),
                )
            )
            snmp.v1v2c_enabled = True
            result.record(f"snmp.v1v2c_communities.{len(snmp.v1v2c_communities) - 1}", line=number)

        for number, tokens in self._lines(context, "config", "snmp", "version"):
            if len(tokens) >= 5:
                version, state = tokens[3].lower(), tokens[4].lower()
                if version in {"v1", "v2c"} and state == "disable":
                    snmp.v1v2c_enabled = False
                result.record("snmp.v1v2c_enabled", line=number)

    def _parse_logging(self, context: ParseContext, result: ParseResult) -> None:
        for number, tokens in self._lines(context, "config", "logging", "syslog", "host"):
            result.ncm.logging.syslog_servers.append(SyslogServer(host=tokens[4]))
            result.record(
                f"logging.syslog_servers.{len(result.ncm.logging.syslog_servers) - 1}",
                line=number,
            )

    def _parse_time(self, context: ParseContext, result: ParseResult) -> None:
        for number, tokens in self._lines(context, "config", "time", "ntp", "server"):
            if len(tokens) >= 6:
                result.ncm.ntp.servers.append(NtpServer(host=tokens[5], authenticated=False))
                result.record(f"ntp.servers.{len(result.ncm.ntp.servers) - 1}", line=number)

        if result.ncm.ntp.servers:
            result.ncm.ntp.authenticated = all(s.authenticated for s in result.ncm.ntp.servers)

    def _parse_interfaces(self, context: ParseContext, result: ParseResult) -> None:
        by_name: dict[str, Interface] = {}
        lines: dict[str, int] = {}

        for number, tokens in self._lines(context, "config", "interface"):
            if len(tokens) < 4:
                continue
            result.consume(number)
            action = tokens[2].lower()
            name = tokens[3]

            if action in {"create", "address", "vlan", "dhcp", "port"}:
                interface = by_name.setdefault(name, Interface(name=name))
                lines.setdefault(name, number)
                if action == "address" and len(tokens) > 4:
                    interface.ip_addresses.append(tokens[4])
                elif action == "vlan" and len(tokens) > 4:
                    interface.vlan = _int_or_none(tokens[4])
                elif action == "create" and len(tokens) > 4:
                    interface.vlan = _int_or_none(tokens[4])

        for name, interface in by_name.items():
            result.ncm.interfaces.append(interface)
            result.record(f"interfaces.{len(result.ncm.interfaces) - 1}", line=lines[name])


def _int_or_none(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _vlan_of(name: str) -> int | None:
    """An AireOS interface name often encodes its VLAN, e.g. `vlan30` or `corp-30`."""
    match = re.search(r"(\d+)$", name)
    return int(match.group(1)) if match else None


__all__ = ["CiscoWlcParser"]
