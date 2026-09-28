"""Radware Alteon ADC configuration (SRS §1.3.1, FR-PARSE-01 … FR-PARSE-05).

Alteon prints its configuration as a flat sequence of **menu paths followed by indented
settings** — the CLI is a menu tree and `/cfg/dump` replays the path you would have
walked to set each value:

    /c/l3/if 1
            ena
            ipver v4
            addr 10.136.85.100
            mask 255.255.255.0

Three properties of that format decided the shape of the code below.

**The path is the context and there is no closing token.** A block runs until the next
line that starts with `/`. Nothing says where it ends, so a parser that looks for a
terminator finds the end of the file.

**Some paths are complete commands.** `/c/sys/access/sshd/ena` sets a value with no
indented body at all, and `/c/sys/access/sshd/on` is a *different* setting on the same
object. Both are real lines from a real dump, so the last segment of a path has to be
read as a possible verb rather than assumed to be an object.

**`/c` and `/cfg` are the same tree.** The interactive CLI accepts the abbreviation and
operators use it; `/cfg/dump` emits the long form. A parser that matches one spelling
reads nothing on half the captures it is given, silently, because an Alteon with no
recognised stanza looks exactly like an Alteon that was not collected.

**What this reads, and what it does not.** The management plane is the priority and is
covered: SSH, Telnet, HTTP/HTTPS, SNMP, NTP, syslog, AAA servers, local users,
interfaces and gateways. That is what makes the existing check library apply to an
Alteon at all — those checks are written against the NCM, not against a vendor. Server
load balancing is modelled to the depth that answers "what does this device publish and
where does it send it", which is the ADC-specific question; health-check tuning,
persistence and SSL policy internals are not, and land in `raw_unparsed` where they are
visible rather than silently dropped.

**This parser has never been run against a real appliance.** The fixture is a verified
published configuration dump extended with the management stanzas from Radware's command
reference. That is the strongest evidence available without hardware, and it is recorded
here rather than discovered later — the same position `test_c9800_ap_summary.py` is in,
for the same reason.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from netsecops.ncm.models import (
    AaaServer,
    Interface,
    LocalUser,
    NormalisedConfig,
    NtpServer,
    RealServer,
    Route,
    ServerGroup,
    SnmpCommunity,
    SyslogServer,
    VirtualServer,
    VirtualService,
)
from netsecops.parsers.base import (
    ConfigParser,
    ParseContext,
    ParseResult,
    is_default_community,
    mask_secret,
)

#: A menu path. `/c` and `/cfg` are the same tree — the CLI accepts the abbreviation and
#: `/cfg/dump` emits the long form, so a capture may contain either.
_PATH = re.compile(r"^/(?:c|cfg)(?:/|$)")

#: Alteon quotes names that may contain spaces. The quotes are not part of the value.
_QUOTED = re.compile(r'^"(.*)"$')

#: Settings that mean "this object is on" / "off" when they stand alone in a block.
_ON = frozenset({"ena", "enabled", "on"})
_OFF = frozenset({"dis", "disabled", "off"})


@dataclass(slots=True)
class _Block:
    """One menu path and the settings indented beneath it."""

    path: str
    line: int
    #: `(line number, text)` per setting, so provenance survives.
    settings: list[tuple[int, str]] = field(default_factory=list)

    @property
    def parts(self) -> list[list[str]]:
        """Path segments, each split into its words.

        `/c/slb/virt 10/service 80 http` is four slash-separated segments, and two of
        them carry arguments after a space:
        `[['c'], ['slb'], ['virt', '10'], ['service', '80', 'http']]`.

        Splitting on `/` alone leaves `virt 10` as a single token, which matches no
        dispatch — so every virtual server, every interface and every local account is
        silently skipped while the parser reports success.
        """
        return [segment.split() for segment in self.path.split("/") if segment.strip()]

    def value(self, key: str) -> tuple[int, str] | None:
        """The first setting with this key, and the line it was on."""
        for line, text in self.settings:
            parts = text.split(None, 1)
            if parts and parts[0] == key:
                return line, _unquote(parts[1].strip()) if len(parts) > 1 else ""
        return None

    def flag(self) -> bool | None:
        """Whether the block enables or disables its object.

        `None` where it says neither, which is a block that configures something without
        turning it on or off — not a block that turns it off.
        """
        for _, text in self.settings:
            word = text.strip().lower()
            if word in _ON:
                return True
            if word in _OFF:
                return False
        return None


def _unquote(value: str) -> str:
    match = _QUOTED.match(value.strip())
    return match.group(1) if match else value.strip()


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value else None
    except ValueError:
        return None


def _blocks(lines: list[str]) -> list[_Block]:
    """Group the dump into path blocks.

    A block starts at a path line and runs to the next one. Text before the first path —
    a banner, a `Dump of configuration` header — belongs to no block and is left for
    `finalise_unparsed` to report.
    """
    found: list[_Block] = []
    current: _Block | None = None

    for number, raw in enumerate(lines, start=1):
        text = raw.rstrip()
        stripped = text.strip()
        if not stripped:
            continue

        if _PATH.match(stripped):
            current = _Block(path=stripped, line=number)
            found.append(current)
            continue

        # Indented, and we are inside a block: a setting. An unindented line that is not
        # a path is not part of the configuration tree and stays unparsed.
        if current is not None and text[:1].isspace():
            current.settings.append((number, stripped))

    return found


class RadwareAlteonParser(ConfigParser):
    """Alteon ADC (`/cfg/dump` or `cc`)."""

    vendor = "radware"
    platform = "radware_alteon"

    #: A dump is wrapped in `script start` / `script end` markers and `/*` comments that
    #: carry the version banner, and ends with a bare `/` returning to the menu root.
    #: None of it is configuration, and counting it as unparsed would understate coverage.
    IGNORE = re.compile(r"^(/\*|script start|script end|Dump of|Configuration dump|/$|-+$)")

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        result.ncm.device.vendor = self.vendor
        result.ncm.device.platform = self.platform

        blocks = _blocks(context.lines)
        if not blocks:
            # Nothing that looks like an Alteon menu path. Distinguished from a sparse
            # configuration because the arithmetic that scores coverage cannot tell the
            # difference, and a 99%-parsed pill over an empty NCM is the worst outcome.
            result.ncm.parse_failed = True
            result.ncm.raw_unparsed = [
                "No Alteon menu path (/c/... or /cfg/...) was found, so nothing was read."
            ]
            return result.ncm

        for block in blocks:
            self._read(block, result)

        self._finish_load_balancer(result)
        result.finalise_unparsed(ignore=self.IGNORE)
        return result.ncm

    # ──────────────────────────── dispatch ──────────────────────────────

    def _read(self, block: _Block, result: ParseResult) -> None:
        parts = block.parts
        # parts[0] is `c` or `cfg`; the tree starts after it.
        tail = parts[1:]
        if not tail:
            return

        area = tail[0][0]
        if area == "sys":
            self._system(block, tail[1:], result)
        elif area == "l3":
            self._layer3(block, tail[1:], result)
        elif area == "slb":
            self._slb(block, tail[1:], result)

    # ───────────────────────────── /c/sys ───────────────────────────────

    def _system(self, block: _Block, tail: list[list[str]], result: ParseResult) -> None:
        ncm = result.ncm
        node = tail[0][0] if tail else ""

        if node == "ssnmp":
            self._snmp(block, result)
            return
        if node == "access":
            self._access(block, tail[1:], result)
            return
        if node == "mmgmt":
            self._management_interface(block, result)
            return
        if node in {"ntp"}:
            self._ntp(block, result)
            return
        if node == "syslog":
            self._syslog(block, result)
            return
        if node in {"radius", "tacacs+", "tacplus"}:
            self._aaa(block, node, result)
            return
        if node == "user":
            self._user(block, tail[1:], result)
            return

        # `/c/sys` itself carries assorted globals. Only the ones a check reads are
        # claimed; the rest stay unparsed, which is the honest record of what we skip.
        if not tail:
            if found := block.value("idle"):
                line, value = found
                # Alteon's `idle` is in minutes and is the CLI session timeout, which is
                # what `exec_timeout_s` means everywhere else in the NCM.
                if (minutes := _int(value)) is not None:
                    ncm.management.session.exec_timeout_s = minutes * 60
                    result.record("management.session.exec_timeout_s", line=line)

    def _snmp(self, block: _Block, result: ParseResult) -> None:
        ncm = result.ncm

        if found := block.value("name"):
            line, value = found
            if value:
                ncm.device.hostname = value
                result.record("device.hostname", line=line)

        # Read and write communities are separate settings on Alteon, and which one a
        # default string is on is the whole finding: `public` read-only is an
        # information leak, `public` read-write is a device somebody else administers.
        for key, rw in (("rcomm", False), ("wcomm", True)):
            if found := block.value(key):
                line, value = found
                if not value:
                    continue
                ncm.snmp.v1v2c_communities.append(
                    SnmpCommunity(
                        name_masked=mask_secret(value),
                        is_default=is_default_community(value),
                        rw=rw,
                    )
                )
                index = len(ncm.snmp.v1v2c_communities) - 1
                result.record(f"snmp.v1v2c_communities.{index}", line=line)

        result.consume(block.line)

    def _access(self, block: _Block, tail: list[list[str]], result: ParseResult) -> None:
        """`/c/sys/access/...` — the management services.

        The last path segment may be a verb: `/c/sys/access/sshd/ena` enables SSH with
        no indented body. So the state is taken from the verb where there is one and
        from the block's own `ena`/`dis` otherwise.
        """
        ncm = result.ncm
        if not tail:
            return

        service = tail[0][0]
        verb = tail[1][0].lower() if len(tail) > 1 else None

        state: bool | None
        if verb in _ON:
            state = True
        elif verb in _OFF:
            state = False
        else:
            state = block.flag()

        if state is None:
            return

        if service in {"sshd", "ssh"}:
            ncm.management.services.ssh.enabled = state
            result.record("management.services.ssh.enabled", line=block.line)
        elif service == "telnet":
            ncm.management.services.telnet.enabled = state
            result.record("management.services.telnet.enabled", line=block.line)
        elif service in {"http", "wport"}:
            ncm.management.services.http.enabled = state
            ncm.features.http_server = state
            result.record("management.services.http.enabled", line=block.line)
        elif service in {"https", "ssl"}:
            ncm.management.services.https.enabled = state
            ncm.features.https_server = state
            result.record("management.services.https.enabled", line=block.line)
        elif service == "snmp":
            ncm.management.services.snmp.enabled = state
            result.record("management.services.snmp.enabled", line=block.line)

    def _management_interface(self, block: _Block, result: ParseResult) -> None:
        """`/c/sys/mmgmt` — the dedicated management port.

        Recorded as an interface flagged `is_management` rather than as a bare address:
        every check that asks "is management on its own network" reads the interface
        list, and an address stored anywhere else is invisible to all of them.
        """
        ncm = result.ncm
        addr = block.value("addr")
        if addr is None or not addr[1]:
            return

        mask = block.value("mask")
        address = f"{addr[1]}/{mask[1]}" if mask and mask[1] else addr[1]

        ncm.interfaces.append(
            Interface(
                name="mgmt",
                ip_addresses=[address],
                admin_up=block.flag(),
                is_management=True,
            )
        )
        result.record(f"interfaces.{len(ncm.interfaces) - 1}", line=block.line)
        result.consume(addr[0])
        if mask:
            result.consume(mask[0])

        # The management gateway is a real route and the only one some appliances have.
        if gw := block.value("gw"):
            ncm.routing.routes.append(
                Route(destination="0.0.0.0/0", next_hop=gw[1], interface="mgmt", protocol="static")
            )
            result.record(f"routing.routes.{len(ncm.routing.routes) - 1}", line=gw[0])

    def _ntp(self, block: _Block, result: ParseResult) -> None:
        ncm = result.ncm
        for key in ("prisrv", "secsrv", "server"):
            if found := block.value(key):
                line, value = found
                if not value:
                    continue
                ncm.ntp.servers.append(NtpServer(host=value, prefer=key == "prisrv"))
                result.record(f"ntp.servers.{len(ncm.ntp.servers) - 1}", line=line)

        if (state := block.flag()) is not None:
            result.consume(block.line)
            if not state and not ncm.ntp.servers:
                # NTP off with no servers is a real answer, and the check that asks
                # whether time is synchronised must see it as one rather than as silence.
                result.record("ntp.servers", line=block.line)

    def _syslog(self, block: _Block, result: ParseResult) -> None:
        ncm = result.ncm
        for key in ("host", "host2", "host3", "host4", "host5"):
            if found := block.value(key):
                line, value = found
                if not value or value == "0.0.0.0":
                    continue
                ncm.logging.syslog_servers.append(SyslogServer(host=value))
                result.record(f"logging.syslog_servers.{len(ncm.logging.syslog_servers) - 1}", line=line)

        if found := block.value("sever"):
            line, value = found
            ncm.logging.level = value
            result.record("logging.level", line=line)

    def _aaa(self, block: _Block, node: str, result: ParseResult) -> None:
        ncm = result.ncm
        kind = "radius" if node == "radius" else "tacacs"

        # `secret`/`key` presence, never the value: the NCM stores whether a shared
        # secret is set, which is what the check asks, and storing the string would put
        # a credential in the snapshot that more people read than the device.
        has_key = block.value("secret") is not None or block.value("key") is not None
        port = block.value("port")

        for key in ("prisrv", "secsrv"):
            if found := block.value(key):
                line, value = found
                if not value or value == "0.0.0.0":
                    continue
                ncm.aaa.servers.append(
                    AaaServer(
                        type=kind,
                        host=value,
                        key_configured=has_key,
                        auth_port=_int(port[1]) if port else None,
                    )
                )
                result.record(f"aaa.servers.{len(ncm.aaa.servers) - 1}", line=line)

        if (state := block.flag()) is not None:
            ncm.aaa.new_model = state or ncm.aaa.new_model
            result.record("aaa.new_model", line=block.line)

    def _user(self, block: _Block, tail: list[list[str]], result: ParseResult) -> None:
        """`/c/sys/user/uid <n>` — a local account."""
        ncm = result.ncm
        if not tail or tail[0][0] != "uid":
            return

        name = block.value("name")
        if name is None or not name[1]:
            return

        # `cos` is Alteon's class of service: `admin`, `oper`, `user`. Kept as the
        # vendor's word rather than mapped to a privilege number, which would invent a
        # scale Alteon does not have.
        cos = block.value("cos")

        ncm.users.append(LocalUser(name=name[1], role=cos[1] if cos else None))
        result.record(f"users.{len(ncm.users) - 1}", line=name[0])

    # ───────────────────────────── /c/l3 ────────────────────────────────

    def _layer3(self, block: _Block, tail: list[list[str]], result: ParseResult) -> None:
        ncm = result.ncm
        if not tail:
            return

        node = tail[0]
        if node[0] == "if" and len(node) > 1:
            addr = block.value("addr")
            if addr is None or not addr[1]:
                return
            mask = block.value("mask")
            address = f"{addr[1]}/{mask[1]}" if mask and mask[1] else addr[1]
            vlan = block.value("vlan")

            ncm.interfaces.append(
                Interface(
                    name=f"if{node[1]}",
                    ip_addresses=[address],
                    admin_up=block.flag(),
                    vlan=_int(vlan[1]) if vlan else None,
                )
            )
            result.record(f"interfaces.{len(ncm.interfaces) - 1}", line=block.line)
            result.consume(addr[0])
            if mask:
                result.consume(mask[0])
            if vlan:
                result.consume(vlan[0])
            return

        if node[0] == "gw" and len(node) > 1:
            addr = block.value("addr")
            if addr is None or not addr[1]:
                return
            # An Alteon gateway is a default route. Recorded as one so the device joins
            # the topology graph like anything else — the graph matches a next hop to an
            # interface address, and a gateway stored under its own name joins nothing.
            ncm.routing.routes.append(
                Route(destination="0.0.0.0/0", next_hop=addr[1], protocol="static")
            )
            result.record(f"routing.routes.{len(ncm.routing.routes) - 1}", line=addr[0])
            result.consume(block.line)

    # ───────────────────────────── /c/slb ───────────────────────────────

    def _slb(self, block: _Block, tail: list[list[str]], result: ParseResult) -> None:
        lb = result.ncm.load_balancer

        if not tail:
            if (state := block.flag()) is not None:
                lb.enabled = state
                result.record("load_balancer.enabled", line=block.line)
            return

        node = tail[0]

        if node[0] == "real" and len(node) > 1:
            rip = block.value("rip")
            rport = block.value("rport")
            lb.real_servers.append(
                RealServer(
                    id=node[1],
                    address=rip[1] if rip else None,
                    enabled=block.flag(),
                    port=_int(rport[1]) if rport else None,
                )
            )
            result.record(f"load_balancer.real_servers.{len(lb.real_servers) - 1}", line=block.line)
            if rip:
                result.consume(rip[0])
            return

        if node[0] == "group" and len(node) > 1:
            # `add <id>` repeats, one per member, so `value()` (which takes the first)
            # is the wrong reader here.
            members = [
                text.split(None, 1)[1].strip()
                for _, text in block.settings
                if text.split(None, 1)[:1] == ["add"] and len(text.split(None, 1)) > 1
            ]
            health = block.value("health")
            lb.groups.append(
                ServerGroup(
                    id=node[1],
                    members=members,
                    health_check=health[1] if health else None,
                )
            )
            result.record(f"load_balancer.groups.{len(lb.groups) - 1}", line=block.line)
            for line, text in block.settings:
                if text.startswith("add ") or text.startswith("health "):
                    result.consume(line)
            return

        if node[0] == "virt" and len(node) > 1:
            self._virtual(block, tail, result)

    def _virtual(self, block: _Block, tail: list[list[str]], result: ParseResult) -> None:
        """`/c/slb/virt <id>` and `/c/slb/virt <id>/service <port> <type>`.

        The service path carries its port and type as *path* arguments rather than as
        settings, which is why the id is split off the path here instead of being read
        from the block body.
        """
        lb = result.ncm.load_balancer
        vid = tail[0][1]

        server = next((v for v in lb.virtual_servers if v.id == vid), None)
        if server is None:
            server = VirtualServer(id=vid)
            lb.virtual_servers.append(server)
            result.record(
                f"load_balancer.virtual_servers.{len(lb.virtual_servers) - 1}", line=block.line
            )

        if len(tail) == 1:
            if vip := block.value("vip"):
                server.address = vip[1]
                result.consume(vip[0])
            if (state := block.flag()) is not None:
                server.enabled = state
            result.consume(block.line)
            return

        # `service 80 http` — or `service 80 http/pip`, a sub-object of the service.
        # Only the service itself is modelled; its sub-objects stay unparsed.
        service = tail[1]
        if service[0] != "service" or len(service) < 2:
            return

        if len(tail) > 2:
            # A sub-object such as `/service 80 http/pip`. Not a listener of its own —
            # counted as one it doubles the published surface of every VIP using one.
            return

        port = _int(service[1])
        kind = service[2] if len(service) > 2 else None

        group = block.value("group")
        rport = block.value("rport")
        sslpol = block.value("sslpol")

        server.services.append(
            VirtualService(
                port=port,
                service=kind,
                group=group[1] if group else None,
                real_port=_int(rport[1]) if rport else None,
                ssl_policy=sslpol[1] if sslpol else None,
            )
        )
        result.consume(block.line)
        for found in (group, rport, sslpol):
            if found:
                result.consume(found[0])

    def _finish_load_balancer(self, result: ParseResult) -> None:
        """`/c/slb on` may be absent while virtual servers exist.

        Left as None that is "we could not tell", which on a device covered in VIPs is
        plainly wrong — the feature is manifestly on. Inferred rather than defaulted,
        and only upward: a dump that says `off` is believed.
        """
        lb = result.ncm.load_balancer
        if lb.enabled is None and lb.virtual_servers:
            lb.enabled = True


__all__ = ["RadwareAlteonParser"]
