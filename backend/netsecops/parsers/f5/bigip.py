"""F5 BIG-IP — LTM and the platform beneath it (SRS §1.3, FR-PARSE-01 … FR-PARSE-05).

`tmsh list` prints a brace tree whose top level is a sequence of typed objects:

    ltm virtual /Common/vs_web_https {
        destination /Common/203.0.113.10:443
        pool /Common/pool_web
        profiles {
            /Common/clientssl-secure {
                context clientside
            }
        }
    }

It looks like Junos and is not. **There are no statement terminators** — a setting is
simply a line inside a block, so the brace depth is the only structure there is, and a
parser cannot tell `pool /Common/pool_web` from a block header without looking at
whether the line ends in `{`. That is why this has its own reader rather than sharing
the Junos one, which keys off the semicolon.

Three shapes of the format decided the code:

**A block header carries the object's type and name together.** `ltm virtual <name> {`
is one header of three tokens, and the type is what says how to read the body. Nothing
else identifies it.

**An empty block is written inline.** `/Common/http { }` appears constantly in a
`profiles` stanza and means "this profile is attached with its defaults". Read as an
unterminated header it swallows the rest of the file.

**A brace-delimited list is also written inline.** `options { dont-insert-empty-
fragments no-tlsv1 no-tlsv1.1 }` is a list of values, not a block of settings.

**F5 states TLS as what is *disabled*.** A client-SSL profile carries `no-tlsv1`,
`no-sslv3` and so on, so the accepted versions are the complement of the options. A
reader that treats the option list as a set of enabled versions reports a profile
offering "no-tlsv1" — a version that does not exist — and misses that TLS 1.0 is on.
That inversion is the single most likely thing to get wrong here, and it decides
whether a listener looks hardened or exposed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from netsecops.core.logging import get_logger
from netsecops.ncm.models import (
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

log = get_logger(__name__)

#: Every TLS version a BIG-IP can offer, in the order a reader expects them. F5 names
#: the *disabled* ones, so this is the set the options subtract from.
_TLS_VERSIONS: tuple[str, ...] = ("SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")

#: `no-tlsv1` → the version it switches off.
_NO_OPTION: dict[str, str] = {
    "no-sslv3": "SSLv3",
    "no-tlsv1": "TLSv1.0",
    "no-tlsv1.1": "TLSv1.1",
    "no-tlsv1.2": "TLSv1.2",
    "no-tlsv1.3": "TLSv1.3",
}

#: `/Common/203.0.113.10:443` — a virtual server's destination carries its partition,
#: its address and its port in one token. IPv6 uses a dot before the port.
_DESTINATION = re.compile(r"^(?:/[^/]+/)?(?P<address>.+?)[:.](?P<port>\d+)$")

#: `/Common/10.20.0.11:8443` — a pool member, same shape.
_MEMBER = _DESTINATION


def _name(value: str) -> str:
    """An object name without its partition.

    `/Common/pool_web` and `pool_web` are the same pool, and a virtual server refers to
    it by whichever spelling the configuration used. Comparing them unstripped makes
    every pool reference miss.
    """
    return value.rsplit("/", 1)[-1] if value.startswith("/") else value


@dataclass(slots=True)
class _Block:
    """One `type name { … }` object, and everything inside it."""

    header: list[str]
    line: int
    settings: dict[str, tuple[int, list[str]]] = field(default_factory=dict)
    children: list[_Block] = field(default_factory=list)

    def value(self, key: str) -> str | None:
        found = self.settings.get(key)
        return " ".join(found[1]) if found and found[1] else None

    def line_of(self, key: str) -> int | None:
        found = self.settings.get(key)
        return found[0] if found else None

    def values(self, key: str) -> list[str]:
        found = self.settings.get(key)
        return list(found[1]) if found else []

    def child(self, *header: str) -> _Block | None:
        for block in self.children:
            if tuple(block.header[: len(header)]) == header:
                return block
        return None


def parse_blocks(lines: list[str]) -> list[_Block]:
    """Read a tmsh brace tree into typed blocks.

    Tolerant by construction (FR-PARSE-03): an unexpected line becomes a setting, an
    unbalanced brace closes at end of input, and nothing raises.
    """
    root = _Block(header=[], line=0)
    stack: list[_Block] = [root]

    for number, raw in enumerate(lines, start=1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue

        if text == "}":
            if len(stack) > 1:
                stack.pop()
            continue

        if text.endswith("{"):
            header = text[:-1].split()
            block = _Block(header=header, line=number)
            stack[-1].children.append(block)
            stack.append(block)
            continue

        # `name { }` — an empty block on one line, which `profiles` is full of.
        if text.endswith("{ }") or text.endswith("{}"):
            header = text.rsplit("{", 1)[0].split()
            if header:
                stack[-1].children.append(_Block(header=header, line=number))
            continue

        # `options { a b c }` — a brace-delimited list of values on one line. A block
        # of settings would have been opened with a trailing brace and closed later.
        if "{" in text and text.endswith("}"):
            key, _, rest = text.partition("{")
            tokens = rest[:-1].split()
            name = key.split()
            if name:
                stack[-1].settings[name[0]] = (number, name[1:] + tokens)
            continue

        tokens = text.split()
        if tokens:
            stack[-1].settings[tokens[0]] = (number, tokens[1:])

    return root.children


class F5BigIpParser(ConfigParser):
    vendor = "f5"
    platform = "f5_bigip"

    IGNORE = re.compile(r"^([{}]|#)")

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        result.ncm.device.vendor = self.vendor
        result.ncm.device.platform = self.platform

        blocks = parse_blocks(context.lines)
        if not blocks:
            result.ncm.parse_failed = True
            result.ncm.raw_unparsed = ["No tmsh object was found, so nothing was read."]
            return result.ncm

        #: client-SSL profiles, resolved before the virtual servers that reference them.
        ssl_profiles = self._ssl_profiles(blocks)

        for block in blocks:
            try:
                self._dispatch(block, ssl_profiles, result)
            except Exception as exc:  # pragma: no cover - defensive, per FR-PARSE-03
                log.warning(
                    "parser.section_failed",
                    platform=self.platform,
                    header=" ".join(block.header[:2]),
                    error=str(exc),
                )

        self._version(result)
        result.finalise_unparsed(ignore=self.IGNORE)
        return result.ncm

    # ──────────────────────────── dispatch ──────────────────────────────

    def _dispatch(
        self, block: _Block, ssl_profiles: dict[str, dict[str, object]], result: ParseResult
    ) -> None:
        header = block.header
        kind = " ".join(header[:2])

        if kind == "sys global-settings":
            self._global_settings(block, result)
        elif kind == "sys sshd":
            self._sshd(block, result)
        elif kind == "sys httpd":
            self._httpd(block, result)
        elif kind == "sys snmp":
            self._snmp(block, result)
        elif kind == "sys syslog":
            self._syslog(block, result)
        elif kind == "sys ntp":
            self._ntp(block, result)
        elif header[:1] == ["auth"] and header[1:2] == ["user"]:
            self._user(block, result)
        elif kind == "net self":
            self._self_ip(block, result)
        elif kind == "net route":
            self._route(block, result)
        elif kind == "ltm pool":
            self._pool(block, result)
        elif kind == "ltm virtual":
            self._virtual(block, ssl_profiles, result)

    # ─────────────────────────── the platform ───────────────────────────

    def _global_settings(self, block: _Block, result: ParseResult) -> None:
        if hostname := block.value("hostname"):
            result.ncm.device.hostname = hostname
            result.record("device.hostname", line=block.line_of("hostname"))

    def _sshd(self, block: _Block, result: ParseResult) -> None:
        ncm = result.ncm
        # The stanza's presence is the service. BIG-IP ships with sshd on and a
        # configuration that removes it is rare, so absence here is genuinely unknown
        # rather than off — which is the opposite of Junos and worth being explicit
        # about, since both are brace formats and the temptation is to treat them alike.
        ncm.management.services.ssh.enabled = True
        result.record("management.services.ssh.enabled", line=block.line)

        if timeout := block.value("inactivity-timeout"):
            try:
                ncm.management.session.exec_timeout_s = int(timeout)
                result.record(
                    "management.session.exec_timeout_s",
                    line=block.line_of("inactivity-timeout"),
                )
            except ValueError:
                pass

        if banner := block.value("banner-text"):
            ncm.management.banners.login = banner.strip('"')
            result.record("management.banners.login", line=block.line_of("banner-text"))

    def _httpd(self, block: _Block, result: ParseResult) -> None:
        ncm = result.ncm
        # The management GUI. It is HTTPS-only on a BIG-IP — there is no plaintext
        # option — so the useful facts are the ciphers and the idle timeout.
        ncm.management.services.https.enabled = True
        ncm.features.https_server = True
        result.record("management.services.https.enabled", line=block.line)

        if ciphers := block.value("ssl-ciphersuite"):
            ncm.management.services.https.ciphers = ciphers.split(":")
            result.record(
                "management.services.https.ciphers", line=block.line_of("ssl-ciphersuite")
            )

    def _snmp(self, block: _Block, result: ParseResult) -> None:
        ncm = result.ncm
        communities = block.child("communities")
        if communities is None:
            return

        for entry in communities.children:
            name = entry.value("community-name")
            if not name:
                continue
            # `access` is `ro` or `rw`, and F5 omits it when read-only.
            access = entry.value("access")
            ncm.snmp.v1v2c_communities.append(
                SnmpCommunity(
                    name_masked=mask_secret(name),
                    is_default=is_default_community(name),
                    rw=access == "rw",
                )
            )
            result.record(
                f"snmp.v1v2c_communities.{len(ncm.snmp.v1v2c_communities) - 1}", line=entry.line
            )

    def _syslog(self, block: _Block, result: ParseResult) -> None:
        ncm = result.ncm
        remote = block.child("remote-servers")
        if remote is None:
            return

        for entry in remote.children:
            host = entry.value("host")
            if not host:
                continue
            port = entry.value("remote-port")
            ncm.logging.syslog_servers.append(
                SyslogServer(host=host, port=int(port) if port and port.isdigit() else None)
            )
            result.record(
                f"logging.syslog_servers.{len(ncm.logging.syslog_servers) - 1}", line=entry.line
            )

    def _ntp(self, block: _Block, result: ParseResult) -> None:
        ncm = result.ncm
        # `servers { 10.0.0.1 10.0.0.2 }` — a brace list, read as a value list.
        for host in block.values("servers"):
            ncm.ntp.servers.append(NtpServer(host=host))
            result.record(f"ntp.servers.{len(ncm.ntp.servers) - 1}", line=block.line_of("servers"))

        if timezone := block.value("timezone"):
            ncm.ntp.timezone = timezone

    def _user(self, block: _Block, result: ParseResult) -> None:
        ncm = result.ncm
        if len(block.header) < 3:
            return
        name = _name(block.header[2])

        # The role lives under `partition-access { <partition> { role <role> } }`.
        role = None
        access = block.child("partition-access")
        if access is not None:
            for partition in access.children:
                if found := partition.value("role"):
                    role = found
                    break

        ncm.users.append(LocalUser(name=name, role=role))
        result.record(f"users.{len(ncm.users) - 1}", line=block.line)

    # ───────────────────────────── network ──────────────────────────────

    def _self_ip(self, block: _Block, result: ParseResult) -> None:
        """`net self` — a BIG-IP's own addresses.

        Recorded as interfaces because that is what every address-based join in this
        product reads: the topology graph matches a route's next hop against an
        interface address, and a self IP stored anywhere else joins nothing.
        """
        ncm = result.ncm
        address = block.value("address")
        if not address:
            return

        vlan = block.value("vlan")
        name = _name(block.header[2]) if len(block.header) > 2 else "self"
        ncm.interfaces.append(
            Interface(
                name=name,
                ip_addresses=[address],
                description=vlan,
                # A self IP exists to be used; BIG-IP has no admin-down for one.
                admin_up=True,
                is_management=name.lower() in {"mgmt", "management"},
            )
        )
        result.record(f"interfaces.{len(ncm.interfaces) - 1}", line=block.line)

    def _route(self, block: _Block, result: ParseResult) -> None:
        ncm = result.ncm
        network = block.value("network")
        gateway = block.value("gw")
        if not gateway:
            return

        # `network default` is F5's spelling of the default route.
        destination = "0.0.0.0/0" if network in {None, "default"} else network
        ncm.routing.routes.append(
            Route(destination=destination, next_hop=gateway, protocol="static")
        )
        result.record(f"routing.routes.{len(ncm.routing.routes) - 1}", line=block.line)
        ncm.routing.static_routes = len(ncm.routing.routes)

    # ─────────────────────── load balancing ─────────────────────────────

    def _ssl_profiles(self, blocks: list[_Block]) -> dict[str, dict[str, object]]:
        """Client-SSL profiles, keyed by name.

        Resolved up front because a virtual server names its profile and the profile is
        a sibling object that may appear after it in the file.
        """
        found: dict[str, dict[str, object]] = {}

        for block in blocks:
            if " ".join(block.header[:3]) != "ltm profile client-ssl":
                continue
            if len(block.header) < 4:
                continue

            # **The inversion.** F5 names the versions it will not speak, so the ones it
            # accepts are everything else. Reading the option list as the enabled set
            # reports a profile offering "no-tlsv1" and hides that TLS 1.0 is live.
            disabled = {
                _NO_OPTION[option] for option in block.values("options") if option in _NO_OPTION
            }
            found[_name(block.header[3])] = {
                "tls_versions": [v for v in _TLS_VERSIONS if v not in disabled],
                "ciphers": block.value("ciphers"),
            }

        return found

    def _pool(self, block: _Block, result: ParseResult) -> None:
        lb = result.ncm.load_balancer
        if len(block.header) < 3:
            return
        name = _name(block.header[2])

        members = block.child("members")
        member_ids: list[str] = []

        if members is not None:
            for entry in members.children:
                raw = entry.header[0] if entry.header else ""
                match = _MEMBER.match(raw)
                address = entry.value("address") or (match.group("address") if match else None)
                port = match.group("port") if match else None
                member_id = _name(raw)
                member_ids.append(member_id)

                lb.real_servers.append(
                    RealServer(
                        id=member_id,
                        address=address,
                        port=int(port) if port and port.isdigit() else None,
                        # `session user-disabled` is how a member is taken out of
                        # rotation without deleting it; `state` reports health, which
                        # is a different question and not a configuration fact.
                        enabled=entry.value("session") != "user-disabled",
                    )
                )
                result.record(
                    f"load_balancer.real_servers.{len(lb.real_servers) - 1}", line=entry.line
                )

        lb.groups.append(
            ServerGroup(id=name, members=member_ids, health_check=block.value("monitor"))
        )
        result.record(f"load_balancer.groups.{len(lb.groups) - 1}", line=block.line)
        lb.enabled = True

    def _virtual(
        self, block: _Block, ssl_profiles: dict[str, dict[str, object]], result: ParseResult
    ) -> None:
        lb = result.ncm.load_balancer
        if len(block.header) < 3:
            return
        name = _name(block.header[2])

        destination = block.value("destination") or ""
        match = _DESTINATION.match(destination)
        address = match.group("address") if match else destination or None
        port = match.group("port") if match else None

        # Which attached profile terminates TLS decides whether the listener is
        # encrypted, and it is the only thing that does — `ip-protocol tcp` says nothing.
        tls_versions: list[str] = []
        ssl_policy: str | None = None
        attached = block.child("profiles")
        if attached is not None:
            for profile in attached.children:
                key = _name(profile.header[0]) if profile.header else ""
                if key in ssl_profiles:
                    entry = ssl_profiles[key]
                    versions = entry.get("tls_versions")
                    if isinstance(versions, list):
                        tls_versions = versions
                    ssl_policy = key

        lb.virtual_servers.append(
            VirtualServer(
                id=name,
                address=address,
                # A BIG-IP virtual server is disabled by the *presence* of `disabled`,
                # so its absence is enabled rather than unknown.
                enabled="disabled" not in block.settings,
                services=[
                    VirtualService(
                        port=int(port) if port and port.isdigit() else None,
                        service="https" if tls_versions else None,
                        group=_name(block.value("pool") or "") or None,
                        ssl_policy=ssl_policy,
                        tls_versions=tls_versions,
                    )
                ],
            )
        )
        result.record(
            f"load_balancer.virtual_servers.{len(lb.virtual_servers) - 1}", line=block.line
        )
        lb.enabled = True

    # ──────────────────────────── version ───────────────────────────────

    def _version(self, result: ParseResult) -> None:
        """Version and serial from the two `show` commands.

        Neither is in the configuration, and without the version no CVE can be matched
        (FR-VUL-01).
        """
        ncm = result.ncm

        if output := result.context.artifact("tmsh -q show sys version"):
            if found := re.search(r"^\s*Version\s+(\S+)", output, re.MULTILINE):
                ncm.device.version = found.group(1)
            if found := re.search(r"^\s*Product\s+(\S+)", output, re.MULTILINE):
                ncm.device.model = ncm.device.model or found.group(1)

        if output := result.context.artifact("tmsh -q show sys hardware"):
            if found := re.search(r"^\s*Chassis Serial\s+(\S+)", output, re.MULTILINE):
                if found.group(1) not in ncm.device.serials:
                    ncm.device.serials.append(found.group(1))
            if found := re.search(r"^\s*Platform\s*\n\s*Name\s+(.+?)\s*$", output, re.MULTILINE):
                ncm.device.model = found.group(1).strip()


__all__ = ["F5BigIpParser", "parse_blocks"]
