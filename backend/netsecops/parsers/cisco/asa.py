"""Cisco ASA configuration parser (FR-PARSE-01 … FR-PARSE-05, FR-FW-01).

The ASA is a firewall, so this parser populates the ``firewall`` branch of the NCM
that the switch parsers leave empty: named interfaces with security levels, network and
service objects, access-lists as an ordered rulebase, and NAT.

Rules are normalised into the common :class:`SecurityRule` tuple here rather than in
Phase 4's analyser, so the shadow/redundancy analysis written for PAN-OS and FortiGate
works on ASA rulebases unchanged (FR-FW-01).

One ASA-specific trap: ``access-list`` lines are flat, not hierarchical, and their
*order within a named list* is the evaluation order. Losing that order would make every
downstream shadowing conclusion wrong, so position is captured explicitly.
"""

from __future__ import annotations

import re
from typing import Any

from ciscoconfparse2 import CiscoConfParse

from netsecops.core.logging import get_logger
from netsecops.ncm.models import (
    AaaServer,
    Acl,
    AclBinding,
    AclEntry,
    Interface,
    LocalUser,
    NatRule,
    NetworkObject,
    NormalisedConfig,
    NtpServer,
    Route,
    SecurityRule,
    SnmpCommunity,
    SyslogServer,
)
from netsecops.parsers.base import (
    CiscoStyleParser,
    ParseContext,
    ParseResult,
    is_default_community,
    mask_secret,
    timeout_to_seconds,
)
from netsecops.parsers.cisco.acl import (
    UNREADABLE,
    read_ports,
    record_bindings,
)
from netsecops.parsers.route_tables import parse_cisco_route_table, store_routes
from netsecops.parsers.routes import connected_routes, parse_asa_route

#: `access-group NAME {in|out} interface NAMEIF`, or `access-group NAME global`.
#:
#: The interface named is the *nameif* — `inside`, `dmz` — not the hardware. That is the
#: name the rulebase is written against and the name the graph records as the interface's
#: zone, so it is kept as written rather than resolved to a physical port.
_ACCESS_GROUP = re.compile(
    r"^access-group\s+(?P<name>\S+)\s+"
    r"(?:(?P<direction>in|out)\s+interface\s+(?P<interface>\S+)|(?P<global_>global))",
    re.IGNORECASE,
)

log = get_logger(__name__)


#: `host X`, `subnet A M`, `range A B` — the ASA's address-object grammar.
_HOST = re.compile(r"^host\s+(\S+)$", re.IGNORECASE)
_SUBNET = re.compile(r"^subnet\s+(\S+)\s+(\S+)$", re.IGNORECASE)
_BARE_MASKED = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$")


def _address_token(text: str) -> str:
    """One ASA address specification, in the vocabulary the resolver reads.

    The resolver understands a bare address, a CIDR prefix and `address/netmask`, and
    nothing else. The ASA writes `host 10.20.0.10` and `subnet 10.20.0.0 255.255.255.0`,
    and this parser stored both verbatim — into object values, into group members and
    into the rules themselves.

    None of them resolved, and the failure was silent in the worst way: an *object* whose
    value could not be read returned an empty address set rather than an error, so every
    rule referencing it was analysed, ordered, and able to match nothing at all. A whole
    ASA rulebase could be inert with no error anywhere. (The resolver now refuses such an
    object outright; this stops it arising.)
    """
    token = text.strip()
    lowered = token.lower()

    if lowered in {"any", "any4"}:
        return "any"
    if match := _HOST.match(token):
        return match.group(1)
    if match := _SUBNET.match(token):
        return f"{match.group(1)}/{match.group(2)}"
    if match := _BARE_MASKED.match(token):
        return f"{match.group(1)}/{match.group(2)}"
    if lowered.startswith(("range ", "fqdn ")):
        # A range is not expressible as a prefix and an FQDN is not an address at all.
        # Marked unreadable so the rule is reported as not understood rather than
        # quietly matching nothing.
        return UNREADABLE
    # `object X`, `object-group X`, `group-object X` — a reference by name.
    parts = token.split()
    if len(parts) == 2 and parts[0].lower() in {"object", "object-group", "group-object"}:
        return parts[1]
    return token


def _member_token(line: str, *, normalise: bool) -> str:
    """One `network-object` / `group-object` line, as a member reference.

    `network-object host 10.100.5.50` yielded `host 10.100.5.50`, which the resolver
    cannot read — so the group resolved to the empty set and every rule using it matched
    nothing. Service groups keep the vendor's wording, which the service resolver reads
    differently.
    """
    _, _, remainder = line.partition(" ")
    remainder = remainder.strip() or line
    return _address_token(remainder) if normalise else remainder


def _protocol_agrees(protocol: str | None, services: list[str]) -> bool:
    """Whether the protocol the device printed is consistent with the parsed entry.

    Used only to verify that the ordinal pairing of `show access-list` output against
    the configuration has not drifted — a mismatch abandons the whole ACL's counts,
    because one misattributed count is worse than none.

    This was a substring test against the service string, which worked only while the
    parser emitted the protocol name inside it (`ip`, `tcp/eq 443`). Normalising those to
    the resolver's vocabulary (`any`, `tcp/443`) turned every `permit ip` entry into a
    mismatch and silently abandoned the counts for any ACL containing one — which is
    most of them, since they all end in `deny ip any any`. A substring test is the wrong
    shape for the question anyway: `ip` is a substring of plenty of things it does not
    mean.
    """
    if protocol is None or not services:
        return True

    head = services[0].split("/", 1)[0].strip().lower()
    if head in {"any", UNREADABLE}:
        # `permit ip …` covers every protocol, so whatever the device printed for this
        # entry is consistent with it.
        return True
    return protocol.strip().lower() == head


def _parse_access_group(line: str) -> AclBinding:
    """One `access-group` line, as a binding.

    An unreadable line becomes an interface-less inbound binding rather than being
    dropped: the ACL *is* bound to something, and forgetting that would put it back in
    the "filters nothing" bucket, where its trailing `deny any` stops being enforced at
    all. An interface of None means "applies everywhere", which is what `global` means
    and is the safe reading of a line this could not parse.
    """
    match = _ACCESS_GROUP.match(line)
    if match is None or match.group("global_"):
        return AclBinding(interface=None, direction="in")
    return AclBinding(interface=match.group("interface"), direction=match.group("direction"))


class CiscoAsaParser(CiscoStyleParser):
    vendor = "cisco"
    platform = "cisco_asa"
    syntax = "asa"

    #: ASA configurations carry structural noise that is not configuration: the `: Saved`
    #: header, `names`, and service lines no baseline check reads. Listing them keeps the
    #: unparsed report meaningful — a report full of known-irrelevant lines would train
    #: readers to ignore it, which is exactly what FR-PARSE-03 is for.
    #:
    #: `route` used to be on this list, as a line nothing read. FR-TOPO-01 is what reads
    #: it: those lines are the forwarding table, and dismissing them as noise is why the
    #: product could describe every rule on a firewall and not which firewall a packet
    #: reaches first.
    IGNORE: re.Pattern[str] = re.compile(
        r"^(?::|names$|end$|exit$|ftp\s+mode|dns\s+|arp\s+timeout"
        r"|timeout\s+|class-map|policy-map|service-policy|prompt\s+|call-home"
        r"|crypto\s+|threat-detection|no\s+threat-detection|same-security-traffic"
        r"|mtu\s+|monitor-interface|failover\s+lan|pager\s+|asdm\s+|boot\s+system"
        r"|Cryptochecksum|enable\s+password)"
    )

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        parse = self.build(context)

        for section in (
            self._parse_device,
            self._parse_management,
            self._parse_users,
            self._parse_aaa,
            self._parse_logging,
            self._parse_ntp,
            self._parse_snmp,
            self._parse_interfaces,
            # After interfaces: connected routes are derived from their addressing, so
            # the interface list has to be populated before this runs.
            self._parse_routing,
            self._parse_objects,
            self._parse_access_lists,
            self._parse_nat,
        ):
            try:
                section(parse, result)
            except Exception as exc:
                log.warning("parser.section_failed", platform=self.platform, error=str(exc))

        result.finalise_unparsed(ignore=self.IGNORE)
        return result.ncm

    # ─────────────────────────────── device ─────────────────────────────

    def _parse_device(self, parse: CiscoConfParse, result: ParseResult) -> None:
        ncm = result.ncm
        ncm.device.vendor = self.vendor
        ncm.device.platform = self.platform

        if hostname := self.first(parse, r"^hostname\s"):
            ncm.device.hostname = self.capture(hostname, r"^hostname\s+(\S+)")
            result.record("device.hostname", line=self.line_number(hostname))

        if domain := self.first(parse, r"^domain-name\s"):
            ncm.device.domain_name = self.capture(domain, r"^domain-name\s+(\S+)")
            result.record("device.domain_name", line=self.line_number(domain))

        # An ASA configuration states its own image version on the first line, so the
        # config alone identifies the software for CVE matching.
        for line_number, text in enumerate(result.context.lines, start=1):
            if match := re.match(r"^ASA Version\s+(\S+)", text.strip()):
                ncm.device.version = match.group(1)
                result.record("device.version", line=line_number)
                break

        self._parse_show_version(result)

        if failover := self.first(parse, r"^failover\s*$"):
            ncm.device.ha.enabled = True
            result.record("device.ha.enabled", line=self.line_number(failover))

    #: `Model Id: ASA5525` or `Hardware:   ASA5525, 8192 MB RAM, ...`
    _MODEL = re.compile(r"^\s*(?:Model Id|Hardware)\s*:\s*([\w-]+)", re.I | re.M)
    #: `Serial Number: JMX1935L0GT`
    _SERIAL = re.compile(r"^\s*Serial Number\s*:\s*(\S+)", re.I | re.M)

    def _parse_show_version(self, result: ParseResult) -> None:
        """Hardware model and serial from `show version` (FR-VUL-01).

        The software version is already in the configuration; the appliance model is
        not, and an ASA advisory is frequently scoped to particular hardware.
        """
        output = result.context.artifact("show version")
        if output is None:
            return

        if match := self._MODEL.search(output):
            result.ncm.device.model = match.group(1).rstrip(",")
            result.record("device.model", line=1)

        if match := self._SERIAL.search(output):
            result.ncm.device.serials = [match.group(1)]
            result.record("device.serials", line=1)

    # ───────────────────────────── management ───────────────────────────

    def _parse_management(self, parse: CiscoConfParse, result: ParseResult) -> None:
        management = result.ncm.management

        ssh_lines = parse.find_objects(r"^ssh\s+\d+\.\d+\.\d+\.\d+")
        management.services.ssh.enabled = bool(ssh_lines) or None
        for obj in ssh_lines:
            result.consume(self.line_number(obj))

        if ssh_version := self.first(parse, r"^ssh\s+version\s"):
            management.services.ssh.version = self.capture_int(ssh_version, r"version\s+(\d)")
            result.record("management.services.ssh.version", line=self.line_number(ssh_version))

        if ssh_timeout := self.first(parse, r"^ssh\s+timeout\s"):
            management.services.ssh.timeout_s = timeout_to_seconds(
                self.capture(ssh_timeout, r"timeout\s+(\d+)")
            )
            result.record("management.services.ssh.timeout_s", line=self.line_number(ssh_timeout))

        if ciphers := self.first(parse, r"^ssh\s+cipher\s+encryption"):
            management.services.ssh.ciphers = ciphers.text.split()[3:]
            result.record("management.services.ssh.ciphers", line=self.line_number(ciphers))

        # Telnet on an ASA is configured per-interface; any line at all means enabled.
        telnet_lines = parse.find_objects(r"^telnet\s+\d+\.\d+\.\d+\.\d+")
        management.services.telnet.enabled = bool(telnet_lines)
        for obj in telnet_lines:
            result.record("management.services.telnet.enabled", line=self.line_number(obj))

        http_lines = parse.find_objects(r"^http\s+\d+\.\d+\.\d+\.\d+")
        if http_server := self.first(parse, r"^http\s+server\s+enable"):
            management.services.https.enabled = True
            management.services.https.port = self.capture_int(http_server, r"enable\s+(\d+)")
            result.record("management.services.https.enabled", line=self.line_number(http_server))
        elif self.present(parse, r"^no\s+http\s+server\s+enable"):
            management.services.https.enabled = False
        for obj in http_lines:
            result.consume(self.line_number(obj))

        if console := self.first(parse, r"^console\s+timeout\s"):
            management.session.console_timeout_s = timeout_to_seconds(
                self.capture(console, r"timeout\s+(\d+)")
            )
            result.record("management.session.console_timeout_s", line=self.line_number(console))

        if banner := self.first(parse, r"^banner\s+login"):
            management.banners.login = banner.text
            result.record("management.banners.login", line=self.line_number(banner))

        for obj in parse.find_objects(r"^password-policy\s"):
            if minimum := self.capture(obj, r"minimum-length\s+(\d+)"):
                management.password_policy.min_length = int(minimum)
                result.record("management.password_policy.min_length", line=self.line_number(obj))
            result.consume(self.line_number(obj))

    # ────────────────────────── users and AAA ───────────────────────────

    def _parse_users(self, parse: CiscoConfParse, result: ParseResult) -> None:
        for obj in parse.find_objects(r"^username\s"):
            name = self.capture(obj, r"^username\s+(\S+)")
            if not name:
                continue
            privilege = self.capture_int(obj, r"privilege\s+(\d+)")
            # `encrypted` and `nt-encrypted` are MD5-family; `pbkdf2` is the modern one.
            weak = "pbkdf2" not in obj.text

            result.ncm.users.append(
                LocalUser(
                    name=name,
                    privilege=privilege,
                    secret_type="pbkdf2" if not weak else "encrypted",
                    weak_hash=weak,
                )
            )
            result.record(f"users.{len(result.ncm.users) - 1}", line=self.line_number(obj))

    def _parse_aaa(self, parse: CiscoConfParse, result: ParseResult) -> None:
        aaa = result.ncm.aaa

        for obj in parse.find_objects(r"^aaa-server\s+\S+\s+\(\S+\)\s+host"):
            start, end = self.family_range(obj)
            host = self.capture(obj, r"host\s+(\S+)")
            group = self.capture(obj, r"^aaa-server\s+(\S+)")
            if not host:
                result.consume(start, end)
                continue

            children = "\n".join(child.text for child in obj.all_children)
            aaa.servers.append(
                AaaServer(
                    type="tacacs" if "tacacs" in (group or "").lower() else "radius",
                    host=host,
                    group=group,
                    key_configured="key " in children,
                )
            )
            result.record(f"aaa.servers.{len(aaa.servers) - 1}", line=start, line_end=end)
            result.consume(start, end)

        for obj in parse.find_objects(r"^aaa-server\s+\S+\s+protocol"):
            start, end = self.family_range(obj)
            result.consume(start, end)

        for obj in parse.find_objects(r"^aaa\s+authentication"):
            result.consume(self.line_number(obj))

    # ──────────────────────── logging, NTP, SNMP ────────────────────────

    def _parse_logging(self, parse: CiscoConfParse, result: ParseResult) -> None:
        logging_ncm = result.ncm.logging

        for obj in parse.find_objects(r"^logging\s+host\s"):
            host = self.capture(obj, r"host\s+\S+\s+(\S+)")
            if host:
                logging_ncm.syslog_servers.append(SyslogServer(host=host))
                result.record(
                    f"logging.syslog_servers.{len(logging_ncm.syslog_servers) - 1}",
                    line=self.line_number(obj),
                )

        if trap := self.first(parse, r"^logging\s+trap\s"):
            logging_ncm.level = self.capture(trap, r"trap\s+(\S+)")
            result.record("logging.level", line=self.line_number(trap))

        if buffered := self.first(parse, r"^logging\s+buffered\s"):
            logging_ncm.buffered.enabled = True
            logging_ncm.buffered.severity = self.capture(buffered, r"buffered\s+(\S+)")
            result.record("logging.buffered.enabled", line=self.line_number(buffered))

        if enabled := self.first(parse, r"^logging\s+enable"):
            result.record("logging.level", line=self.line_number(enabled))

        if timestamp := self.first(parse, r"^logging\s+timestamp"):
            logging_ncm.timestamps = "enabled"
            result.record("logging.timestamps", line=self.line_number(timestamp))

        for obj in parse.find_objects(r"^logging\s"):
            result.consume(self.line_number(obj))

    def _parse_ntp(self, parse: CiscoConfParse, result: ParseResult) -> None:
        ntp = result.ncm.ntp

        for obj in parse.find_objects(r"^ntp\s+server\s"):
            host = self.capture(obj, r"ntp\s+server\s+(\S+)")
            if not host:
                continue
            key_id = self.capture_int(obj, r"key\s+(\d+)")
            ntp.servers.append(
                NtpServer(host=host, authenticated=key_id is not None, key_id=key_id)
            )
            result.record(f"ntp.servers.{len(ntp.servers) - 1}", line=self.line_number(obj))

        if ntp.servers:
            ntp.authenticated = any(s.authenticated for s in ntp.servers)

        for obj in parse.find_objects(r"^ntp\s"):
            result.consume(self.line_number(obj))

    def _parse_snmp(self, parse: CiscoConfParse, result: ParseResult) -> None:
        snmp = result.ncm.snmp
        hosts = parse.find_objects(r"^snmp-server\s+host\s")

        for obj in hosts:
            community = self.capture(obj, r"community\s+(\S+)")
            if community:
                snmp.v1v2c_communities.append(
                    SnmpCommunity(
                        name_masked=mask_secret(community),
                        is_default=is_default_community(community),
                        rw=False,
                    )
                )
                result.record(
                    f"snmp.v1v2c_communities.{len(snmp.v1v2c_communities) - 1}",
                    line=self.line_number(obj),
                )

        snmp.v1v2c_enabled = bool(snmp.v1v2c_communities)

        if location := self.first(parse, r"^snmp-server\s+location"):
            snmp.location = location.text.split("location", 1)[1].strip()
            result.record("snmp.location", line=self.line_number(location))

        for obj in parse.find_objects(r"^snmp-server\s"):
            result.consume(self.line_number(obj))

    # ───────────────────────────── interfaces ───────────────────────────

    def _parse_interfaces(self, parse: CiscoConfParse, result: ParseResult) -> None:
        for obj in parse.find_objects(r"^interface\s"):
            start, end = self.family_range(obj)
            name = self.capture(obj, r"^interface\s+(\S+)")
            if not name:
                continue

            children = "\n".join(child.text for child in obj.all_children)
            interface = Interface(name=name)
            interface.admin_up = "shutdown" not in children

            for child in obj.children:
                text = child.text.strip()
                if match := re.match(r"nameif\s+(\S+)", text):
                    # On an ASA the nameif *is* the zone for policy purposes.
                    interface.zone = match.group(1)
                    interface.is_management = match.group(1).lower() in {"management", "mgmt"}
                elif match := re.match(r"ip address\s+(\S+)\s+(\S+)", text):
                    interface.ip_addresses.append(f"{match.group(1)}/{match.group(2)}")
                elif match := re.match(r"vlan\s+(\d+)", text):
                    interface.vlan = int(match.group(1))
                elif match := re.match(r"description\s+(.+)", text):
                    interface.description = match.group(1)

            result.ncm.interfaces.append(interface)
            result.record(f"interfaces.{len(result.ncm.interfaces) - 1}", line=start, line_end=end)
            result.consume(start, end)

        result.ncm.firewall.zones = sorted({i.zone for i in result.ncm.interfaces if i.zone})

    # ────────────────────────────── routing ─────────────────────────────

    def _parse_routing(self, parse: CiscoConfParse, result: ParseResult) -> None:
        """The forwarding table, from lines this parser used to discard (FR-TOPO-01).

        An ASA is usually the device a path *ends* at, so its table matters twice over:
        it says which way traffic leaves, and the interface each route exits names the
        nameif — which on an ASA is the security zone the rulebase is written against.
        That makes an ASA route the join between "where does this packet go" and "which
        rule decides", which is the whole point of walking a path.
        """
        collected: list[tuple[Route, int | None]] = []
        for obj in parse.find_objects(r"^route\s"):
            route = parse_asa_route(obj.text)
            if route is None:
                continue
            collected.append((route, self.line_number(obj)))

        collected.extend((route, None) for route in connected_routes(result.ncm.interfaces))

        # The ASA spells it `show route`, without the `ip`.
        store_routes(
            result,
            "show route",
            parser=parse_cisco_route_table,
            from_config=collected,
        )

    # ──────────────────────────── objects ───────────────────────────────

    def _parse_objects(self, parse: CiscoConfParse, result: ParseResult) -> None:
        firewall = result.ncm.firewall

        for obj in parse.find_objects(r"^object\s+(network|service)\s"):
            start, end = self.family_range(obj)
            match = re.match(r"^object\s+(network|service)\s+(\S+)", obj.text)
            if not match:
                result.consume(start, end)
                continue

            kind, name = match.groups()
            value = None
            for child in obj.children:
                text = child.text.strip()
                if text.startswith(("host ", "subnet ", "range ", "fqdn ", "service ")):
                    value = text
                    break

            # Address objects are normalised; service objects keep the vendor's wording,
            # which the service resolver reads in its own way.
            if kind == "network" and value:
                value = _address_token(value)
            network_object = NetworkObject(name=name, type=kind, value=value)
            (firewall.address_objects if kind == "network" else firewall.service_objects).append(
                network_object
            )
            result.consume(start, end)

        for obj in parse.find_objects(r"^object-group\s"):
            start, end = self.family_range(obj)
            match = re.match(r"^object-group\s+(\S+)\s+(\S+)", obj.text)
            if not match:
                result.consume(start, end)
                continue

            kind, name = match.groups()
            is_service = kind.startswith("service")
            members = [
                _member_token(child.text.strip(), normalise=not is_service)
                for child in obj.children
                if child.text.strip().startswith(
                    ("network-object", "service-object", "group-object", "port-object")
                )
            ]
            group = NetworkObject(name=name, type=kind, members=members)
            (
                firewall.service_groups if kind.startswith("service") else firewall.address_groups
            ).append(group)
            result.consume(start, end)

    # ────────────────────────── access lists ────────────────────────────

    def _parse_access_lists(self, parse: CiscoConfParse, result: ParseResult) -> None:
        """ACLs, as both an NCM ACL and a normalised firewall rulebase (FR-FW-01)."""
        firewall = result.ncm.firewall
        acls: dict[str, Acl] = {}
        order = 0

        for obj in parse.find_objects(r"^access-list\s"):
            text = obj.text.strip()
            result.consume(self.line_number(obj))

            match = re.match(
                r"^access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(.*)$", text
            )
            if not match:
                # `access-list X remark ...` and standard ACLs land here; the remark is
                # not a rule, so it is skipped rather than mis-parsed into one.
                continue

            name, action, protocol, remainder = match.groups()
            acl = acls.setdefault(name, Acl(name=name, type="extended"))
            acl.entries.append(
                AclEntry(
                    action=action,
                    protocol=protocol,
                    log="log" in remainder,
                    raw=text,
                    sequence=len(acl.entries) + 1,
                )
            )

            tokens = remainder.split()
            source, destination, position = self._split_source_destination(tokens)

            order += 1
            firewall.security_rules.append(
                SecurityRule(
                    order=order,
                    name=name,
                    # Each ACL is its own enforcement context: it is bound to particular
                    # interfaces, and an entry in one is never evaluated against a packet
                    # that an entry in another sees.
                    rulebase=name,
                    action="allow" if action == "permit" else "deny",
                    src=[source] if source else [],
                    dst=[destination] if destination else [],
                    services=self._services(protocol, tokens, position),
                    log_end="log" in remainder,
                )
            )

        bindings: dict[str, list[AclBinding]] = {}
        raw_bindings: dict[str, list[str]] = {}
        for name, acl in acls.items():
            applied = parse.find_objects(rf"^access-group\s+{re.escape(name)}\s")
            for obj in applied:
                line = obj.text.strip()
                raw_bindings.setdefault(name, []).append(line)
                bindings.setdefault(name, []).append(_parse_access_group(line))
                result.consume(self.line_number(obj))
            result.ncm.acls.append(acl)

        # An ASA ACL with no `access-group` filters nothing, and a detached one is common
        # here because it is written before the change window that binds it. Beyond that,
        # *which* list is bound where is what lets the path walk pick the one governing a
        # hop rather than evaluating all of them as a single ordered list.
        record_bindings(result.ncm, bindings, raw=raw_bindings)

        for obj in parse.find_objects(r"^access-group\s"):
            result.consume(self.line_number(obj))

        self._apply_hit_counts(result)

    # ────────────────────────── ACL hit counts ──────────────────────────

    #: `access-list NAME line 7 extended permit tcp ...` — the ACE header the show
    #: output puts in front of every entry. `elements`/`name hash` summary lines and
    #: the `cached ACL log flows` preamble do not match, which is how they are skipped.
    _SHOW_ACE = re.compile(r"^access-list\s+(\S+)\s+line\s+(\d+)\s+(.*)$")
    #: `(hitcnt=1423)`. Absent on the object-group parent line, which carries no count
    #: of its own — the expanded children below it do.
    _HITCNT = re.compile(r"\(hitcnt=(\d+)\)")

    def _apply_hit_counts(self, result: ParseResult) -> None:
        """Attach `show access-list` hit counts to the parsed rulebase (FR-FW-03).

        The counts are not in the running configuration, so without this every ASA
        rule reports an unknown hit count and the unused-rule checks never fire.

        Two properties of the show output make naive matching wrong, and both are the
        reason this is ordinal-with-verification rather than a text comparison:

        * **Remarks occupy line numbers.** `access-list X remark ...` is line 1 and the
          first real ACE is line 2, so the Nth ACE is not line N. Remarks are dropped
          from both sides before pairing.
        * **Object-group ACEs expand.** One configured ACE becomes a parent line with no
          count plus one child line per expanded combination, all sharing its line
          number. The configured rule was matched whenever *any* child was, so counts
          are summed per line number. Taking the parent alone would report a busy rule
          as never hit, which is the one error that gets a live rule deleted.

        Text matching is not an option either: the show output resolves ports to names,
        printing `eq https` where the configuration says `eq 443`.

        So pairing is ordinal, and then *verified* — action and protocol must agree on
        every pair. If any disagrees the whole ACL is abandoned with its counts left
        None, because a drift of one somewhere in the list misattributes every count
        after it, and a wrong count is worse here than no count: `hit_count` of 0 means
        *never hit* and is what the cleanup checks act on, while None means unknown and
        is reported as Not Evaluated.
        """
        output = result.context.artifact("show access-list")
        if output is None:
            return

        counts = self._read_hit_counts(output)
        if not counts:
            return

        rules_by_acl: dict[str, list[SecurityRule]] = {}
        for rule in result.ncm.firewall.security_rules:
            if rule.name:
                rules_by_acl.setdefault(rule.name, []).append(rule)

        for acl, observed in counts.items():
            rules = rules_by_acl.get(acl)
            if rules is None or len(rules) != len(observed):
                # The device is enforcing a different number of entries than we parsed
                # out of the configuration. Which of the two is authoritative is not
                # knowable from here, so nothing is attributed.
                continue

            paired = list(zip(rules, observed, strict=True))
            if any(
                rule.action != ("allow" if action == "permit" else "deny")
                or not _protocol_agrees(protocol, rule.services)
                for rule, (action, protocol, _) in paired
            ):
                log.warning("parser.hit_counts_misaligned", platform=self.platform, acl=acl)
                continue

            for rule, (_, _, hits) in paired:
                rule.hit_count = hits

    def _read_hit_counts(self, output: str) -> dict[str, list[tuple[str, str | None, int | None]]]:
        """Per-ACL ACE list of ``(action, protocol, hits)``, in device order.

        ``hits`` is None when no line for that entry carried a count at all — an
        object-group parent whose children were somehow absent, for instance. Summing
        those to 0 would invent a never-hit verdict out of missing data.
        """
        # (acl, line number) -> [action, protocol, running total or None]
        merged: dict[tuple[str, int], list[Any]] = {}
        order: list[tuple[str, int]] = []

        for line in output.splitlines():
            match = self._SHOW_ACE.match(line.strip())
            if not match:
                continue

            acl, number, remainder = match.group(1), int(match.group(2)), match.group(3)
            tokens = remainder.split()
            if not tokens or tokens[0] == "remark":
                continue

            # `extended permit tcp ...` and the rarer `permit tcp ...` both occur.
            if tokens[0] in {"extended", "standard"}:
                tokens = tokens[1:]
            if not tokens or tokens[0] not in {"permit", "deny"}:
                continue

            action = tokens[0]
            protocol = tokens[1] if len(tokens) > 1 else None
            hits = int(m.group(1)) if (m := self._HITCNT.search(remainder)) else None

            key = (acl, number)
            if key not in merged:
                merged[key] = [action, protocol, hits]
                order.append(key)
            elif hits is not None:
                current = merged[key][2]
                merged[key][2] = hits if current is None else current + hits

        counts: dict[str, list[tuple[str, str | None, int | None]]] = {}
        for acl, number in order:
            action, protocol, hits = merged[(acl, number)]
            counts.setdefault(acl, []).append((action, protocol, hits))
        return counts

    @staticmethod
    def _split_source_destination(tokens: list[str]) -> tuple[str, str, int]:
        """Split an ASA ACE tail into source, destination and where the ports begin.

        ASA syntax is positional and varies in width: ``any``/``host X``/``X mask``/
        ``object-group G`` each consume a different number of tokens. Getting this
        wrong silently swaps source and destination, which would invert every
        reachability conclusion drawn from the rulebase — so it is done explicitly.
        """

        def take(index: int) -> tuple[str, int]:
            if index >= len(tokens):
                return "", index
            # Named `word` rather than `token` so the string comparisons below are not
            # flagged as a hardcoded credential; it is also the name the IOS reader uses.
            word = tokens[index]
            if word in {"any", "any4"}:
                return "any", index + 1
            if word == "any6":
                # Left as written. A v6 rule genuinely does not match a v4 packet, so it
                # failing to resolve into the v4 space is the right outcome rather than
                # a gap to paper over.
                return word, index + 1
            if word in {"host", "object", "object-group"}:
                # The keyword is grammar, not part of the name. Returning `host
                # 10.20.0.10` or `object-group GRP-ADMINS` produced a string the
                # resolver could not look up: it landed in the rule's `unresolved` list
                # and the rule stopped matching anything — so every ASA entry naming a
                # host or a group was invisible, and its access list fell through to the
                # implicit deny. The IOS reader has always stripped it.
                if index + 1 < len(tokens):
                    return tokens[index + 1], index + 2
                return UNREADABLE, index + 1
            if word == "interface":
                # `interface outside` means whatever address that interface holds, which
                # is not knowable from the rulebase alone. The sentinel says so; a name
                # here would look like an object that merely happens to be missing.
                return UNREADABLE, index + 2 if index + 1 < len(tokens) else index + 1
            # A bare address is followed by its mask.
            if index + 1 < len(tokens) and re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[index + 1]):
                return f"{word}/{tokens[index + 1]}", index + 2
            return word, index + 1

        source, position = take(0)
        destination, position = take(position)

        return source, destination, position

    @staticmethod
    def _services(protocol: str, tokens: list[str], position: int) -> list[str]:
        """The ACE's service, in the vocabulary the resolver reads.

        This used to emit the raw operator — `tcp/eq 443 log` — and `ip` for a
        protocol-agnostic entry. Neither resolves: `ip` is not a protocol name and
        `eq 443 log` is not a port range, so both landed in the rule's `unresolved` list
        and took it out of matching. The effect was that **no ASA rule matched anything**
        in a path walk: every list fell through to its implicit deny, so every path
        across an ASA was reported blocked. It went unnoticed because the flattened
        rulebase hit some other list's `deny ip any any` first and produced the same
        answer for a different wrong reason.

        `read_ports` is the IOS/NX-OS reader, used here rather than reimplemented, so
        there is one dialect rather than two — including its refusal to express `neq`,
        which marks the rule partial instead of quietly widening it.
        """
        # `permit ip …` means every protocol, which is what `any` means to the resolver.
        # It is what `parse_ace` already emits for the same entry on IOS.
        if protocol in {"ip", "ipv4"}:
            return ["any"]

        services, _, refused = read_ports(tokens, position, protocol)
        if refused:
            return [UNREADABLE]
        return services or [protocol]

    # ──────────────────────────────── NAT ───────────────────────────────

    def _parse_nat(self, parse: CiscoConfParse, result: ParseResult) -> None:
        firewall = result.ncm.firewall
        order = 0

        for obj in parse.find_objects(r"^nat\s+\("):
            order += 1
            rule = NatRule(
                order=order,
                direction=self.capture(obj, r"^nat\s+\(([^)]+)\)"),
                raw=obj.text.strip(),
            )
            _normalise_twice_nat(rule)
            firewall.nat_rules.append(rule)
            result.consume(self.line_number(obj))

        for obj in parse.find_objects(r"^object\s+network\s"):
            object_name = self.capture(obj, r"^object\s+network\s+(\S+)")
            for child in obj.all_children:
                if child.text.strip().startswith("nat ("):
                    order += 1
                    rule = NatRule(order=order, raw=child.text.strip())
                    _normalise_object_nat(rule, object_name)
                    firewall.nat_rules.append(rule)


#  ───────────────────────────── NAT normalisation ─────────────────────────────
#
# ASA is the only one of the four platforms that ships no structured NAT at all: the
# collector returns configuration text, so the grammar has to be read here. Both forms
# are handled, and both leave `translation_unreadable` set rather than guessing when
# the line says something this does not model.


#: The keyword that must follow `source` or `destination` in a twice-NAT line.
_NAT_KINDS = frozenset({"static", "dynamic"})


def _normalise_twice_nat(rule: NatRule) -> None:
    """`nat (real,mapped) source {static|dynamic} REAL MAPPED [destination static …]`.

    Two traps in ASA's own syntax, and getting either backwards inverts the answer.

    **`destination static` reverses its arguments.** In `source static A B`, A is real
    and B is mapped; in `destination static C D`, C is *mapped* and D is *real*. Cisco
    writes it that way because the clause reads from the perspective of a packet
    arriving on the mapped interface, and it is the single most-confused thing in the
    syntax.

    **`interface` is not an address.** It means whichever address the named interface
    currently holds, which is not in this line. Resolving it needs the device's
    interface table, so it is recorded as unreadable here and the consumer decides.
    """
    tokens = rule.raw.split()
    if not tokens or tokens[0] != "nat":
        return

    interfaces = rule.direction or ""
    real_ifc, _, mapped_ifc = interfaces.partition(",")

    index = 0
    while index < len(tokens):
        word = tokens[index]

        # Both clauses are `<clause> static|dynamic A B`. The keyword is checked rather
        # than assumed: without it, a malformed or unfamiliar line consumes four tokens
        # from the wrong offset and silently produces confident nonsense.
        if word == "source" and index + 3 < len(tokens) and tokens[index + 1] in _NAT_KINDS:
            kind = tokens[index + 1]
            real, mapped = tokens[index + 2], tokens[index + 3]
            rule.original_source = [] if real == "any" else [real]
            if mapped == "interface":
                rule.translation_unreadable = (
                    f"the source becomes whichever address interface "
                    f"{mapped_ifc or 'the mapped interface'} holds, which this line "
                    "does not state"
                )
            elif kind == "dynamic" and mapped == "any":
                rule.translation_unreadable = "a dynamic pool, chosen per session"
            else:
                rule.translated_source = [mapped]
            index += 4
            continue

        if word == "destination" and index + 3 < len(tokens) and tokens[index + 1] in _NAT_KINDS:
            # Reversed, deliberately: mapped first, then real. See the docstring.
            mapped, real = tokens[index + 2], tokens[index + 3]
            rule.original_destination = [] if mapped == "any" else [mapped]
            if mapped == "interface":
                rule.original_destination = []
                rule.translation_unreadable = (
                    f"the destination matched is whichever address interface "
                    f"{real_ifc or 'the real interface'} holds, which this line "
                    "does not state"
                )
            else:
                rule.translated_destination = [real]
            index += 4
            continue

        if word == "service" and index + 2 < len(tokens):
            rule.original_ports = [tokens[index + 1]]
            index += 3
            continue

        index += 1


def _normalise_object_nat(rule: NatRule, object_name: str | None) -> None:
    """`nat (real,mapped) static|dynamic MAPPED`, inside `object network NAME`.

    The object itself is the real address — the line never names it — so without the
    enclosing object's name this form says nothing matchable. That is why the name is
    threaded in rather than parsed out of the line.
    """
    tokens = rule.raw.split()
    if len(tokens) < 3 or tokens[0] != "nat":
        return

    rule.direction = rule.direction or (
        tokens[1][1:-1] if tokens[1].startswith("(") and tokens[1].endswith(")") else None
    )

    try:
        kind_at = next(i for i, t in enumerate(tokens) if t in {"static", "dynamic"})
    except StopIteration:
        return
    if kind_at + 1 >= len(tokens):
        return

    mapped = tokens[kind_at + 1]
    if not object_name:
        rule.translation_unreadable = (
            "this NAT line sits inside a network object whose name could not be read, "
            "so what it translates is unknown"
        )
        return

    rule.original_source = [object_name]
    if mapped == "interface":
        rule.translation_unreadable = (
            f"{object_name} is translated to whichever address the mapped interface "
            "holds, which this line does not state"
        )
    else:
        rule.translated_source = [mapped]


__all__ = ["CiscoAsaParser"]
