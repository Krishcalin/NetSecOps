"""Cisco NX-OS configuration parser (FR-PARSE-01 … FR-PARSE-05).

NX-OS looks like IOS but differs in ways that matter to a parser:

- Features are explicitly enabled (``feature ssh``, ``feature bgp``), so presence in
  the ``feature`` list is authoritative rather than inferred.
- Roles replace privilege levels for local users.
- Telnet is *off* by default and must be switched on with ``feature telnet`` — the
  reverse of IOS, so the same absence means the opposite thing.

That last point is exactly why this is a separate parser rather than a flag on the IOS
one: the NCM's "absent means unknown" discipline only holds if each parser knows its
own platform's defaults.
"""

from __future__ import annotations

import re

from ciscoconfparse2 import CiscoConfParse
from ciscoconfparse2.models_cisco import IOSCfgLine

from netsecops.core.logging import get_logger
from netsecops.ncm.models import (
    AaaMethodList,
    AaaServer,
    Acl,
    AclEntry,
    Interface,
    InterfaceSecurity,
    LocalUser,
    NormalisedConfig,
    NtpServer,
    Route,
    RoutingProtocol,
    SecurityRule,
    SnmpCommunity,
    SnmpV3User,
    SyslogServer,
    Vlan,
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
    interface_bindings,
    parse_ace,
    record_bindings,
)
from netsecops.parsers.route_tables import parse_nxos_route_table, store_routes
from netsecops.parsers.routes import connected_routes, parse_ios_static_route

log = get_logger(__name__)


class CiscoNxosParser(CiscoStyleParser):
    vendor = "cisco"
    platform = "cisco_nxos"
    syntax = "nxos"

    #: Structural lines with no bearing on any baseline check. Keeping the unparsed
    #: report free of known-irrelevant entries is what makes it worth reading.
    IGNORE: re.Pattern[str] = re.compile(
        r"^(end$|exit$|version\s|boot\s|vrf\s+context|ip\s+route\s|copp\s|system\s"
        r"|hardware\s|rmon\s|cli\s|no\s+password\s+strength-check$|ip\s+domain-lookup$"
        r"|switchport$|no\s+shutdown$|shutdown$|vdc\s|limit-resource)"
    )

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        parse = self.build(context)

        features = self._parse_feature_list(parse, result)

        for section in (
            self._parse_device,
            lambda p, r: self._parse_management(p, r, features),
            self._parse_users,
            self._parse_aaa,
            self._parse_logging,
            self._parse_ntp,
            self._parse_snmp,
            self._parse_interfaces,
            self._parse_l2,
            self._parse_routing,
            self._parse_acls,
        ):
            try:
                section(parse, result)
            except Exception as exc:
                log.warning("parser.section_failed", platform=self.platform, error=str(exc))

        result.finalise_unparsed(ignore=self.IGNORE)
        return result.ncm

    # ───────────────────────────── features ─────────────────────────────

    def _parse_feature_list(self, parse: CiscoConfParse, result: ParseResult) -> set[str]:
        """NX-OS states which features are on, so nothing here needs inferring."""
        enabled: set[str] = set()
        for obj in parse.find_objects(r"^feature\s"):
            name = self.capture(obj, r"^feature\s+(\S+)")
            if name:
                enabled.add(name)
            result.consume(self.line_number(obj))

        result.ncm.features.extra = dict.fromkeys(sorted(enabled), True)
        return enabled

    # ─────────────────────────────── device ─────────────────────────────

    def _parse_device(self, parse: CiscoConfParse, result: ParseResult) -> None:
        ncm = result.ncm
        ncm.device.vendor = self.vendor
        ncm.device.platform = self.platform

        if hostname := self.first(parse, r"^(?:hostname|switchname)\s"):
            ncm.device.hostname = self.capture(hostname, r"^(?:hostname|switchname)\s+(\S+)")
            result.record("device.hostname", line=self.line_number(hostname))

        # Unlike IOS, an NX-OS running-config opens with the *image* version, so the
        # configuration alone is enough to identify the software for CVE matching.
        for line_number, text in enumerate(result.context.lines, start=1):
            if match := re.search(r"version\s+([\d.()A-Za-z]+)", text):
                if text.strip().startswith("version"):
                    ncm.device.version = match.group(1)
                    result.record("device.version", line=line_number)
                    break

        self._parse_show_version(result)

    #: `    cisco Nexus9000 C93180YC-EX Chassis` — the chassis line names the hardware a
    #: hardware CPE is built from (FR-VUL-01).
    _CHASSIS = re.compile(r"^\s*cisco\s+(.+?)\s+[Cc]hassis", re.M)
    #: `  Processor Board ID FDO21120U5D`
    _SERIAL = re.compile(r"^\s*Processor Board ID\s+(\S+)", re.I | re.M)

    def _parse_show_version(self, result: ParseResult) -> None:
        """Chassis model and serial from `show version`.

        The version is already known from the configuration; what only `show version`
        carries is the hardware, and a hardware CPE is what end-of-life and
        platform-specific advisories are written against (FR-VUL-01, FR-VUL-05).
        """
        output = result.context.artifact("show version")
        if output is None:
            return

        if match := self._CHASSIS.search(output):
            result.ncm.device.model = match.group(1).strip()
            result.record("device.model", line=1)

        if match := self._SERIAL.search(output):
            result.ncm.device.serials = [match.group(1)]
            result.record("device.serials", line=1)

    # ───────────────────────────── management ───────────────────────────

    def _parse_management(
        self, parse: CiscoConfParse, result: ParseResult, features: set[str]
    ) -> None:
        management = result.ncm.management

        # Both of these are authoritative on NX-OS: a feature absent from the list is
        # genuinely off, not merely unmentioned.
        management.services.ssh.enabled = "ssh" in features
        management.services.telnet.enabled = "telnet" in features
        result.ncm.features.extra["telnet"] = "telnet" in features

        if ssh_key := self.first(parse, r"^ssh\s+key\s+rsa\s+\d+"):
            management.services.ssh.host_key_bits = self.capture_int(ssh_key, r"rsa\s+(\d+)")
            result.record("management.services.ssh.host_key_bits", line=self.line_number(ssh_key))

        if http := self.first(parse, r"^feature\s+nxapi"):
            management.services.https.enabled = True
            result.record("management.services.https.enabled", line=self.line_number(http))

        for line_obj in parse.find_objects(r"^line\s+vty"):
            start, end = self.family_range(line_obj)
            for child in line_obj.children:
                if match := re.match(r"\s*exec-timeout\s+(\d+)", child.text):
                    management.session.exec_timeout_s = timeout_to_seconds(match.group(1))
                    result.record("management.session.exec_timeout_s", line=self.line_number(child))
            result.consume(start, end)

        for kind in ("motd", "exec"):
            if banner := self.first(parse, rf"^banner\s+{kind}\s"):
                start, end = self.family_range(banner)
                setattr(management.banners, kind, banner.text)
                result.record(f"management.banners.{kind}", line=start, line_end=end)

        # The negated form is the one that matters: `no password strength-check` is
        # precisely the weakness a check looks for, and anchoring on `^password` alone
        # matched only the secure case and silently reported the insecure one absent.
        if policy := self.first(parse, r"^(?:no\s+)?password\s+strength-check"):
            management.password_policy.complexity_required = "no " not in policy.text
            result.record(
                "management.password_policy.complexity_required", line=self.line_number(policy)
            )

    # ────────────────────────────── users ───────────────────────────────

    def _parse_users(self, parse: CiscoConfParse, result: ParseResult) -> None:
        for obj in parse.find_objects(r"^username\s"):
            match = re.match(r"^username\s+(\S+)", obj.text)
            if not match:
                continue

            # NX-OS uses named roles; network-admin is the equivalent of privilege 15.
            role = self.capture(obj, r"role\s+(\S+)")
            secret_type = self.capture(obj, r"password\s+(\d)\s")

            result.ncm.users.append(
                LocalUser(
                    name=match.group(1),
                    role=role,
                    privilege=15 if role == "network-admin" else None,
                    secret_type=secret_type,
                    weak_hash=(secret_type in {"0", "7"}) if secret_type else None,
                )
            )
            result.record(f"users.{len(result.ncm.users) - 1}", line=self.line_number(obj))

    # ─────────────────────────────── AAA ────────────────────────────────

    def _parse_aaa(self, parse: CiscoConfParse, result: ParseResult) -> None:
        aaa = result.ncm.aaa

        for kind, target in (
            ("authentication", aaa.authentication),
            ("authorization", aaa.authorization),
            ("accounting", aaa.accounting),
        ):
            for obj in parse.find_objects(rf"^aaa\s+{kind}\s"):
                parts = obj.text.split()
                if len(parts) < 4:
                    result.consume(self.line_number(obj))
                    continue
                target.append(AaaMethodList(name=parts[3], purpose=parts[2], methods=parts[4:]))
                result.record(f"aaa.{kind}.{len(target) - 1}", line=self.line_number(obj))

        # False when method lists were parsed and none falls back; None only when there
        # were none to look at. See the same line in `ios.py` for what `or None` cost.
        aaa.local_fallback = (
            any(m.falls_back_to_local for m in aaa.authentication) if aaa.authentication else None
        )

        for pattern, server_type in (
            (r"^tacacs-server\s+host\s+(\S+)", "tacacs"),
            (r"^radius-server\s+host\s+(\S+)", "radius"),
        ):
            for obj in parse.find_objects(pattern):
                host = self.capture(obj, pattern)
                if not host:
                    continue
                aaa.servers.append(
                    AaaServer(
                        type=server_type,
                        host=host,
                        key_configured="key " in obj.text,
                        key_type=self.capture(obj, r"key\s+(\d)\s"),
                        timeout_s=self.capture_int(obj, r"timeout\s+(\d+)"),
                    )
                )
                result.record(f"aaa.servers.{len(aaa.servers) - 1}", line=self.line_number(obj))

        for obj in parse.find_objects(r"^aaa\s+group\s+server"):
            start, end = self.family_range(obj)
            result.consume(start, end)

    # ──────────────────────── logging, NTP, SNMP ────────────────────────

    def _parse_logging(self, parse: CiscoConfParse, result: ParseResult) -> None:
        logging_ncm = result.ncm.logging

        for obj in parse.find_objects(r"^logging\s+server\s"):
            host = self.capture(obj, r"logging\s+server\s+(\S+)")
            if not host:
                continue
            logging_ncm.syslog_servers.append(
                SyslogServer(host=host, severity=self.capture(obj, r"server\s+\S+\s+(\d)"))
            )
            result.record(
                f"logging.syslog_servers.{len(logging_ncm.syslog_servers) - 1}",
                line=self.line_number(obj),
            )

        if logfile := self.first(parse, r"^logging\s+logfile\s"):
            logging_ncm.buffered.enabled = True
            logging_ncm.buffered.severity = self.capture(logfile, r"logfile\s+\S+\s+(\d)")
            result.record("logging.buffered.enabled", line=self.line_number(logfile))

        if timestamp := self.first(parse, r"^logging\s+timestamp\s"):
            logging_ncm.timestamps = self.capture(timestamp, r"timestamp\s+(\S+)")
            result.record("logging.timestamps", line=self.line_number(timestamp))

        if source := self.first(parse, r"^logging\s+source-interface"):
            logging_ncm.source_interface = self.capture(source, r"source-interface\s+(\S+)")
            result.record("logging.source_interface", line=self.line_number(source))

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

        if authenticate := self.first(parse, r"^ntp\s+authenticate\s*$"):
            ntp.authenticated = True
            result.record("ntp.authenticated", line=self.line_number(authenticate))
        elif ntp.servers:
            ntp.authenticated = any(s.authenticated for s in ntp.servers)

        for obj in parse.find_objects(r"^ntp\s"):
            result.consume(self.line_number(obj))

    def _parse_snmp(self, parse: CiscoConfParse, result: ParseResult) -> None:
        snmp = result.ncm.snmp
        communities = parse.find_objects(r"^snmp-server\s+community\s")

        for obj in communities:
            match = re.match(
                r"^snmp-server\s+community\s+(\S+)(?:\s+(?:group\s+(\S+)|(ro|rw)))?",
                obj.text,
                re.IGNORECASE,
            )
            if not match:
                continue
            raw, group, access = match.groups()
            snmp.v1v2c_communities.append(
                SnmpCommunity(
                    name_masked=mask_secret(raw),
                    is_default=is_default_community(raw),
                    rw=(access or "").lower() == "rw" or (group or "").endswith("admin"),
                )
            )
            result.record(
                f"snmp.v1v2c_communities.{len(snmp.v1v2c_communities) - 1}",
                line=self.line_number(obj),
            )

        snmp.v1v2c_enabled = bool(communities)

        for obj in parse.find_objects(r"^snmp-server\s+user\s"):
            parts = obj.text.split()
            if len(parts) < 3:
                continue
            level = "noAuthNoPriv"
            if " priv " in obj.text:
                level = "authPriv"
            elif " auth " in obj.text:
                level = "authNoPriv"

            snmp.v3_users.append(
                SnmpV3User(
                    name=parts[2],
                    group=parts[3] if len(parts) > 3 and not parts[3].startswith("auth") else None,
                    level=level,
                    auth=self.capture(obj, r"auth\s+(md5|sha|sha256|sha512)"),
                    priv=self.capture(obj, r"priv\s+(des|3des|aes(?:-?\d+)?)"),
                )
            )
            result.record(f"snmp.v3_users.{len(snmp.v3_users) - 1}", line=self.line_number(obj))

        for obj in parse.find_objects(r"^snmp-server\s"):
            result.consume(self.line_number(obj))

    # ───────────────────── interfaces, L2, routing, ACLs ────────────────

    def _parse_interfaces(self, parse: CiscoConfParse, result: ParseResult) -> None:
        for obj in parse.find_objects(r"^interface\s"):
            start, end = self.family_range(obj)
            name = self.capture(obj, r"^interface\s+(\S+)")
            if not name:
                continue

            children = "\n".join(child.text for child in obj.all_children)
            interface = Interface(name=name, security=InterfaceSecurity())

            # NX-OS interfaces are routed by default and `shutdown` unless told
            # otherwise on some platforms, so `no shutdown` is the meaningful signal.
            interface.admin_up = "no shutdown" in children or (
                None if "shutdown" not in children else False
            )
            interface.description = self._child_capture(obj, r"\s*description\s+(.+)")

            for child in obj.children:
                text = child.text.strip()
                if match := re.match(r"ip address\s+(\S+)", text):
                    interface.ip_addresses.append(match.group(1))
                elif match := re.match(r"switchport access vlan\s+(\d+)", text):
                    interface.vlan = int(match.group(1))
                elif match := re.match(r"switchport mode\s+(\S+)", text):
                    interface.mode = match.group(1)
                elif match := re.match(r"switchport trunk native vlan\s+(\d+)", text):
                    interface.native_vlan = int(match.group(1))

            security = interface.security
            security.bpduguard = "spanning-tree bpduguard enable" in children or None
            security.port_security = "switchport port-security" in children or None
            security.dhcp_snooping_trust = "ip dhcp snooping trust" in children or None
            security.arp_inspection_trust = "ip arp inspection trust" in children or None
            security.storm_control = "storm-control" in children or None

            result.ncm.interfaces.append(interface)
            result.record(f"interfaces.{len(result.ncm.interfaces) - 1}", line=start, line_end=end)
            result.consume(start, end)

    def _child_capture(self, obj: IOSCfgLine, pattern: str) -> str | None:
        for child in obj.children:
            if match := re.match(pattern, child.text):
                return match.group(1).strip()
        return None

    def _parse_l2(self, parse: CiscoConfParse, result: ParseResult) -> None:
        l2 = result.ncm.l2

        for obj in parse.find_objects(r"^vlan\s+\d"):
            start, end = self.family_range(obj)
            raw = self.capture(obj, r"^vlan\s+([\d,\-]+)")
            if raw and raw.isdigit():
                l2.vlans.append(
                    Vlan(id=int(raw), name=self._child_capture(obj, r"\s*name\s+(\S+)"))
                )
                result.record(f"l2.vlans.{len(l2.vlans) - 1}", line=start, line_end=end)
            result.consume(start, end)

        if mode := self.first(parse, r"^spanning-tree\s+mode\s"):
            l2.spanning_tree.mode = self.capture(mode, r"mode\s+(\S+)")
            result.record("l2.spanning_tree.mode", line=self.line_number(mode))

        if bpdu := self.first(parse, r"^spanning-tree\s+port\s+type\s+edge\s+bpduguard\s+default"):
            l2.spanning_tree.bpduguard_default = True
            result.record("l2.spanning_tree.bpduguard_default", line=self.line_number(bpdu))

        if snooping := self.first(parse, r"^ip\s+dhcp\s+snooping\s*$"):
            l2.dhcp_snooping_enabled = True
            result.record("l2.dhcp_snooping_enabled", line=self.line_number(snooping))

    def _parse_routing(self, parse: CiscoConfParse, result: ParseResult) -> None:
        routing = result.ncm.routing

        for pattern, name in (
            (r"^router\s+ospf\s+(\S+)", "ospf"),
            (r"^router\s+bgp\s+(\S+)", "bgp"),
            (r"^router\s+eigrp\s+(\S+)", "eigrp"),
        ):
            for obj in parse.find_objects(pattern):
                start, end = self.family_range(obj)
                children = "\n".join(child.text for child in obj.all_children)
                routing.protocols.append(
                    RoutingProtocol(
                        name=name,
                        instance=self.capture(obj, pattern),
                        authentication=("authentication" in children or "password" in children)
                        or None,
                    )
                )
                result.record(
                    f"routing.protocols.{len(routing.protocols) - 1}", line=start, line_end=end
                )
                result.consume(start, end)

        # Same grammar as IOS, so the same reader (FR-TOPO-01). NX-OS writes the mask as
        # a prefix length where IOS writes it dotted, which `to_cidr` absorbs — the one
        # difference that would otherwise need a second regex here.
        collected: list[tuple[Route, int | None]] = []
        for obj in parse.find_objects(r"^ip\s+route\s"):
            route = parse_ios_static_route(obj.text)
            if route is None:
                continue
            collected.append((route, self.line_number(obj)))

        collected.extend((route, None) for route in connected_routes(result.ncm.interfaces))

        # `vrf all` rather than the global table: FR-TOPO-02 requires VRFs to be separate
        # forwarding domains, and a collection that only ever sees one cannot honour it.
        store_routes(
            result,
            "show ip route vrf all",
            parser=parse_nxos_route_table,
            from_config=collected,
        )

    def _parse_acls(self, parse: CiscoConfParse, result: ParseResult) -> None:
        """ACLs, as both an NCM ACL and a normalised rulebase (FR-PARSE-02, FR-FW-01).

        NX-OS writes prefixes (`10.1.1.0/24`) where IOS writes wildcard masks, so most
        entries need no conversion — but the same parser handles both, because the rest
        of the grammar is shared and a Nexus will still accept the wildcard form.

        Each ACL is its own `rulebase`: entries in different ACLs are bound to different
        interfaces and never see the same packet.
        """
        firewall = result.ncm.firewall

        for obj in parse.find_objects(r"^ip\s+access-list\s"):
            start, end = self.family_range(obj)
            name = self.capture(obj, r"^ip\s+access-list\s+(\S+)")
            if not name:
                continue

            acl = Acl(name=name, type="extended")
            for child in obj.children:
                text = child.text.strip()
                ace = parse_ace(text)
                if ace is None:
                    continue

                acl.entries.append(
                    AclEntry(
                        sequence=ace.sequence if ace.sequence is not None else len(acl.entries) + 1,
                        action=ace.action,
                        protocol=ace.protocol,
                        source=ace.source,
                        destination=ace.destination,
                        ports=", ".join(ace.services) or None,
                        log=ace.log,
                        raw=text,
                    )
                )

                firewall.security_rules.append(
                    SecurityRule(
                        order=len(firewall.security_rules) + 1,
                        name=name,
                        rulebase=name,
                        action="allow" if ace.action == "permit" else "deny",
                        src=[ace.source],
                        dst=[ace.destination],
                        services=list(ace.services) if not ace.partial else [UNREADABLE],
                        log_end=ace.log,
                    )
                )

            result.ncm.acls.append(acl)
            result.record(f"acls.{len(result.ncm.acls) - 1}", line=start, line_end=end)
            result.consume(start, end)

        self._bind_acls(parse, result)

    def _bind_acls(self, parse: CiscoConfParse, result: ParseResult) -> None:
        """Record which interface each ACL is applied to, and in which direction.

        The same shape as IOS, and the same reader — NX-OS differs only in also
        accepting `ip port access-group` for a layer-2 port ACL.
        """
        applied, raw = interface_bindings(
            parse, r"^\s*ip\s+(?:port\s+)?access-group\s+(\S+)\s+(in|out)"
        )
        record_bindings(result.ncm, applied, raw=raw)


__all__ = ["CiscoNxosParser"]
