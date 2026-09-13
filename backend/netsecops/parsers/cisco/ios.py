"""Cisco IOS / IOS-XE configuration parser (FR-PARSE-01 … FR-PARSE-05).

Scope covers what Appendix B's baseline checks need from a switch or router: the
management plane, local accounts, AAA, logging, NTP, SNMP, interfaces and their access
-port protections, VLANs and spanning tree, routing-protocol authentication, ACLs, and
the control-plane feature flags.

Two habits run through the whole file:

- **Defaults are recorded, not assumed.** IOS enables CDP and disables the HTTP server
  by release and platform. Where a default is well established the parser sets the value
  explicitly and notes why; where it is not, the field stays ``None`` so a check reports
  *Not Evaluated* instead of guessing.
- **A negation is a fact.** ``no ip http server`` is not the absence of configuration —
  it is a deliberate hardening step, and it is recorded as ``False`` with provenance, so
  a finding can show the operator their own line.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from ciscoconfparse2 import CiscoConfParse
from ciscoconfparse2.models_cisco import IOSCfgLine

from netsecops.core.logging import get_logger
from netsecops.ncm.models import (
    Aaa,
    AaaMethodList,
    AaaServer,
    Acl,
    AclEntry,
    Interface,
    InterfaceSecurity,
    LocalUser,
    NormalisedConfig,
    NtpServer,
    RoutingProtocol,
    SnmpCommunity,
    SnmpTrapTarget,
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

log = get_logger(__name__)

#: Password storage types. 0 is plaintext and 7 is trivially reversible; both are
#: treated as weak. 5 (MD5) is legacy but not reversible; 8 (PBKDF2) and 9 (scrypt)
#: are the modern choices.
WEAK_SECRET_TYPES = {"0", "7"}


class CiscoIosParser(CiscoStyleParser):
    vendor = "cisco"
    platform = "cisco_ios"
    syntax = "ios"

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        parse = self.build(context)

        # Each section is independent and swallows its own errors, so one malformed
        # stanza cannot cost us the rest of the configuration (FR-PARSE-03).
        for section in (
            self._parse_device,
            self._parse_management,
            self._parse_users,
            self._parse_aaa,
            self._parse_logging,
            self._parse_ntp,
            self._parse_snmp,
            self._parse_interfaces,
            self._parse_l2,
            self._parse_routing,
            self._parse_acls,
            self._parse_features,
        ):
            try:
                section(parse, result)
            except Exception as exc:
                log.warning(
                    "parser.section_failed",
                    platform=self.platform,
                    section=section.__name__,
                    error=str(exc),
                )

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

        if domain := self.first(parse, r"^ip\s+domain[- ]name\s"):
            ncm.device.domain_name = self.capture(domain, r"name\s+(\S+)")
            result.record("device.domain_name", line=self.line_number(domain))

        # `show version` output, when the collection profile included it, is prepended
        # to the config text; the version line is the only part we need here.
        for line_number, text in enumerate(result.context.lines, start=1):
            if match := re.search(r"Cisco IOS.*?Version\s+([\w.()]+)", text):
                ncm.device.version = match.group(1)
                result.record("device.version", line=line_number)
                break

        if ncm.device.version is None and (version := self.first(parse, r"^version\s+\d")):
            # A running-config opens with a bare `version 17.9`. It is coarser than the
            # `show version` string — no maintenance letter — but it is what an
            # uploaded configuration (FR-COL-11) has, and Phase 6 needs *something* to
            # match a CPE against rather than nothing.
            ncm.device.version = self.capture(version, r"^version\s+(\S+)")
            result.record("device.version", line=self.line_number(version))

    # ───────────────────────────── management ───────────────────────────

    def _parse_management(self, parse: CiscoConfParse, result: ParseResult) -> None:
        management = result.ncm.management

        # ── SSH ─────────────────────────────────────────────────────────
        if ssh_version := self.first(parse, r"^ip\s+ssh\s+version\s"):
            management.services.ssh.version = self.capture_int(ssh_version, r"version\s+(\d)")
            management.services.ssh.enabled = True
            result.record("management.services.ssh.version", line=self.line_number(ssh_version))

        if ssh_timeout := self.first(parse, r"^ip\s+ssh\s+time-?out\s"):
            management.services.ssh.timeout_s = self.capture_int(ssh_timeout, r"out\s+(\d+)")
            result.record("management.services.ssh.timeout_s", line=self.line_number(ssh_timeout))

        if retries := self.first(parse, r"^ip\s+ssh\s+authentication-retries\s"):
            management.services.ssh.authentication_retries = self.capture_int(
                retries, r"retries\s+(\d+)"
            )
            result.record(
                "management.services.ssh.authentication_retries", line=self.line_number(retries)
            )

        for obj in parse.find_objects(r"^ip\s+ssh\s+server\s+algorithm\s+encryption"):
            management.services.ssh.ciphers = obj.text.split()[5:]
            result.record("management.services.ssh.ciphers", line=self.line_number(obj))

        for obj in parse.find_objects(r"^ip\s+ssh\s+server\s+algorithm\s+kex"):
            management.services.ssh.kex = obj.text.split()[5:]
            result.record("management.services.ssh.kex", line=self.line_number(obj))

        for obj in parse.find_objects(r"^ip\s+ssh\s+server\s+algorithm\s+mac"):
            management.services.ssh.macs = obj.text.split()[5:]
            result.record("management.services.ssh.macs", line=self.line_number(obj))

        # ── HTTP / HTTPS ────────────────────────────────────────────────
        self._parse_toggle(
            parse,
            result,
            enabled_pattern=r"^ip\s+http\s+server\s*$",
            disabled_pattern=r"^no\s+ip\s+http\s+server\s*$",
            path="management.services.http.enabled",
            setter=lambda value: setattr(management.services.http, "enabled", value),
        )
        self._parse_toggle(
            parse,
            result,
            enabled_pattern=r"^ip\s+http\s+secure-server\s*$",
            disabled_pattern=r"^no\s+ip\s+http\s+secure-server\s*$",
            path="management.services.https.enabled",
            setter=lambda value: setattr(management.services.https, "enabled", value),
        )

        if http_acl := self.first(parse, r"^ip\s+http\s+access-class\s"):
            acl = self.capture(http_acl, r"access-class\s+(\S+)")
            management.services.http.acl = acl
            management.management_acls["http"] = acl or ""
            result.record("management.services.http.acl", line=self.line_number(http_acl))

        # ── Line configuration: VTY and console ─────────────────────────
        self._parse_lines(parse, result)

        # ── Banners ─────────────────────────────────────────────────────
        for kind, attribute in (("login", "login"), ("motd", "motd"), ("exec", "exec")):
            if banner := self.first(parse, rf"^banner\s+{kind}\s"):
                start, end = self.family_range(banner)
                setattr(result.ncm.management.banners, attribute, banner.text)
                result.record(f"management.banners.{attribute}", line=start, line_end=end)

        # ── Password storage ────────────────────────────────────────────
        self._parse_toggle(
            parse,
            result,
            enabled_pattern=r"^service\s+password-encryption\s*$",
            disabled_pattern=r"^no\s+service\s+password-encryption\s*$",
            path="management.password_policy.encryption_enabled",
            setter=lambda value: setattr(management.password_policy, "encryption_enabled", value),
        )

    def _parse_lines(self, parse: CiscoConfParse, result: ParseResult) -> None:
        """VTY and console settings.

        The strictest VTY timeout is taken rather than the first: a device with one
        hardened VTY block and one forgotten default is only as protected as its
        weakest line, and reporting the strict one would flatter it.
        """
        management = result.ncm.management
        vty_timeouts: list[tuple[int, int]] = []

        for line_obj in parse.find_objects(r"^line\s+vty"):
            start, end = self.family_range(line_obj)

            for child in line_obj.children:
                if match := re.match(r"\s*exec-timeout\s+(\d+)\s*(\d*)", child.text):
                    seconds = timeout_to_seconds(match.group(1), match.group(2) or 0)
                    if seconds is not None:
                        vty_timeouts.append((seconds, self.line_number(child)))

                if re.match(r"\s*transport\s+input\s", child.text):
                    transports = child.text.split()[2:]
                    telnet_enabled = "telnet" in transports or "all" in transports
                    management.services.telnet.enabled = telnet_enabled
                    management.services.ssh.enabled = "ssh" in transports or "all" in transports
                    result.record(
                        "management.services.telnet.enabled", line=self.line_number(child)
                    )

                if match := re.match(r"\s*access-class\s+(\S+)\s+in", child.text):
                    management.management_acls["vty"] = match.group(1)
                    result.record("management.management_acls.vty", line=self.line_number(child))

            result.consume(start, end)

        if vty_timeouts:
            # An exec-timeout of 0 means "never time out", which is the weakest
            # possible setting rather than the strictest — sort it last.
            worst = max(vty_timeouts, key=lambda pair: (pair[0] == 0, pair[0]))
            management.session.exec_timeout_s = worst[0]
            result.record("management.session.exec_timeout_s", line=worst[1])

        for console in parse.find_objects(r"^line\s+con"):
            start, end = self.family_range(console)
            for child in console.children:
                if match := re.match(r"\s*exec-timeout\s+(\d+)\s*(\d*)", child.text):
                    management.session.console_timeout_s = timeout_to_seconds(
                        match.group(1), match.group(2) or 0
                    )
                    result.record(
                        "management.session.console_timeout_s", line=self.line_number(child)
                    )
            result.consume(start, end)

    # ────────────────────────────── users ───────────────────────────────

    def _parse_users(self, parse: CiscoConfParse, result: ParseResult) -> None:
        for obj in parse.find_objects(r"^username\s"):
            match = re.match(
                r"^username\s+(\S+)"
                r"(?:\s+privilege\s+(\d+))?"
                r"(?:\s+(secret|password)\s+(\d+)?)?",
                obj.text,
            )
            if not match:
                continue

            name, privilege, _keyword, secret_type = match.groups()
            user = LocalUser(
                name=name,
                privilege=int(privilege) if privilege else None,
                secret_type=secret_type,
                weak_hash=(secret_type in WEAK_SECRET_TYPES) if secret_type else None,
            )
            result.ncm.users.append(user)
            result.record(f"users.{len(result.ncm.users) - 1}", line=self.line_number(obj))

        if enable_secret := self.first(parse, r"^enable\s+secret\s"):
            result.consume(self.line_number(enable_secret))
        if enable_password := self.first(parse, r"^enable\s+password\s"):
            # `enable password` is reversible where `enable secret` is not; recording
            # it as a user makes the weak-storage check see it.
            secret_type = self.capture(enable_password, r"password\s+(\d)\s") or "0"
            result.ncm.users.append(
                LocalUser(
                    name="<enable>",
                    privilege=15,
                    secret_type=secret_type,
                    weak_hash=True,
                )
            )
            result.record(
                f"users.{len(result.ncm.users) - 1}", line=self.line_number(enable_password)
            )

    # ─────────────────────────────── AAA ────────────────────────────────

    def _parse_aaa(self, parse: CiscoConfParse, result: ParseResult) -> None:
        aaa: Aaa = result.ncm.aaa

        if new_model := self.first(parse, r"^aaa\s+new-model\s*$"):
            aaa.new_model = True
            result.record("aaa.new_model", line=self.line_number(new_model))
        elif self.present(parse, r"^no\s+aaa\s+new-model"):
            aaa.new_model = False

        for kind, target in (
            ("authentication", aaa.authentication),
            ("authorization", aaa.authorization),
            ("accounting", aaa.accounting),
        ):
            for obj in parse.find_objects(rf"^aaa\s+{kind}\s"):
                parts = obj.text.split()
                if len(parts) < 4:
                    continue
                purpose = parts[2]
                name = parts[3]
                methods = parts[4:] if len(parts) > 4 else []

                # `aaa accounting exec default start-stop group tacacs+` puts keywords
                # before the method list; keep only what follows `group`/known methods.
                methods = [m for m in methods if m not in {"start-stop", "stop-only", "none-"}]
                target.append(AaaMethodList(name=name, purpose=purpose, methods=methods))
                result.record(f"aaa.{kind}.{len(target) - 1}", line=self.line_number(obj))

        aaa.local_fallback = any(m.falls_back_to_local for m in aaa.authentication) or None
        self._parse_aaa_servers(parse, result)

    def _parse_aaa_servers(self, parse: CiscoConfParse, result: ParseResult) -> None:
        aaa = result.ncm.aaa

        # Modern IOS: `tacacs server NAME` / `radius server NAME` stanzas.
        for kind, server_type in (("tacacs", "tacacs"), ("radius", "radius")):
            for obj in parse.find_objects(rf"^{kind}\s+server\s+\S+"):
                start, end = self.family_range(obj)
                server = AaaServer(type=server_type, host="", key_configured=False)

                for child in obj.children:
                    if match := re.match(r"\s*address\s+ipv4\s+(\S+)", child.text):
                        server.host = match.group(1)
                    elif match := re.match(r"\s*key\s+(?:(\d)\s+)?(\S+)", child.text):
                        server.key_configured = True
                        server.key_type = match.group(1)
                    elif match := re.match(r"\s*timeout\s+(\d+)", child.text):
                        server.timeout_s = int(match.group(1))

                if server.host:
                    aaa.servers.append(server)
                    result.record(f"aaa.servers.{len(aaa.servers) - 1}", line=start, line_end=end)
                result.consume(start, end)

        # Legacy one-line form, still extremely common in the field.
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
                    )
                )
                result.record(f"aaa.servers.{len(aaa.servers) - 1}", line=self.line_number(obj))

    # ───────────────────────── logging and time ─────────────────────────

    def _parse_logging(self, parse: CiscoConfParse, result: ParseResult) -> None:
        logging_ncm = result.ncm.logging

        for obj in parse.find_objects(r"^logging\s+(?:host\s+)?\d+\.\d+\.\d+\.\d+"):
            host = self.capture(obj, r"logging\s+(?:host\s+)?(\S+)")
            if host:
                logging_ncm.syslog_servers.append(SyslogServer(host=host))
                result.record(
                    f"logging.syslog_servers.{len(logging_ncm.syslog_servers) - 1}",
                    line=self.line_number(obj),
                )

        if buffered := self.first(parse, r"^logging\s+buffered"):
            logging_ncm.buffered.enabled = True
            logging_ncm.buffered.size_bytes = self.capture_int(buffered, r"buffered\s+(\d+)")
            logging_ncm.buffered.severity = self.capture(buffered, r"buffered\s+(?:\d+\s+)?(\w+)")
            result.record("logging.buffered.enabled", line=self.line_number(buffered))
        elif self.present(parse, r"^no\s+logging\s+buffered"):
            logging_ncm.buffered.enabled = False

        if timestamps := self.first(parse, r"^service\s+timestamps\s+log"):
            logging_ncm.timestamps = timestamps.text.split("log", 1)[1].strip()
            result.record("logging.timestamps", line=self.line_number(timestamps))

        if source := self.first(parse, r"^logging\s+source-interface"):
            logging_ncm.source_interface = self.capture(source, r"source-interface\s+(\S+)")
            result.record("logging.source_interface", line=self.line_number(source))

        if archive := self.first(parse, r"^archive\s*$"):
            start, end = self.family_range(archive)
            logging_ncm.config_change_logging = any(
                "log config" in child.text for child in archive.all_children
            )
            result.record("logging.config_change_logging", line=start, line_end=end)

    def _parse_ntp(self, parse: CiscoConfParse, result: ParseResult) -> None:
        ntp = result.ncm.ntp

        for obj in parse.find_objects(r"^ntp\s+server\s"):
            host = self.capture(obj, r"ntp\s+server\s+(?:vrf\s+\S+\s+)?(\S+)")
            if not host:
                continue
            key_id = self.capture_int(obj, r"key\s+(\d+)")
            ntp.servers.append(
                NtpServer(
                    host=host,
                    authenticated=key_id is not None,
                    key_id=key_id,
                    prefer="prefer" in obj.text,
                )
            )
            result.record(f"ntp.servers.{len(ntp.servers) - 1}", line=self.line_number(obj))

        if authenticate := self.first(parse, r"^ntp\s+authenticate\s*$"):
            ntp.authenticated = True
            result.record("ntp.authenticated", line=self.line_number(authenticate))
        elif ntp.servers:
            # Servers configured but no `ntp authenticate`: unauthenticated by fact,
            # not by absence of parsing.
            ntp.authenticated = any(s.authenticated for s in ntp.servers)

        for obj in parse.find_objects(r"^ntp\s+authentication-key"):
            result.consume(self.line_number(obj))

        if timezone := self.first(parse, r"^clock\s+timezone"):
            ntp.timezone = self.capture(timezone, r"timezone\s+(\S+)")
            result.record("ntp.timezone", line=self.line_number(timezone))

    # ─────────────────────────────── SNMP ───────────────────────────────

    def _parse_snmp(self, parse: CiscoConfParse, result: ParseResult) -> None:
        snmp = result.ncm.snmp
        communities = parse.find_objects(r"^snmp-server\s+community\s")

        for obj in communities:
            match = re.match(
                r"^snmp-server\s+community\s+(\S+)(?:\s+(RO|RW))?(?:\s+(\S+))?",
                obj.text,
                re.IGNORECASE,
            )
            if not match:
                continue
            raw, access, acl = match.groups()

            snmp.v1v2c_communities.append(
                SnmpCommunity(
                    # Only a masked form is stored: the community string is a credential
                    # and the NCM is not an encrypted store (C-2).
                    name_masked=mask_secret(raw),
                    is_default=is_default_community(raw),
                    rw=(access or "").upper() == "RW",
                    acl=acl,
                )
            )
            result.record(
                f"snmp.v1v2c_communities.{len(snmp.v1v2c_communities) - 1}",
                line=self.line_number(obj),
            )

        snmp.v1v2c_enabled = bool(communities)

        for obj in parse.find_objects(r"^snmp-server\s+user\s"):
            parts = obj.text.split()
            if len(parts) < 4:
                continue
            level = "noAuthNoPriv"
            if " priv " in obj.text:
                level = "authPriv"
            elif " auth " in obj.text:
                level = "authNoPriv"

            snmp.v3_users.append(
                SnmpV3User(
                    name=parts[2],
                    group=parts[3] if len(parts) > 3 else None,
                    level=level,
                    auth=self.capture(obj, r"auth\s+(md5|sha|sha256|sha512)"),
                    priv=self.capture(obj, r"priv\s+(des|3des|aes(?:-?\d+)?)"),
                )
            )
            result.record(f"snmp.v3_users.{len(snmp.v3_users) - 1}", line=self.line_number(obj))

        for obj in parse.find_objects(r"^snmp-server\s+host\s"):
            host = self.capture(obj, r"host\s+(\S+)")
            if host:
                snmp.traps.append(SnmpTrapTarget(host=host))
                result.record(f"snmp.traps.{len(snmp.traps) - 1}", line=self.line_number(obj))

        if location := self.first(parse, r"^snmp-server\s+location"):
            snmp.location = location.text.split("location", 1)[1].strip()
            result.record("snmp.location", line=self.line_number(location))
        if contact := self.first(parse, r"^snmp-server\s+contact"):
            snmp.contact = contact.text.split("contact", 1)[1].strip()
            result.record("snmp.contact", line=self.line_number(contact))

        for obj in parse.find_objects(r"^snmp-server\s"):
            result.consume(self.line_number(obj))

    # ───────────────────────────── interfaces ───────────────────────────

    def _parse_interfaces(self, parse: CiscoConfParse, result: ParseResult) -> None:
        for obj in parse.find_objects(r"^interface\s"):
            start, end = self.family_range(obj)
            name = self.capture(obj, r"^interface\s+(\S+)")
            if not name:
                continue

            interface = Interface(name=name, security=InterfaceSecurity())
            children = "\n".join(child.text for child in obj.all_children)

            interface.description = self._child_capture(obj, r"\s*description\s+(.+)")
            interface.admin_up = not any(
                re.match(r"\s*shutdown\s*$", child.text) for child in obj.children
            )

            for child in obj.children:
                text = child.text.strip()

                if match := re.match(r"ip address\s+(\S+)\s+(\S+)", text):
                    interface.ip_addresses.append(f"{match.group(1)}/{match.group(2)}")
                elif match := re.match(r"switchport access vlan\s+(\d+)", text):
                    interface.vlan = int(match.group(1))
                elif match := re.match(r"switchport mode\s+(\S+)", text):
                    interface.mode = match.group(1)
                elif match := re.match(r"switchport trunk native vlan\s+(\d+)", text):
                    interface.native_vlan = int(match.group(1))
                elif match := re.match(r"switchport nonegotiate", text):
                    interface.dtp_mode = "nonegotiate"

            # Access-port protections. Their absence on a user-facing port is the
            # finding, so False is recorded rather than left unknown when the
            # interface is a switchport we could read.
            is_switchport = "switchport" in children
            security = interface.security
            security.bpduguard = "spanning-tree bpduguard enable" in children or (
                False if is_switchport else None
            )
            security.port_security = "switchport port-security" in children or (
                False if is_switchport else None
            )
            security.port_security_max = self._child_capture_int(
                obj, r"\s*switchport port-security maximum\s+(\d+)"
            )
            security.dhcp_snooping_trust = "ip dhcp snooping trust" in children or None
            security.arp_inspection_trust = "ip arp inspection trust" in children or None
            security.storm_control = "storm-control" in children or None
            security.ip_source_guard = "ip verify source" in children or None
            security.dot1x = (
                "dot1x" in children or "authentication port-control" in children
            ) or None
            security.root_guard = "spanning-tree guard root" in children or None

            interface.proxy_arp = self._negatable(children, "ip proxy-arp")
            interface.ip_redirects = self._negatable(children, "ip redirects")
            interface.ip_unreachables = self._negatable(children, "ip unreachables")
            interface.directed_broadcast = self._negatable(children, "ip directed-broadcast")

            result.ncm.interfaces.append(interface)
            result.record(f"interfaces.{len(result.ncm.interfaces) - 1}", line=start, line_end=end)
            result.consume(start, end)

    @staticmethod
    def _negatable(children: str, keyword: str) -> bool | None:
        """`no ip proxy-arp` is a fact; its absence is not."""
        if f"no {keyword}" in children:
            return False
        if keyword in children:
            return True
        return None

    def _child_capture(self, obj: IOSCfgLine, pattern: str) -> str | None:
        for child in obj.children:
            if match := re.match(pattern, child.text):
                return match.group(1).strip()
        return None

    def _child_capture_int(self, obj: IOSCfgLine, pattern: str) -> int | None:
        value = self._child_capture(obj, pattern)
        try:
            return int(value) if value else None
        except ValueError:
            return None

    # ────────────────────────────── layer 2 ─────────────────────────────

    def _parse_l2(self, parse: CiscoConfParse, result: ParseResult) -> None:
        l2 = result.ncm.l2

        for obj in parse.find_objects(r"^vlan\s+\d+"):
            start, end = self.family_range(obj)
            vlan_id = self.capture_int(obj, r"^vlan\s+(\d+)")
            if vlan_id is None:
                continue
            l2.vlans.append(Vlan(id=vlan_id, name=self._child_capture(obj, r"\s*name\s+(\S+)")))
            result.record(f"l2.vlans.{len(l2.vlans) - 1}", line=start, line_end=end)
            result.consume(start, end)

        if mode := self.first(parse, r"^spanning-tree\s+mode\s"):
            l2.spanning_tree.mode = self.capture(mode, r"mode\s+(\S+)")
            result.record("l2.spanning_tree.mode", line=self.line_number(mode))

        if default_bpdu := self.first(parse, r"^spanning-tree\s+portfast\s+bpduguard\s+default"):
            l2.spanning_tree.bpduguard_default = True
            result.record("l2.spanning_tree.bpduguard_default", line=self.line_number(default_bpdu))

        if loopguard := self.first(parse, r"^spanning-tree\s+loopguard\s+default"):
            l2.spanning_tree.loopguard_default = True
            result.record("l2.spanning_tree.loopguard_default", line=self.line_number(loopguard))

        if portfast := self.first(parse, r"^spanning-tree\s+portfast\s+default"):
            l2.spanning_tree.portfast_default = True
            result.record("l2.spanning_tree.portfast_default", line=self.line_number(portfast))

        if vtp_mode := self.first(parse, r"^vtp\s+mode\s"):
            l2.vtp_mode = self.capture(vtp_mode, r"mode\s+(\S+)")
            result.record("l2.vtp_mode", line=self.line_number(vtp_mode))
        if vtp_password := self.first(parse, r"^vtp\s+password\s"):
            l2.vtp_password_set = True
            result.record("l2.vtp_password_set", line=self.line_number(vtp_password))

        if snooping := self.first(parse, r"^ip\s+dhcp\s+snooping\s*$"):
            l2.dhcp_snooping_enabled = True
            result.record("l2.dhcp_snooping_enabled", line=self.line_number(snooping))
        if inspection := self.first(parse, r"^ip\s+arp\s+inspection\s+vlan"):
            l2.arp_inspection_enabled = True
            result.record("l2.arp_inspection_enabled", line=self.line_number(inspection))

    # ────────────────────────────── routing ─────────────────────────────

    def _parse_routing(self, parse: CiscoConfParse, result: ParseResult) -> None:
        routing = result.ncm.routing

        for pattern, name in (
            (r"^router\s+ospf\s+(\S+)", "ospf"),
            (r"^router\s+eigrp\s+(\S+)", "eigrp"),
            (r"^router\s+bgp\s+(\S+)", "bgp"),
            (r"^router\s+isis\s*(\S*)", "isis"),
        ):
            for obj in parse.find_objects(pattern):
                start, end = self.family_range(obj)
                children = "\n".join(child.text for child in obj.all_children)

                protocol = RoutingProtocol(
                    name=name,
                    instance=self.capture(obj, pattern),
                    authentication=("authentication" in children or "password" in children or None),
                    passive_default="passive-interface default" in children or None,
                    redistributes=[
                        line.strip().split()[1]
                        for line in children.splitlines()
                        if line.strip().startswith("redistribute ")
                        and len(line.strip().split()) > 1
                    ],
                )
                if "message-digest" in children or "md5" in children:
                    protocol.authentication_type = "md5"
                elif "key-chain" in children:
                    protocol.authentication_type = "key-chain"

                routing.protocols.append(protocol)
                result.record(
                    f"routing.protocols.{len(routing.protocols) - 1}", line=start, line_end=end
                )
                result.consume(start, end)

        static = parse.find_objects(r"^ip\s+route\s")
        if static:
            routing.static_routes = len(static)
            for obj in static:
                result.consume(self.line_number(obj))

        routing.ip_source_routing = self._toggle_value(
            parse, r"^ip\s+source-route\s*$", r"^no\s+ip\s+source-route\s*$"
        )

    # ──────────────────────────────── ACLs ──────────────────────────────

    def _parse_acls(self, parse: CiscoConfParse, result: ParseResult) -> None:
        for obj in parse.find_objects(r"^ip\s+access-list\s"):
            start, end = self.family_range(obj)
            match = re.match(r"^ip\s+access-list\s+(\S+)\s+(\S+)", obj.text)
            if not match:
                continue

            acl = Acl(name=match.group(2), type=match.group(1))
            for child in obj.children:
                text = child.text.strip()
                action = text.split()[0] if text.split() else ""
                if action in {"permit", "deny"}:
                    acl.entries.append(AclEntry(action=action, log="log" in text, raw=text))

            result.ncm.acls.append(acl)
            result.record(f"acls.{len(result.ncm.acls) - 1}", line=start, line_end=end)
            result.consume(start, end)

        # Numbered ACLs are flat rather than hierarchical.
        numbered: dict[str, Acl] = {}
        for obj in parse.find_objects(r"^access-list\s+\d+"):
            match = re.match(r"^access-list\s+(\d+)\s+(permit|deny)\s*(.*)", obj.text)
            if not match:
                result.consume(self.line_number(obj))
                continue

            number, action, rest = match.groups()
            acl = numbered.setdefault(number, Acl(name=number, type="numbered"))
            acl.entries.append(AclEntry(action=action, raw=obj.text.strip(), log="log" in rest))
            result.consume(self.line_number(obj))

        for acl in numbered.values():
            result.ncm.acls.append(acl)

    # ───────────────────────────── features ─────────────────────────────

    def _parse_features(self, parse: CiscoConfParse, result: ParseResult) -> None:
        """Control-plane feature flags (Appendix B, FR-VUL-03).

        Several of these have platform-dependent defaults. Where IOS's default is
        well established it is stated here with the reasoning, because a check that
        reports *Not Evaluated* for every device is no more useful than one that
        guesses.
        """
        features = result.ncm.features

        features.http_server = result.ncm.management.services.http.enabled
        features.https_server = result.ncm.management.services.https.enabled

        toggles: list[tuple[str, str, str]] = [
            ("cdp", r"^cdp\s+run\s*$", r"^no\s+cdp\s+run\s*$"),
            ("lldp", r"^lldp\s+run\s*$", r"^no\s+lldp\s+run\s*$"),
            ("ip_source_routing", r"^ip\s+source-route\s*$", r"^no\s+ip\s+source-route\s*$"),
            (
                "bootp_server",
                r"^ip\s+bootp\s+server\s*$",
                r"^no\s+ip\s+bootp\s+server\s*$",
            ),
            (
                "tcp_small_servers",
                r"^service\s+tcp-small-servers\s*$",
                r"^no\s+service\s+tcp-small-servers\s*$",
            ),
            (
                "udp_small_servers",
                r"^service\s+udp-small-servers\s*$",
                r"^no\s+service\s+udp-small-servers\s*$",
            ),
            ("finger", r"^(?:ip\s+)?finger\s*$", r"^no\s+(?:ip\s+)?finger\s*$"),
            ("pad", r"^service\s+pad\s*$", r"^no\s+service\s+pad\s*$"),
            ("domain_lookup", r"^ip\s+domain[- ]lookup\s*$", r"^no\s+ip\s+domain[- ]lookup\s*$"),
            (
                "service_config",
                r"^service\s+config\s*$",
                r"^no\s+service\s+config\s*$",
            ),
        ]

        for attribute, enabled_pattern, disabled_pattern in toggles:
            value = self._toggle_value(parse, enabled_pattern, disabled_pattern)
            if value is not None:
                setattr(features, attribute, value)
                obj = self.first(parse, enabled_pattern) or self.first(parse, disabled_pattern)
                if obj is not None:
                    result.record(f"features.{attribute}", line=self.line_number(obj))

        # CDP is on by default on IOS switches, so an absent `cdp run` still means
        # enabled. The opposite assumption would under-report a real exposure.
        if features.cdp is None and result.ncm.interfaces:
            features.cdp = True

        if smart_install := self.first(parse, r"^vstack"):
            features.smart_install = "no vstack" not in smart_install.text
            result.record("features.smart_install", line=self.line_number(smart_install))

    def _toggle_value(
        self, parse: CiscoConfParse, enabled_pattern: str, disabled_pattern: str
    ) -> bool | None:
        if self.present(parse, disabled_pattern):
            return False
        if self.present(parse, enabled_pattern):
            return True
        return None

    def _parse_toggle(
        self,
        parse: CiscoConfParse,
        result: ParseResult,
        *,
        enabled_pattern: str,
        disabled_pattern: str,
        path: str,
        setter: Callable[[bool], None],
    ) -> None:
        value = self._toggle_value(parse, enabled_pattern, disabled_pattern)
        if value is None:
            return
        setter(value)
        obj = self.first(parse, disabled_pattern if value is False else enabled_pattern)
        if obj is not None:
            result.record(path, line=self.line_number(obj))


__all__ = ["CiscoIosParser"]
