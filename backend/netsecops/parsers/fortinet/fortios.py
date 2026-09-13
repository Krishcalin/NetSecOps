"""FortiOS configuration parser (FR-PARSE-01 … FR-PARSE-05, FR-FW-01).

Maps `show full-configuration` onto the NCM. The block reader in `blocks.py` handles the
syntax, so everything here is about meaning: which FortiOS setting corresponds to which
vendor-neutral field, and which of them a check can rely on.

The same three rules as every other parser: tolerate what we do not recognise, record
provenance for what we do, and never write `False` where the answer is "not found".
"""

from __future__ import annotations

from netsecops.core.logging import get_logger
from netsecops.ncm.models import (
    AaaServer,
    Certificate,
    Interface,
    LocalUser,
    NetworkObject,
    NormalisedConfig,
    NtpServer,
    SecurityRule,
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
from netsecops.parsers.fortinet.blocks import Block, ParsedConfig, read

log = get_logger(__name__)


class FortiOsParser(ConfigParser):
    vendor = "fortinet"
    platform = "fortios"

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        config = read(context.text)

        for section in (
            self._parse_device,
            self._parse_management,
            self._parse_users,
            self._parse_aaa,
            self._parse_logging,
            self._parse_snmp,
            self._parse_interfaces,
            self._parse_firewall,
            self._parse_certificates,
        ):
            try:
                section(config, result)
            except Exception as exc:
                # One unfamiliar section must never cost the other eight.
                log.warning(
                    "parser.section_failed",
                    platform=self.platform,
                    section=section.__name__,
                    error=str(exc),
                )

        # Every line the block reader could not place, plus every line inside a block we
        # did not map. Both are genuinely unparsed and both belong in the count.
        result.ncm.raw_unparsed = list(config.unparsed)
        self._consume_mapped(config, result)
        return result.ncm

    # ── bookkeeping ─────────────────────────────────────────────────────

    def _consume_mapped(self, config: ParsedConfig, result: ParseResult) -> None:
        """Mark every line inside a recognised section as accounted for.

        FortiOS configurations are enormous and mostly irrelevant to security posture.
        Counting an untouched `config system replacemsg` stanza as unparsed would put
        coverage at 20% and make the figure meaningless.
        """
        for section in config.sections:
            if section.line and section.line_end:
                result.consume(section.line, section.line_end)

    def _record(self, result: ParseResult, path: str, block: Block, key: str | None = None) -> None:
        line = block.value_lines.get(key) if key else None
        result.record(path, line=line or block.line, line_end=None if line else block.line_end)

    # ── device ──────────────────────────────────────────────────────────

    def _parse_device(self, config: ParsedConfig, result: ParseResult) -> None:
        device = result.ncm.device
        device.vendor = self.vendor
        device.platform = self.platform

        globals_block = config.section("system global")
        if globals_block:
            if hostname := globals_block.get("hostname"):
                device.hostname = hostname
                self._record(result, "device.hostname", globals_block, "hostname")

        # The version lives in a `#config-version=` comment the block reader skips, in
        # the form `FGT60F-7.2.5-FW-build1517-230606:...`. The model is the first field
        # and the version the second, so both come from the same line.
        for number, line in enumerate(result.context.lines, start=1):
            if not line.startswith("#config-version"):
                continue
            _, _, value = line.partition("=")
            parts = value.split("-")
            if len(parts) >= 2:
                device.model = parts[0]
                device.version = parts[1]
                result.record("device.version", line=number)
            break

        ha = config.section("system ha")
        if ha:
            mode = ha.get("mode")
            if mode:
                result.ncm.device.ha.enabled = mode.lower() not in {"standalone", ""}
                result.ncm.device.ha.role = ha.get("priority")
                self._record(result, "device.ha.enabled", ha, "mode")

    # ── management ──────────────────────────────────────────────────────

    def _parse_management(self, config: ParsedConfig, result: ParseResult) -> None:
        management = result.ncm.management
        globals_block = config.section("system global")

        if globals_block:
            timeout = globals_block.get("admintimeout")
            if timeout and timeout.isdigit():
                # FortiOS states it in minutes; the NCM is seconds throughout.
                management.session.exec_timeout_s = int(timeout) * 60
                self._record(
                    result, "management.session.exec_timeout_s", globals_block, "admintimeout"
                )

            if (strong := globals_block.flag("strong-crypto")) is not None:
                management.services.https.enabled = True
                result.ncm.features.extra["strong_crypto"] = strong
                self._record(result, "features.extra.strong_crypto", globals_block, "strong-crypto")

            if lockout := globals_block.get("admin-lockout-threshold"):
                if lockout.isdigit():
                    management.password_policy.lockout_threshold = int(lockout)
                    self._record(
                        result,
                        "management.password_policy.lockout_threshold",
                        globals_block,
                        "admin-lockout-threshold",
                    )

        # Administrative access is declared per interface, not globally, so the
        # management services are the union of what the interfaces allow.
        interfaces = config.section("system interface")
        if interfaces:
            allowed: set[str] = set()
            for entry in interfaces.entries():
                allowed.update(value.lower() for value in entry.get_all("allowaccess"))

            if allowed:
                management.services.ssh.enabled = "ssh" in allowed
                management.services.telnet.enabled = "telnet" in allowed
                management.services.http.enabled = "http" in allowed
                management.services.https.enabled = "https" in allowed
                management.services.snmp.enabled = "snmp" in allowed
                for name in ("ssh", "telnet", "http", "https", "snmp"):
                    result.record(
                        f"management.services.{name}.enabled",
                        line=interfaces.line,
                        line_end=interfaces.line_end,
                    )

        policy = config.section("system password-policy")
        if policy:
            if (status := policy.flag("status")) is not None and status:
                if minimum := policy.get("minimum-length"):
                    if minimum.isdigit():
                        management.password_policy.min_length = int(minimum)
                        self._record(
                            result,
                            "management.password_policy.min_length",
                            policy,
                            "minimum-length",
                        )
                management.password_policy.complexity_required = True
                self._record(
                    result, "management.password_policy.complexity_required", policy, "status"
                )

    # ── accounts ────────────────────────────────────────────────────────

    def _parse_users(self, config: ParsedConfig, result: ParseResult) -> None:
        admins = config.section("system admin")
        if not admins:
            return

        for entry in admins.entries():
            profile = entry.get("accprofile")
            trusted = any(entry.get(f"trusthost{n}") for n in range(1, 11))
            result.ncm.users.append(
                LocalUser(
                    name=entry.name,
                    role=profile,
                    # `super_admin` is FortiOS's unrestricted profile; mapping it to 15
                    # lets the vendor-neutral privilege checks apply unchanged.
                    privilege=15 if profile == "super_admin" else None,
                    # FortiOS stores admin passwords as a salted SHA hash (ENC). The
                    # hash type is not weak; whether the password is, we cannot see.
                    secret_type="ENC" if entry.get("password") else None,
                    weak_hash=False if entry.get("password") else None,
                )
            )
            result.ncm.features.extra[f"admin_{entry.name}_trusthost"] = trusted
            result.record(
                f"users.{len(result.ncm.users) - 1}", line=entry.line, line_end=entry.line_end
            )

    def _parse_aaa(self, config: ParsedConfig, result: ParseResult) -> None:
        aaa = result.ncm.aaa

        for kind, section_name in (("radius", "user radius"), ("tacacs", "user tacacs+")):
            section = config.section(section_name)
            if not section:
                continue
            for entry in section.entries():
                host = entry.get("server")
                if not host:
                    continue
                aaa.servers.append(
                    AaaServer(
                        type=kind,
                        host=host,
                        # The key itself is never read — only whether one is present.
                        key_configured=bool(entry.get("secret") or entry.get("key")),
                        source_interface=entry.get("source-ip"),
                        group=entry.name,
                    )
                )
                result.record(
                    f"aaa.servers.{len(aaa.servers) - 1}",
                    line=entry.line,
                    line_end=entry.line_end,
                )

        if aaa.servers:
            # FortiOS always retains local admin accounts; there is no equivalent of
            # `aaa new-model` that can lock them out.
            aaa.local_fallback = True
            aaa.new_model = True

    # ── logging and time ────────────────────────────────────────────────

    def _parse_logging(self, config: ParsedConfig, result: ParseResult) -> None:
        logging_ncm = result.ncm.logging

        for section in config.sections_matching("log syslogd"):
            if not section.flag("status"):
                continue
            host = section.get("server")
            if host:
                logging_ncm.syslog_servers.append(
                    SyslogServer(
                        host=host,
                        port=int(section.get("port") or 514)
                        if (section.get("port") or "514").isdigit()
                        else None,
                        facility=section.get("facility"),
                    )
                )
                self._record(
                    result,
                    f"logging.syslog_servers.{len(logging_ncm.syslog_servers) - 1}",
                    section,
                    "server",
                )
            if source := section.get("source-ip"):
                logging_ncm.source_interface = source
                self._record(result, "logging.source_interface", section, "source-ip")

        memory = config.section("log memory setting")
        if memory and (status := memory.flag("status")) is not None:
            logging_ncm.buffered.enabled = status
            self._record(result, "logging.buffered.enabled", memory, "status")

        ntp = config.section("system ntp")
        if ntp:
            if (sync := ntp.flag("ntpsync")) is not None and sync:
                servers = ntp.child("ntpserver")
                if servers:
                    for entry in servers.entries():
                        host = entry.get("server")
                        if host:
                            result.ncm.ntp.servers.append(
                                NtpServer(
                                    host=host,
                                    authenticated=bool(entry.get("authentication")),
                                )
                            )
                            result.record(
                                f"ntp.servers.{len(result.ncm.ntp.servers) - 1}",
                                line=entry.line,
                                line_end=entry.line_end,
                            )
                elif (ntp.get("type") or "").lower() == "fortiguard":
                    # FortiGuard's pool is a legitimate source with no per-server entry.
                    result.ncm.ntp.servers.append(NtpServer(host="fortiguard", authenticated=False))
                    self._record(result, "ntp.servers.0", ntp, "type")

            if result.ncm.ntp.servers:
                result.ncm.ntp.authenticated = any(s.authenticated for s in result.ncm.ntp.servers)
            if source := ntp.get("source-ip"):
                result.ncm.ntp.source_interface = source
                self._record(result, "ntp.source_interface", ntp, "source-ip")

        timezone = config.section("system global")
        if timezone and (tz := timezone.get("timezone")):
            result.ncm.ntp.timezone = tz
            self._record(result, "ntp.timezone", timezone, "timezone")

    # ── SNMP ────────────────────────────────────────────────────────────

    def _parse_snmp(self, config: ParsedConfig, result: ParseResult) -> None:
        snmp = result.ncm.snmp

        communities = config.section("system snmp community")
        if communities:
            for entry in communities.entries():
                name = entry.get("name")
                if not name:
                    continue
                hosts = entry.child("hosts")
                snmp.v1v2c_communities.append(
                    SnmpCommunity(
                        name_masked=mask_secret(name),
                        is_default=is_default_community(name),
                        # FortiOS communities are read-only unless a host grants more;
                        # `query-v1-status`/`query-v2c-status` gate reads, and there is
                        # no write equivalent, so rw is knowably False.
                        rw=False,
                        acl=", ".join(h.get("ip") or "" for h in (hosts.entries() if hosts else []))
                        or None,
                    )
                )
                result.record(
                    f"snmp.v1v2c_communities.{len(snmp.v1v2c_communities) - 1}",
                    line=entry.line,
                    line_end=entry.line_end,
                )
            snmp.v1v2c_enabled = bool(snmp.v1v2c_communities)

        users = config.section("system snmp user")
        if users:
            for entry in users.entries():
                auth = entry.get("auth-proto")
                priv = entry.get("priv-proto")
                level = "noAuthNoPriv"
                if auth and priv:
                    level = "authPriv"
                elif auth:
                    level = "authNoPriv"
                snmp.v3_users.append(
                    SnmpV3User(
                        name=entry.name,
                        level=level,
                        auth=auth,
                        priv=priv,
                    )
                )
                result.record(
                    f"snmp.v3_users.{len(snmp.v3_users) - 1}",
                    line=entry.line,
                    line_end=entry.line_end,
                )

    # ── interfaces ──────────────────────────────────────────────────────

    def _parse_interfaces(self, config: ParsedConfig, result: ParseResult) -> None:
        section = config.section("system interface")
        if not section:
            return

        for entry in section.entries():
            address = entry.get_all("ip")
            status = entry.get("status")
            result.ncm.interfaces.append(
                Interface(
                    name=entry.name,
                    description=entry.get("description") or entry.get("alias"),
                    admin_up=None if status is None else status.lower() == "up",
                    ip_addresses=[" ".join(address)] if address else [],
                    zone=entry.get("role"),
                    is_management="mgmt" in (entry.get("role") or "").lower() or None,
                )
            )
            result.record(
                f"interfaces.{len(result.ncm.interfaces) - 1}",
                line=entry.line,
                line_end=entry.line_end,
            )

    # ── the firewall (FR-FW-01) ─────────────────────────────────────────

    def _parse_firewall(self, config: ParsedConfig, result: ParseResult) -> None:
        firewall = result.ncm.firewall

        addresses = config.section("firewall address")
        if addresses:
            for entry in addresses.entries():
                firewall.address_objects.append(
                    NetworkObject(
                        name=entry.name,
                        type=entry.get("type", "subnet"),
                        value=_address_value(entry),
                    )
                )
                result.record(
                    f"firewall.address_objects.{len(firewall.address_objects) - 1}",
                    line=entry.line,
                    line_end=entry.line_end,
                )

        groups = config.section("firewall addrgrp")
        if groups:
            for entry in groups.entries():
                firewall.address_groups.append(
                    NetworkObject(name=entry.name, type="group", members=entry.get_all("member"))
                )
                result.record(
                    f"firewall.address_groups.{len(firewall.address_groups) - 1}",
                    line=entry.line,
                    line_end=entry.line_end,
                )

        services = config.section("firewall service custom")
        if services:
            for entry in services.entries():
                value, protocol = _service_value(entry)
                firewall.service_objects.append(
                    NetworkObject(name=entry.name, type=protocol, value=value)
                )
                result.record(
                    f"firewall.service_objects.{len(firewall.service_objects) - 1}",
                    line=entry.line,
                    line_end=entry.line_end,
                )

        service_groups = config.section("firewall service group")
        if service_groups:
            for entry in service_groups.entries():
                firewall.service_groups.append(
                    NetworkObject(name=entry.name, type="group", members=entry.get_all("member"))
                )
                result.record(
                    f"firewall.service_groups.{len(firewall.service_groups) - 1}",
                    line=entry.line,
                    line_end=entry.line_end,
                )

        policies = config.section("firewall policy")
        if policies:
            zones: set[str] = set()
            for order, entry in enumerate(policies.entries(), start=1):
                src_zones = entry.get_all("srcintf")
                dst_zones = entry.get_all("dstintf")
                zones.update(src_zones)
                zones.update(dst_zones)

                status = entry.get("status")
                log_setting = (entry.get("logtraffic") or "").lower()

                firewall.security_rules.append(
                    SecurityRule(
                        order=order,
                        name=entry.get("name") or entry.name,
                        # A FortiOS policy is enabled unless `set status disable`.
                        enabled=status is None or status.lower() == "enable",
                        src_zones=src_zones,
                        src=entry.get_all("srcaddr") or ["all"],
                        dst_zones=dst_zones,
                        dst=entry.get_all("dstaddr") or ["all"],
                        services=entry.get_all("service") or ["ALL"],
                        applications=entry.get_all("application-list"),
                        users=entry.get_all("groups") or entry.get_all("users"),
                        action=entry.get("action") or "deny",
                        # `logtraffic all` logs everything, `utm` only UTM events, and
                        # `disable` nothing. Absent means the platform default, which
                        # differs by version — so it stays None rather than guessed.
                        log_start=None if not log_setting else log_setting == "all",
                        log_end=None if not log_setting else log_setting in {"all", "utm"},
                        profiles=_profiles(entry),
                        schedule=entry.get("schedule"),
                    )
                )
                result.record(
                    f"firewall.security_rules.{len(firewall.security_rules) - 1}",
                    line=entry.line,
                    line_end=entry.line_end,
                )

            firewall.zones = sorted(z for z in zones if z)
            if firewall.zones:
                result.record("firewall.zones", line=policies.line, line_end=policies.line_end)

    # ── certificates ────────────────────────────────────────────────────

    def _parse_certificates(self, config: ParsedConfig, result: ParseResult) -> None:
        for section_name in ("vpn certificate local", "certificate local"):
            section = config.section(section_name)
            if not section:
                continue
            for entry in section.entries():
                result.ncm.certificates.append(
                    Certificate(
                        name=entry.name,
                        # FortiOS stores the certificate body inline; the fields we
                        # would want (expiry, key size) are inside the PEM, which the
                        # configuration alone does not expose in a parseable form.
                        # Leaving them None is what makes the expiry checks report Not
                        # Evaluated rather than inventing a date.
                        subject=entry.get("name"),
                    )
                )
                result.record(
                    f"certificates.{len(result.ncm.certificates) - 1}",
                    line=entry.line,
                    line_end=entry.line_end,
                )


def _address_value(entry: Block) -> str:
    """Render a FortiOS address object as something `parse_address` understands."""
    kind = (entry.get("type") or "ipmask").lower()

    if kind == "iprange":
        start, end = entry.get("start-ip"), entry.get("end-ip")
        return f"{start}-{end}" if start and end else ""

    if kind == "fqdn":
        # An FQDN resolves at runtime; the configuration does not say to what. It is
        # kept by name so the object is not lost, but it contributes no addresses.
        return ""

    subnet = entry.get_all("subnet")
    if len(subnet) == 2:
        address, mask = subnet
        if mask == "255.255.255.255":
            return address
        try:
            prefix = sum(bin(int(octet)).count("1") for octet in mask.split("."))
        except ValueError:
            return address
        return f"{address}/{prefix}"

    return subnet[0] if subnet else ""


def _service_value(entry: Block) -> tuple[str, str]:
    """Render a FortiOS service object, returning (value, protocol)."""
    for key, protocol in (("tcp-portrange", "tcp"), ("udp-portrange", "udp")):
        ports = entry.get_all(key)
        if ports:
            # FortiOS writes `dst[:src]`; only the destination range matters here.
            cleaned = ",".join(part.split(":")[0] for part in ports)
            return f"{protocol}/{cleaned}", protocol

    if (entry.get("protocol") or "").upper() == "ICMP":
        return "icmp", "icmp"

    number = entry.get("protocol-number")
    if number and number.isdigit():
        return f"proto-{number}", number

    return "any", "any"


def _profiles(entry: Block) -> dict[str, str]:
    """Which security profiles a policy applies.

    An empty dict means none, which is what the no-profiles finding keys on. FortiOS
    names each profile type separately rather than having one `profile-group` field, so
    they are collected individually.
    """
    profiles: dict[str, str] = {}
    for key, label in (
        ("ips-sensor", "ips"),
        ("av-profile", "antivirus"),
        ("webfilter-profile", "url"),
        ("dnsfilter-profile", "dns"),
        ("application-list", "application"),
        ("ssl-ssh-profile", "decryption"),
        ("file-filter-profile", "file"),
        ("profile-group", "group"),
    ):
        value = entry.get(key)
        if value:
            profiles[label] = value
    return profiles


__all__ = ["FortiOsParser"]
