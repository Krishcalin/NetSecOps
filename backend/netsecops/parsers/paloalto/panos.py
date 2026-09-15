"""PAN-OS configuration parser (FR-PARSE-01 … FR-PARSE-05, FR-FW-01).

PAN-OS exports its configuration as XML, which is a gift compared with the line formats:
the structure is explicit and there is no ambiguity about where a stanza ends. The work
is in the shape rather than the syntax.

**Vsys.** A firewall may carry several virtual systems, each with its own objects and
its own rulebase. They are separate policy domains — a rule in vsys2 cannot shadow one
in vsys1 — so names are qualified with their vsys and the analyser sees them as
different zones. Flattening them would invent relationships that cannot exist.

**Shared objects.** Panorama and multi-vsys firewalls put common objects in a `shared`
section that every vsys can reference. A name resolves to its vsys-local definition
first and the shared one second, which is what the device does.

**Parsed with defusedxml.** A device configuration is attacker-influenced input;
ElementTree will process external entities and expansion bombs, and this runs on a
worker with network access to the estate.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring

if TYPE_CHECKING:
    # Type-only. Every tree in this module is built by `defusedxml.fromstring` above;
    # importing `xml.etree` at runtime would be flagged by bandit (B405) and would
    # invite someone to reach for the unsafe parser later.
    from xml.etree.ElementTree import Element

from netsecops.core.logging import get_logger
from netsecops.ncm.models import (
    Certificate,
    Firewall,
    Interface,
    LocalUser,
    NatRule,
    NetworkObject,
    NormalisedConfig,
    NtpServer,
    SecurityRule,
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


def _text(element: Element | None, path: str, default: str | None = None) -> str | None:
    """Text of a child element, or the default. Never raises on a missing path."""
    if element is None:
        return default
    found = element.find(path)
    if found is None or found.text is None:
        return default
    value = found.text.strip()
    return value or default


def _members(element: Element | None, path: str) -> list[str]:
    """PAN-OS lists are `<path><member>a</member><member>b</member></path>`."""
    if element is None:
        return []
    container = element.find(path)
    if container is None:
        return []
    return [m.text.strip() for m in container.findall("member") if m.text and m.text.strip()]


def _entries(element: Element | None, path: str) -> Iterator[tuple[str, Element]]:
    """`<path><entry name="x">…</entry></path>`, yielding (name, element)."""
    if element is None:
        return
    container = element.find(path)
    if container is None:
        return
    for entry in container.findall("entry"):
        name = entry.get("name")
        if name:
            yield name, entry


def _yes(element: Element | None, path: str) -> bool | None:
    """PAN-OS booleans are the strings `yes` and `no`.

    Absent stays None: `<log-end>no</log-end>` and no `<log-end>` at all are different
    facts, and the NCM's absent-is-not-false rule depends on keeping them apart.
    """
    value = _text(element, path)
    if value is None:
        return None
    return value.lower() == "yes"


class PanOsParser(ConfigParser):
    vendor = "paloalto"
    platform = "panos"

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)

        try:
            root = fromstring(context.text)
        except (ParseError, DefusedXmlException) as exc:
            # Not well-formed XML, or well-formed but hostile — defusedxml raises
            # `EntitiesForbidden` / `DTDForbidden` / `ExternalReferenceForbidden` rather
            # than `ParseError` for an expansion bomb or an XXE payload, and catching
            # only the latter would let a malicious configuration crash the worker
            # instead of being recorded as an unreadable snapshot.
            #
            # Either way there is nothing to salvage — everything below assumes a tree —
            # but the collection still produced a snapshot, and every check will honestly
            # report Not Evaluated rather than the device being reported clean.
            log.warning("parser.xml_invalid", platform=self.platform, error=str(exc))
            result.ncm.device.vendor = self.vendor
            result.ncm.device.platform = self.platform
            result.ncm.raw_unparsed = [f"1: the configuration is not well-formed XML: {exc}"]
            return result.ncm

        # An API response wraps the configuration in <response><result>.
        config = root.find(".//config") if root.tag != "config" else root
        if config is None:
            config = root

        for section in (
            self._parse_device,
            self._parse_management,
            self._parse_users,
            self._parse_logging,
            self._parse_snmp,
            self._parse_interfaces,
            self._parse_firewall,
            self._parse_certificates,
        ):
            try:
                section(config, result)
            except Exception as exc:
                log.warning(
                    "parser.section_failed",
                    platform=self.platform,
                    section=section.__name__,
                    error=str(exc),
                )

        self._account_for_lines(result)
        return result.ncm

    # ── bookkeeping ─────────────────────────────────────────────────────

    def _account_for_lines(self, result: ParseResult) -> None:
        """Coverage over an XML document.

        Line-level coverage is the wrong measure here — a `<entry>` spans ten lines and
        contributes one fact — so every line of a well-formed document counts as
        accounted for, and the honesty is carried instead by the unresolved-object
        findings and by checks reporting Not Evaluated. Claiming 12% coverage because
        closing tags are not "parsed" would make the number meaningless.
        """
        result.consume(1, max(1, len(result.context.lines)))

    def _record(self, result: ParseResult, path: str, element: Element) -> None:
        """Provenance for an XML node.

        ElementTree discards line numbers, so an excerpt would need a second pass with
        a location-aware parser. The path is recorded with no line, which makes findings
        cite the setting rather than a line number — honest, and better than a
        confident wrong line.
        """
        result.ncm.provenance.record(path, result.context.provenance(1, 1))

    # ── device ──────────────────────────────────────────────────────────

    def _device_config(self, config: Element) -> Element | None:
        return config.find(".//devices/entry/deviceconfig")

    def _parse_device(self, config: Element, result: ParseResult) -> None:
        device = result.ncm.device
        device.vendor = self.vendor
        device.platform = self.platform

        system = config.find(".//devices/entry/deviceconfig/system")
        if system is None:
            return

        device.hostname = _text(system, "hostname")
        device.domain_name = _text(system, "domain")
        if device.hostname:
            self._record(result, "device.hostname", system)

        # The running version is not in the configuration: it comes from `show system
        # info`, which the profile issues as a separate request. Read from the supporting
        # artefact, and left None when that request did not run — the matcher then
        # reports "unknown version" rather than guessing (FR-VUL-01).
        self._parse_system_info(result)

        ha = config.find(".//devices/entry/deviceconfig/high-availability")
        if ha is not None:
            enabled = _yes(ha, "enabled")
            if enabled is not None:
                device.ha.enabled = enabled
                self._record(result, "device.ha.enabled", ha)

    #: The `show system info` request, exactly as the collection profile spells it.
    SYSTEM_INFO = "GET /api/?type=op&cmd=<show><system><info></info></system></show>"

    def _parse_system_info(self, result: ParseResult) -> None:
        """Software version, model and serial from `show system info` (FR-VUL-01).

        PAN-OS answers with XML, so this parses rather than string-matching: a
        `<sw-version>` substring also occurs inside `<multi-vsys>` blocks and in the
        plugin list on some releases, and taking the first textual match picked up a
        plugin's version on those.
        """
        output = result.context.artifact(self.SYSTEM_INFO)
        if output is None:
            return

        try:
            info = fromstring(output)
        except (ParseError, DefusedXmlException) as exc:
            log.warning("parser.system_info_invalid", platform=self.platform, error=str(exc))
            return

        device = result.ncm.device
        # `result/system/sw-version`, with the API's outer <response> wrapper optional
        # depending on how the artefact was captured.
        system = info.find(".//system") if info.tag != "system" else info
        if system is None:
            return

        if (version := _text(system, "sw-version")) is not None:
            device.version = version
            result.record("device.version", line=1)

        if (model := _text(system, "model")) is not None:
            device.model = model
            result.record("device.model", line=1)

        if (serial := _text(system, "serial")) is not None:
            device.serials = [serial]
            result.record("device.serials", line=1)

    # ── management ──────────────────────────────────────────────────────

    def _parse_management(self, config: Element, result: ParseResult) -> None:
        management = result.ncm.management
        system = config.find(".//devices/entry/deviceconfig/system")
        if system is None:
            return

        service = system.find("service")
        if service is not None:
            # PAN-OS spells these as *disable* flags, so the sense is inverted. Getting
            # this backwards would report a hardened device as wide open.
            for name, tag in (
                ("telnet", "disable-telnet"),
                ("http", "disable-http"),
                ("snmp", "disable-snmp"),
            ):
                disabled = _yes(service, tag)
                if disabled is not None:
                    getattr(management.services, name).enabled = not disabled
                    self._record(result, f"management.services.{name}.enabled", service)

            https_disabled = _yes(service, "disable-https")
            if https_disabled is not None:
                management.services.https.enabled = not https_disabled
                self._record(result, "management.services.https.enabled", service)

            ssh_disabled = _yes(service, "disable-ssh")
            if ssh_disabled is not None:
                management.services.ssh.enabled = not ssh_disabled
                self._record(result, "management.services.ssh.enabled", service)

        permitted = _members(system, "permitted-ip")
        if not permitted:
            permitted = [name for name, _ in _entries(system, "permitted-ip")]
        if permitted:
            management.management_acls["permitted-ip"] = ", ".join(permitted)
            self._record(result, "management.management_acls", system)

        timeout = _text(system, "idle-timeout")
        if timeout and timeout.isdigit():
            # PAN-OS states the idle timeout in minutes.
            management.session.exec_timeout_s = int(timeout) * 60
            self._record(result, "management.session.exec_timeout_s", system)

        login_banner = _text(system, "login-banner")
        if login_banner:
            management.banners.login = login_banner
            self._record(result, "management.banners.login", system)

        policy = config.find(".//mgt-config/password-complexity")
        if policy is not None:
            enabled = _yes(policy, "enabled")
            if enabled is not None:
                management.password_policy.complexity_required = enabled
                self._record(result, "management.password_policy.complexity_required", policy)
            minimum = _text(policy, "minimum-length")
            if minimum and minimum.isdigit():
                management.password_policy.min_length = int(minimum)
                self._record(result, "management.password_policy.min_length", policy)

    # ── accounts ────────────────────────────────────────────────────────

    def _parse_users(self, config: Element, result: ParseResult) -> None:
        for name, entry in _entries(config.find(".//mgt-config"), "users"):
            permissions = entry.find("permissions")
            role = None
            if permissions is not None:
                if permissions.find("role-based/superuser") is not None:
                    role = "superuser"
                elif permissions.find("role-based/devicereader") is not None:
                    role = "devicereader"
                elif permissions.find("role-based/superreader") is not None:
                    role = "superreader"
                else:
                    custom = permissions.find("role-based/custom")
                    role = _text(custom, "profile") if custom is not None else None

            result.ncm.users.append(
                LocalUser(
                    name=name,
                    role=role,
                    privilege=15 if role == "superuser" else None,
                    # PAN-OS stores a bcrypt/md5-crypt hash in `phash`. The prefix says
                    # which, and `$1$` is md5-crypt — weak by modern standards.
                    secret_type=_hash_type(_text(entry, "phash")),
                    weak_hash=_is_weak_hash(_text(entry, "phash")),
                )
            )
            self._record(result, f"users.{len(result.ncm.users) - 1}", entry)

    # ── logging and time ────────────────────────────────────────────────

    def _parse_logging(self, config: Element, result: ParseResult) -> None:
        logging_ncm = result.ncm.logging

        for profile_name, profile in _entries(config.find(".//shared/log-settings"), "syslog"):
            for server_name, server in _entries(profile, "server"):
                host = _text(server, "server")
                if not host:
                    continue
                port = _text(server, "port")
                logging_ncm.syslog_servers.append(
                    SyslogServer(
                        host=host,
                        port=int(port) if port and port.isdigit() else None,
                        transport=_text(server, "transport"),
                        facility=_text(server, "facility"),
                    )
                )
                self._record(
                    result,
                    f"logging.syslog_servers.{len(logging_ncm.syslog_servers) - 1}",
                    server,
                )
                log.debug("panos.syslog", profile=profile_name, server=server_name)

        ntp = config.find(".//devices/entry/deviceconfig/system/ntp-servers")
        if ntp is not None:
            for tag in ("primary-ntp-server", "secondary-ntp-server"):
                ntp_server = ntp.find(tag)
                if ntp_server is None:
                    continue
                host = _text(ntp_server, "ntp-server-address")
                if not host:
                    continue
                # `authentication-type/none` is explicit in PAN-OS, which is why this
                # can be answered rather than left unknown.
                auth = ntp_server.find("authentication-type")
                authenticated = (
                    auth is not None and auth.find("none") is None and len(list(auth)) > 0
                )
                result.ncm.ntp.servers.append(NtpServer(host=host, authenticated=authenticated))
                self._record(result, f"ntp.servers.{len(result.ncm.ntp.servers) - 1}", ntp_server)

            if result.ncm.ntp.servers:
                result.ncm.ntp.authenticated = all(s.authenticated for s in result.ncm.ntp.servers)

        system = config.find(".//devices/entry/deviceconfig/system")
        timezone = _text(system, "timezone")
        if timezone:
            result.ncm.ntp.timezone = timezone
            if system is not None:
                self._record(result, "ntp.timezone", system)

    # ── SNMP ────────────────────────────────────────────────────────────

    def _parse_snmp(self, config: Element, result: ParseResult) -> None:
        snmp = result.ncm.snmp
        setting = config.find(".//devices/entry/deviceconfig/system/snmp-setting/access-setting")
        if setting is None:
            return

        version = setting.find("version")
        if version is None:
            return

        v2c = version.find("v2c")
        if v2c is not None:
            community = _text(v2c, "snmp-community-string")
            if community:
                snmp.v1v2c_communities.append(
                    SnmpCommunity(
                        name_masked=mask_secret(community),
                        is_default=is_default_community(community),
                        # PAN-OS SNMP is read-only; there is no write community.
                        rw=False,
                    )
                )
                snmp.v1v2c_enabled = True
                self._record(result, "snmp.v1v2c_communities.0", v2c)

        v3 = version.find("v3")
        if v3 is not None:
            from netsecops.ncm.models import SnmpV3User

            for view_name, view in _entries(v3, "views"):
                for user_name, user in _entries(view, "users"):
                    snmp.v3_users.append(
                        SnmpV3User(
                            name=user_name,
                            # PAN-OS v3 requires both auth and priv passwords, so a
                            # configured v3 user is authPriv by construction.
                            level="authPriv",
                            group=view_name,
                        )
                    )
                    self._record(result, f"snmp.v3_users.{len(snmp.v3_users) - 1}", user)

    # ── interfaces ──────────────────────────────────────────────────────

    def _parse_interfaces(self, config: Element, result: ParseResult) -> None:
        network = config.find(".//devices/entry/network")
        if network is None:
            return

        zones_by_interface: dict[str, str] = {}
        for _vsys_name, vsys in _entries(config.find(".//devices/entry"), "vsys"):
            for zone_name, zone in _entries(vsys, "zone"):
                for member in _members(zone.find("network"), "layer3"):
                    zones_by_interface[member] = zone_name

        ethernet = network.find("interface/ethernet")
        for name, entry in _entries(ethernet, ".") if ethernet is not None else []:
            layer3 = entry.find("layer3")
            addresses = [n for n, _ in _entries(layer3, "ip")] if layer3 is not None else []
            result.ncm.interfaces.append(
                Interface(
                    name=name,
                    description=_text(entry, "comment"),
                    ip_addresses=addresses,
                    zone=zones_by_interface.get(name),
                )
            )
            self._record(result, f"interfaces.{len(result.ncm.interfaces) - 1}", entry)

    # ── the firewall (FR-FW-01) ─────────────────────────────────────────

    def _parse_firewall(self, config: Element, result: ParseResult) -> None:
        firewall = result.ncm.firewall
        device_entry = config.find(".//devices/entry")

        # Shared objects first so a vsys-local definition of the same name overrides
        # them, which is the order PAN-OS resolves in.
        shared = config.find(".//shared")
        self._collect_objects(shared, firewall, result, prefix="")

        zones: set[str] = set()
        vsys_list = list(_entries(device_entry, "vsys"))

        for vsys_name, vsys in vsys_list:
            # Names are qualified only when there is more than one vsys. With a single
            # vsys — the overwhelmingly common case — qualifying would make every
            # finding read `vsys1/web-servers` for no benefit.
            prefix = f"{vsys_name}/" if len(vsys_list) > 1 else ""

            self._collect_objects(vsys, firewall, result, prefix=prefix)

            for zone_name, _zone in _entries(vsys, "zone"):
                zones.add(f"{prefix}{zone_name}")

            rules = vsys.find("rulebase/security/rules")
            for order, (rule_name, entry) in enumerate(
                _entries(rules, ".") if rules is not None else [],
                start=len(firewall.security_rules) + 1,
            ):
                firewall.security_rules.append(self._security_rule(rule_name, entry, order, prefix))
                self._record(
                    result,
                    f"firewall.security_rules.{len(firewall.security_rules) - 1}",
                    entry,
                )

            nat = vsys.find("rulebase/nat/rules")
            for nat_name, entry in _entries(nat, ".") if nat is not None else []:
                firewall.nat_rules.append(
                    NatRule(
                        order=len(firewall.nat_rules) + 1,
                        name=f"{prefix}{nat_name}",
                        original=", ".join(_members(entry, "source")) or "any",
                        translated=_translated(entry),
                        service=_text(entry, "service", "any"),
                        direction="destination"
                        if entry.find("destination-translation") is not None
                        else "source",
                    )
                )
                self._record(result, f"firewall.nat_rules.{len(firewall.nat_rules) - 1}", entry)

        firewall.zones = sorted(zones)

    def _collect_objects(
        self, scope: Element | None, firewall: Firewall, result: ParseResult, *, prefix: str
    ) -> None:
        if scope is None:
            return

        for name, entry in _entries(scope, "address"):
            firewall.address_objects.append(
                NetworkObject(
                    name=f"{prefix}{name}",
                    type=_address_type(entry),
                    value=_address_value(entry),
                )
            )

        for name, entry in _entries(scope, "address-group"):
            # `_members` rather than a comprehension: an empty `<member/>` has text None,
            # and calling .strip() on it would raise out of the whole firewall section,
            # losing every rule and object over one malformed group.
            members = _members(entry, "static")
            firewall.address_groups.append(
                NetworkObject(
                    name=f"{prefix}{name}",
                    type="dynamic" if entry.find("dynamic") is not None else "group",
                    # A dynamic group's membership is decided at runtime by tag match,
                    # so the configuration alone cannot say what is in it. Empty members
                    # makes the rule resolve to nothing, and the unresolved-object
                    # finding says why rather than the rule silently covering nothing.
                    members=[f"{prefix}{m}" if prefix else m for m in members],
                )
            )

        for name, entry in _entries(scope, "service"):
            value, protocol = _service_value(entry)
            firewall.service_objects.append(
                NetworkObject(name=f"{prefix}{name}", type=protocol, value=value)
            )

        for name, entry in _entries(scope, "service-group"):
            members = _members(entry, "members")
            firewall.service_groups.append(
                NetworkObject(
                    name=f"{prefix}{name}",
                    type="group",
                    members=[f"{prefix}{m}" if prefix else m for m in members],
                )
            )

    def _security_rule(self, name: str, entry: Element, order: int, prefix: str) -> SecurityRule:
        profile_setting = entry.find("profile-setting")
        profiles: dict[str, str] = {}
        if profile_setting is not None:
            group = _members(profile_setting, "group")
            if group:
                profiles["group"] = ", ".join(group)
            individual = profile_setting.find("profiles")
            if individual is not None:
                for tag, label in (
                    ("virus", "antivirus"),
                    ("spyware", "anti-spyware"),
                    ("vulnerability", "ips"),
                    ("url-filtering", "url"),
                    ("file-blocking", "file"),
                    ("wildfire-analysis", "wildfire"),
                    ("data-filtering", "data"),
                ):
                    members = _members(individual, tag)
                    if members:
                        profiles[label] = ", ".join(members)

        disabled = _yes(entry, "disabled")

        return SecurityRule(
            order=order,
            name=f"{prefix}{name}",
            enabled=not disabled if disabled is not None else True,
            src_zones=[f"{prefix}{z}" for z in _members(entry, "from")],
            src=_members(entry, "source") or ["any"],
            dst_zones=[f"{prefix}{z}" for z in _members(entry, "to")],
            dst=_members(entry, "destination") or ["any"],
            services=_members(entry, "service") or ["any"],
            applications=_members(entry, "application"),
            users=_members(entry, "source-user"),
            action=_text(entry, "action", "allow") or "allow",
            log_start=_yes(entry, "log-start"),
            log_end=_yes(entry, "log-end"),
            profiles=profiles,
            schedule=_text(entry, "schedule"),
        )

    # ── certificates ────────────────────────────────────────────────────

    def _parse_certificates(self, config: Element, result: ParseResult) -> None:
        for name, entry in _entries(config.find(".//shared"), "certificate"):
            result.ncm.certificates.append(
                Certificate(
                    name=name,
                    subject=_text(entry, "subject"),
                    issuer=_text(entry, "issuer"),
                    not_after=_text(entry, "not-valid-after"),
                    not_before=_text(entry, "not-valid-before"),
                    # PAN-OS marks a certificate it generated itself with <ca>yes</ca>.
                    self_signed=_yes(entry, "ca"),
                )
            )
            self._record(result, f"certificates.{len(result.ncm.certificates) - 1}", entry)


# ────────────────────────────── helpers ─────────────────────────────────────


def _address_type(entry: Element) -> str:
    for tag in ("ip-netmask", "ip-range", "ip-wildcard", "fqdn"):
        if entry.find(tag) is not None:
            return tag
    return "unknown"


def _address_value(entry: Element) -> str:
    """Render a PAN-OS address object for the interval parser.

    An FQDN resolves at runtime and the configuration does not say to what, so it
    contributes no addresses — the object is kept by name and the rule using it
    reports as unresolved rather than silently covering nothing.
    """
    for tag in ("ip-netmask", "ip-range"):
        value = _text(entry, tag)
        if value:
            return value
    return ""


def _service_value(entry: Element) -> tuple[str, str]:
    protocol_element = entry.find("protocol")
    if protocol_element is None:
        return "any", "any"

    for protocol in ("tcp", "udp"):
        node = protocol_element.find(protocol)
        if node is not None:
            port = _text(node, "port", "")
            return f"{protocol}/{port}" if port else protocol, protocol

    return "any", "any"


def _translated(entry: Element) -> str:
    destination = entry.find("destination-translation")
    if destination is not None:
        address = _text(destination, "translated-address")
        port = _text(destination, "translated-port")
        return f"{address}:{port}" if port else (address or "")

    source = entry.find("source-translation")
    if source is not None:
        for path in (
            "dynamic-ip-and-port/interface-address/interface",
            "dynamic-ip-and-port/translated-address/member",
            "static-ip/translated-address",
        ):
            value = _text(source, path)
            if value:
                return value
    return ""


def _hash_type(phash: str | None) -> str | None:
    if not phash:
        return None
    if phash.startswith("$1$"):
        return "md5-crypt"
    if phash.startswith(("$5$", "$6$")):
        return "sha-crypt"
    if phash.startswith("$2"):
        return "bcrypt"
    return "unknown"


def _is_weak_hash(phash: str | None) -> bool | None:
    """md5-crypt is the weak one PAN-OS still accepts on older configurations."""
    kind = _hash_type(phash)
    if kind is None:
        return None
    if kind == "unknown":
        # Not recognised is not the same as weak. Returning None makes the check
        # report Not Evaluated rather than accusing a device of something unproven.
        return None
    return kind == "md5-crypt"


__all__ = ["PanOsParser"]
