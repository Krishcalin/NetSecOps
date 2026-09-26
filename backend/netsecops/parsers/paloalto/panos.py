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
from datetime import UTC, datetime
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
    Route,
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
from netsecops.parsers.routes import connected_routes, store, to_cidr

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


def _epoch_to_iso(value: str | None) -> str | None:
    """A PAN-OS Unix timestamp as ISO-8601, or None when there is no answer.

    Zero is the important case. PAN-OS reports a rule that has never matched with
    `<last-hit-timestamp>0</last-hit-timestamp>`, and converting that literally yields
    1970-01-01 — an idle age of twenty thousand days, which `no_recent_hits` would
    report as a stale rule on evidence that says only "never used". Never-hit is
    already reported by `hit_count == 0`; the idle clock has to stay unanswered.
    """
    if value is None or not value.strip().lstrip("-").isdigit():
        return None
    epoch = int(value.strip())
    if epoch <= 0:
        return None
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat()


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
            result.ncm.parse_failed = True
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

        self._parse_routing(network, result)

    # ── routing (FR-TOPO-01) ────────────────────────────────────────────

    def _parse_routing(self, network: Element, result: ParseResult) -> None:
        """Static routes, per virtual router.

        Called from the interface parser because it needs the same ``network`` element
        and the interface list it has just built.

        **The virtual router is carried as the VRF, and that matters here more than on
        the other platforms.** Separate virtual routers on one PAN-OS firewall are
        separate forwarding tables by design — an internet VR and a management VR
        commonly hold conflicting default routes, and merging them produces a graph where
        a packet can cross between two networks that are deliberately isolated. That is
        the one error class a reachability answer must never make.
        """
        collected: list[tuple[Route, int | None]] = []

        for vr_name, vr_entry in _entries(network, "virtual-router"):
            static = vr_entry.find("routing-table/ip/static-route")
            for _route_name, route_entry in _entries(static, ".") if static is not None else []:
                destination = to_cidr(_text(route_entry, "destination") or "")
                if destination is None:
                    continue

                # `nexthop` is a choice element: an IP, a next-VR, or discard. Only the
                # first is an edge to somewhere — a discard route is a deliberate black
                # hole and drawing it as a hop would invent reachability.
                next_hop = _text(route_entry, "nexthop/ip-address")
                metric = _text(route_entry, "metric")

                collected.append(
                    (
                        Route(
                            destination=destination,
                            next_hop=next_hop,
                            interface=_text(route_entry, "interface"),
                            protocol="static",
                            metric=int(metric) if metric and metric.isdigit() else None,
                            vrf=vr_name,
                        ),
                        # PAN-OS is XML: an element has no line number the way a CLI line
                        # does, and the parser's provenance for XML is element-based
                        # throughout. None keeps that consistent rather than inventing a
                        # line that would point at the wrong place in the file.
                        None,
                    )
                )

        collected.extend((route, None) for route in connected_routes(result.ncm.interfaces))

        store(result, collected)

    # ── the firewall (FR-FW-01) ─────────────────────────────────────────

    #: The op command whose response carries per-rule counters. Must stay byte-identical
    #: to the entry in `adapters/profiles.py`, which is how the artefact is keyed.
    RULE_HIT_COUNT = (
        "GET /api/?type=op&cmd=<show><rule-hit-count><vsys><vsys-name>"
        "<entry name='vsys1'><rule-base><entry name='security'><rules><all>"
        "</all></rules></entry></rule-base></entry></vsys-name></vsys>"
        "</rule-hit-count></show>"
    )

    def _read_hit_counts(self, result: ParseResult) -> dict[str, dict[str, tuple[int, str | None]]]:
        """Per-vsys, per-rule ``(hits, last hit as ISO-8601)`` from `show rule-hit-count`.

        Keyed by rule name rather than by position, because PAN-OS rule names are unique
        within a rulebase. That makes this materially safer than the ASA equivalent,
        where the show output has to be paired ordinally and verified.

        .. warning::

           The response shape below is written from PAN-OS documentation, not from a
           captured device response — there is no PAN-OS lab behind this repository. The
           element names (``rule-hit-count/vsys/entry/rule-base/entry/rules/entry`` with
           ``hit-count`` and ``last-hit-timestamp`` children) need confirming against a
           real 10.x/11.x device before the counts are relied on for rule removal. Until
           then a shape mismatch degrades to "no counts found", which leaves every rule
           at ``hit_count = None`` and reports Not Evaluated — the same position we were
           in before, and never a false never-hit verdict.
        """
        output = result.context.artifact(self.RULE_HIT_COUNT)
        if output is None:
            return {}

        try:
            root = fromstring(output)
        except ParseError as exc:
            log.warning("parser.hit_counts_invalid", platform=self.platform, error=str(exc))
            return {}

        counts: dict[str, dict[str, tuple[int, str | None]]] = {}
        for vsys_name, vsys in _entries(root.find(".//rule-hit-count/vsys"), "."):
            rules = vsys.find("rule-base/entry[@name='security']/rules")
            if rules is None:
                continue
            for rule_name, entry in _entries(rules, "."):
                hits = _text(entry, "hit-count")
                if hits is None or not hits.strip().isdigit():
                    continue
                counts.setdefault(vsys_name, {})[rule_name] = (
                    int(hits),
                    _epoch_to_iso(_text(entry, "last-hit-timestamp")),
                )
        return counts

    def _parse_firewall(self, config: Element, result: ParseResult) -> None:
        firewall = result.ncm.firewall
        device_entry = config.find(".//devices/entry")
        hit_counts = self._read_hit_counts(result)

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

            vsys_counts = hit_counts.get(vsys_name, {})
            rules = vsys.find("rulebase/security/rules")
            for order, (rule_name, entry) in enumerate(
                _entries(rules, ".") if rules is not None else [],
                start=len(firewall.security_rules) + 1,
            ):
                rule = self._security_rule(rule_name, entry, order, prefix)
                # A rule the counters did not mention keeps hit_count None. Defaulting
                # it to 0 would read as "never matched any traffic" and is what the
                # cleanup advice acts on.
                if (observed := vsys_counts.get(rule_name)) is not None:
                    rule.hit_count, rule.last_hit = observed
                firewall.security_rules.append(rule)
                self._record(
                    result,
                    f"firewall.security_rules.{len(firewall.security_rules) - 1}",
                    entry,
                )

            nat = vsys.find("rulebase/nat/rules")
            for nat_name, entry in _entries(nat, ".") if nat is not None else []:
                nat_rule = NatRule(
                    order=len(firewall.nat_rules) + 1,
                    name=f"{prefix}{nat_name}",
                    original=", ".join(_members(entry, "source")) or "any",
                    translated=_translated(entry),
                    service=_text(entry, "service", "any"),
                    direction="destination"
                    if entry.find("destination-translation") is not None
                    else "source",
                )
                _normalise_nat(entry, nat_rule)
                firewall.nat_rules.append(nat_rule)
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


def _normalise_nat(entry: Element, rule: NatRule) -> None:
    """Fill the normalised NAT fields from a PAN-OS `rulebase/nat/rules` entry.

    PAN-OS is the one platform whose configuration says everything plainly: `source`
    and `destination` are the pre-translation match conditions, and the two
    `*-translation` blocks say what each becomes. The legacy `original` field could not
    express that — it holds the source members whatever the rule translates — which is
    why a matcher could never be built on it.

    Two forms are deliberately left unreadable rather than approximated. A
    `dynamic-ip-and-port` source translation to an *interface* becomes whatever address
    that interface holds, which is not in this rule; and `dynamic-translated-address`
    picks from a pool per session, so no single answer is correct. Both set
    `translation_unreadable`, because a path crossing a rule nobody could read is a
    weaker answer than one crossing a rule that plainly does not match.
    """
    rule.original_source = [m for m in _members(entry, "source") if m.lower() != "any"]
    rule.original_destination = [m for m in _members(entry, "destination") if m.lower() != "any"]
    service = _text(entry, "service")
    if service and service.lower() != "any":
        rule.original_ports = [service]

    destination = entry.find("destination-translation")
    if destination is not None:
        address = _text(destination, "translated-address")
        if address:
            rule.translated_destination = [address]
        port = _text(destination, "translated-port")
        if port and port.isdigit():
            rule.translated_port = int(port)

    source = entry.find("source-translation")
    if source is not None:
        static = _text(source, "static-ip/translated-address")
        if static:
            rule.translated_source = [static]
        else:
            pool = _members(source, "dynamic-ip-and-port/translated-address")
            interface = _text(source, "dynamic-ip-and-port/interface-address/interface")
            if interface:
                rule.translation_unreadable = (
                    f"the source is translated to whatever address {interface} holds, "
                    "which this rule does not state"
                )
            elif len(pool) == 1:
                rule.translated_source = list(pool)
            elif pool:
                rule.translation_unreadable = (
                    f"the source is translated to one of {len(pool)} pool addresses, "
                    "chosen per session"
                )


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
