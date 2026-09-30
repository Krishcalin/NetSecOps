"""Juniper Junos — SRX, MX and EX (SRS §1.3, FR-PARSE-01 … FR-PARSE-05).

One parser for the whole family, because the configuration format is a property of the
operating system rather than of the box: an SRX has a `security` hierarchy and an EX
does not, and a parser that reads both simply finds the second empty.

**Junos has two configuration formats and they are the same configuration.** The default
is a brace hierarchy; `| display set` prints flat `set` statements. Both are what an
operator will hand us — the flat form because the profile asks for it, the brace form
because that is what `show configuration` gives and what somebody uploading offline will
paste.

Reading only one of them would be the failure this codebase keeps finding: a brace-form
capture fed to a set-only parser produces an empty NCM, which is indistinguishable from
a device with nothing configured. So `to_set_statements` normalises the brace form into
the flat one and everything downstream reads a single representation.

Three things about that conversion are load-bearing:

**Line numbers must survive it.** A finding cites the line its evidence came from, and
after flattening, `set system services ssh root-login deny` comes from the line that
said `root-login deny;` — not from the line that said `system {`. Each emitted statement
carries the number of the line that terminated it.

**`inactive:` is not a comment.** Junos marks a deactivated statement by prefixing it,
and the statement stays in the configuration. Dropping the prefix silently reports a
disabled service as enabled; dropping the whole line loses that somebody left it there.
It is emitted with the marker intact and read as *present but inactive*.

**A brace can be inside a quoted string.** `description "wan { primary }";` is legal.
The depth tracker only treats a trailing brace as structural, which is the rule Junos's
own formatter follows when it emits one statement per line.
"""

from __future__ import annotations

import re

from netsecops.core.logging import get_logger
from netsecops.ncm.models import (
    AaaServer,
    Interface,
    LocalUser,
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

log = get_logger(__name__)

#: `## Last commit:` banners and `/* … */` blocks carry no configuration.
_COMMENT = re.compile(r"^(##|/\*|\*/|#)")

#: Junos marks a deactivated statement with this prefix and keeps it in the file.
_INACTIVE = "inactive:"

#: `family inet address 10.0.0.1/30` — the prefix is stored with its mask.
_ADDRESS = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")


def _tokens(text: str) -> list[str]:
    """Split a statement into tokens, keeping quoted strings whole.

    `description "wan link"` is two tokens, not three. Nothing else in Junos syntax
    needs quoting, and a naive split turns every multi-word description into a set of
    tokens the dispatch below then fails to match.
    """
    return [part for part in re.findall(r'"[^"]*"|\S+', text) if part]


def _unquote(value: str) -> str:
    return value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value


def _values(tokens: list[str]) -> list[str]:
    """A Junos multi-valued field, without its brackets.

    `application [ junos-http junos-https ]` is two applications. The brackets are
    syntax, and kept they become members of the set — so a rule matching two
    applications reports four, two of which match no application object anywhere.
    """
    return [_unquote(token) for token in tokens if token not in {"[", "]"}]


def to_set_statements(lines: list[str]) -> list[tuple[int, list[str], bool]]:
    """Normalise either Junos format into flat statements.

    Returns `(line number, tokens, inactive)` per statement, where the line number is
    the one that *terminated* it — the line a finding should cite.

    A capture already in `set` form is passed through: every line starting with `set` is
    taken as-is, and `delete`/`deactivate` lines are ignored because a `| display set`
    dump contains none and anything else is not a configuration.
    """
    statements: list[tuple[int, list[str], bool]] = []
    stack: list[str] = []
    #: One entry per open brace: how many tokens it pushed, and whether it was
    #: deactivated. A frame rather than a flag because `security-zone trust {` pushes
    #: two tokens and a closing brace must remove exactly those two — and because
    #: deactivating a block deactivates everything inside it, however deep.
    frames: list[tuple[int, bool]] = []

    for number, raw in enumerate(lines, start=1):
        text = raw.strip()
        if not text or _COMMENT.match(text):
            continue

        # Junos appends `## SECRET-DATA` *after* the semicolon on every line holding a
        # hash or a key. Left in place the line does not end with `;`, so it terminates
        # nothing and the statement is dropped — which silently loses every encrypted
        # password and every shared secret, and those are exactly the lines whose
        # presence a check asks about. Only stripped where the quotes before it balance,
        # so a description genuinely containing `##` survives.
        if "##" in text:
            before_comment, _, _ = text.partition("##")
            if before_comment.count('"') % 2 == 0:
                text = before_comment.strip()
            if not text:
                continue

        inactive = False
        if text.startswith(_INACTIVE):
            inactive = True
            text = text[len(_INACTIVE) :].strip()

        if text.startswith("set "):
            # Already flat. `display set` never nests, so the stack is irrelevant here.
            statements.append((number, _tokens(text[4:]), inactive))
            continue

        if text in {"}", "};"}:
            if frames:
                pushed, _ = frames.pop()
                del stack[len(stack) - pushed :]
            continue

        if text.endswith("{"):
            head = _tokens(text[:-1].strip())
            if head:
                frames.append((len(head), inactive))
                stack.extend(head)
            continue

        if text.endswith(";"):
            body = _tokens(text[:-1].strip())
            if body:
                within_inactive = any(flag for _, flag in frames)
                statements.append((number, [*stack, *body], inactive or within_inactive))
            continue

        # A statement broken across lines, or output that is not configuration. Left
        # for `finalise_unparsed` to report rather than guessed at.

    return statements


class JunosParser(ConfigParser):
    """Junos configuration, in either of its two formats."""

    vendor = "juniper"
    platform = "juniper_junos"

    IGNORE = re.compile(r"^([{}]|\}\s*;?|##|/\*|\*/|version\s)")

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        result.ncm.device.vendor = self.vendor
        result.ncm.device.platform = self.platform

        statements = to_set_statements(context.lines)
        if not statements:
            result.ncm.parse_failed = True
            result.ncm.raw_unparsed = [
                "No Junos statement was found, in either the brace or the `set` form."
            ]
            return result.ncm

        # Grouped so each section sees only what it needs, and an exception in one
        # cannot take the rest of the configuration with it (FR-PARSE-03).
        for handler in (
            self._system,
            self._interfaces,
            self._routing,
            self._snmp,
            self._security,
        ):
            try:
                handler(statements, result)
            except Exception as exc:  # pragma: no cover - defensive, per FR-PARSE-03
                # Logged rather than swallowed. A section that throws leaves its part of
                # the NCM empty, and an empty section is indistinguishable from a device
                # that has none of that configured — so the only trace anybody gets is
                # this line.
                log.warning(
                    "parser.section_failed",
                    platform=self.platform,
                    section=handler.__name__,
                    error=str(exc),
                )

        self._version(result)
        result.finalise_unparsed(ignore=self.IGNORE)
        return result.ncm

    # ──────────────────────────── helpers ───────────────────────────────

    @staticmethod
    def _under(
        statements: list[tuple[int, list[str], bool]], *prefix: str
    ) -> list[tuple[int, list[str], bool]]:
        """Statements beneath a hierarchy, with the prefix removed."""
        depth = len(prefix)
        return [
            (line, tokens[depth:], inactive)
            for line, tokens, inactive in statements
            if tuple(tokens[:depth]) == prefix and len(tokens) > depth
        ]

    @staticmethod
    def _has(statements: list[tuple[int, list[str], bool]], *prefix: str) -> int | None:
        """The line a hierarchy was configured on, or None.

        Returns the line so the caller can record provenance; an *inactive* statement
        returns None, because a deactivated service is not an enabled one.
        """
        depth = len(prefix)
        for line, tokens, inactive in statements:
            if tuple(tokens[:depth]) == prefix and not inactive:
                return line
        return None

    # ───────────────────────────── system ───────────────────────────────

    def _system(self, statements: list[tuple[int, list[str], bool]], result: ParseResult) -> None:
        ncm = result.ncm
        system = self._under(statements, "system")

        for line, tokens, _ in system:
            if tokens[:1] == ["host-name"] and len(tokens) > 1:
                ncm.device.hostname = _unquote(tokens[1])
                result.record("device.hostname", line=line)
            elif tokens[:1] == ["domain-name"] and len(tokens) > 1:
                ncm.device.domain_name = _unquote(tokens[1])
                result.record("device.domain_name", line=line)

        self._services(system, result)
        self._login(system, result)
        self._syslog(system, result)
        self._time_and_aaa(system, result)

    def _services(self, system: list[tuple[int, list[str], bool]], result: ParseResult) -> None:
        """`system services` — what the control plane answers on.

        Junos enables a service by the *presence* of its stanza, so absence is the
        normal way to be disabled. That makes `None` wrong here in one specific case
        and right in another, and the distinction is the whole reason this reads the way
        it does: a configuration we actually parsed and in which `telnet` does not
        appear is a device with telnet off, and `False` is the honest answer. A
        configuration we could not read at all never reaches this method.
        """
        ncm = result.ncm
        services = self._under(system, "services")

        ssh_line = self._has(services, "ssh")
        ncm.management.services.ssh.enabled = ssh_line is not None
        result.record("management.services.ssh.enabled", line=ssh_line)

        telnet_line = self._has(services, "telnet")
        ncm.management.services.telnet.enabled = telnet_line is not None
        result.record("management.services.telnet.enabled", line=telnet_line)

        web = self._under(services, "web-management")
        http_line = self._has(web, "http")
        https_line = self._has(web, "https")
        ncm.management.services.http.enabled = http_line is not None
        ncm.management.services.https.enabled = https_line is not None
        ncm.features.http_server = http_line is not None
        ncm.features.https_server = https_line is not None
        result.record("management.services.http.enabled", line=http_line)
        result.record("management.services.https.enabled", line=https_line)

        for line, tokens, _ in self._under(services, "ssh"):
            if tokens[:1] == ["protocol-version"] and len(tokens) > 1:
                # `v2` → 2. A device pinned to v1 is the finding, and it is a number
                # everywhere else in the NCM.
                ncm.management.services.ssh.version = 2 if tokens[1] == "v2" else 1
                result.record("management.services.ssh.version", line=line)
            elif tokens[:1] == ["root-login"] and len(tokens) > 1:
                # Not an NCM field of its own; recorded as a management ACL entry so the
                # fact survives rather than being dropped for want of a home.
                ncm.management.management_acls["ssh-root-login"] = tokens[1]
                result.record("management.management_acls", line=line)
            elif tokens[:1] == ["connection-limit"] and len(tokens) > 1:
                try:
                    ncm.management.session.max_sessions = int(tokens[1])
                    result.record("management.session.max_sessions", line=line)
                except ValueError:
                    continue

    def _login(self, system: list[tuple[int, list[str], bool]], result: ParseResult) -> None:
        ncm = result.ncm

        for line, tokens, _ in self._under(system, "login", "user"):
            if len(tokens) < 3 or tokens[1] != "class":
                continue
            ncm.users.append(LocalUser(name=_unquote(tokens[0]), role=tokens[2]))
            result.record(f"users.{len(ncm.users) - 1}", line=line)

        # `system login message` is Junos's banner, and a device with none is a finding
        # in several benchmarks.
        for line, tokens, _ in self._under(system, "login"):
            if tokens[:1] == ["message"] and len(tokens) > 1:
                ncm.management.banners.login = _unquote(" ".join(tokens[1:]))
                result.record("management.banners.login", line=line)

        idle = self._under(system, "login", "idle-timeout")
        for line, tokens, _ in idle:
            try:
                ncm.management.session.exec_timeout_s = int(tokens[0]) * 60
                result.record("management.session.exec_timeout_s", line=line)
            except (ValueError, IndexError):
                continue

    def _syslog(self, system: list[tuple[int, list[str], bool]], result: ParseResult) -> None:
        ncm = result.ncm
        seen: set[str] = set()

        for line, tokens, _ in self._under(system, "syslog", "host"):
            host = _unquote(tokens[0])
            if not host or host in seen:
                continue
            seen.add(host)
            ncm.logging.syslog_servers.append(SyslogServer(host=host))
            result.record(f"logging.syslog_servers.{len(ncm.logging.syslog_servers) - 1}", line=line)

    def _time_and_aaa(
        self, system: list[tuple[int, list[str], bool]], result: ParseResult
    ) -> None:
        ncm = result.ncm

        seen_ntp: set[str] = set()
        for line, tokens, _ in self._under(system, "ntp", "server"):
            host = tokens[0]
            if host in seen_ntp:
                continue
            seen_ntp.add(host)
            ncm.ntp.servers.append(NtpServer(host=host, prefer="prefer" in tokens))
            result.record(f"ntp.servers.{len(ncm.ntp.servers) - 1}", line=line)

        for kind, prefix in (("radius", "radius-server"), ("tacacs", "tacplus-server")):
            seen: set[str] = set()
            for line, tokens, _ in self._under(system, prefix):
                host = tokens[0]
                if host in seen:
                    continue
                seen.add(host)
                # The secret is never stored — only that one is set. Junos writes it as
                # `secret "$9$…"`, an encrypted form that is reversible.
                has_secret = any(
                    t[:1] == ["secret"] for _, t, _ in self._under(system, prefix, host)
                )
                ncm.aaa.servers.append(
                    AaaServer(type=kind, host=host, key_configured=has_secret or None)
                )
                result.record(f"aaa.servers.{len(ncm.aaa.servers) - 1}", line=line)

        if ncm.aaa.servers:
            ncm.aaa.new_model = True

        # `authentication-order` is Junos's method list, and whether `password` appears
        # after the server is exactly the local-fallback question.
        for line, tokens, _ in self._under(system, "authentication-order"):
            order = _values(tokens)
            ncm.aaa.local_fallback = "password" in order
            result.record("aaa.local_fallback", line=line)

    # ─────────────────────────── interfaces ─────────────────────────────

    def _interfaces(
        self, statements: list[tuple[int, list[str], bool]], result: ParseResult
    ) -> None:
        ncm = result.ncm
        found: dict[str, Interface] = {}
        lines: dict[str, int] = {}

        for line, tokens, inactive in self._under(statements, "interfaces"):
            name = tokens[0]
            if name.startswith("<"):
                continue

            # A logical unit is its own interface everywhere else in this product —
            # `ge-0/0/0.0` is what a zone binds and what a route egresses.
            unit = None
            if tokens[1:2] == ["unit"] and len(tokens) > 2:
                unit = tokens[2]
            key = f"{name}.{unit}" if unit is not None else name

            interface = found.setdefault(key, Interface(name=key))
            lines.setdefault(key, line)

            if inactive:
                interface.admin_up = False
            if tokens[-1:] == ["disable"]:
                interface.admin_up = False
            elif interface.admin_up is None:
                interface.admin_up = True

            if "description" in tokens:
                index = tokens.index("description")
                if len(tokens) > index + 1:
                    interface.description = _unquote(" ".join(tokens[index + 1 :]))

            if "address" in tokens:
                index = tokens.index("address")
                if len(tokens) > index + 1 and _ADDRESS.match(tokens[index + 1]):
                    interface.ip_addresses.append(tokens[index + 1])

            if name in {"fxp0", "em0", "me0"}:
                # Junos's out-of-band management ports, by convention on every platform
                # that has one. Flagged so the "is management separated" checks see it.
                interface.is_management = True

        for key, interface in found.items():
            ncm.interfaces.append(interface)
            result.record(f"interfaces.{len(ncm.interfaces) - 1}", line=lines.get(key))

    # ──────────────────────────── routing ───────────────────────────────

    def _routing(self, statements: list[tuple[int, list[str], bool]], result: ParseResult) -> None:
        ncm = result.ncm

        for line, tokens, _ in self._under(statements, "routing-options", "static", "route"):
            destination = tokens[0]
            next_hop = None
            if "next-hop" in tokens:
                index = tokens.index("next-hop")
                if len(tokens) > index + 1:
                    next_hop = tokens[index + 1]
            discard = "discard" in tokens or "reject" in tokens
            if next_hop is None and not discard:
                continue

            ncm.routing.routes.append(
                Route(
                    destination=destination,
                    next_hop=next_hop,
                    protocol="static",
                    interface="discard" if discard and next_hop is None else None,
                )
            )
            result.record(f"routing.routes.{len(ncm.routing.routes) - 1}", line=line)

        ncm.routing.static_routes = len(ncm.routing.routes)

    # ───────────────────────────── snmp ─────────────────────────────────

    def _snmp(self, statements: list[tuple[int, list[str], bool]], result: ParseResult) -> None:
        ncm = result.ncm
        seen: set[str] = set()

        for line, tokens, _ in self._under(statements, "snmp", "community"):
            name = _unquote(tokens[0])
            if not name or name in seen:
                continue
            seen.add(name)

            # `authorization read-write` is the finding; Junos defaults to read-only
            # when the statement is absent, so absence here is a real answer.
            authorisation = [t for _, t, _ in self._under(statements, "snmp", "community", name)]
            rw = any(t[:2] == ["authorization", "read-write"] for t in authorisation)

            ncm.snmp.v1v2c_communities.append(
                SnmpCommunity(
                    name_masked=mask_secret(name),
                    is_default=is_default_community(name),
                    rw=rw,
                )
            )
            result.record(f"snmp.v1v2c_communities.{len(ncm.snmp.v1v2c_communities) - 1}", line=line)

    # ──────────────────────────── security ──────────────────────────────

    def _security(self, statements: list[tuple[int, list[str], bool]], result: ParseResult) -> None:
        """The SRX hierarchy. Absent on an MX or EX, which is not an error."""
        ncm = result.ncm

        for _, tokens, _ in self._under(statements, "security", "zones", "security-zone"):
            zone = tokens[0]
            if zone not in ncm.firewall.zones:
                ncm.firewall.zones.append(zone)

        self._address_book(statements, result)
        self._policies(statements, result)

    def _address_book(
        self, statements: list[tuple[int, list[str], bool]], result: ParseResult
    ) -> None:
        """`security address-book` — the objects policies match on.

        **Not optional, and `test_silent_emptiness` proved it.** A policy matching
        `destination-address dmz-web` resolves that name against the address objects;
        with none parsed it resolves to the empty set, and a rule whose destination is
        empty can never match a packet. Nothing errors and nothing is logged — the rule
        is simply skipped every time, so the rulebase silently behaves as though the
        entry were absent. That is the exact defect the sweep exists to catch, and it
        caught this parser's first draft.

        Both placements are read. Junos 12.1 and later put the book at
        `security address-book <book> address <name> <value>`; older SRX configurations
        put it per zone at `security zones security-zone <zone> address-book address …`,
        and plenty of live configurations still carry the old form.
        """
        ncm = result.ncm
        seen: set[str] = set()

        def add(name: str, value: str | None, members: list[str], line: int) -> None:
            if name in seen:
                return
            seen.add(name)
            target = ncm.firewall.address_groups if members else ncm.firewall.address_objects
            target.append(
                NetworkObject(name=name, type="address", value=value, members=members)
            )
            index = len(target) - 1
            key = "address_groups" if members else "address_objects"
            result.record(f"firewall.{key}.{index}", line=line)

        for prefix in (
            ("security", "address-book"),
            ("security", "zones", "security-zone"),
        ):
            for line, tokens, _ in self._under(statements, *prefix):
                # `<book> address <name> <value>` or `<zone> address-book address <name> <value>`
                try:
                    marker = tokens.index("address-book") if "address-book" in tokens else -1
                    rest = tokens[marker + 1 :] if marker >= 0 else tokens[1:]
                except ValueError:  # pragma: no cover - defensive
                    continue

                if rest[:1] == ["address"] and len(rest) >= 3:
                    add(rest[1], rest[2], [], line)
                elif rest[:1] == ["address-set"] and len(rest) >= 4 and rest[2] == "address":
                    # `address-set web-servers address dmz-web` — one member per line,
                    # so the set is accumulated rather than replaced.
                    existing = next(
                        (g for g in ncm.firewall.address_groups if g.name == rest[1]), None
                    )
                    if existing is None:
                        add(rest[1], None, [rest[3]], line)
                    elif rest[3] not in existing.members:
                        existing.members.append(rest[3])

    @staticmethod
    def _apply_policy_tail(rule: SecurityRule, tail: list[str], inactive: bool) -> None:
        """Apply one `match ...` or `then ...` fragment of a policy to its rule."""
        if tail[:1] == ["match"] and len(tail) > 2:
            field, values = tail[1], _values(tail[2:])
            if field == "source-address":
                rule.src.extend(values)
            elif field == "destination-address":
                rule.dst.extend(values)
            elif field == "application":
                rule.applications.extend(values)
        elif tail[:1] == ["then"] and len(tail) > 1:
            action = tail[1]
            if action in {"permit", "deny", "reject"}:
                rule.action = "allow" if action == "permit" else action
            elif action == "log":
                rule.log_start = "session-init" in tail
                rule.log_end = "session-close" in tail
        if inactive:
            rule.enabled = False

    def _policies(self, statements: list[tuple[int, list[str], bool]], result: ParseResult) -> None:
        ncm = result.ncm
        rules: dict[tuple[str, str, str], SecurityRule] = {}
        global_rules: dict[str, SecurityRule] = {}
        lines: dict[object, int] = {}
        default_action: str | None = None
        default_line: int | None = None

        for line, tokens, inactive in self._under(statements, "security", "policies"):
            # `from-zone trust to-zone untrust policy allow-web match source-address any`
            if (
                tokens[:1] == ["from-zone"]
                and len(tokens) >= 6
                and tokens[2] == "to-zone"
                and tokens[4] == "policy"
            ):
                src_zone, dst_zone, name = tokens[1], tokens[3], tokens[5]
                key = (src_zone, dst_zone, name)
                rule = rules.get(key)
                if rule is None:
                    rule = SecurityRule(
                        order=len(rules) + 1,
                        name=name,
                        rulebase=f"{src_zone}->{dst_zone}",
                        src_zones=[src_zone],
                        dst_zones=[dst_zone],
                        # Junos has no implicit permit: a policy with no `then` is not a
                        # permit, so the default here is the safe one and is overwritten
                        # only by an explicit action below.
                        action="deny",
                        enabled=not inactive,
                    )
                    rules[key] = rule
                    lines[key] = line
                self._apply_policy_tail(rule, tokens[6:], inactive)

            # `global policy allow-any match ... then permit` — applies to any zone pair
            # and is evaluated after the zone-specific rulebases. Empty src/dst zones mean
            # "any zone" to the matcher (firewall/analysis.py:559), which is the semantics.
            elif tokens[:1] == ["global"] and len(tokens) >= 3 and tokens[1] == "policy":
                name = tokens[2]
                rule = global_rules.get(name)
                if rule is None:
                    rule = SecurityRule(
                        order=0,  # assigned below, after the zone-pair rules
                        name=name,
                        rulebase="global",
                        src_zones=[],
                        dst_zones=[],
                        action="deny",
                        enabled=not inactive,
                    )
                    global_rules[name] = rule
                    lines[("global", name)] = line
                self._apply_policy_tail(rule, tokens[3:], inactive)

            # `default-policy permit-all` / `default-policy deny-all` — the device-wide
            # action when nothing else matches. Dropping it made a `permit-all` default
            # read as an implicit deny, so a query over otherwise-unmatched traffic
            # returned a false `blocked` (audit CRITICAL).
            elif tokens[:1] == ["default-policy"] and len(tokens) >= 2:
                default_action = tokens[1]
                default_line = line

        order = 0

        def _emit(rule: SecurityRule, at: int | None) -> None:
            nonlocal order
            order += 1
            rule.order = order
            ncm.firewall.security_rules.append(rule)
            result.record(
                f"firewall.security_rules.{len(ncm.firewall.security_rules) - 1}",
                line=at,
            )

        # Zone-specific first, then global, then the device default — Junos evaluation
        # order, which is what a first-match connectivity walk depends on.
        for key, rule in rules.items():
            _emit(rule, lines.get(key))
        for gname, rule in global_rules.items():
            _emit(rule, lines.get(("global", gname)))
        if default_action is not None:
            _emit(
                SecurityRule(
                    order=0,
                    name="default-policy",
                    rulebase="default",
                    src_zones=[],
                    dst_zones=[],
                    src=["any"],
                    dst=["any"],
                    applications=["any"],
                    action="allow" if default_action == "permit-all" else "deny",
                    enabled=True,
                ),
                default_line,
            )

    # ──────────────────────────── version ───────────────────────────────

    def _version(self, result: ParseResult) -> None:
        """Junos version, model and serial from `show version` and `show chassis hardware`.

        Not in the configuration on any Junos platform, and without it no CVE can be
        matched (FR-VUL-01) — which is exactly what the supporting-artefact path exists
        to carry.
        """
        ncm = result.ncm

        if output := result.context.artifact("show version"):
            if match := re.search(r"^Junos:\s*(\S+)", output, re.MULTILINE):
                ncm.device.version = match.group(1)
            elif match := re.search(r"JUNOS Software Release \[([^\]]+)\]", output):
                ncm.device.version = match.group(1)
            if match := re.search(r"^Model:\s*(\S+)", output, re.MULTILINE):
                ncm.device.model = match.group(1)

        if output := result.context.artifact("show chassis hardware"):
            # `Chassis   JN123456AB   SRX345` — the chassis line carries the serial the
            # vendor's own support portal asks for.
            if match := re.search(r"^Chassis\s+(\S+)\s+(\S+)", output, re.MULTILINE):
                serial = match.group(1)
                if serial not in ncm.device.serials:
                    ncm.device.serials.append(serial)
                ncm.device.model = ncm.device.model or match.group(2)


__all__ = ["JunosParser", "to_set_statements"]
