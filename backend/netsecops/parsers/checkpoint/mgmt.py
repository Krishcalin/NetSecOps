"""Check Point Management API parser (FR-PARSE-01 … FR-PARSE-05, FR-FW-01).

Check Point is unlike every other platform here: the security policy does not live on
the gateway that enforces it. It lives on a management server, and a gateway holds only
a compiled copy. So the thing worth assessing is read from the Management API, not from
the device — which is why this parser takes JSON rather than configuration text.

**The input is a bundle, not one response.** A collection issues several `show-*` calls
and stores the replies together, keyed by the API command that produced each one:

```json
{"show-access-rulebase": {...}, "show-gateways-and-servers": {...}}
```

Keying by command is what lets a partial collection stay useful: if
`show-gateways-and-servers` failed and `show-access-rulebase` succeeded, the rulebase is
still assessed and only the gateway-derived fields report *Not Evaluated* (FR-COL-08).
A flat merged blob could not express that difference.

Four Check Point shapes that have no equivalent in the other parsers:

**Sections.** A rulebase is a list that mixes `access-rule` entries with
`access-section` entries, and a section contains its own nested list of rules. Sections
are presentation only — the gateway evaluates one flat ordered sequence — so they are
flattened here. Skipping the nested lists would silently drop most of the policy, since
most real rulebases put every rule inside a section.

**Negation.** `source-negate: true` means "anything *except* this source". It is carried
to the NCM as a flag and applied by the resolver, which inverts the address set. Dropping
the flag would make the rule read as its exact opposite.

**`Inner Layer` is not a verdict.** An action of `Inner Layer` delegates the decision to
an ordered sub-policy this response does not contain. Recording it as allow or deny would
both be wrong, so it is kept verbatim; `permits` then reports False, which keeps the rule
out of the permit-only policy findings rather than producing confident nonsense about it.

**The objects dictionary.** Object definitions arrive inline in `objects-dictionary`
rather than needing separate lookups, and the same object may appear in several
responses. They are collected once, de-duplicated by UID.
"""

from __future__ import annotations

import json
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.ncm.models import (
    Interface,
    LocalUser,
    NatRule,
    NetworkObject,
    NormalisedConfig,
    SecurityRule,
)
from netsecops.parsers.base import ConfigParser, ParseContext, ParseResult

log = get_logger(__name__)

#: Actions that let traffic through. Everything else — `Drop`, `Reject`, `Inner Layer`
#: — is either a denial or not a verdict at all, and must not be treated as a permit.
_ACCEPTING_ACTIONS = frozenset({"accept", "allow", "permit"})

#: Check Point's stand-in for "any". `CpmiAnyObject` is the type; `Any` is the name.
_ANY_NAMES = frozenset({"any", "any object"})

#: `track-type` values that mean nothing is recorded.
_NO_TRACK = frozenset({"none", "no log"})


def _as_list(value: Any) -> list[Any]:
    """Check Point returns a bare object where a list of one is expected, and vice
    versa, depending on the call. Normalising here keeps every caller from guessing."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _names(value: Any) -> list[str]:
    """Object references as names, with Check Point's several spellings of `any`."""
    out: list[str] = []
    for item in _as_list(value):
        name = item.get("name") if isinstance(item, dict) else item
        if name is None:
            continue
        text = str(name).strip()
        if not text:
            continue
        out.append("any" if text.lower() in _ANY_NAMES else text)
    return out


def _flag(entry: Any, key: str) -> bool | None:
    """A boolean the API may simply not have sent.

    Absent stays None so the NCM's absent-is-not-false rule holds: a rulebase fetched
    without `details-level: full` omits most flags, and reading those as False would
    report every rule as disabled and unlogged.
    """
    if not isinstance(entry, dict) or key not in entry:
        return None
    return bool(entry[key])


class CheckPointMgmtParser(ConfigParser):
    vendor = "checkpoint"
    platform = "checkpoint_mgmt"

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        result.ncm.device.vendor = self.vendor
        result.ncm.device.platform = self.platform

        try:
            bundle = json.loads(context.text) if context.text.strip() else {}
        except ValueError as exc:
            # A truncated or non-JSON artefact. There is nothing to salvage, but the
            # snapshot survives and every check reports Not Evaluated rather than the
            # device being reported clean.
            log.warning("parser.json_invalid", platform=self.platform, error=str(exc))
            result.ncm.raw_unparsed = [f"1: the collected artefact is not valid JSON: {exc}"]
            return result.ncm

        if not isinstance(bundle, dict):
            result.ncm.raw_unparsed = ["1: the collected artefact is not a command bundle"]
            return result.ncm

        for section in (
            self._parse_gateways,
            self._parse_administrators,
            self._parse_objects,
            self._parse_rulebase,
            self._parse_nat,
        ):
            try:
                section(bundle, result)
            except Exception as exc:
                log.warning(
                    "parser.section_failed",
                    platform=self.platform,
                    section=section.__name__,
                    error=str(exc),
                )

        self._account_for_commands(bundle, result)
        return result.ncm

    # ── bookkeeping ─────────────────────────────────────────────────────

    def _account_for_commands(self, bundle: dict[str, Any], result: ParseResult) -> None:
        """Coverage over a command bundle.

        Line coverage means nothing for JSON, so the honest measure is which *commands*
        in the bundle this parser understood. A response the collector fetched and
        nothing here reads is exactly the gap `raw_unparsed` exists to make visible.
        """
        known = {
            "show-access-rulebase",
            "show-nat-rulebase",
            "show-gateways-and-servers",
            "show-administrators",
            "show-hosts",
            "show-networks",
            "show-address-ranges",
            "show-groups",
            "show-services-tcp",
            "show-services-udp",
            "show-service-groups",
        }
        result.ncm.raw_unparsed = [
            f"1: no rule reads the response to '{command}'"
            for command in sorted(bundle)
            if command not in known
        ]
        result.consume(1, max(1, len(result.context.lines)))

    def _record(self, result: ParseResult, path: str) -> None:
        """Provenance for a JSON bundle.

        There are no meaningful line numbers in a re-serialised API response, so the
        path is what a finding cites. That is more useful here than a line number would
        be: `show-access-rulebase` rule 4 is something an operator can go and look at,
        whereas "line 812 of the JSON" is not.
        """
        result.ncm.provenance.record(path, result.context.provenance(1, 1))

    # ── gateways ────────────────────────────────────────────────────────

    def _parse_gateways(self, bundle: dict[str, Any], result: ParseResult) -> None:
        response = bundle.get("show-gateways-and-servers")
        if not isinstance(response, dict):
            return

        gateways = [
            obj
            for obj in _as_list(response.get("objects"))
            if (isinstance(obj, dict) and "gateway" in str(obj.get("type", "")).lower())
            or (isinstance(obj, dict) and str(obj.get("type", "")).lower() == "simple-gateway")
        ]
        if not gateways:
            return

        # A management server may hold hundreds of gateways. This artefact describes one
        # device, so the first gateway is the subject and the rest are context — the
        # manager child-enumeration path is what turns the others into their own devices.
        gateway = gateways[0]
        device = result.ncm.device
        device.hostname = str(gateway.get("name") or "") or None
        device.model = str(gateway.get("hardware") or "") or None
        device.version = str(gateway.get("version") or "") or None
        self._record(result, "device.hostname")

        for interface in _as_list(gateway.get("interfaces")):
            if not isinstance(interface, dict):
                continue
            ipv4 = interface.get("ipv4-address")
            result.ncm.interfaces.append(
                Interface(
                    name=str(interface.get("name") or ""),
                    ip_addresses=[str(ipv4)] if ipv4 else [],
                    description=str(interface.get("comments") or "") or None,
                )
            )

        blades = gateway.get("network-security-blades")
        if isinstance(blades, dict):
            # Which blades are on decides which checks are even applicable: a gateway
            # without the IPS blade cannot be faulted for rules that lack an IPS profile.
            result.ncm.firewall.profiles = {
                str(name): bool(enabled) for name, enabled in blades.items()
            }
            self._record(result, "firewall.profiles")

    # ── administrators ──────────────────────────────────────────────────

    def _parse_administrators(self, bundle: dict[str, Any], result: ParseResult) -> None:
        response = bundle.get("show-administrators")
        if not isinstance(response, dict):
            return

        for admin in _as_list(response.get("objects")):
            if not isinstance(admin, dict):
                continue
            permissions = admin.get("permissions-profile")
            role = None
            if isinstance(permissions, dict):
                role = str(permissions.get("name") or "") or None
            elif permissions:
                role = str(permissions)

            result.ncm.users.append(
                LocalUser(
                    name=str(admin.get("name") or ""),
                    role=role,
                    # Check Point's super-user profile is named "Super User"; mapping it
                    # to 15 lets the vendor-neutral privilege checks apply unchanged.
                    privilege=15
                    if role and role.lower() in {"super user", "read write all"}
                    else None,
                    # The API never returns password material, only the method — so
                    # there is nothing here to redact, and nothing to leak.
                    secret_type=str(admin.get("authentication-method") or "") or None,
                )
            )
            self._record(result, f"users.{len(result.ncm.users) - 1}")

    # ── objects (FR-FW-01) ──────────────────────────────────────────────

    def _parse_objects(self, bundle: dict[str, Any], result: ParseResult) -> None:
        """Collect object definitions from every response that carries them.

        The same object appears in the dictionaries of several responses, so they are
        de-duplicated by UID. Name would be the wrong key: two objects in different
        Check Point domains can share a name.
        """
        seen: set[str] = set()
        firewall = result.ncm.firewall

        def absorb(obj: Any) -> None:
            if not isinstance(obj, dict):
                return
            uid = str(obj.get("uid") or obj.get("name") or "")
            if not uid or uid in seen:
                return
            seen.add(uid)

            name = str(obj.get("name") or "")
            kind = str(obj.get("type") or "").lower()

            if kind == "host":
                value = obj.get("ipv4-address") or obj.get("ipv6-address")
                if value:
                    firewall.address_objects.append(
                        NetworkObject(name=name, type="host", value=str(value))
                    )
            elif kind == "network":
                subnet = obj.get("subnet4") or obj.get("subnet6")
                mask = obj.get("mask-length4", obj.get("mask-length6"))
                if subnet and mask is not None:
                    firewall.address_objects.append(
                        NetworkObject(name=name, type="network", value=f"{subnet}/{mask}")
                    )
            elif kind == "address-range":
                first = obj.get("ipv4-address-first") or obj.get("ipv6-address-first")
                last = obj.get("ipv4-address-last") or obj.get("ipv6-address-last")
                if first and last:
                    firewall.address_objects.append(
                        NetworkObject(name=name, type="range", value=f"{first}-{last}")
                    )
            elif kind == "group":
                firewall.address_groups.append(
                    NetworkObject(name=name, type="group", members=_names(obj.get("members")))
                )
            elif kind in {"service-tcp", "service-udp"}:
                protocol = kind.removeprefix("service-")
                port = obj.get("port")
                if port is not None:
                    # Check Point writes an open-ended range as ">1023"; the interval
                    # parser reads `1024-65535`, and passing the raw form through would
                    # make the service resolve to nothing.
                    firewall.service_objects.append(
                        NetworkObject(name=name, type=protocol, value=f"{protocol}/{_port(port)}")
                    )
            elif kind == "service-group":
                firewall.service_groups.append(
                    NetworkObject(name=name, type="group", members=_names(obj.get("members")))
                )
            elif kind in {"cpmianyobject", "cpmiglobalobject"}:
                # `Any` needs no definition; the resolver knows the name.
                return

        for response in bundle.values():
            if not isinstance(response, dict):
                continue
            for obj in _as_list(response.get("objects-dictionary")):
                absorb(obj)
            # `show-hosts`, `show-networks` and friends return their results in
            # `objects` rather than in a dictionary.
            for obj in _as_list(response.get("objects")):
                absorb(obj)

    # ── the rulebase (FR-FW-01, FR-FW-03) ───────────────────────────────

    def _parse_rulebase(self, bundle: dict[str, Any], result: ParseResult) -> None:
        response = bundle.get("show-access-rulebase")
        if not isinstance(response, dict):
            return

        firewall = result.ncm.firewall
        layer = str(response.get("name") or "") or None
        if layer and layer not in firewall.zones:
            # Check Point has no zones in the Fortinet or PAN-OS sense. The layer is the
            # nearest equivalent — a policy domain whose rules only ever compete with
            # each other — so it is carried as one, which is what keeps rules in
            # different layers from being compared.
            firewall.zones.append(layer)

        for entry in self._flatten(_as_list(response.get("rulebase"))):
            order = len(firewall.security_rules) + 1
            firewall.security_rules.append(self._rule(entry, order, layer))
            self._record(result, f"firewall.security_rules.{order - 1}")

    def _flatten(self, entries: list[Any]) -> list[dict[str, Any]]:
        """Flatten sections into the single ordered sequence the gateway evaluates.

        Sections are a management-console convenience with no effect on matching. A
        parser that read only the top level would miss every rule inside one, which in a
        real rulebase is nearly all of them — and would report a firewall as having four
        rules when it has four hundred.
        """
        flat: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            # Any `*-section`: the access rulebase uses `access-section` and the NAT
            # rulebase `nat-section`. Matching only the former left the NAT section
            # itself recorded as though it were a rule, and every rule inside it lost.
            if str(entry.get("type", "")).lower().endswith("-section"):
                flat.extend(self._flatten(_as_list(entry.get("rulebase"))))
            else:
                flat.append(entry)
        return flat

    def _rule(self, entry: dict[str, Any], order: int, layer: str | None) -> SecurityRule:
        action = entry.get("action")
        action_name = (
            str(action.get("name") or "") if isinstance(action, dict) else str(action or "")
        )

        track = entry.get("track")
        logged: bool | None = None
        if isinstance(track, dict):
            # `track-type` is the tracking mode; `type` is the API's object discriminator
            # and is the literal string "Track" on every rule. Reading `type` first made
            # every rule look logged, so no Check Point gateway would ever have had an
            # unlogged rule reported — the check would have passed universally and
            # silently.
            track_type = track.get("track-type")
            if track_type is None:
                track_type = track.get("type")
            if isinstance(track_type, dict):
                track_type = track_type.get("name")
            if track_type is not None:
                logged = str(track_type).strip().lower() not in _NO_TRACK

        # Check Point names most rules only by their comment, and many not at all. An
        # empty name would make every finding read "rule ()", so the rule number is the
        # fallback — which is also how the console displays it.
        name = str(entry.get("name") or "").strip()
        if not name:
            number = entry.get("rule-number")
            name = f"Rule {number}" if number is not None else f"Rule {order}"

        profiles: dict[str, str] = {}
        inspection = entry.get("inspection-settings") or entry.get("action-settings")
        if isinstance(inspection, dict):
            for key, value in inspection.items():
                if isinstance(value, dict) and value.get("name"):
                    profiles[str(key)] = str(value["name"])
                elif isinstance(value, str) and value:
                    profiles[str(key)] = value

        return SecurityRule(
            order=order,
            name=name,
            # `enabled` absent means the response was not fetched at full detail. True is
            # the safe reading: treating an unknown rule as disabled would drop it from
            # the analysis and hide whatever it shadows.
            enabled=_flag(entry, "enabled") is not False,
            src=_names(entry.get("source")) or ["any"],
            dst=_names(entry.get("destination")) or ["any"],
            src_negate=bool(entry.get("source-negate")),
            dst_negate=bool(entry.get("destination-negate")),
            services=_names(entry.get("service")) or ["any"],
            # Check Point layers are policy domains in the same sense as PAN-OS vsys:
            # rules in different layers never compete, and the analyser uses zones to
            # keep them apart.
            src_zones=[layer] if layer else [],
            dst_zones=[layer] if layer else [],
            users=_names(entry.get("source-user") or entry.get("user-check")),
            # Kept verbatim rather than mapped. `Inner Layer` is neither allow nor deny —
            # it delegates to a sub-policy this response does not contain — and forcing
            # it into one would be a confident guess about traffic nobody assessed.
            action=action_name or "unknown",
            log_end=logged,
            profiles=profiles,
            hit_count=_hits(entry.get("hits")),
            last_hit=_last_hit(entry.get("hits")),
        )

    # ── NAT (FR-FW-04) ──────────────────────────────────────────────────

    def _parse_nat(self, bundle: dict[str, Any], result: ParseResult) -> None:
        response = bundle.get("show-nat-rulebase")
        if not isinstance(response, dict):
            return

        firewall = result.ncm.firewall
        for entry in self._flatten(_as_list(response.get("rulebase"))):
            original = _names(entry.get("original-source")) or ["any"]
            translated_dst = _names(entry.get("translated-destination"))
            firewall.nat_rules.append(
                NatRule(
                    order=len(firewall.nat_rules) + 1,
                    name=str(entry.get("name") or f"NAT {len(firewall.nat_rules) + 1}"),
                    original=", ".join(original),
                    translated=", ".join(
                        translated_dst or _names(entry.get("translated-source")) or ["original"]
                    ),
                    service=", ".join(_names(entry.get("original-service")) or ["any"]),
                    # A translated *destination* is what publishes an internal host to
                    # the outside; a translated source is not (FR-FW-04).
                    direction="destination" if translated_dst else "source",
                )
            )
            self._record(result, f"firewall.nat_rules.{len(firewall.nat_rules) - 1}")


# ────────────────────────────── helpers ─────────────────────────────────────


def _port(port: Any) -> str:
    """Normalise Check Point's port spellings for the interval parser.

    `>1023`, `<1024` and `1024-65535` all appear in real service objects. Passing the
    comparison forms through unchanged would make the service resolve to nothing, and
    the rule using it would silently cover no traffic at all.
    """
    text = str(port).strip()
    if text.startswith(">="):
        return f"{text[2:]}-65535"
    if text.startswith(">"):
        try:
            return f"{int(text[1:]) + 1}-65535"
        except ValueError:
            return text
    if text.startswith("<="):
        return f"0-{text[2:]}"
    if text.startswith("<"):
        try:
            return f"0-{int(text[1:]) - 1}"
        except ValueError:
            return text
    return text


def _hits(hits: Any) -> int | None:
    if not isinstance(hits, dict):
        return None
    value = hits.get("value")
    return int(value) if isinstance(value, int) else None


def _last_hit(hits: Any) -> str | None:
    if not isinstance(hits, dict):
        return None
    last = hits.get("last-date")
    if isinstance(last, dict):
        last = last.get("iso-8601") or last.get("posix")
    return str(last) if last else None


__all__ = ["CheckPointMgmtParser"]
