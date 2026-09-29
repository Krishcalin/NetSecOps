"""Cisco Firepower via the FMC REST API (SRS §1.3, FR-PARSE-01 … FR-PARSE-05).

FMC has had a read-only allow-list since the device families were scoped and no profile
and no parser. Unlike Alteon and Barracuda the blocker was never evidence — the endpoint
list has been in SRS §8.2 all along — it was simply unbuilt.

**The input is a bundle keyed by endpoint**, the way the Check Point management parser is
keyed by command: a Firepower policy needs the access policy, its rules and the object
catalogue, and none of them is the configuration on its own.

Three things about the API decided the shape of the code.

**`MONITOR` is not an action, it is the absence of one.** FMC's access rules can be
`ALLOW`, `TRUST`, `BLOCK`, `BLOCK_WITH_RESET`, `MONITOR` and the two interactive block
variants. Every one of them decides what happens to the packet *except* `MONITOR`, which
logs the match and carries on to the next rule. Mapped to allow it makes the rulebase
look permissive; mapped to deny it makes it look restrictive; and mapped to either it
makes a broad monitoring rule shadow everything below it. It is carried through as its
own action and `ResolvedRule.terminates` is what stops the shadowing analysis treating
it as a decision.

**Every match field is `{"objects": [...], "literals": [...]}`.** A rule may name an
address object, an inline address, or both, and a reader that takes only `objects`
silently drops every literal — producing a rule whose source is empty, which can never
match a packet and is the exact defect `test_silent_emptiness` exists to catch.

**An absent match field means `any`.** FMC omits `sourceNetworks` entirely on a rule
that matches every source, so absence is the broadest possible value rather than the
narrowest. Reading it as an empty set turns the most dangerous rule in a policy into one
that appears to match nothing.
"""

from __future__ import annotations

import json
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.ncm.models import (
    NetworkObject,
    NormalisedConfig,
    SecurityRule,
)
from netsecops.parsers.base import ConfigParser, ParseContext, ParseResult

log = get_logger(__name__)

#: FMC's access-rule actions, mapped to the NCM's vocabulary.
#:
#: `TRUST` permits and additionally skips deep inspection, which is a different fact
#: from `ALLOW` and one worth keeping — but for the purpose of "does traffic pass", it
#: passes. `MONITOR` is deliberately not mapped onto either half; see the module note.
_ACTIONS: dict[str, str] = {
    "ALLOW": "allow",
    "TRUST": "allow",
    "BLOCK": "deny",
    "BLOCK_WITH_RESET": "reject",
    "BLOCK_INTERACTIVE": "deny",
    "BLOCK_RESET_INTERACTIVE": "reject",
    "MONITOR": "monitor",
}

#: Endpoints this parser reads. Anything else in the bundle is reported as unread.
_ACCESS_RULES = "/accessrules"


def _items(payload: Any) -> list[dict[str, Any]]:
    """The objects in an FMC response.

    FMC wraps a collection in `{"items": [...], "paging": {...}}` and returns a bare
    object for a single fetch. Both are accepted; a response that is neither yields
    nothing rather than raising.
    """
    if isinstance(payload, dict):
        if isinstance(payload.get("items"), list):
            return [item for item in payload["items"] if isinstance(item, dict)]
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _members(field: Any) -> list[str] | None:
    """A rule's match members, or None where the field was absent.

    **None and `[]` are different answers and the difference is the whole point.** FMC
    omits a match field on a rule that matches everything, so absence is `any` — the
    broadest possible value. An empty list means the field was present and empty, which
    on FMC does not happen but on a malformed capture does, and a rule with an empty
    source can never match a packet.
    """
    if field is None:
        return None
    if not isinstance(field, dict):
        return []

    found: list[str] = []
    for entry in field.get("objects") or []:
        if isinstance(entry, dict) and entry.get("name"):
            found.append(str(entry["name"]))
    # Literals carry the value rather than a name — an address typed into the rule
    # instead of being made an object. Dropping them empties the rule.
    for entry in field.get("literals") or []:
        if isinstance(entry, dict) and entry.get("value"):
            found.append(str(entry["value"]))
    return found


def _match(field: Any) -> list[str]:
    """A match list for the NCM, where absent becomes the literal `any`."""
    members = _members(field)
    return ["any"] if members is None else members


class CiscoFmcParser(ConfigParser):
    vendor = "cisco"
    platform = "cisco_ftd_fmc"

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        result.ncm.device.vendor = self.vendor
        result.ncm.device.platform = self.platform

        try:
            bundle = json.loads(context.text) if context.text.strip() else {}
        except ValueError as exc:
            log.warning("parser.json_invalid", platform=self.platform, error=str(exc))
            result.ncm.raw_unparsed = [f"1: the collected artefact is not valid JSON: {exc}"]
            result.ncm.parse_failed = True
            return result.ncm

        if not isinstance(bundle, dict) or not bundle:
            result.ncm.raw_unparsed = ["1: the collected artefact is not an endpoint bundle"]
            result.ncm.parse_failed = True
            return result.ncm

        for handler in (self._version, self._devices, self._objects, self._rules):
            try:
                handler(bundle, result)
            except Exception as exc:  # pragma: no cover - defensive, per FR-PARSE-03
                log.warning(
                    "parser.section_failed",
                    platform=self.platform,
                    section=handler.__name__,
                    error=str(exc),
                )

        self._account_for_endpoints(bundle, result)
        return result.ncm

    # ───────────────────────── the appliance ────────────────────────────

    def _version(self, bundle: dict[str, Any], result: ParseResult) -> None:
        for endpoint, payload in bundle.items():
            if not endpoint.endswith("/info/serverversion"):
                continue
            for item in _items(payload):
                if version := item.get("serverVersion"):
                    result.ncm.device.version = str(version)
                    result.ncm.provenance.record(
                        "device.version", result.context.provenance(1, 1)
                    )

    def _devices(self, bundle: dict[str, Any], result: ParseResult) -> None:
        """`devicerecords` — the sensors this FMC manages.

        Recorded as the *managed* devices' facts rather than the manager's own: an FMC
        is a management centre, and the model and version that matter for a CVE are the
        sensor's. The first is taken for `device.model` because a single-sensor
        deployment is the common case and a wrong model is worse than none.
        """
        ncm = result.ncm
        for endpoint, payload in bundle.items():
            if not endpoint.endswith("/devices/devicerecords"):
                continue
            for item in _items(payload):
                if serial := item.get("id"):
                    # FMC does not expose a chassis serial over this endpoint; the
                    # device UUID is what it has, and it is what a later fetch keys on.
                    if str(serial) not in ncm.device.serials:
                        ncm.device.serials.append(str(serial))
                if not ncm.device.model and item.get("model"):
                    ncm.device.model = str(item["model"])
                if not ncm.device.hostname and item.get("hostName"):
                    ncm.device.hostname = str(item["hostName"])

    # ──────────────────────────── objects ───────────────────────────────

    def _objects(self, bundle: dict[str, Any], result: ParseResult) -> None:
        """The object catalogue a rule's members resolve against.

        Without it every rule naming an object resolves to the empty set and can never
        match a packet — the defect `test_silent_emptiness` exists to catch, and the one
        the Junos parser shipped with in its first draft.
        """
        ncm = result.ncm
        seen: set[str] = set()

        for endpoint, payload in bundle.items():
            if "/object/" not in endpoint:
                continue
            is_group = endpoint.rstrip("/").endswith(("networkgroups", "portobjectgroups"))

            for item in _items(payload):
                name = item.get("name")
                if not name or name in seen:
                    continue
                seen.add(str(name))

                members = [
                    str(entry["name"])
                    for entry in item.get("objects") or []
                    if isinstance(entry, dict) and entry.get("name")
                ]
                # A group may hold inline values as well as named objects.
                members += [
                    str(entry["value"])
                    for entry in item.get("literals") or []
                    if isinstance(entry, dict) and entry.get("value")
                ]

                value = item.get("value")
                if value is None and item.get("port"):
                    protocol = item.get("protocol") or ""
                    value = f"{protocol}/{item['port']}".strip("/")

                target = ncm.firewall.address_groups if (is_group or members) else (
                    ncm.firewall.service_objects
                    if "port" in endpoint
                    else ncm.firewall.address_objects
                )
                target.append(
                    NetworkObject(
                        name=str(name),
                        type=str(item.get("type") or ""),
                        value=str(value) if value is not None else None,
                        members=members,
                    )
                )

    # ───────────────────────────── rules ────────────────────────────────

    def _rules(self, bundle: dict[str, Any], result: ParseResult) -> None:
        ncm = result.ncm
        order = 0

        for endpoint in sorted(bundle):
            if not endpoint.rstrip("/").endswith(_ACCESS_RULES):
                continue
            # `/policy/accesspolicies/<uuid>/accessrules` — the policy is the rulebase,
            # and entries in different access policies are never applied to the same
            # packet. Carried so the shadowing analysis does not compare across them.
            rulebase = endpoint.rstrip("/").rsplit("/", 2)[-2]

            for item in _items(bundle[endpoint]):
                order += 1
                raw_action = str(item.get("action") or "").upper()
                action = _ACTIONS.get(raw_action)
                if action is None:
                    # An action FMC added after this was written. Recorded verbatim and
                    # lower-cased rather than guessed at: `permits` is False for
                    # anything it does not recognise, which is the safe direction.
                    action = raw_action.lower() or "deny"

                ncm.firewall.security_rules.append(
                    SecurityRule(
                        order=order,
                        name=str(item.get("name") or ""),
                        rulebase=rulebase,
                        # FMC sends `enabled` as a real boolean, so absence is unknown
                        # rather than disabled — and a rule assumed disabled is a rule
                        # the analysis silently stops reporting on.
                        enabled=bool(item.get("enabled", True)),
                        src_zones=_match(item.get("sourceZones")),
                        dst_zones=_match(item.get("destinationZones")),
                        src=_match(item.get("sourceNetworks")),
                        dst=_match(item.get("destinationNetworks")),
                        services=_match(item.get("destinationPorts")),
                        applications=[
                            str(entry["name"])
                            for entry in (item.get("applications") or {}).get("applications")
                            or []
                            if isinstance(entry, dict) and entry.get("name")
                        ],
                        users=[
                            str(entry["name"])
                            for entry in (item.get("users") or {}).get("objects") or []
                            if isinstance(entry, dict) and entry.get("name")
                        ],
                        action=action,
                        log_start=item.get("logBegin"),
                        log_end=item.get("logEnd"),
                        profiles={
                            key: str(value["name"])
                            for key, value in (
                                ("ips", item.get("ipsPolicy")),
                                ("file", item.get("filePolicy")),
                                ("variable_set", item.get("variableSet")),
                            )
                            if isinstance(value, dict) and value.get("name")
                        },
                    )
                )
                result.ncm.provenance.record(
                    f"firewall.security_rules.{len(ncm.firewall.security_rules) - 1}",
                    result.context.provenance(1, 1),
                )

        # Zones are not fetched separately; they are whatever the rules name.
        zones = {
            zone
            for rule in ncm.firewall.security_rules
            for zone in (*rule.src_zones, *rule.dst_zones)
            if zone != "any"
        }
        ncm.firewall.zones = sorted(zones)

    # ─────────────────────────── bookkeeping ────────────────────────────

    def _account_for_endpoints(self, bundle: dict[str, Any], result: ParseResult) -> None:
        """Coverage over a bundle of endpoints.

        Line coverage means nothing for JSON, so the honest measure is which endpoints
        were understood.
        """
        result.ncm.raw_unparsed = [
            f"1: no rule reads the response to '{endpoint}'"
            for endpoint in sorted(bundle)
            if not (
                endpoint.rstrip("/").endswith(_ACCESS_RULES)
                or "/object/" in endpoint
                or endpoint.endswith("/info/serverversion")
                or endpoint.endswith("/devices/devicerecords")
            )
        ]
        result.consume(1, max(1, len(result.context.lines)))


__all__ = ["CiscoFmcParser"]
