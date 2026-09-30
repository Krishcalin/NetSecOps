"""VMware NSX-T distributed firewall, from the Policy API (SRS §1.3).

**Read from an export, not from a live collection.** NSX has a parser and deliberately
no collection profile: the Policy API needs a credential and a pagination-aware
transport that this product does not have yet, and a parser wired to a collector that
does not exist is the capability-with-no-surface pattern. What it has instead is
FR-COL-11 — somebody exports the JSON and uploads it — which is how an air-gapped or
read-restricted environment was always going to read NSX anyway.

The bundle is keyed by endpoint, the way the FMC and Barracuda bundles are.

**The distributed firewall is not an ordered list, it is a tree**, and that is the thing
most likely to be flattened wrongly. A security policy holds rules and carries its own
`sequence_number`; the rules carry theirs within it. Evaluation order is policy sequence
first, then rule sequence — so sorting rules by their own number alone interleaves rules
from different policies and produces a precedence analysis about a rulebase that does not
exist.

**`ANY` is spelled several ways and one of them is an empty list.** NSX writes
`["ANY"]` for a wide match and omits or empties the field in some exports. Both mean
every address, and an empty list read literally is a rule that can never match.

**A group is a path, not a name.** `source_groups` holds
`/infra/domains/default/groups/web-servers`, and the object catalogue is keyed on the
last segment. Compared unstripped, every rule's members resolve to nothing.
"""

from __future__ import annotations

import json
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.ncm.models import NetworkObject, NormalisedConfig, SecurityRule
from netsecops.parsers.base import ConfigParser, ParseContext, ParseResult

log = get_logger(__name__)

#: NSX rule actions, mapped to the NCM's vocabulary. `JUMP_TO_APPLICATION` hands the
#: packet to the application-tier section and decides nothing itself — the same
#: non-terminating shape as Firepower's MONITOR, and carried through as `monitor` so
#: `ResolvedRule.terminates` keeps it out of the shadowing analysis.
_ACTIONS: dict[str, str] = {
    "ALLOW": "allow",
    "DROP": "deny",
    "REJECT": "reject",
    "JUMP_TO_APPLICATION": "monitor",
}

#: Every spelling NSX uses for "match everything".
_ANY = frozenset({"ANY", "any", "*"})


def _results(payload: Any) -> list[dict[str, Any]]:
    """The objects in a Policy API response.

    NSX wraps a collection in `{"results": [...], "result_count": N}` and returns a bare
    object for a single fetch.
    """
    if isinstance(payload, dict):
        if isinstance(payload.get("results"), list):
            return [item for item in payload["results"] if isinstance(item, dict)]
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _leaf(path: str) -> str:
    """The object name at the end of a policy path.

    `/infra/domains/default/groups/web-servers` is how a rule refers to a group, and
    `web-servers` is how the group is catalogued. Compared unstripped every member
    resolves to nothing and the rule reads as matching no address at all.
    """
    return path.rstrip("/").rsplit("/", 1)[-1] if "/" in path else path


def _members(field: Any) -> list[str]:
    """A rule's match members, with every spelling of `any` normalised.

    An empty list is `any` here and not `nothing`: NSX omits or empties a field on a
    wide match, and a rule whose source is the empty set can never match a packet.
    """
    if not isinstance(field, list) or not field:
        return ["any"]
    found = [_leaf(str(entry)) for entry in field if entry]
    if not found or any(entry in _ANY for entry in found):
        return ["any"]
    return found


class VmwareNsxParser(ConfigParser):
    vendor = "vmware"
    platform = "vmware_nsx"

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

        for handler in (self._version, self._groups, self._services, self._policies):
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

    # ─────────────────────────── the manager ────────────────────────────

    def _version(self, bundle: dict[str, Any], result: ParseResult) -> None:
        for endpoint, payload in bundle.items():
            if "node/version" not in endpoint:
                continue
            for item in _results(payload):
                if version := item.get("product_version") or item.get("node_version"):
                    result.ncm.device.version = str(version)
                if name := item.get("product_name"):
                    result.ncm.device.model = str(name)

    # ──────────────────────────── objects ───────────────────────────────

    def _groups(self, bundle: dict[str, Any], result: ParseResult) -> None:
        """Groups, which is what an NSX rule matches on rather than addresses.

        A group's membership can be static (`IPAddressExpression`) or dynamic (a tag
        query). **The dynamic ones are recorded with no members on purpose**: their
        membership is computed by the manager from live VM state and is not in the
        configuration, so inventing an empty set would report a rule matching nothing
        when it may match hundreds of workloads. `type` says which kind it is so a
        reader can tell "no members" from "membership not knowable from a config".
        """
        ncm = result.ncm
        for endpoint, payload in bundle.items():
            if "/groups" not in endpoint:
                continue
            for item in _results(payload):
                name = item.get("display_name") or item.get("id")
                if not name:
                    continue

                members: list[str] = []
                dynamic = False
                for expression in item.get("expression") or []:
                    if not isinstance(expression, dict):
                        continue
                    kind = expression.get("resource_type")
                    if kind == "IPAddressExpression":
                        members += [str(v) for v in expression.get("ip_addresses") or []]
                    elif kind == "PathExpression":
                        members += [_leaf(str(v)) for v in expression.get("paths") or []]
                    elif kind in {"Condition", "NestedExpression"}:
                        dynamic = True

                ncm.firewall.address_groups.append(
                    NetworkObject(
                        name=str(name),
                        # Any dynamic condition makes the group externally resolved — its
                        # real membership is whatever currently carries the tag, which is
                        # not in the export. A group that ALSO lists static members is
                        # still dynamic: typing it a plain 'group' made the static members
                        # look like the complete set, so a rule using it resolved to just
                        # those and silently excluded everything the tag matches
                        # (invariant 2). Only a purely static group is 'group'.
                        type="dynamic-group" if dynamic else "group",
                        members=members,
                    )
                )

    def _services(self, bundle: dict[str, Any], result: ParseResult) -> None:
        ncm = result.ncm
        for endpoint, payload in bundle.items():
            if "/services" not in endpoint:
                continue
            for item in _results(payload):
                name = item.get("display_name") or item.get("id")
                if not name:
                    continue
                ports: list[str] = []
                for entry in item.get("service_entries") or []:
                    if not isinstance(entry, dict):
                        continue
                    protocol = entry.get("l4_protocol") or entry.get("protocol") or ""
                    for port in entry.get("destination_ports") or []:
                        ports.append(f"{protocol}/{port}".strip("/"))
                ncm.firewall.service_objects.append(
                    NetworkObject(
                        name=str(name),
                        type="service",
                        value=ports[0] if len(ports) == 1 else None,
                        members=ports if len(ports) > 1 else [],
                    )
                )

    # ───────────────────────────── rules ────────────────────────────────

    def _policies(self, bundle: dict[str, Any], result: ParseResult) -> None:
        """Security policies and their rules, in evaluation order.

        **Order is policy sequence first, then rule sequence.** The distributed firewall
        is a tree and the analysis needs a list; flattening it by rule number alone
        interleaves rules from different policies and produces a precedence analysis
        about a rulebase that does not exist.
        """
        ncm = result.ncm
        policies: list[dict[str, Any]] = []

        for endpoint, payload in bundle.items():
            if "security-policies" not in endpoint:
                continue
            policies.extend(_results(payload))

        # `sequence_number` is the manager's own ordering. A policy without one sorts
        # last rather than first: NSX defaults it high, and guessing zero would promote
        # an unordered policy above every deliberate one.
        policies.sort(key=lambda p: (int(p.get("sequence_number") or 1_000_000), str(p.get("id"))))

        order = 0
        for policy in policies:
            name = str(policy.get("display_name") or policy.get("id") or "")
            rules = [r for r in policy.get("rules") or [] if isinstance(r, dict)]
            rules.sort(key=lambda r: int(r.get("sequence_number") or 0))

            for raw in rules:
                order += 1
                action = _ACTIONS.get(str(raw.get("action") or "").upper())
                if action is None:
                    action = str(raw.get("action") or "deny").lower()

                ncm.firewall.security_rules.append(
                    SecurityRule(
                        order=order,
                        name=str(raw.get("display_name") or raw.get("id") or ""),
                        # The policy is the rulebase: two policies are separate ordered
                        # sections and the shadowing analysis must not compare across
                        # them any more than it compares two ASA access lists.
                        rulebase=name,
                        # NSX disables a rule with `disabled: true`, so absence is
                        # enabled rather than unknown.
                        enabled=not bool(raw.get("disabled", False)),
                        src=_members(raw.get("source_groups")),
                        dst=_members(raw.get("destination_groups")),
                        services=_members(raw.get("services")),
                        # `scope` is where the rule is applied — a group of workloads,
                        # or DFW-wide. It is the nearest thing NSX has to a zone.
                        src_zones=_members(raw.get("scope")),
                        src_negate=bool(raw.get("sources_excluded", False)),
                        dst_negate=bool(raw.get("destinations_excluded", False)),
                        action=action,
                        log_end=raw.get("logged"),
                        profiles=(
                            {"direction": str(raw["direction"])} if raw.get("direction") else {}
                        ),
                    )
                )

        ncm.firewall.zones = sorted(
            {zone for rule in ncm.firewall.security_rules for zone in rule.src_zones}
            - {"any"}
        )

    # ─────────────────────────── bookkeeping ────────────────────────────

    def _account_for_endpoints(self, bundle: dict[str, Any], result: ParseResult) -> None:
        known = ("security-policies", "/groups", "/services", "node/version")
        result.ncm.raw_unparsed = [
            f"1: no rule reads the response to '{endpoint}'"
            for endpoint in sorted(bundle)
            if not any(marker in endpoint for marker in known)
        ]
        result.consume(1, max(1, len(result.context.lines)))


__all__ = ["VmwareNsxParser"]
