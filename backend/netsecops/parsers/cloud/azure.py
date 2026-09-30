"""Azure network security groups, from an export (SRS §1.3).

Same position as AWS: read from an export, no live collector yet, and here because a
path query that crosses from a data centre into a virtual network is the query nothing
else in the estate can answer. See `docs/algosec-parity.md` for the boundary against
OverWatch.

`az network nsg list -o json` produces the input.

**An NSG is ordered, unlike an AWS security group, and that changes everything.** Rules
carry a `priority` from 100 to 4096, lowest first, and the first match wins. So:

* precedence is real here, and the shadowing analysis is meaningful — rules are sorted
  by priority before they are emitted, because the analysis is a statement about
  evaluation order and feeding it the JSON's arbitrary order would produce confident
  nonsense;
* `direction` splits the rulebase in two. Inbound and outbound rules are evaluated
  independently, so an inbound rule cannot shadow an outbound one and they carry
  different `rulebase` values;
* **every NSG has invisible default rules.** `AllowVnetInBound`, `AllowAzureLoadBalancerInBound`
  and `DenyAllInBound` sit at priorities 65000-65500 and do not appear in
  `securityRules` — they are in `defaultSecurityRules`, which most exports include and
  some omit. Without the final `DenyAllInBound`, an NSG reads as having no catch-all,
  and every permissiveness check that looks for one reports a finding that is not true.

**`*` is Azure's `any`, and so is `Internet`, and they are not the same thing.** `*`
matches every address; `Internet` is a service tag meaning everything outside the
virtual network. Both are wide, only one is unbounded, and flattening them together
loses the distinction that matters when reading an inbound rule.

**A rule may carry singular or plural fields.** `sourceAddressPrefix` and
`sourceAddressPrefixes` both exist and Azure populates exactly one. A reader that checks
only the singular form drops every multi-prefix rule — silently, because the field is
simply absent rather than empty.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.ncm.models import NetworkObject, NormalisedConfig, SecurityRule
from netsecops.parsers.base import ConfigParser, ParseContext, ParseResult

log = get_logger(__name__)

#: Azure's wildcard. `Internet` is deliberately *not* here — it is a service tag with a
#: narrower meaning, and collapsing the two loses the difference between "anywhere" and
#: "anywhere outside this virtual network".
_ANY = frozenset({"*"})


def _is_address_literal(member: str) -> bool:
    """Whether a rule member is a CIDR or bare address rather than a service tag.

    A dot is not proof: regional service tags (Storage.EastUS, Sql.WestEurope) all carry
    one. Only a value that actually parses as an IP address or network is a literal.
    """
    try:
        ipaddress.ip_network(member, strict=False)
    except ValueError:
        return False
    return True


def _payload(bundle: Any) -> list[dict[str, Any]]:
    """The NSGs in an export, whatever it was wrapped in.

    `az network nsg list` emits a bare list; the ARM REST API wraps it in `{"value": []}`;
    a hand-made bundle keys it by command. All three appear in practice.
    """
    if isinstance(bundle, list):
        return [item for item in bundle if isinstance(item, dict)]
    if not isinstance(bundle, dict):
        return []
    if isinstance(bundle.get("value"), list):
        return [item for item in bundle["value"] if isinstance(item, dict)]

    found: list[dict[str, Any]] = []
    for value in bundle.values():
        found.extend(_payload(value))
    return found


def _members(properties: dict[str, Any], singular: str, plural: str) -> list[str]:
    """One of Azure's paired singular/plural fields.

    Exactly one is populated and the other is absent, so a reader that checks only the
    singular drops every multi-prefix rule without any sign that it did.
    """
    values = properties.get(plural)
    if isinstance(values, list) and values:
        found = [str(v) for v in values if v]
    else:
        single = properties.get(singular)
        found = [str(single)] if single else []

    if not found:
        return ["any"]
    return ["any" if value in _ANY else value for value in found]


def _services(properties: dict[str, Any]) -> list[str]:
    protocol = str(properties.get("protocol") or "*").lower()
    protocol = "any" if protocol in {"*", ""} else protocol

    ports = properties.get("destinationPortRanges")
    if isinstance(ports, list) and ports:
        values = [str(p) for p in ports if p]
    else:
        single = properties.get("destinationPortRange")
        values = [str(single)] if single else []

    if not values:
        return ["any"]
    return [
        "any" if port in {"*", "0-65535"} else (f"{protocol}/{port}" if protocol != "any" else port)
        for port in values
    ]


class AzureNsgParser(ConfigParser):
    vendor = "azure"
    platform = "azure_nsg"

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        result.ncm.device.vendor = self.vendor
        result.ncm.device.platform = self.platform

        try:
            bundle = json.loads(context.text) if context.text.strip() else None
        except ValueError as exc:
            log.warning("parser.json_invalid", platform=self.platform, error=str(exc))
            result.ncm.raw_unparsed = [f"1: the collected artefact is not valid JSON: {exc}"]
            result.ncm.parse_failed = True
            return result.ncm

        groups = _payload(bundle)
        if not groups:
            result.ncm.raw_unparsed = [
                "1: no network security groups were found in the export — expected the "
                "output of `az network nsg list`"
            ]
            result.ncm.parse_failed = True
            return result.ncm

        self._groups(groups, result)
        result.consume(1, max(1, len(result.context.lines)))
        return result.ncm

    def _groups(self, groups: list[dict[str, Any]], result: ParseResult) -> None:
        ncm = result.ncm
        order = 0
        names: set[str] = set()

        for group in groups:
            nsg = str(group.get("name") or "")
            names.add(nsg)
            properties = group.get("properties")
            properties = properties if isinstance(properties, dict) else group

            # The defaults are part of the policy and most exports carry them. Included
            # because the last of them is `DenyAllInBound`, and an NSG read without it
            # appears to have no catch-all — which every permissiveness check looks for.
            rules = [
                *(properties.get("securityRules") or []),
                *(properties.get("defaultSecurityRules") or []),
            ]

            # Sorted by priority, per direction. The analysis is a statement about
            # evaluation order, and the JSON's order is whatever ARM felt like.
            ordered = sorted(
                (r for r in rules if isinstance(r, dict)),
                key=lambda r: int(
                    (r.get("properties") or r).get("priority") or 65_535
                ),
            )

            for raw in ordered:
                rule_properties = raw.get("properties")
                rule_properties = rule_properties if isinstance(rule_properties, dict) else raw

                direction = str(rule_properties.get("direction") or "Inbound").lower()
                access = str(rule_properties.get("access") or "Deny").lower()
                order += 1

                ncm.firewall.security_rules.append(
                    SecurityRule(
                        order=order,
                        name=str(raw.get("name") or ""),
                        # Inbound and outbound are evaluated independently, so an
                        # inbound rule cannot shadow an outbound one. Separate
                        # rulebases is what stops the analysis claiming it can.
                        rulebase=f"{nsg}/{direction}",
                        src=_members(
                            rule_properties, "sourceAddressPrefix", "sourceAddressPrefixes"
                        ),
                        dst=_members(
                            rule_properties,
                            "destinationAddressPrefix",
                            "destinationAddressPrefixes",
                        ),
                        services=_services(rule_properties),
                        action="allow" if access == "allow" else "deny",
                        profiles={
                            "direction": direction,
                            "priority": str(rule_properties.get("priority") or ""),
                            "nsg": nsg,
                        },
                    )
                )
                result.ncm.provenance.record(
                    f"firewall.security_rules.{len(ncm.firewall.security_rules) - 1}",
                    result.context.provenance(1, 1),
                )

        self._service_tags(result)
        ncm.firewall.zones = sorted(names)
        ncm.device.model = "Network security groups"

    @staticmethod
    def _service_tags(result: ParseResult) -> None:
        """Register the service tags the rules referred to.

        `Internet`, `VirtualNetwork`, `AzureLoadBalancer` and the rest are names for
        address ranges **Microsoft publishes and changes**, and they are not in an NSG
        export. Left as bare strings a rule naming one resolves to nothing and reads as
        matching no traffic, which on an inbound allow is the opposite of the truth.

        Recorded as objects typed `service-tag` so the difference is legible: not "the
        parser could not read this", but "this stands for a set defined elsewhere".
        """
        ncm = result.ncm
        known = {o.name for o in ncm.firewall.address_objects}

        for rule in ncm.firewall.security_rules:
            for member in (*rule.src, *rule.dst):
                if member == "any" or member in known:
                    continue
                # Anything that is not an address literal is a tag. A dot or colon is not
                # proof of an address: regional service tags always carry a dot
                # (Storage.EastUS, Sql.WestEurope, AzureCloud.westus2). Only something
                # that actually parses as an address or network is a literal; everything
                # else stands for a set Microsoft defines elsewhere and is typed a tag,
                # rather than falling to the unresolved/MISSING bucket as a fake gap.
                if _is_address_literal(member):
                    continue
                known.add(member)
                ncm.firewall.address_objects.append(
                    NetworkObject(name=member, type="service-tag", value=None)
                )


__all__ = ["AzureNsgParser"]
