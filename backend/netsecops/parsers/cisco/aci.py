"""Cisco ACI, from the APIC REST API (SRS §1.3).

Read from an export rather than a live collection, for the reason given in
`policies.py`: the collector needs a credential type this product does not have, and a
parser wired to a collector that does not exist is the capability-with-no-surface
pattern. FR-COL-11 carries it — somebody exports the JSON and uploads it.

**ACI is not a firewall and modelling it as one is the whole difficulty.** There is no
ordered rulebase. The fabric is default-deny between endpoint groups, and connectivity
exists only where a *contract* is consumed by one EPG and provided by another. So the
security question is not "which rule matches first" but "which pairs of EPGs can talk,
and over what".

That is flattened here into `security_rules` deliberately, because every engine in this
product — shadowing, permissiveness, the path walk — reads that shape. Three things
follow from the flattening and each is a way to be wrong:

**Order is meaningless.** ACI evaluates no sequence, so `order` is assignment order and
nothing more. Two ACI rules are never in a precedence relationship, which is why every
rule carries the same `rulebase`: the shadowing analysis compares within a rulebase and
would otherwise report an earlier contract as shadowing a later one on a fabric where
neither precedes anything.

**A contract is bidirectional unless its subject says otherwise.** `vzSubj` carries
`revFltPorts`, and a subject with reverse filter ports permits the return traffic
implicitly. A reader that ignores it reports half the connectivity the fabric actually
has.

**`vzAny` is every EPG in the VRF.** A contract consumed by `vzAny` is the ACI spelling
of an any-source rule, and it is the single most permissive thing a fabric can contain —
so it is normalised to `any` rather than left as an object name nothing resolves.

**Everything arrives as `imdata`.** APIC wraps every response in
`{"totalCount": "N", "imdata": [{"<className>": {"attributes": {...}, "children": [...]}}]}`
— one single-key dict per object, keyed by its class. That envelope is uniform across
all two hundred classes, which is what makes one reader possible.
"""

from __future__ import annotations

import json
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.ncm.models import NetworkObject, NormalisedConfig, SecurityRule
from netsecops.parsers.base import ConfigParser, ParseContext, ParseResult

log = get_logger(__name__)

#: The one rulebase name every ACI rule carries. ACI has no ordered policy, so two
#: rules are never in a precedence relationship — but the shadowing analysis compares
#: within a rulebase, and giving each contract its own would stop it comparing at all.
#: One shared name keeps *overlap* detection working, which is the analysis that does
#: mean something here.
_RULEBASE = "aci-contracts"

#: `vzAny` is every EPG in the VRF — the ACI spelling of "any source".
_ANY_EPG = "vzAny"


def _objects(payload: Any, class_name: str) -> list[dict[str, Any]]:
    """Every object of a class in an APIC response.

    APIC wraps each object as a single-key dict keyed by its class name, so a response
    may hold several classes at once. Filtering by class here is what lets one reader
    serve all of them.
    """
    if isinstance(payload, dict):
        entries = payload.get("imdata")
    else:
        entries = payload
    if not isinstance(entries, list):
        return []

    found: list[dict[str, Any]] = []
    for entry in entries:
        if isinstance(entry, dict) and class_name in entry:
            body = entry[class_name]
            if isinstance(body, dict):
                found.append(body)
    return found


def _attributes(obj: dict[str, Any]) -> dict[str, Any]:
    attributes = obj.get("attributes")
    return attributes if isinstance(attributes, dict) else {}


def _children(obj: dict[str, Any], class_name: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for child in obj.get("children") or []:
        if isinstance(child, dict) and class_name in child:
            body = child[class_name]
            if isinstance(body, dict):
                found.append(body)
    return found


def _tenant_of(dn: str) -> str:
    """The tenant a distinguished name belongs to.

    `uni/tn-Production/brc-web-to-db` → `Production`. Contracts in different tenants
    govern different traffic and a name alone collides across them.
    """
    for part in dn.split("/"):
        if part.startswith("tn-"):
            return part[3:]
    return ""


class CiscoAciParser(ConfigParser):
    vendor = "cisco"
    platform = "cisco_aci"

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

        filters = self._filters(bundle)
        epgs = self._epgs(bundle, result)

        try:
            self._contracts(bundle, filters, epgs, result)
        except Exception as exc:  # pragma: no cover - defensive, per FR-PARSE-03
            log.warning("parser.section_failed", platform=self.platform, error=str(exc))

        self._version(bundle, result)
        self._account_for_endpoints(bundle, result)
        return result.ncm

    # ─────────────────────────── the fabric ─────────────────────────────

    def _version(self, bundle: dict[str, Any], result: ParseResult) -> None:
        for payload in bundle.values():
            for obj in _objects(payload, "firmwareCtrlrRunning"):
                if version := _attributes(obj).get("version"):
                    result.ncm.device.version = str(version)
                    return

    # ──────────────────────────── objects ───────────────────────────────

    def _filters(self, bundle: dict[str, Any]) -> dict[str, list[str]]:
        """`vzFilter` → the protocol/port pairs its entries allow.

        A contract names filters; the filters carry the actual ports. Without them every
        rule's service set is empty and can never match — the inert-rulebase defect.
        """
        found: dict[str, list[str]] = {}

        for payload in bundle.values():
            for obj in _objects(payload, "vzFilter"):
                attributes = _attributes(obj)
                name = str(attributes.get("name") or "")
                if not name:
                    continue

                ports: list[str] = []
                for entry in _children(obj, "vzEntry"):
                    entry_attributes = _attributes(entry)
                    protocol = str(entry_attributes.get("prot") or "")
                    start = entry_attributes.get("dFromPort")
                    end = entry_attributes.get("dToPort")

                    # `unspecified` is ACI's word for "every port", and read as a port
                    # name it matches nothing at all.
                    if not start or start == "unspecified":
                        ports.append(protocol if protocol not in {"", "unspecified"} else "any")
                        continue
                    ports.append(
                        f"{protocol}/{start}" if start == end else f"{protocol}/{start}-{end}"
                    )

                found[name] = ports or ["any"]

        return found

    def _epgs(self, bundle: dict[str, Any], result: ParseResult) -> dict[str, list[str]]:
        """`fvAEPg` → the subnets behind each endpoint group.

        An EPG is the ACI unit of policy and is not an address. Its addresses come from
        the bridge domain's subnets, which a rule's source and destination ultimately
        resolve to — so each EPG becomes a group object and the rules name the group.
        """
        ncm = result.ncm
        found: dict[str, list[str]] = {}

        subnets: dict[str, list[str]] = {}
        for payload in bundle.values():
            for obj in _objects(payload, "fvSubnet"):
                attributes = _attributes(obj)
                dn = str(attributes.get("dn") or "")
                ip = str(attributes.get("ip") or "")
                if not ip:
                    continue
                # `uni/tn-X/BD-web/subnet-[10.0.0.1/24]` — the bridge domain is the
                # segment between the two.
                bridge = ""
                for part in dn.split("/"):
                    if part.startswith("BD-"):
                        bridge = part[3:]
                subnets.setdefault(bridge, []).append(ip)

        for payload in bundle.values():
            for obj in _objects(payload, "fvAEPg"):
                attributes = _attributes(obj)
                name = str(attributes.get("name") or "")
                if not name:
                    continue

                bridge = ""
                for child in _children(obj, "fvRsBd"):
                    bridge = str(_attributes(child).get("tnFvBDName") or "")

                members = subnets.get(bridge, [])
                found[name] = members
                ncm.firewall.address_groups.append(
                    NetworkObject(
                        name=name,
                        # An EPG with no subnet is not an empty EPG — its bridge domain
                        # simply was not exported, or it is an L2 EPG with no gateway.
                        # `type` says which so a reader can tell the two apart.
                        type="epg" if members else "epg-no-subnet",
                        members=members,
                    )
                )

        return found

    # ──────────────────────── contracts as rules ────────────────────────

    def _contracts(
        self,
        bundle: dict[str, Any],
        filters: dict[str, list[str]],
        epgs: dict[str, list[str]],
        result: ParseResult,
    ) -> None:
        """Every consumer/provider pair a contract creates, as a rule.

        A contract on its own permits nothing. Connectivity exists where one EPG
        consumes it and another provides it, so the rule is the *pair* — and a contract
        with providers and no consumers is dead configuration that permits nothing,
        which is worth seeing rather than counting as a rule.
        """
        ncm = result.ncm

        consumers: dict[str, list[str]] = {}
        providers: dict[str, list[str]] = {}

        for payload in bundle.values():
            for relation, target in (("fvRsCons", consumers), ("fvRsProv", providers)):
                for obj in _objects(payload, relation):
                    attributes = _attributes(obj)
                    contract = str(attributes.get("tnVzBrCPName") or "")
                    dn = str(attributes.get("dn") or "")
                    if not contract:
                        continue
                    # `uni/tn-X/ap-App/epg-Web/rscons-web-to-db` — the EPG is the
                    # segment before the relation.
                    epg = ""
                    for part in dn.split("/"):
                        if part.startswith("epg-"):
                            epg = part[4:]
                    target.setdefault(contract, []).append(epg or _ANY_EPG)

        order = 0
        for payload in bundle.values():
            for obj in _objects(payload, "vzBrCP"):
                attributes = _attributes(obj)
                name = str(attributes.get("name") or "")
                if not name:
                    continue
                tenant = _tenant_of(str(attributes.get("dn") or ""))

                services: list[str] = []
                reverse = False
                for subject in _children(obj, "vzSubj"):
                    subject_attributes = _attributes(subject)
                    # `revFltPorts` is what makes a contract bidirectional. Ignored, the
                    # return traffic looks unpermitted and half the fabric's real
                    # connectivity goes unreported.
                    if str(subject_attributes.get("revFltPorts") or "").lower() == "yes":
                        reverse = True
                    for attachment in _children(subject, "vzRsSubjFiltAtt"):
                        filter_name = str(_attributes(attachment).get("tnVzFilterName") or "")
                        services += filters.get(filter_name, [filter_name] if filter_name else [])

                for consumer in consumers.get(name, []):
                    for provider in providers.get(name, []):
                        order += 1
                        ncm.firewall.security_rules.append(
                            SecurityRule(
                                order=order,
                                name=f"{name}: {consumer} → {provider}",
                                # One rulebase for the whole fabric. ACI evaluates no
                                # sequence, so no two of these precede one another — but
                                # the analysis compares within a rulebase, and one name
                                # each would stop it comparing at all.
                                rulebase=_RULEBASE,
                                src=["any"] if consumer == _ANY_EPG else [consumer],
                                dst=["any"] if provider == _ANY_EPG else [provider],
                                services=services or ["any"],
                                # The fabric is default-deny; a contract exists to
                                # permit. There is no deny contract.
                                action="allow",
                                profiles={
                                    "tenant": tenant,
                                    "contract": name,
                                    "bidirectional": "yes" if reverse else "no",
                                },
                            )
                        )
                        result.ncm.provenance.record(
                            f"firewall.security_rules.{len(ncm.firewall.security_rules) - 1}",
                            result.context.provenance(1, 1),
                        )

        ncm.firewall.zones = sorted(epgs)

    # ─────────────────────────── bookkeeping ────────────────────────────

    def _account_for_endpoints(self, bundle: dict[str, Any], result: ParseResult) -> None:
        known = ("vzBrCP", "vzFilter", "fvAEPg", "fvSubnet", "fvRsCons", "fvRsProv",
                 "firmwareCtrlrRunning")
        result.ncm.raw_unparsed = [
            f"1: no rule reads the response to '{endpoint}'"
            for endpoint in sorted(bundle)
            if not any(marker in endpoint for marker in known)
        ]
        result.consume(1, max(1, len(result.context.lines)))


__all__ = ["CiscoAciParser"]
