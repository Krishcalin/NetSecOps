"""AWS security groups and network ACLs, from an export (SRS §1.3).

**Why this is here at all, given OverWatch scans AWS.** They ask different questions.
A CNAPP asks whether a cloud account is misconfigured; NetSecOps asks whether a packet
can get from one place to another across the whole estate. A security group is a
firewall rule on that path, and a path that crosses from a data centre into a VPC is
exactly the query nothing else can answer — so the rules belong in the topology graph
regardless of who else reads them. That boundary is recorded in `docs/algosec-parity.md`.

Read from an export rather than a live collection: no collection profile, no credential,
no SigV4. `aws ec2 describe-security-groups --output json` produces the input and
FR-COL-11 ingests it.

**A security group is not an ordered rulebase and the difference matters.** Every rule in
every group that applies to an interface is evaluated, there is no first-match, and there
is no deny — a security group can only permit. Three consequences the code depends on:

* `action` is always `allow`. There is no other value, so a group with no rules permits
  nothing rather than denying everything.
* Ordering is meaningless, so every rule carries the same `rulebase` and `order` is
  assignment order. Two security-group rules are never in a precedence relationship, and
  reporting one as shadowing another would be advice to delete a rule that is doing
  exactly what it was written to do.
* **The direction is in the field name, not in the rule.** `IpPermissions` is ingress and
  `IpPermissionsEgress` is egress, and the objects inside them are identical in shape. A
  reader that parses both from one function without carrying the direction produces a
  rulebase where every egress rule looks like an ingress one.

**`-1` means every port and it is not a port.** AWS writes `IpProtocol: "-1"` for "all
protocols", and omits `FromPort`/`ToPort` entirely with it. Read literally that is a rule
matching protocol minus-one on no ports, which matches nothing — turning the most
permissive rule AWS can express into one that appears inert.
"""

from __future__ import annotations

import json
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.ncm.models import NetworkObject, NormalisedConfig, SecurityRule
from netsecops.parsers.base import ConfigParser, ParseContext, ParseResult

log = get_logger(__name__)

#: One rulebase for every security-group rule. They are not ordered against one another,
#: so no two are in a precedence relationship — but the analysis compares within a
#: rulebase, and one name each would stop it comparing at all.
_RULEBASE = "aws-security-groups"

#: AWS's "every protocol". Not a protocol number.
_ANY_PROTOCOL = "-1"


def _payload(bundle: Any, *keys: str) -> list[dict[str, Any]]:
    """A named collection out of an export, whatever it was wrapped in.

    Accepts the CLI's `{"SecurityGroups": [...]}`, a bare list, and a bundle keyed by
    command — all three are what an export actually looks like depending on who made it.
    """
    if isinstance(bundle, list):
        return [item for item in bundle if isinstance(item, dict)]
    if not isinstance(bundle, dict):
        return []

    for key in keys:
        if isinstance(bundle.get(key), list):
            return [item for item in bundle[key] if isinstance(item, dict)]

    # A bundle keyed by command or endpoint: look one level down.
    found: list[dict[str, Any]] = []
    for value in bundle.values():
        found.extend(_payload(value, *keys))
    return found


def _service(permission: dict[str, Any]) -> str:
    """One `IpPermission` as a protocol/port string.

    `-1` is every protocol *and* every port, and AWS omits the port fields with it.
    """
    protocol = str(permission.get("IpProtocol") or "").lower()
    if protocol in {_ANY_PROTOCOL, "", "all"}:
        return "any"

    start = permission.get("FromPort")
    end = permission.get("ToPort")
    if start is None:
        # A protocol with no ports — ICMP, or a protocol number. The protocol alone is
        # the service.
        return protocol
    if start == end or end is None:
        return f"{protocol}/{start}"
    # `0-65535` is every port of that protocol, which several exports write out in full.
    try:
        if int(start) == 0 and int(end) == 65535:
            return f"{protocol}/any"
    except (TypeError, ValueError):
        return f"{protocol}/{start}-{end}"
    return f"{protocol}/{start}-{end}"


def _sources(permission: dict[str, Any]) -> list[str]:
    """Where a permission allows traffic from, across all four kinds of source.

    AWS expresses a source as a CIDR, an IPv6 CIDR, another security group, or a prefix
    list, and a rule may carry several at once. Reading only `IpRanges` — the obvious
    one — drops every group-to-group rule, which is how a well-built VPC does most of
    its work.
    """
    found: list[str] = []

    for entry in permission.get("IpRanges") or []:
        if isinstance(entry, dict) and entry.get("CidrIp"):
            found.append(str(entry["CidrIp"]))
    for entry in permission.get("Ipv6Ranges") or []:
        if isinstance(entry, dict) and entry.get("CidrIpv6"):
            found.append(str(entry["CidrIpv6"]))
    for entry in permission.get("UserIdGroupPairs") or []:
        if isinstance(entry, dict) and entry.get("GroupId"):
            found.append(str(entry["GroupId"]))
    for entry in permission.get("PrefixListIds") or []:
        if isinstance(entry, dict) and entry.get("PrefixListId"):
            found.append(str(entry["PrefixListId"]))

    return found or ["any"]


class AwsParser(ConfigParser):
    vendor = "aws"
    platform = "aws_vpc"

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

        groups = _payload(bundle, "SecurityGroups")
        if not groups:
            result.ncm.raw_unparsed = [
                "1: no SecurityGroups were found in the export — expected the output of "
                "`aws ec2 describe-security-groups`"
            ]
            result.ncm.parse_failed = True
            return result.ncm

        self._groups(groups, result)
        result.consume(1, max(1, len(result.context.lines)))
        return result.ncm

    def _groups(self, groups: list[dict[str, Any]], result: ParseResult) -> None:
        ncm = result.ncm
        order = 0
        vpcs: set[str] = set()

        for group in groups:
            group_id = str(group.get("GroupId") or "")
            group_name = str(group.get("GroupName") or group_id)
            if vpc := group.get("VpcId"):
                vpcs.add(str(vpc))

            # The group itself is an object, so a rule naming another group as its
            # source has something to resolve against.
            #
            # **Typed `security-group` because its membership is not in this export.** A
            # group stands for the set of instances attached to it, and that lives in
            # `describe-instances`. Recorded as an object with no members and a type that
            # says why, rather than as an object the parser failed to read — the two are
            # different facts and only one of them is a defect.
            ncm.firewall.address_groups.append(
                NetworkObject(name=group_id or group_name, type="security-group", members=[])
            )

            for direction, key in (("ingress", "IpPermissions"), ("egress", "IpPermissionsEgress")):
                for permission in group.get(key) or []:
                    if not isinstance(permission, dict):
                        continue
                    order += 1
                    members = _sources(permission)
                    service = _service(permission)

                    ncm.firewall.security_rules.append(
                        SecurityRule(
                            order=order,
                            name=f"{group_name} {direction}",
                            rulebase=_RULEBASE,
                            # The direction lives in the field name, not in the rule, so
                            # it is carried explicitly — source and destination are
                            # otherwise indistinguishable between the two lists.
                            src=members if direction == "ingress" else [group_id],
                            dst=[group_id] if direction == "ingress" else members,
                            services=[service],
                            # A security group can only permit. There is no deny form,
                            # so a group with no rules permits nothing rather than
                            # denying everything.
                            action="allow",
                            profiles={
                                "direction": direction,
                                "group": group_id,
                                "vpc": str(group.get("VpcId") or ""),
                            },
                        )
                    )
                    result.ncm.provenance.record(
                        f"firewall.security_rules.{len(ncm.firewall.security_rules) - 1}",
                        result.context.provenance(1, 1),
                    )

        # Prefix lists are AWS-managed address sets — `pl-...` for S3, DynamoDB and the
        # rest — and their contents are not in this export either. Same treatment as a
        # security group, for the same reason.
        known = {o.name for o in ncm.firewall.address_groups}
        for rule in ncm.firewall.security_rules:
            for member in (*rule.src, *rule.dst):
                if member.startswith("pl-") and member not in known:
                    known.add(member)
                    ncm.firewall.address_groups.append(
                        NetworkObject(name=member, type="prefix-list", members=[])
                    )

        ncm.firewall.zones = sorted(vpcs)
        # There is no single hostname for a VPC. The account's groups are the unit, and
        # naming the device after one of them would be arbitrary.
        ncm.device.model = "VPC security groups"


__all__ = ["AwsParser"]
