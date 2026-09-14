"""Cisco ISE parser (FR-AAA-02).

ISE is the authentication service the rest of the estate depends on, and it is read
through two different APIs that disagree about everything. The legacy **ERS** API
answers with `{"SearchResult": {"resources": [...]}}` and wraps each object in a
type-named key. The newer **OpenAPI** answers with a bare list or `{"response": [...]}`.
A deployment answers with one, the other, or both depending on which version it runs and
which endpoint is asked, so :func:`_records` accepts all three shapes rather than
betting on one.

Like the Check Point parser, the input is a *bundle* keyed by the endpoint that produced
each response, so a partial collection stays useful: if the policy-set endpoint returned
403 because the account lacks the role, the network devices are still read and only the
policy checks report Not Evaluated (FR-COL-08).

**The allowed-protocols list is the point.** ISE ships with a default "Default Network
Access" protocol set that permits PAP, CHAP, MS-CHAPv1 and EAP-MD5, and almost nobody
narrows it, because doing so breaks whichever forgotten device still uses one. Every
weak method any policy will accept is flattened into one list, because the question
worth asking is about the *server* — a single rule still accepting MS-CHAPv1 is a way
in regardless of how careful the other forty are.
"""

from __future__ import annotations

import json
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.ncm.models import (
    AuthPolicy,
    CommandSet,
    IdentityStore,
    LocalUser,
    NormalisedConfig,
    RadiusClient,
)
from netsecops.parsers.base import ConfigParser, ParseContext, ParseResult

log = get_logger(__name__)

#: ISE's spellings, normalised to the NCM's. Its policy objects name protocols in at
#: least three casings across API versions, and a check comparing raw strings would miss
#: exactly the ones it was written to catch.
_PROTOCOL_NAMES: dict[str, str] = {
    "allowpapascii": "PAP",
    "processhostlookup": "MAB",
    "allowchap": "CHAP",
    "allowmschapv1": "MS-CHAPv1",
    "allowmschapv2": "MS-CHAPv2",
    "alloweapmd5": "EAP-MD5",
    "alloweaptls": "EAP-TLS",
    "allowleap": "LEAP",
    "allowpeap": "PEAP",
    "alloweapfast": "EAP-FAST",
    "allowteap": "TEAP",
    "alloweapttls": "EAP-TTLS",
    "allowpreferredeapprotocol": "",
}


def _records(payload: Any) -> list[dict[str, Any]]:
    """Every object in an ISE response, whichever API shape it arrived in.

    ERS wraps results in `SearchResult.resources` and each detail object in a
    type-named key (`{"NetworkDevice": {...}}`); OpenAPI returns a bare list or
    `{"response": [...]}`. Accepting all three is not defensiveness for its own sake —
    a deployment genuinely answers differently per endpoint and per version.
    """
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if not isinstance(payload, dict):
        return []

    search = payload.get("SearchResult")
    if isinstance(search, dict) and isinstance(search.get("resources"), list):
        return [item for item in search["resources"] if isinstance(item, dict)]

    for key in ("response", "resources", "items"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    # An ERS detail response: a single object under its own type name.
    if len(payload) == 1:
        inner = next(iter(payload.values()))
        if isinstance(inner, dict):
            return [inner]
        if isinstance(inner, list):
            return [item for item in inner if isinstance(item, dict)]

    return [payload]


def _bool(value: Any) -> bool | None:
    """ISE returns booleans as bools and as the strings 'true'/'false'."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    return None


class CiscoIseParser(ConfigParser):
    vendor = "cisco"
    platform = "cisco_ise"

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        result.ncm.device.vendor = self.vendor
        result.ncm.device.platform = self.platform
        result.ncm.aaa_server.product = "ise"

        try:
            bundle = json.loads(context.text) if context.text.strip() else {}
        except ValueError as exc:
            log.warning("parser.json_invalid", platform=self.platform, error=str(exc))
            result.ncm.raw_unparsed = [f"1: the collected artefact is not valid JSON: {exc}"]
            return result.ncm

        if not isinstance(bundle, dict):
            result.ncm.raw_unparsed = ["1: the collected artefact is not a bundle of responses"]
            return result.ncm

        for section in (
            self._parse_deployment,
            self._parse_network_devices,
            self._parse_identity_stores,
            self._parse_policies,
            self._parse_command_sets,
            self._parse_admins,
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

    _KNOWN = frozenset(
        {
            "deployment/node",
            "networkdevice",
            "networkdevicegroup",
            "activedirectory",
            "identitystore",
            "internaluser",
            "policy/network-access/policy-set",
            "policy/network-access/authentication",
            "policy/network-access/authorization",
            "allowedprotocols",
            "policy/device-admin/command-sets",
            "adminuser",
            "admin/settings",
        }
    )

    def _account_for_commands(self, bundle: dict[str, Any], result: ParseResult) -> None:
        result.ncm.raw_unparsed = [
            f"1: no rule reads the response to '{endpoint}'"
            for endpoint in sorted(bundle)
            if endpoint.lower() not in self._KNOWN
        ]
        result.consume(1, max(1, len(result.context.lines)))

    def _record(self, result: ParseResult, path: str) -> None:
        result.ncm.provenance.record(path, result.context.provenance(1, 1))

    def _get(self, bundle: dict[str, Any], endpoint: str) -> list[dict[str, Any]]:
        for key, payload in bundle.items():
            if key.lower() == endpoint:
                return _records(payload)
        return []

    # ── deployment ──────────────────────────────────────────────────────

    def _parse_deployment(self, bundle: dict[str, Any], result: ParseResult) -> None:
        nodes = self._get(bundle, "deployment/node")
        if not nodes:
            return

        node = nodes[0]
        device = result.ncm.device
        device.hostname = str(node.get("hostname") or node.get("name") or "") or None
        device.version = str(node.get("nodeversion") or node.get("version") or "") or None
        if device.hostname:
            self._record(result, "device.hostname")

    # ── network devices, which FR-AAA-05 correlates ─────────────────────

    def _parse_network_devices(self, bundle: dict[str, Any], result: ParseResult) -> None:
        """Every switch, controller and firewall permitted to authenticate here.

        This is the half of FR-AAA-05 that finds devices nobody put in the inventory: a
        switch configured on ISE and unknown to NetSecOps is a device being
        authenticated against, and assessed by nothing.
        """
        aaa_server = result.ncm.aaa_server

        for record in self._get(bundle, "networkdevice"):
            addresses = record.get("NetworkDeviceIPList") or record.get("ipList") or []
            address = None
            if isinstance(addresses, list) and addresses:
                first = addresses[0]
                address = (
                    str(first.get("ipaddress") or first.get("ipAddress") or "")
                    if isinstance(first, dict)
                    else str(first)
                ) or None

            radius = record.get("authenticationSettings") or {}
            tacacs = record.get("tacacsSettings") or {}

            # ISE never returns the shared secret itself, so the fingerprint stays None
            # and FR-AAA-05 reports reuse as "unknown" for this source rather than as
            # "not reused" — the distinction the requirement explicitly asks for.
            aaa_server.clients.append(
                RadiusClient(
                    name=str(record.get("name") or "") or "unnamed",
                    address=address,
                    secret_configured=bool(radius.get("radiusSharedSecret"))
                    or bool(tacacs.get("sharedSecret"))
                    or None,
                    secret_fingerprint=None,
                    vendor=str(record.get("profileName") or "") or None,
                    description=str(record.get("description") or "") or None,
                    tls=_bool(radius.get("dtlsRequired")),
                    enabled=True,
                )
            )
            self._record(result, f"aaa_server.clients.{len(aaa_server.clients) - 1}")

    # ── identity stores ─────────────────────────────────────────────────

    def _parse_identity_stores(self, bundle: dict[str, Any], result: ParseResult) -> None:
        aaa_server = result.ncm.aaa_server

        for record in self._get(bundle, "activedirectory"):
            aaa_server.identity_stores.append(
                IdentityStore(
                    name=str(record.get("name") or "") or "active-directory",
                    type="active-directory",
                    host=str(record.get("domain") or "") or None,
                    # AD joins are Kerberos/LDAPS in practice; ISE does not expose a
                    # per-join flag here, so this stays unknown rather than assumed.
                    tls=None,
                )
            )
            self._record(
                result, f"aaa_server.identity_stores.{len(aaa_server.identity_stores) - 1}"
            )

        for record in self._get(bundle, "identitystore"):
            aaa_server.identity_stores.append(
                IdentityStore(
                    name=str(record.get("name") or "") or "unnamed",
                    type=str(record.get("type") or "") or None,
                    host=str(record.get("hostname") or record.get("host") or "") or None,
                    tls=_bool(record.get("enableSecureConnection")),
                )
            )
            self._record(
                result, f"aaa_server.identity_stores.{len(aaa_server.identity_stores) - 1}"
            )

    # ── policy, and the protocols it will accept ────────────────────────

    def _parse_policies(self, bundle: dict[str, Any], result: ParseResult) -> None:
        aaa_server = result.ncm.aaa_server
        protocols: set[str] = set()

        for record in self._get(bundle, "allowedprotocols"):
            for key, value in record.items():
                name = _PROTOCOL_NAMES.get(key.lower())
                if name and _bool(value):
                    protocols.add(name)

            # The EAP inner methods sit one level down, and a PEAP tunnel that still
            # permits MS-CHAPv1 inside it is the classic finding here.
            for nested_key in ("eapTls", "peap", "eapFast", "eapTtls", "teap"):
                nested = record.get(nested_key)
                if not isinstance(nested, dict):
                    continue
                for key, value in nested.items():
                    name = _PROTOCOL_NAMES.get(key.lower())
                    if name and _bool(value):
                        protocols.add(name)

            # Named explicitly rather than sliced out of the key. Deriving the version
            # from character positions produced "TLSLS1.2", which is not a TLS version
            # and would never match a check comparing against "TLS1.0".
            for version_key, version in (
                ("allowTLS10", "TLS1.0"),
                ("allowTLS11", "TLS1.1"),
                ("allowTLS12", "TLS1.2"),
                ("allowTLS13", "TLS1.3"),
            ):
                if _bool(record.get(version_key)):
                    aaa_server.tls_versions.append(version)

        for kind in ("authentication", "authorization"):
            for order, record in enumerate(
                self._get(bundle, f"policy/network-access/{kind}"), start=1
            ):
                rule = record.get("rule") or record
                aaa_server.policies.append(
                    AuthPolicy(
                        name=str(rule.get("name") or "") or f"rule-{order}",
                        order=int(rule.get("rank", order) or order),
                        kind=kind,
                        enabled=str(rule.get("state") or "enabled").lower() == "enabled",
                        condition=_condition_summary(rule.get("condition")),
                        identity_source=str(
                            record.get("identitySourceName")
                            or record.get("identityStoreName")
                            or ""
                        )
                        or None,
                        result=str(record.get("profile") or record.get("profiles") or "") or None,
                    )
                )
                self._record(result, f"aaa_server.policies.{len(aaa_server.policies) - 1}")

        if protocols:
            aaa_server.allowed_protocols = sorted(protocols)
            self._record(result, "aaa_server.allowed_protocols")

    # ── TACACS+ command authorisation ───────────────────────────────────

    def _parse_command_sets(self, bundle: dict[str, Any], result: ParseResult) -> None:
        aaa_server = result.ncm.aaa_server

        for record in self._get(bundle, "policy/device-admin/command-sets"):
            commands = record.get("commands") or {}
            entries = commands.get("commandList") if isinstance(commands, dict) else commands
            listed = [
                f"{item.get('grant', '')} {item.get('command', '')}".strip()
                for item in (entries or [])
                if isinstance(item, dict)
            ]

            aaa_server.command_sets.append(
                CommandSet(
                    name=str(record.get("name") or "") or "unnamed",
                    # A set that permits anything unmatched makes every rule in it
                    # advisory — the interesting flag, and easy to miss in a UI.
                    permit_unmatched=_bool(record.get("permitUnmatched")),
                    commands=listed,
                )
            )
            self._record(result, f"aaa_server.command_sets.{len(aaa_server.command_sets) - 1}")

    # ── administrators of ISE itself ────────────────────────────────────

    def _parse_admins(self, bundle: dict[str, Any], result: ParseResult) -> None:
        for record in self._get(bundle, "adminuser"):
            result.ncm.users.append(
                LocalUser(
                    name=str(record.get("name") or "") or "unnamed",
                    role=_first_role(record),
                    privilege=15 if _is_super_admin(record) else None,
                )
            )
            self._record(result, f"users.{len(result.ncm.users) - 1}")

        for record in self._get(bundle, "admin/settings"):
            session = record.get("sessionTimeout") or record.get("maxSessionTime")
            if isinstance(session, int | str) and str(session).isdigit():
                # ISE states it in minutes; the NCM is seconds everywhere.
                result.ncm.aaa_server.admin_session_timeout_s = int(session) * 60
                result.ncm.management.session.exec_timeout_s = int(session) * 60
                self._record(result, "aaa_server.admin_session_timeout_s")

            # `or` would be wrong here, and was: `False or None` is None, so an ISE
            # deployment that explicitly reports MFA *disabled* — the finding — came
            # through as "not determined" and the check reported Not Evaluated. A real
            # False is an answer, and the first key that supplies one wins.
            for key in ("mfaEnabled", "enableMFA"):
                mfa = _bool(record.get(key))
                if mfa is not None:
                    result.ncm.aaa_server.admin_mfa_enabled = mfa
                    self._record(result, "aaa_server.admin_mfa_enabled")
                    break


def _condition_summary(condition: Any) -> str | None:
    """A readable one-line form of an ISE policy condition.

    The full structure is a nested tree of dictionaries that is unreadable in a finding
    and enormous in the NCM. The summary is what an operator needs to recognise the rule
    in their own console; the console remains the place to read the whole thing.
    """
    if condition is None:
        return None
    if isinstance(condition, str):
        return condition
    if not isinstance(condition, dict):
        return None

    if name := condition.get("name") or condition.get("conditionType"):
        attribute = condition.get("attributeName")
        value = condition.get("attributeValue")
        if attribute and value:
            return f"{attribute} {condition.get('operator', '=')} {value}"
        return str(name)

    children = condition.get("children")
    if isinstance(children, list) and children:
        parts = [_condition_summary(child) for child in children[:4]]
        joined = " and ".join(p for p in parts if p)
        return joined or None
    return None


def _first_role(record: dict[str, Any]) -> str | None:
    roles = record.get("adminGroups") or record.get("roles") or []
    if isinstance(roles, list) and roles:
        first = roles[0]
        return str(first.get("name") if isinstance(first, dict) else first) or None
    return None


def _is_super_admin(record: dict[str, Any]) -> bool:
    roles = record.get("adminGroups") or record.get("roles") or []
    names = [
        str(role.get("name") if isinstance(role, dict) else role).lower()
        for role in (roles if isinstance(roles, list) else [])
    ]
    return any("super" in name for name in names)


__all__ = ["CiscoIseParser"]
