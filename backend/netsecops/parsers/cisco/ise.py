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
    BackupStatus,
    Certificate,
    CommandSet,
    DeviceGroup,
    GuestAccess,
    IdentityStore,
    LocalUser,
    NormalisedConfig,
    RadiusClient,
    Repository,
)
from netsecops.parsers.base import ConfigParser, ParseContext, ParseResult, first_known
from netsecops.parsers.bundle import ResponseBundle, whole_key

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
            raw = json.loads(context.text) if context.text.strip() else {}
        except ValueError as exc:
            log.warning("parser.json_invalid", platform=self.platform, error=str(exc))
            result.ncm.raw_unparsed = [f"1: the collected artefact is not valid JSON: {exc}"]
            result.ncm.parse_failed = True
            return result.ncm

        if not isinstance(raw, dict):
            result.ncm.raw_unparsed = ["1: the collected artefact is not a bundle of responses"]
            result.ncm.parse_failed = True
            return result.ncm

        bundle = ResponseBundle(raw, normalise=whole_key, extract=_records)

        for section in (
            self._parse_deployment,
            self._parse_network_devices,
            self._parse_device_groups,
            self._parse_identity_stores,
            self._parse_internal_users,
            self._parse_policies,
            self._parse_command_sets,
            self._parse_admins,
            self._parse_certificates,
            self._parse_guest_access,
            self._parse_repositories,
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

    def _account_for_commands(self, bundle: ResponseBundle, result: ParseResult) -> None:
        """Responses nothing in this parser read.

        Asked of the bundle rather than compared against a hand-kept list of endpoints
        we believe we read. That list had drifted — it named three endpoints no rule
        here touched — and a claim of coverage the code does not have silences exactly
        the gap it was written to report.
        """
        result.ncm.raw_unparsed = [
            f"1: no rule reads the response to '{endpoint}'" for endpoint in bundle.unread()
        ]
        result.consume(1, max(1, len(result.context.lines)))

    def _record(self, result: ParseResult, path: str) -> None:
        result.ncm.provenance.record(path, result.context.provenance(1, 1))

    # ── deployment ──────────────────────────────────────────────────────

    def _parse_deployment(self, bundle: ResponseBundle, result: ParseResult) -> None:
        nodes = bundle.get("deployment/node")
        if not nodes:
            return

        node = nodes[0]
        device = result.ncm.device
        device.hostname = str(node.get("hostname") or node.get("name") or "") or None
        device.version = str(node.get("nodeversion") or node.get("version") or "") or None
        if device.hostname:
            self._record(result, "device.hostname")

    # ── network devices, which FR-AAA-05 correlates ─────────────────────

    def _parse_network_devices(self, bundle: ResponseBundle, result: ParseResult) -> None:
        """Every switch, controller and firewall permitted to authenticate here.

        This is the half of FR-AAA-05 that finds devices nobody put in the inventory: a
        switch configured on ISE and unknown to NetSecOps is a device being
        authenticated against, and assessed by nothing.
        """
        aaa_server = result.ncm.aaa_server

        for record in bundle.get("networkdevice"):
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

    def _parse_identity_stores(self, bundle: ResponseBundle, result: ParseResult) -> None:
        aaa_server = result.ncm.aaa_server

        for record in bundle.get("activedirectory"):
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

        for record in bundle.get("identitystore"):
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

    def _parse_policies(self, bundle: ResponseBundle, result: ParseResult) -> None:
        aaa_server = result.ncm.aaa_server
        protocols: set[str] = set()

        for record in bundle.get("allowedprotocols"):
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
            for order, record in enumerate(bundle.get(f"policy/network-access/{kind}"), start=1):
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

    def _parse_command_sets(self, bundle: ResponseBundle, result: ParseResult) -> None:
        aaa_server = result.ncm.aaa_server

        for record in bundle.get("policy/device-admin/command-sets"):
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

    def _parse_admins(self, bundle: ResponseBundle, result: ParseResult) -> None:
        for record in bundle.get("adminuser"):
            result.ncm.users.append(
                LocalUser(
                    name=str(record.get("name") or "") or "unnamed",
                    role=_first_role(record),
                    privilege=15 if _is_super_admin(record) else None,
                )
            )
            self._record(result, f"users.{len(result.ncm.users) - 1}")

        for record in bundle.get("admin/settings"):
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

    # ── the EAP certificate, which is the one that matters ──────────────

    def _parse_certificates(self, bundle: ResponseBundle, result: ParseResult) -> None:
        """System certificates, with what each one is used for.

        The usage list is the reason this is worth collecting separately from any other
        certificate inventory. An ISE node holds several — admin, portal, pxGrid, EAP —
        and only one of them is presented to every wireless supplicant on the network
        during 802.1X. When that one expires, every EAP-TLS and PEAP client fails
        authentication at once, and the outage looks like a wireless fault rather than a
        certificate fault for the first hour of it.

        The dates are stored exactly as ISE printed them (Java's ``Date.toString``).
        Interpreting them is :mod:`netsecops.ncm.certificates`' job, and it reports a
        date it cannot read rather than dropping the certificate.
        """
        for record in bundle.get("certs/system-certificate"):
            usage = _usage(record)
            result.ncm.certificates.append(
                Certificate(
                    name=str(record.get("friendlyName") or record.get("name") or "") or None,
                    subject=str(record.get("issuedTo") or record.get("subject") or "") or None,
                    issuer=str(record.get("issuedBy") or record.get("issuer") or "") or None,
                    not_before=str(record.get("validFrom") or record.get("notBefore") or "")
                    or None,
                    not_after=str(record.get("expirationDate") or record.get("notAfter") or "")
                    or None,
                    key_bits=_int_or_none(record.get("keySize")),
                    sig_alg=str(record.get("signatureAlgorithm") or "") or None,
                    self_signed=_bool(record.get("selfSigned")),
                    usage=usage,
                )
            )
            self._record(result, f"certificates.{len(result.ncm.certificates) - 1}")

    # ── network device groups (FR-AAA-02) ───────────────────────────────

    def _parse_device_groups(self, bundle: ResponseBundle, result: ParseResult) -> None:
        """The groups authorisation rules are actually written against.

        An ISE rule reads `DEVICE:Device Type EQUALS Device Type#All Device Types#
        Switches`, which says nothing about which switches. Without the group membership
        the rule is unauditable — and adding a device to the wrong group is how a device
        quietly acquires a policy nobody reviewed for it.
        """
        aaa_server = result.ncm.aaa_server

        for record in bundle.get("networkdevicegroup"):
            name = str(record.get("name") or "") or "unnamed"
            # ISE writes the hierarchy into the name as `Root#Parent#Child`. Split so
            # the structure survives into the NCM rather than being one opaque string.
            parts = [part for part in name.split("#") if part]
            aaa_server.device_groups.append(
                DeviceGroup(
                    name=parts[-1] if parts else name,
                    parent="#".join(parts[:-1]) or None if len(parts) > 1 else None,
                    description=str(record.get("description") or "") or None,
                    kind=str(record.get("othername") or record.get("rootGroupName") or "")
                    or (parts[0] if len(parts) > 1 else None),
                )
            )
            self._record(result, f"aaa_server.device_groups.{len(aaa_server.device_groups) - 1}")

    # ── internal users (FR-AAA-02) ──────────────────────────────────────

    def _parse_internal_users(self, bundle: ResponseBundle, result: ParseResult) -> None:
        """Accounts held in ISE's own store rather than in the directory.

        These are the accounts that survive a directory outage and, more often, the ones
        that survive a leaver process built entirely around the directory. ISE does not
        return the password hash, so `secret_type` stays None and the weak-hash checks
        report Not Evaluated rather than guessing.
        """
        for record in bundle.get("internaluser"):
            groups = record.get("identityGroups")
            result.ncm.users.append(
                LocalUser(
                    name=str(record.get("name") or "") or "unnamed",
                    role=str(groups) if isinstance(groups, str) and groups else None,
                    # `enabled: false` is not "no account"; it is an account someone can
                    # re-enable. It is recorded as a user either way.
                    privilege=None,
                )
            )
            self._record(result, f"users.{len(result.ncm.users) - 1}")

    # ── guest access (FR-AAA-02) ────────────────────────────────────────

    def _parse_guest_access(self, bundle: ResponseBundle, result: ParseResult) -> None:
        """The deliberately-reachable part of the deployment.

        Only populated when the endpoint answered. An absent `guest` block means the
        settings were not collected, which is why it is `None` rather than an empty
        object — an empty object reads as "we looked and there is no guest access".
        """
        record = bundle.first("guestsettings")
        if record is None:
            return

        portals = record.get("portals") or record.get("portalNames") or []
        result.ncm.aaa_server.guest = GuestAccess(
            enabled=_bool(record.get("enabled")),
            self_registration=first_known(
                _bool(record.get("selfRegistration")),
                _bool(record.get("allowGuestToCreateAccounts")),
            ),
            # The pairing is the finding: self-registration alone is a choice,
            # self-registration without sponsor approval is open access.
            sponsor_approval_required=first_known(
                _bool(record.get("requireSponsorApproval")),
                _bool(record.get("sponsorApprovalRequired")),
            ),
            max_account_duration_days=_int_or_none(
                record.get("maxAccountDurationDays") or record.get("accountDurationDays")
            ),
            credentials_sent_in_clear=first_known(
                _bool(record.get("sendCredentialsBySms")),
                _bool(record.get("sendCredentialsByEmail")),
            ),
            https_only=first_known(
                _bool(record.get("httpsOnly")), _bool(record.get("securePortalOnly"))
            ),
            portals=[str(portal) for portal in portals if portal]
            if isinstance(portals, list)
            else [],
        )
        self._record(result, "aaa_server.guest")

    # ── repositories and backup (FR-AAA-02) ─────────────────────────────

    def _parse_repositories(self, bundle: ResponseBundle, result: ParseResult) -> None:
        """Where the backup goes, and whether it is arriving.

        An ISE backup holds every shared secret, every certificate and the credentials
        for the estate, so the transport that carries it is an estate-wide question. FTP
        and TFTP move that archive across the network in the clear.
        """
        aaa_server = result.ncm.aaa_server

        for record in bundle.get("repository"):
            protocol = str(record.get("protocol") or "").strip().lower() or None
            aaa_server.repositories.append(
                Repository(
                    name=str(record.get("name") or "") or "unnamed",
                    protocol=protocol,
                    host=str(record.get("serverName") or record.get("host") or "") or None,
                    path=str(record.get("path") or "") or None,
                    # None where the protocol was not reported. Defaulting to False
                    # would assert an insecurity we did not observe.
                    encrypted_transport=_SECURE_TRANSPORT.get(protocol)
                    if protocol is not None
                    else None,
                )
            )
            self._record(result, f"aaa_server.repositories.{len(aaa_server.repositories) - 1}")

        status = bundle.first("backup-restore/config/last-backup-status")
        if status is None:
            return

        outcome = str(status.get("status") or status.get("lastBackupStatus") or "") or None
        aaa_server.backup = BackupStatus(
            # Scheduled and succeeding are different facts, and a schedule failing since
            # a password change looks identical to a healthy one in the configuration.
            scheduled=first_known(_bool(status.get("scheduled")), _bool(status.get("isScheduled"))),
            last_backup_at=str(status.get("startDate") or status.get("lastBackupOn") or "") or None,
            last_backup_status=outcome,
            encrypted=_bool(status.get("encrypted")),
            repository=str(status.get("repositoryName") or status.get("repository") or "") or None,
        )
        self._record(result, "aaa_server.backup")


#: Whether a repository protocol protects the archive in transit. Absent from the map
#: means the protocol is unrecognised, and the field stays None rather than being
#: guessed either way.
_SECURE_TRANSPORT: dict[str, bool] = {
    "sftp": True,
    "scp": True,
    "https": True,
    "nfs": False,
    "ftp": False,
    "tftp": False,
    "http": False,
    "disk": True,
    "cdrom": True,
}


def _usage(record: dict[str, Any]) -> list[str]:
    """What ISE says the certificate is presented for.

    Spelled several ways across versions — a list under ``usedBy``, a comma-joined
    string under ``keyUsage``, or a set of booleans per role.
    """
    for key in ("usedBy", "keyUsage", "usages"):
        value = record.get(key)
        if isinstance(value, list):
            return [str(item) for item in value if item]
        if isinstance(value, str) and value.strip():
            return [part.strip() for part in value.split(",") if part.strip()]

    flags = {
        "eap": ("eapAuthentication", "eap"),
        "admin": ("admin",),
        "portal": ("portal",),
        "pxgrid": ("pxgrid",),
        "radsec": ("radsec",),
    }
    return sorted(label for label, keys in flags.items() if any(_bool(record.get(k)) for k in keys))


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


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
