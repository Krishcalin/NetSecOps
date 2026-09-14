"""FortiAuthenticator parser (FR-AAA-03).

A straightforward REST API, read as a bundle keyed by endpoint like ISE and Check Point.
Every list response is `{"objects": [...], "meta": {...}}`, which is one shape rather
than ISE's three — the parsing here is correspondingly dull, and the interesting work is
in the mapping.

Two things worth noting:

**`secret` comes back masked**, like ISE's, so the fingerprint stays None and FR-AAA-05
reports reuse as "unknown" for this source. Only the FreeRADIUS and tac_plus parsers can
answer that question, because only their configurations contain the real key.

**EAP methods are per-policy, not global.** A FortiAuthenticator policy names the methods
it accepts, so the server-wide list is the union across policies — the same reasoning as
ISE, and for the same reason: one policy still accepting MS-CHAPv1 is a way in whatever
the others do.
"""

from __future__ import annotations

import json
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.ncm.models import (
    AuthPolicy,
    Certificate,
    IdentityStore,
    LocalUser,
    NormalisedConfig,
    RadiusClient,
)
from netsecops.parsers.base import ConfigParser, ParseContext, ParseResult, first_known

log = get_logger(__name__)

#: FortiAuthenticator's spellings, normalised to the NCM's.
_PROTOCOLS: dict[str, str] = {
    "pap": "PAP",
    "chap": "CHAP",
    "ms-chap": "MS-CHAPv1",
    "mschap": "MS-CHAPv1",
    "ms-chapv2": "MS-CHAPv2",
    "mschapv2": "MS-CHAPv2",
    "eap-md5": "EAP-MD5",
    "eap-tls": "EAP-TLS",
    "eap-ttls": "EAP-TTLS",
    "peap": "PEAP",
    "eap-gtc": "EAP-GTC",
}


def _objects(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        objects = payload.get("objects")
        if isinstance(objects, list):
            return [item for item in objects if isinstance(item, dict)]
        return [payload]
    return []


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    return None


def _first_bool(record: dict[str, Any], *keys: str) -> bool | None:
    """The first key supplying a real answer. See `parsers.base.first_known`."""
    return first_known(*(_bool(record.get(key)) for key in keys))


class FortiAuthenticatorParser(ConfigParser):
    vendor = "fortinet"
    platform = "fortiauthenticator"

    _KNOWN = frozenset(
        {
            "radiusclients",
            "localusers",
            "usergroups",
            "ldapservers",
            "certificates",
            "system",
            "adminprofiles",
            "policies",
        }
    )

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        result.ncm.device.vendor = self.vendor
        result.ncm.device.platform = self.platform
        result.ncm.aaa_server.product = "fortiauthenticator"

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
            self._parse_system,
            self._parse_clients,
            self._parse_identity_stores,
            self._parse_policies,
            self._parse_users,
            self._parse_certificates,
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

        result.ncm.raw_unparsed = [
            f"1: no rule reads the response to '{endpoint}'"
            for endpoint in sorted(bundle)
            if endpoint.strip("/").split("/")[-1].lower() not in self._KNOWN
        ]
        result.consume(1, max(1, len(context.lines)))
        return result.ncm

    def _get(self, bundle: dict[str, Any], name: str) -> list[dict[str, Any]]:
        for key, payload in bundle.items():
            if key.strip("/").split("/")[-1].lower() == name:
                return _objects(payload)
        return []

    def _record(self, result: ParseResult, path: str) -> None:
        result.ncm.provenance.record(path, result.context.provenance(1, 1))

    # ── sections ────────────────────────────────────────────────────────

    def _parse_system(self, bundle: dict[str, Any], result: ParseResult) -> None:
        for record in self._get(bundle, "system"):
            device = result.ncm.device
            device.hostname = str(record.get("hostname") or "") or None
            device.version = (
                str(record.get("firmware_version") or record.get("version") or "") or None
            )
            if device.hostname:
                self._record(result, "device.hostname")

            timeout = record.get("admin_idle_timeout")
            if isinstance(timeout, int | str) and str(timeout).isdigit():
                # FortiAuthenticator states it in minutes.
                result.ncm.aaa_server.admin_session_timeout_s = int(timeout) * 60
                result.ncm.management.session.exec_timeout_s = int(timeout) * 60
                self._record(result, "aaa_server.admin_session_timeout_s")

            mfa = _bool(record.get("admin_mfa"))
            if mfa is not None:
                result.ncm.aaa_server.admin_mfa_enabled = mfa
                self._record(result, "aaa_server.admin_mfa_enabled")

    def _parse_clients(self, bundle: dict[str, Any], result: ParseResult) -> None:
        aaa_server = result.ncm.aaa_server

        for record in self._get(bundle, "radiusclients"):
            aaa_server.clients.append(
                RadiusClient(
                    name=str(record.get("name") or "") or "unnamed",
                    address=str(record.get("client") or record.get("ip") or "") or None,
                    secret_configured=bool(record.get("secret")),
                    # Masked by the API, so reuse is "unknown" for this source — the
                    # distinction FR-AAA-05 asks for, rather than a fingerprint of
                    # `********` that would report the whole estate as sharing one key.
                    secret_fingerprint=None,
                    vendor=str(record.get("vendor") or "") or None,
                    description=str(record.get("description") or "") or None,
                    enabled=_bool(record.get("enabled")),
                )
            )
            self._record(result, f"aaa_server.clients.{len(aaa_server.clients) - 1}")

    def _parse_identity_stores(self, bundle: dict[str, Any], result: ParseResult) -> None:
        aaa_server = result.ncm.aaa_server

        for record in self._get(bundle, "ldapservers"):
            aaa_server.identity_stores.append(
                IdentityStore(
                    name=str(record.get("name") or "") or "unnamed",
                    type="ldap",
                    host=str(record.get("server") or record.get("primary_server") or "") or None,
                    tls=_first_bool(record, "secure_connection", "use_ssl"),
                )
            )
            self._record(
                result, f"aaa_server.identity_stores.{len(aaa_server.identity_stores) - 1}"
            )

    def _parse_policies(self, bundle: dict[str, Any], result: ParseResult) -> None:
        aaa_server = result.ncm.aaa_server
        protocols: set[str] = set()

        for order, record in enumerate(self._get(bundle, "policies"), start=1):
            methods = record.get("eap_types") or record.get("auth_methods") or []
            named = sorted(
                {
                    _PROTOCOLS[str(method).strip().lower()]
                    for method in (methods if isinstance(methods, list) else [methods])
                    if str(method).strip().lower() in _PROTOCOLS
                }
            )
            protocols.update(named)

            aaa_server.policies.append(
                AuthPolicy(
                    name=str(record.get("name") or "") or f"policy-{order}",
                    order=int(record.get("order", order) or order),
                    kind="authentication",
                    enabled=_bool(record.get("enabled")),
                    allowed_protocols=named,
                    identity_source=str(record.get("realm") or record.get("user_group") or "")
                    or None,
                )
            )
            self._record(result, f"aaa_server.policies.{len(aaa_server.policies) - 1}")

        if protocols:
            aaa_server.allowed_protocols = sorted(protocols)
            self._record(result, "aaa_server.allowed_protocols")

    def _parse_users(self, bundle: dict[str, Any], result: ParseResult) -> None:
        for record in self._get(bundle, "adminprofiles"):
            result.ncm.users.append(
                LocalUser(
                    name=str(record.get("name") or "") or "unnamed",
                    role=str(record.get("profile") or record.get("role") or "") or None,
                    privilege=15
                    if str(record.get("profile") or "").lower() in {"admin", "super_admin"}
                    else None,
                )
            )
            self._record(result, f"users.{len(result.ncm.users) - 1}")

    # ── certificates ────────────────────────────────────────────────────

    def _parse_certificates(self, bundle: dict[str, Any], result: ParseResult) -> None:
        """Local and CA certificates, for the expiry timeline (FR-AAA-06).

        FortiAuthenticator is the EAP endpoint for the FortiGate wireless estate, so the
        server certificate here is presented to every supplicant. Its expiry is a
        wireless outage with a date on it, which is exactly the kind of thing that is
        obvious in hindsight and invisible until the morning it happens.
        """
        for record in self._get(bundle, "certificates"):
            result.ncm.certificates.append(
                Certificate(
                    name=str(record.get("name") or record.get("cn") or "") or None,
                    subject=str(record.get("subject") or record.get("cn") or "") or None,
                    issuer=str(record.get("issuer") or record.get("ca") or "") or None,
                    not_before=str(record.get("valid_from") or record.get("not_before") or "")
                    or None,
                    not_after=str(record.get("valid_to") or record.get("not_after") or "") or None,
                    key_bits=_int_or_none(record.get("key_size") or record.get("keysize")),
                    sig_alg=str(record.get("signature_algorithm") or "") or None,
                    self_signed=_bool(record.get("self_signed")),
                    usage=_usage(record),
                )
            )
            self._record(result, f"certificates.{len(result.ncm.certificates) - 1}")


def _usage(record: dict[str, Any]) -> list[str]:
    value = record.get("usage") or record.get("type")
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str) and value.strip():
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


__all__ = ["FortiAuthenticatorParser"]
