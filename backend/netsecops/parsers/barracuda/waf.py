"""Barracuda Web Application Firewall, over the v3.2 REST API (SRS §1.3.1).

**The blocker this closes.** `barracuda_waf` had a read-only allow-list and no parser
because, as `docs/new-device-families.md` recorded, "nothing in Barracuda's public
documentation names the field that says whether a service *blocks or merely logs* —
which is the single most important fact about a WAF".

It does now: Barracuda publish the **v3.2 OpenAPI specification** in their own
`barracudanetworks/waf-automation` repository, and `Service_basic_security.json` defines

    "mode": {"type": "string", "enum": ["Passive", "Active"]}

That is the field. `Passive` inspects everything and stops nothing, and it is the state
an appliance's own dashboard flatters — a passive WAF reports attacks in exactly the way
an active one does, so a screen full of blocked-looking events says nothing about
whether anything was blocked.

**The field names here are authoritative; the response envelope is not.** The published
specification defines every object's properties and gives no schema for a GET response,
so the shape *around* the data is the one thing still unverified. Rather than guess one,
`_records` accepts all three shapes the API is plausibly using — a bare list, a list
under `data`, an object keyed by name under `data` — and the tests exercise each. A
parser that assumed the wrong envelope would read nothing at all and report a WAF with
no services, which is indistinguishable from an appliance nobody has configured.

**The input is a bundle, not one response**, keyed by endpoint path the way the Check
Point management parser is keyed by command. A WAF's posture needs four calls per
service — the service, its basic security, its SSL security and its back ends — and
none of them is the configuration on its own.
"""

from __future__ import annotations

import json
import re
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.ncm.models import (
    NormalisedConfig,
    RealServer,
    VirtualServer,
    VirtualService,
)
from netsecops.parsers.base import ConfigParser, ParseContext, ParseResult

log = get_logger(__name__)

#: `/services/<name>/basic-security` → `<name>`. The name may contain anything a
#: hostname may, which is why this is anchored rather than split on `/`.
_SERVICE_SUB = re.compile(r"^/services/(?P<name>[^/]+)/(?P<sub>basic-security|ssl-security|servers)$")

#: Barracuda spells booleans as words, and inconsistently: `Yes`/`No` on the SSL object,
#: `On`/`Off` on the service. Both appear in the published specification.
_TRUE = frozenset({"yes", "on", "true", "enabled"})
_FALSE = frozenset({"no", "off", "false", "disabled"})

#: `enable-<x>` → the version it enables. From `Service_ssl_security.json`.
_TLS_FLAGS: dict[str, str] = {
    "enable-ssl-3": "SSLv3",
    "enable-tls-1": "TLSv1.0",
    "enable-tls-1-1": "TLSv1.1",
    "enable-tls-1-2": "TLSv1.2",
    "enable-tls-1-3": "TLSv1.3",
}

#: Service types that terminate TLS, per the `type` enum in `Service.json`. The rest
#: carry cleartext, and which is which is the question a WAF service is asked first.
_ENCRYPTED_TYPES = frozenset({"https", "instant ssl", "custom ssl", "ftp ssl"})


def _word_bool(value: Any) -> bool | None:
    """A Barracuda word-boolean, or None where it said nothing.

    Absent stays None so the NCM's absent-is-not-false rule holds: a WAF whose SSL
    object was not collected must not report every TLS version as disabled, which would
    render the most hardened possible appliance and hide that nothing was read.
    """
    if not isinstance(value, str):
        return None
    lowered = value.strip().lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    return None


def _records(payload: Any) -> list[tuple[str | None, dict[str, Any]]]:
    """Objects out of a GET response, whichever envelope it used.

    Three shapes are accepted and the published specification rules out none of them:

    * a bare list of objects,
    * ``{"data": [ … ]}``,
    * ``{"data": {"<name>": { … }}}`` — keyed by name, which is how several Barracuda
      collections read and the only shape where the *name* lives outside the object.

    Returns `(name or None, object)`, so a caller can fall back to the object's own
    `name` field when the envelope did not supply one.
    """
    if isinstance(payload, dict) and "data" in payload:
        payload = payload["data"]

    if isinstance(payload, list):
        return [(None, item) for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        # A dict of objects keyed by name — unless it *is* a single object, which is
        # what `/services/<name>/ssl-security` returns. The difference is whether the
        # values are dicts.
        if payload and all(isinstance(value, dict) for value in payload.values()):
            return [(key, value) for key, value in payload.items()]
        return [(None, payload)]

    return []


def _one(payload: Any) -> dict[str, Any]:
    """The single object a per-service endpoint returns."""
    found = _records(payload)
    return found[0][1] if found else {}


class BarracudaWafParser(ConfigParser):
    vendor = "barracuda"
    platform = "barracuda_waf"

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

        if not isinstance(bundle, dict):
            result.ncm.raw_unparsed = ["1: the collected artefact is not an endpoint bundle"]
            result.ncm.parse_failed = True
            return result.ncm

        if not bundle:
            result.ncm.raw_unparsed = ["1: the collected artefact is empty"]
            result.ncm.parse_failed = True
            return result.ncm

        try:
            self._services(bundle, result)
            self._per_service(bundle, result)
        except Exception as exc:  # pragma: no cover - defensive, per FR-PARSE-03
            log.warning("parser.section_failed", platform=self.platform, error=str(exc))

        self._account_for_endpoints(bundle, result)
        return result.ncm

    # ──────────────────────────── services ──────────────────────────────

    def _services(self, bundle: dict[str, Any], result: ParseResult) -> None:
        """`GET /services` — the published web applications.

        Each becomes a virtual server. A WAF is a reverse proxy, so its services are
        VIPs with listeners on them and its back ends are real servers; modelling them
        as anything else would put a WAF outside every view that already understands
        what a device publishes.
        """
        lb = result.ncm.load_balancer

        for key, record in _records(bundle.get("/services")):
            name = key or str(record.get("name") or "").strip()
            if not name:
                continue

            kind = str(record.get("type") or "").strip()
            lb.virtual_servers.append(
                VirtualServer(
                    id=name,
                    address=record.get("ip-address") or None,
                    enabled=_word_bool(record.get("status")),
                    services=[
                        VirtualService(
                            port=_port(record.get("port")),
                            service=kind or None,
                            # Filled by `/basic-security` and `/ssl-security` below.
                            # Left None here rather than defaulted: a service whose
                            # security objects were not collected must not read as one
                            # that is passive, nor as one that is active.
                        )
                    ],
                )
            )
            result.record(f"load_balancer.virtual_servers.{len(lb.virtual_servers) - 1}", line=1)

        if lb.virtual_servers:
            lb.enabled = True

    def _per_service(self, bundle: dict[str, Any], result: ParseResult) -> None:
        """The three per-service endpoints, matched back to their service."""
        lb = result.ncm.load_balancer
        by_name = {server.id: server for server in lb.virtual_servers}

        for endpoint, payload in bundle.items():
            match = _SERVICE_SUB.match(endpoint)
            if match is None:
                continue

            server = by_name.get(match.group("name"))
            if server is None:
                # A security object for a service `/services` did not list. Not dropped
                # silently: `_account_for_endpoints` reports the endpoint as unread.
                continue

            sub = match.group("sub")
            if sub == "basic-security":
                self._basic_security(server, _one(payload), result)
            elif sub == "ssl-security":
                self._ssl_security(server, _one(payload), result)
            elif sub == "servers":
                self._servers(payload, result)

    def _basic_security(
        self, server: VirtualServer, record: dict[str, Any], result: ParseResult
    ) -> None:
        """`mode` is the whole point of this endpoint."""
        if not server.services:
            return
        listener = server.services[0]

        mode = str(record.get("mode") or "").strip().lower()
        if mode in {"active", "passive"}:
            listener.enforcement = mode
            result.record(f"load_balancer.virtual_servers.{server.id}.enforcement", line=1)

        if policy := record.get("web-firewall-policy"):
            listener.policy = str(policy)

    def _ssl_security(
        self, server: VirtualServer, record: dict[str, Any], result: ParseResult
    ) -> None:
        if not server.services:
            return
        listener = server.services[0]

        # Only the versions explicitly enabled. A flag the appliance did not send is
        # neither on nor off, and listing it as accepted would invent an exposure.
        enabled = [
            version for flag, version in _TLS_FLAGS.items() if _word_bool(record.get(flag)) is True
        ]
        if enabled:
            listener.tls_versions = enabled
            result.record(f"load_balancer.virtual_servers.{server.id}.tls_versions", line=1)

        listener.hsts = _word_bool(record.get("enable-hsts"))

        # `ssl-tls-presets` names the posture in Barracuda's own words — "Mozilla Modern
        # Compatibility", "Factory Preset" — which is more useful to an operator than
        # the cipher list it expands to, and is what they would change.
        if preset := record.get("ssl-tls-presets"):
            listener.ssl_policy = str(preset)
        elif ciphers := record.get("ciphers"):
            listener.ssl_policy = str(ciphers)

    def _servers(self, payload: Any, result: ParseResult) -> None:
        """`GET /services/<name>/servers` — the back ends behind a service."""
        lb = result.ncm.load_balancer

        for key, record in _records(payload):
            name = key or str(record.get("hostname") or record.get("ip-address") or "").strip()
            if not name:
                continue
            status = str(record.get("status") or "").strip().lower()
            lb.real_servers.append(
                RealServer(
                    id=name,
                    address=record.get("ip-address") or record.get("hostname") or None,
                    # `In Service` is the only status that means it is taking traffic;
                    # the other three are all forms of out-of-service.
                    enabled=(status == "in service") if status else None,
                    port=_port(record.get("port")),
                )
            )
            result.record(f"load_balancer.real_servers.{len(lb.real_servers) - 1}", line=1)

    # ─────────────────────────── bookkeeping ────────────────────────────

    def _account_for_endpoints(self, bundle: dict[str, Any], result: ParseResult) -> None:
        """Coverage over a bundle of endpoints.

        Line coverage means nothing for JSON, so the honest measure is which *endpoints*
        this parser read. One the collector fetched and nothing here understands is
        exactly the gap `raw_unparsed` exists to make visible.
        """
        known: set[str] = {"/services"}
        for endpoint in bundle:
            if _SERVICE_SUB.match(endpoint):
                known.add(endpoint)

        result.ncm.raw_unparsed = [
            f"1: no rule reads the response to '{endpoint}'"
            for endpoint in sorted(bundle)
            if endpoint not in known
        ]
        result.consume(1, max(1, len(result.context.lines)))


def _port(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


__all__ = ["BarracudaWafParser"]
