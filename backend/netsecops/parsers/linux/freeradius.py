"""FreeRADIUS parser (FR-AAA-04).

The collection reads a handful of files under `/etc/freeradius/3.0` and stores them as a
bundle keyed by path, so a host where `mods-available/eap` was unreadable still yields
its client list and only the EAP checks report Not Evaluated.

**This is the only AAA source that exposes a shared secret.** ISE and FortiAuthenticator
return `********`; a FreeRADIUS `clients.conf` contains `secret = <the actual key>`. Two
consequences, and they pull in opposite directions:

*The secret must never be stored.* It is fingerprinted and discarded — the fingerprint
is the same function the redaction module uses, so a secret seen here and a secret seen
in a switch's own configuration produce the same value.

*That fingerprint is what makes FR-AAA-05's reuse detection real.* Where every other
source can only report "unknown", this one can say that fourteen devices share one key
— without NetSecOps ever holding it.
"""

from __future__ import annotations

import json

from netsecops.core.logging import get_logger
from netsecops.core.redaction import fingerprint
from netsecops.ncm.models import AuthPolicy, IdentityStore, NormalisedConfig, RadiusClient
from netsecops.parsers.base import ConfigParser, ParseContext, ParseResult, first_known
from netsecops.parsers.linux.conf import ConfBlock, read

log = get_logger(__name__)

#: FreeRADIUS module names that *are* authentication protocols. A host with the `mschap`
#: module built and referenced will accept MS-CHAP, whatever the policy says elsewhere.
_EAP_MODULES: dict[str, str] = {
    "md5": "EAP-MD5",
    "leap": "LEAP",
    "gtc": "EAP-GTC",
    "tls": "EAP-TLS",
    "ttls": "EAP-TTLS",
    "peap": "PEAP",
    "mschapv2": "MS-CHAPv2",
    "fast": "EAP-FAST",
    "pwd": "EAP-PWD",
}


def _bundle(text: str) -> dict[str, str]:
    """The collected files, keyed by path.

    A bare configuration — someone pasting one file rather than a collection — is
    accepted as `clients.conf`, because refusing it would make the offline-import path
    (FR-COL-11) useless for exactly the host most likely to be imported by hand.
    """
    stripped = text.strip()
    if not stripped:
        return {}

    if stripped.startswith("{"):
        try:
            loaded = json.loads(stripped)
        except ValueError:
            return {"clients.conf": text}
        if isinstance(loaded, dict):
            return {str(k): str(v) for k, v in loaded.items()}

    return {"clients.conf": text}


class FreeRadiusParser(ConfigParser):
    vendor = "linux"
    platform = "freeradius"

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        result.ncm.device.vendor = self.vendor
        result.ncm.device.platform = self.platform
        result.ncm.aaa_server.product = "freeradius"

        files = _bundle(context.text)

        for section in (
            self._parse_clients,
            self._parse_eap,
            self._parse_identity_stores,
            self._parse_sites,
        ):
            try:
                section(files, result)
            except Exception as exc:
                log.warning(
                    "parser.section_failed",
                    platform=self.platform,
                    section=section.__name__,
                    error=str(exc),
                )

        result.ncm.raw_unparsed = self._unparsed(files)
        result.consume(1, max(1, len(context.lines)))
        return result.ncm

    def _unparsed(self, files: dict[str, str]) -> list[str]:
        """What was not understood, at both levels.

        A bundle has two ways of hiding something: a *file* nothing reads, and a *line*
        inside a file that was read. Reporting only the first was the original version,
        and it meant a `clients.conf` full of syntax this parser cannot handle came back
        with an empty `raw_unparsed` — indistinguishable from a file understood
        completely. The shared tolerance test in `test_parsers.py` is what caught it.
        """
        known = ("clients.conf", "radiusd.conf", "eap", "default", "inner-tunnel", "proxy.conf")
        unparsed: list[str] = []

        for path in sorted(files):
            if not any(marker in path for marker in known):
                unparsed.append(f"1: no rule reads '{path}'")
                continue
            for line in read(files[path]).unparsed:
                unparsed.append(f"{path} {line}")

        return unparsed

    def _find(self, files: dict[str, str], *markers: str) -> str | None:
        for path, content in files.items():
            if any(marker in path for marker in markers):
                return content
        return None

    def _record(self, result: ParseResult, path: str) -> None:
        result.ncm.provenance.record(path, result.context.provenance(1, 1))

    # ── clients, which FR-AAA-05 correlates ─────────────────────────────

    def _parse_clients(self, files: dict[str, str], result: ParseResult) -> None:
        content = self._find(files, "clients.conf")
        if content is None:
            return

        aaa_server = result.ncm.aaa_server

        for block in read(content).of_kind("client"):
            secret = block.get("secret")
            aaa_server.clients.append(
                RadiusClient(
                    name=block.name,
                    address=block.get("ipaddr") or block.get("ipv4addr") or block.get("ipv6addr"),
                    secret_configured=secret is not None,
                    # Fingerprinted and discarded. The same function the redaction module
                    # uses, so one key seen here and in a switch's own configuration
                    # produces one value — which is what makes reuse detectable across
                    # sources without the secret ever being stored (C-2, FR-AAA-05).
                    secret_fingerprint=fingerprint(secret) if secret else None,
                    vendor=block.get("nastype"),
                    description=block.get("shortname"),
                    # RadSec: a client reached over TLS rather than the shared secret.
                    tls=_radsec(block),
                    enabled=True,
                )
            )
            self._record(result, f"aaa_server.clients.{len(aaa_server.clients) - 1}")

    # ── what the server will accept ─────────────────────────────────────

    def _parse_eap(self, files: dict[str, str], result: ParseResult) -> None:
        content = self._find(files, "eap")
        if content is None:
            return

        aaa_server = result.ncm.aaa_server
        parsed = read(content)
        protocols: set[str] = set()

        for eap in parsed.of_kind("eap"):
            default_type = eap.get("default_eap_type")
            if default_type and default_type.lower() in _EAP_MODULES:
                protocols.add(_EAP_MODULES[default_type.lower()])

            # A method is available if its sub-block exists, whether or not it is the
            # default. `md5 { }` present means the server will do EAP-MD5 on request —
            # which is the finding, and is invisible if only the default is read.
            for child in eap.children:
                name = _EAP_MODULES.get(child.kind.lower())
                if name:
                    protocols.add(name)

            for tls_block in eap.children_of("tls-config"):
                for key in ("tls_min_version", "tls_max_version"):
                    version = tls_block.get(key)
                    if version:
                        aaa_server.tls_versions.append(f"TLS{version.strip().strip('"')}")

        if protocols:
            aaa_server.allowed_protocols = sorted(set(aaa_server.allowed_protocols) | protocols)
            self._record(result, "aaa_server.allowed_protocols")
        if aaa_server.tls_versions:
            aaa_server.tls_versions = sorted(set(aaa_server.tls_versions))
            self._record(result, "aaa_server.tls_versions")

    def _parse_identity_stores(self, files: dict[str, str], result: ParseResult) -> None:
        content = self._find(files, "radiusd.conf", "ldap")
        if content is None:
            return

        aaa_server = result.ncm.aaa_server
        for block in read(content).of_kind("ldap"):
            aaa_server.identity_stores.append(
                IdentityStore(
                    name=block.name,
                    type="ldap",
                    host=block.get("server"),
                    # `start_tls = yes` or an ldaps:// server. A directory bind in the
                    # clear carries credentials on every authentication — so a `no` here
                    # is the finding, and `or` would have discarded it.
                    tls=first_known(
                        block.flag("start_tls"),
                        True if str(block.get("server") or "").startswith("ldaps://") else None,
                    ),
                )
            )
            self._record(
                result, f"aaa_server.identity_stores.{len(aaa_server.identity_stores) - 1}"
            )

    def _parse_sites(self, files: dict[str, str], result: ParseResult) -> None:
        """The virtual server's `authorize` section, which is FreeRADIUS's policy."""
        content = self._find(files, "default", "inner-tunnel")
        if content is None:
            return

        aaa_server = result.ncm.aaa_server
        parsed = read(content)

        for order, server_block in enumerate(parsed.of_kind("server"), start=1):
            for section in ("authorize", "authenticate"):
                child = server_block.child(section)
                if child is None:
                    continue
                aaa_server.policies.append(
                    AuthPolicy(
                        name=f"{server_block.name}/{section}",
                        order=order,
                        kind="authentication",
                        enabled=True,
                        # FreeRADIUS's policy is a list of module names in order, which
                        # is genuinely what decides the outcome.
                        condition=", ".join(sorted(child.values)) or None,
                    )
                )
                self._record(result, f"aaa_server.policies.{len(aaa_server.policies) - 1}")

        # PAP and CHAP are modules rather than policy settings, and their presence in
        # the authorize list is what makes them acceptable.
        protocols = set(aaa_server.allowed_protocols)
        for block in parsed.walk():
            for key in block.values:
                if key.lower() == "pap":
                    protocols.add("PAP")
                elif key.lower() == "chap":
                    protocols.add("CHAP")
                elif key.lower() in {"mschap", "ms-chap"}:
                    protocols.add("MS-CHAPv1")
        if protocols != set(aaa_server.allowed_protocols):
            aaa_server.allowed_protocols = sorted(protocols)
            self._record(result, "aaa_server.allowed_protocols")


def _radsec(block: ConfBlock) -> bool | None:
    """Whether this client is reached over TLS rather than the shared secret."""
    if block.flag("proto") is not None:
        return None
    proto = (block.get("proto") or "").strip().lower()
    if proto:
        return proto == "tls"
    tls = block.child("tls")
    return True if tls is not None else None


__all__ = ["FreeRadiusParser"]
