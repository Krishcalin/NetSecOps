"""tac_plus / tac_plus-ng parser (FR-AAA-04).

TACACS+ is what most estates use for *device administration*, which makes this the
server that decides who may type `configure terminal` on the whole network. The two
findings it exists to surface:

**A group whose default service is permit.** `default service = permit` means every
command not explicitly denied is allowed, so the carefully written `cmd` rules below it
are decoration. It is one line in a long file and reads like a sensible default.

**Cleartext credentials.** tac_plus stores per-user secrets inline, and
`login = cleartext <password>` is common in configurations that grew from a lab. The
password is fingerprinted for reuse detection and discarded; the *storage type* is what
reaches the NCM, because that is the finding.

The shared key is the other half of FR-AAA-05: unlike ISE, a tac_plus configuration
contains the real key, so reuse across an estate is genuinely detectable here.
"""

from __future__ import annotations

import json

from netsecops.core.logging import get_logger
from netsecops.core.redaction import fingerprint
from netsecops.ncm.models import CommandSet, LocalUser, NormalisedConfig, RadiusClient
from netsecops.parsers.base import ConfigParser, ParseContext, ParseResult
from netsecops.parsers.linux.conf import ConfBlock, ParsedConf, read

log = get_logger(__name__)

#: How tac_plus stores a user's password, and whether that is acceptable. `des` and
#: `cleartext` are the two that appear in practice; only one of them is defensible, and
#: it is not the one most configurations use.
_WEAK_STORAGE = frozenset({"cleartext", "des"})


def _bundle(text: str) -> dict[str, str]:
    stripped = text.strip()
    if not stripped:
        return {}
    if stripped.startswith("{"):
        try:
            loaded = json.loads(stripped)
        except ValueError:
            return {"tac_plus.conf": text}
        if isinstance(loaded, dict):
            return {str(k): str(v) for k, v in loaded.items()}
    return {"tac_plus.conf": text}


class TacPlusParser(ConfigParser):
    vendor = "linux"
    platform = "tac_plus"

    def parse(self, context: ParseContext) -> NormalisedConfig:
        result = ParseResult(context)
        result.ncm.device.vendor = self.vendor
        result.ncm.device.platform = self.platform
        result.ncm.aaa_server.product = "tac_plus"

        files = _bundle(context.text)
        content = next(
            (text for path, text in files.items() if "tac_plus" in path or "tac-plus" in path),
            next(iter(files.values()), None),
        )
        if content is None:
            return result.ncm

        parsed = read(content)

        for section in (
            self._parse_clients,
            self._parse_groups,
            self._parse_users,
        ):
            try:
                section(parsed, result)
            except Exception as exc:
                log.warning(
                    "parser.section_failed",
                    platform=self.platform,
                    section=section.__name__,
                    error=str(exc),
                )

        result.ncm.raw_unparsed = list(parsed.unparsed)
        result.consume(1, max(1, len(context.lines)))
        return result.ncm

    def _record(self, result: ParseResult, path: str) -> None:
        result.ncm.provenance.record(path, result.context.provenance(1, 1))

    # ── the devices that may authenticate here ──────────────────────────

    def _parse_clients(self, parsed: ParsedConf, result: ParseResult) -> None:
        aaa_server = result.ncm.aaa_server

        # The global key, which applies to every client that does not override it. A
        # single key shared by the whole estate is the common shape and the finding.
        global_key = parsed.values.get("key")
        global_fingerprint = fingerprint(global_key) if global_key else None

        hosts = parsed.of_kind("host") + parsed.of_kind("client")
        for block in hosts:
            own_key = block.get("key")
            # `host = 198.51.100.31 { name = core-sw-01 }`: the block's argument is the
            # address and the inner `name` is what an operator calls it. Using the
            # argument as the name would make every finding cite an IP, and the
            # FR-AAA-05 correlation is far easier to read by hostname.
            address = block.get("address") or (block.name if _looks_like_ip(block.name) else None)
            aaa_server.clients.append(
                RadiusClient(
                    name=block.get("name") or block.name,
                    address=address,
                    secret_configured=bool(own_key or global_key),
                    # The real key is fingerprinted and discarded. This is the one AAA
                    # source where reuse is genuinely detectable rather than "unknown".
                    secret_fingerprint=fingerprint(own_key) if own_key else global_fingerprint,
                    enabled=True,
                )
            )
            self._record(result, f"aaa_server.clients.{len(aaa_server.clients) - 1}")

        if not hosts and global_key:
            # A configuration with a global key and no per-host blocks still has a key
            # worth correlating — reporting no clients at all would lose it.
            aaa_server.clients.append(
                RadiusClient(
                    name="(global key)",
                    secret_configured=True,
                    secret_fingerprint=global_fingerprint,
                )
            )
            self._record(result, "aaa_server.clients.0")

    # ── command authorisation ───────────────────────────────────────────

    def _parse_groups(self, parsed: ParsedConf, result: ParseResult) -> None:
        aaa_server = result.ncm.aaa_server

        for block in parsed.of_kind("group"):
            default_service = (block.get("default service") or block.get("default") or "").lower()
            commands: list[str] = []

            for command_block in block.children_of("cmd"):
                verb = command_block.name
                # `permit .*` and `deny .*` are bare directives, not assignments — the
                # whole of tac_plus command authorisation is written that way.
                commands.extend(
                    f"{verb} {directive}"
                    for directive in command_block.directives
                    if directive.startswith(("permit", "deny"))
                )

            # `X or None` is the same trap that bit the ISE and FortiAuthenticator
            # parsers, and it was written here too: when the service is `deny`, the
            # expression is `False or None`, so a group that explicitly denies unmatched
            # commands — the *correct* configuration — reported as "not determined" and
            # the check said Not Evaluated. Three states, spelled out.
            permit_unmatched: bool | None = None
            if "permit" in default_service:
                permit_unmatched = True
            elif "deny" in default_service:
                permit_unmatched = False

            aaa_server.command_sets.append(
                CommandSet(
                    name=block.name,
                    # The finding: everything not explicitly denied is permitted, which
                    # makes every rule below it advisory. One line, easy to miss.
                    permit_unmatched=permit_unmatched,
                    commands=sorted(set(commands)),
                )
            )
            self._record(result, f"aaa_server.command_sets.{len(aaa_server.command_sets) - 1}")

    # ── local accounts on the AAA server itself ─────────────────────────

    def _parse_users(self, parsed: ParsedConf, result: ParseResult) -> None:
        for block in parsed.of_kind("user"):
            storage, secret = _credential(block)

            result.ncm.users.append(
                LocalUser(
                    name=block.name,
                    role=block.get("member"),
                    # The storage type is the finding; the credential itself never
                    # reaches the NCM.
                    secret_type=storage,
                    weak_hash=(storage in _WEAK_STORAGE) if storage else None,
                )
            )
            self._record(result, f"users.{len(result.ncm.users) - 1}")
            del secret


def _credential(block: ConfBlock) -> tuple[str | None, str | None]:
    """How this user's password is stored, and the value — which the caller discards.

    tac_plus writes `login = des <hash>` or, far too often, `login = cleartext <pw>`.
    Returning both keeps the parsing in one place while making it obvious at the call
    site that only the first half is kept.
    """
    for key in ("login", "pap", "chap"):
        raw = block.get(key)
        if not raw:
            continue
        parts = raw.split(None, 1)
        if not parts:
            continue
        storage = parts[0].strip().lower()
        return storage, (parts[1] if len(parts) > 1 else None)
    return None, None


def _looks_like_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


__all__ = ["TacPlusParser"]
