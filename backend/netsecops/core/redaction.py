"""Configuration redaction (FR-COL-13, SEC-09).

A device configuration is full of credentials: SNMP communities, TACACS keys, VPN
pre-shared keys, password hashes, certificate private keys. NetSecOps stores the
original encrypted for diffing and hashing, and shows a redacted copy — so the common
case (reading a config in the UI, pasting a finding into a ticket) never moves secrets
around, while ``config:view_unredacted`` remains available, audited, to the few who
need it.

This is separate from :mod:`netsecops.core.logging`'s scrubber. That one is defensive:
a last line of defence over arbitrary log values. This one is structural: it knows
device configuration syntax and redacts by *rule*, keeping the surrounding line intact
so the config stays readable and diffable.

A redacted value keeps a stable placeholder that includes a short hash of the secret.
Two devices sharing a TACACS key therefore show the same placeholder — which is how
FR-AAA-05's "shared-secret reuse" check works without ever handling the secret.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Final

#: The marker shown in place of a secret.
REDACTED: Final[str] = "«redacted"


@dataclass(frozen=True, slots=True)
class RedactionRule:
    """One pattern whose capture group 2 is the secret."""

    name: str
    pattern: re.Pattern[str]
    #: Set when the rule's whole match should go, rather than one group.
    whole_line: bool = False


def _rule(name: str, pattern: str, *, whole_line: bool = False) -> RedactionRule:
    return RedactionRule(name, re.compile(pattern, re.IGNORECASE), whole_line=whole_line)


#: Ordered: more specific patterns first, since the first match wins per line.
RULES: Final[tuple[RedactionRule, ...]] = (
    # ── SNMP ────────────────────────────────────────────────────────────
    # Keyed on the `community` keyword wherever it appears, not on a line prefix:
    # ASA writes `snmp-server host <if> <ip> community <secret> version 2c`, so a rule
    # anchored to the start of the line misses it entirely.
    # The negative lookahead is not cosmetic. AireOS writes
    # `config snmp community create <name>`, and without it this rule matched
    # `community create` and redacted the word "create" — leaving the real community
    # string in the line, in a line that now *contained a redaction placeholder* and so
    # looked as though it had been handled. A rule that half-fires is worse than one
    # that misses: a miss is caught by the leak tests, and this was not.
    _rule(
        "snmp_community",
        r"(\bcommunity\s+)(?!(?:create|delete|mode|accessmode|ipaddr)\b)(\S+)",
    ),
    # v3 auth and priv keys sit on the same line, so each needs its own rule and all
    # rules must be applied — see redact_line.
    _rule("snmp_v3_auth", r"(\bauth\s+(?:md5|sha|sha256|sha512)\s+)(\S+)"),
    _rule("snmp_v3_priv", r"(\bpriv\s+(?:des|3des|aes)(?:-?\d+)?(?:\s+\d+)?\s+)(\S+)"),
    # NX-OS omits the algorithm: `priv 0xdeadbeef localizedkey`. Matching only things
    # that look like key material keeps this from redacting the *username* on a v3
    # trap line, which would be noise rather than protection.
    _rule("snmp_v3_priv_raw", r"(\bpriv\s+)(0x[0-9a-fA-F]{8,}|[A-Za-z0-9+/=]{12,})\b"),
    # A trap target's trailing token is a community on v1/v2c but a *username* on v3,
    # so the negative lookahead keeps the rule from redacting something harmless and
    # making the config look more secret-laden than it is.
    _rule(
        "snmp_host_community",
        r"^(\s*snmp-server\s+host\s+\S+(?:\s+(?:traps|informs))?(?:\s+version\s+(?:1|2c))?\s+)"
        r"(?!version\s)(\S+)",
    ),
    # ── AAA shared secrets ──────────────────────────────────────────────
    _rule("tacacs_key", r"^(\s*(?:tacacs-server\s+)?key\s+(?:\d\s+)?)(\S+)"),
    _rule("radius_key", r"^(\s*radius-server\s+key\s+(?:\d\s+)?)(\S+)"),
    # NX-OS and IOS both allow the key inline on the host line:
    # `tacacs-server host 10.0.0.1 key 7 <secret> timeout 5`.
    _rule(
        "server_host_key",
        r"^(\s*(?:tacacs-server|radius-server)\s+host\s+\S+.*?\bkey\s+(?:\d+\s+)?)(\S+)",
    ),
    _rule("server_key", r"^(\s*server-private\s+\S+\s+key\s+(?:\d\s+)?)(\S+)"),
    _rule("ntp_auth_key", r"(\s*ntp\s+authentication-key\s+\d+\s+\w+\s+)(\S+)"),
    _rule("key_string", r"^(\s*key-string\s+(?:\d\s+)?)(\S+)"),
    # ── VLAN trunking ───────────────────────────────────────────────────
    _rule("vtp_password", r"^(\s*vtp\s+password\s+)(\S+)"),
    # ── Local credentials ───────────────────────────────────────────────
    _rule("enable_secret", r"^(\s*enable\s+secret\s+(?:\d\s+)?)(\S+)"),
    _rule("enable_password", r"^(\s*enable\s+password\s+(?:\d\s+)?)(\S+)"),
    _rule(
        "username_secret",
        r"^(\s*username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+(?:\d\s+)?)(\S+)",
    ),
    _rule("line_password", r"^(\s*password\s+(?:\d\s+)?)(\S+)"),
    # ── VPN ─────────────────────────────────────────────────────────────
    _rule(
        "pre_shared_key",
        r"^(\s*(?:pre-shared-key|preshared-key)\s+(?:address\s+\S+\s+)?(?:key\s+)?)(\S+)",
    ),
    _rule("crypto_key", r"^(\s*crypto\s+isakmp\s+key\s+)(\S+)"),
    # ── ASA / NX-OS spellings ───────────────────────────────────────────
    _rule("asa_passwd", r"^(\s*passwd\s+)(\S+)"),
    _rule("nxos_user", r"^(\s*username\s+\S+\s+password\s+(?:\d\s+)?)(\S+)"),
    # ── FortiOS ─────────────────────────────────────────────────────────
    # Every secret on a FortiGate is a `set <key> [ENC] <value>` statement, and the key
    # names are consistent: password, passwd, secret, *-pwd, key, psksecret. One rule
    # covers them all, which matters because the set is open-ended — FortiOS adds new
    # `set ...-pwd` fields between releases, and a list of literal key names would be
    # out of date the first time it did.
    #
    # This was added after a RADIUS shared secret reached the NCM through a provenance
    # excerpt: the rules above are Cisco-shaped and `set secret ENC <value>` matched
    # none of them. A new vendor's syntax slipping past redaction is the failure mode
    # this whole module exists to prevent.
    #
    # The keyword must *end* the setting name, give or take a one-letter suffix — FortiOS
    # writes `set auth-pwd-l` for the local SNMP password. A trailing `\S*` was tried
    # first and was wrong in the other direction: it matched `set password-controls 12`
    # and `set password-expiration-days 90`, which are Gaia *policy settings*, and
    # redacted the minimum password length as though it were a credential. Over-redaction
    # is the safer failure, but it destroys the evidence a finding is supposed to show.
    _rule(
        "fortios_secret",
        r"^(\s*set\s+(?:\S+[-_])?(?:password|passwd|secret|pwd|key|psksecret|privatekey)"
        r"(?:[-_][a-z])?\s+(?:ENC\s+)?)(\S+)",
    ),
    # `set member` on a user group can carry a token; `set ppk-secret`, `set ssl-key`
    # and friends are covered by the rule above. Community strings on FortiOS use the
    # `set name` field inside `config system snmp community`, which cannot be matched
    # by keyword alone without redacting every object name in the file — the parser
    # masks it instead, at the point it knows the context.
    # ── Cisco WLC AireOS ────────────────────────────────────────────────
    # AireOS is a flat command list, and its secrets sit in positional arguments with no
    # keyword in front of them — `config radius auth add 1 10.0.0.1 1812 ascii <secret>`
    # matches none of the keyword-driven rules above. This is the same failure the
    # FortiOS rule was added for, in a third syntax: a new vendor's shape slipping past
    # redaction is what this module exists to prevent, and it has now happened twice.
    #
    # Anchored on `ascii`/`hex`, which is the token AireOS puts immediately before a
    # shared secret on every one of these commands.
    _rule(
        "aireos_server_secret",
        r"^(\s*config\s+(?:radius|tacacs)\s+\w+\s+add\s+.*?\b(?:ascii|hex)\s+)(\S+)",
    ),
    # `config mgmtuser add <name> <password> <role>`: positional, with the password in
    # the middle. The trailing group is kept so the role survives — it is what the
    # least-privilege check reads, and redacting the whole tail would blind it.
    _rule(
        "aireos_mgmtuser",
        r"^(\s*config\s+mgmtuser\s+add\s+\S+\s+)(\S+)",
    ),
    _rule(
        "aireos_mgmtuser_password",
        r"^(\s*config\s+mgmtuser\s+password\s+\S+\s+)(\S+)",
    ),
    # A community string is a credential. The parser masks it into the NCM separately;
    # this is what keeps the raw line out of a provenance excerpt.
    _rule("aireos_snmp_community", r"^(\s*config\s+snmp\s+community\s+create\s+)(\S+)"),
    _rule(
        "aireos_wlan_psk",
        r"^(\s*config\s+wlan\s+security\s+wpa\s+akm\s+psk\s+set-key\s+\S+\s+)(\S+)",
    ),
    # ── Wireless ────────────────────────────────────────────────────────
    _rule("wpa_psk", r"^(\s*(?:wpa-psk|psk)\s+(?:ascii|hex)\s+(?:\d\s+)?)(\S+)"),
    # ── Key material ────────────────────────────────────────────────────
    _rule("certificate_blob", r"^\s*(?:[0-9A-Fa-f]{32,})\s*$", whole_line=True),
)

#: Multi-line blocks whose entire body is key material.
BLOCK_MARKERS: Final[tuple[tuple[str, str], ...]] = (
    ("-----BEGIN", "-----END"),
    ("certificate self-signed", "quit"),
    ("certificate ca", "quit"),
)


def fingerprint(secret: str) -> str:
    """Short, stable fingerprint of a secret.

    Included in the placeholder so identical secrets are recognisably identical across
    devices — which is exactly what FR-AAA-05's shared-secret reuse check needs — while
    being far too short to attack the value offline.
    """
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:8]


def placeholder(rule_name: str, secret: str) -> str:
    return f"{REDACTED}:{rule_name}:{fingerprint(secret)}»"


def redact_line(line: str) -> tuple[str, str | None]:
    """Redact one configuration line.

    Returns ``(redacted_line, first_rule_applied_or_None)``. The line keeps its keyword
    and indentation so the result is still readable and diffable.

    **Every** rule is applied, not just the first that matches. A single line can carry
    more than one secret — ``snmp-server user u g v3 auth sha AUTH priv aes 128 PRIV``
    carries two — and stopping at the first match would leave the rest in plain sight.
    """
    applied: list[str] = []
    current = line

    for rule in RULES:
        if rule.whole_line:
            if rule.pattern.match(current) and REDACTED not in current:
                indent = current[: len(current) - len(current.lstrip())]
                current = f"{indent}{placeholder(rule.name, current.strip())}"
                applied.append(rule.name)
            continue

        def substitute(match: re.Match[str], _name: str = rule.name) -> str:
            prefix, secret = match.group(1), match.group(2)
            # Never redact a placeholder produced by an earlier rule: doing so would
            # double-wrap it and destroy the fingerprint that makes reuse detectable.
            if REDACTED in secret:
                return match.group(0)
            applied.append(_name)
            return f"{prefix}{placeholder(_name, secret)}"

        current = rule.pattern.sub(substitute, current)

    return current, (applied[0] if applied else None)


def redact_config(text: str) -> str:
    """Redact a whole configuration (FR-COL-13).

    Block-structured key material (PEM bodies, embedded certificates) is handled
    separately: those are many lines of base64 with no keyword to anchor on, so the
    block is collapsed rather than matched line by line.
    """
    lines = text.splitlines()
    output: list[str] = []
    in_block: str | None = None

    for line in lines:
        stripped = line.strip()

        if in_block is not None:
            if stripped.startswith(in_block) or stripped == in_block:
                output.append(line)
                in_block = None
            # The body is dropped entirely; the delimiters remain so the structure of
            # the configuration is still visible in a diff.
            continue

        opened = next(
            (end for start, end in BLOCK_MARKERS if stripped.upper().startswith(start.upper())),
            None,
        )
        if opened is not None:
            output.append(line)
            indent = line[: len(line) - len(line.lstrip())]
            output.append(f"{indent}{REDACTED}:key-material»")
            in_block = opened
            continue

        redacted, _ = redact_line(line)
        output.append(redacted)

    return "\n".join(output) + ("\n" if text.endswith("\n") else "")


def redaction_summary(text: str) -> dict[str, int]:
    """Count redactions by rule — shown alongside a config so nothing looks lost."""
    counts: dict[str, int] = {}
    for line in text.splitlines():
        _, rule_name = redact_line(line)
        if rule_name:
            counts[rule_name] = counts.get(rule_name, 0) + 1
    return counts


def contains_secret(text: str) -> bool:
    """True when any redaction rule matches. Used by tests as a leak tripwire."""
    return any(redact_line(line)[1] is not None for line in text.splitlines())


__all__ = [
    "REDACTED",
    "RULES",
    "RedactionRule",
    "contains_secret",
    "fingerprint",
    "redact_config",
    "redact_line",
    "redaction_summary",
]
