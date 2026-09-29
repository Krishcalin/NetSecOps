"""Read-only enforcement (SRS §8) — the guarantee the whole product rests on.

NetSecOps promises it never modifies a target device. That promise is worth exactly as
much as its enforcement, so enforcement lives here, in one vendor-agnostic engine that
every adapter must pass through *before* anything reaches the wire.

Four layers, in the order they run:

1. **Injection guard.** A command carrying a separator (``;``, ``&&``, a newline,
   ``$(``) is rejected outright, whatever it starts with. Without this, an allow-listed
   prefix could smuggle a second command along behind it — and adapters interpolate
   arguments such as interface and WLAN names into commands.
2. **Allow-list.** Every adapter declares the exact commands it may issue. Anything not
   on the list is rejected (SRS §8.1 item 1). This is the primary control.
3. **Deny-list.** A global regex additionally blocks write verbs, catching an
   allow-list entry that was mis-specified (SRS §8.1 item 2). Entries that legitimately
   look like writes but only affect the CLI session — ``terminal length 0``,
   ``set cli pager off`` — must be declared ``session_only`` to pass this layer, which
   forces that judgement to be explicit and reviewable rather than incidental.
4. **HTTP method restriction.** REST adapters may issue ``GET``; ``POST`` only for the
   narrow, enumerated cases in SRS §8.1 item 3.

A violation raises :class:`ReadOnlyViolationError`, which aborts the collection and is
recorded as a critical audit event (FR-COL-04). It is never caught and retried: it means
the platform tried to do something it guarantees it never does.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final, Literal
from urllib.parse import parse_qs, unquote

from netsecops.core.errors import ReadOnlyViolationError
from netsecops.core.logging import get_logger

log = get_logger(__name__)

HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


# ─────────────────────────── layer 1: injection guard ───────────────────────

#: Sequences that let one command become two, or that substitute a command's output.
#: Checked before anything else, because an allow-list match on the prefix is
#: meaningless if the suffix carries a second command.
COMMAND_SEPARATORS: Final[tuple[str, ...]] = (
    ";",
    "&&",
    "||",
    "\n",
    "\r",
    "`",
    "$(",
    "&",
    ">",
    "<",
)

#: ``|`` is legitimate in a few allow-listed Cisco commands (``show logging | include``),
#: so it is not a blanket separator. Adapters that must never pipe (FortiGate SSH, per
#: SRS §8.2) declare ``forbid_pipe=True`` on their policy instead.
PIPE: Final[str] = "|"


# ─────────────────────────── layer 3: the deny-list ─────────────────────────

#: SRS §8.1 item 2, verbatim in intent: obvious write verbs, blocked even when an
#: allow-list entry would have permitted them.
#:
#: ``diagnose`` carries a negative lookahead because most of FortiGate's ``diagnose sys``
#: and ``diagnose hardware`` subtrees read rather than act, while the rest of the
#: ``diagnose`` tree does not.
#:
#: **The lookahead is not a safety boundary, and the earlier wording here claimed it was.**
#: ``diagnose sys kill <signal> <pid>`` is a documented FortiGate command that terminates
#: a process, and this pattern lets it through. What actually contains the damage is the
#: allow-list, which admits exactly ``diagnose sys top`` from the whole tree — and which
#: is consulted *first*, so an unlisted ``diagnose`` command never reaches this pattern at
#: all. Widening a ``diagnose`` allow-list entry on the strength of this lookahead would
#: be relying on a guard that does not exist.
#: Radware Alteon is why the last alternative exists. Every other platform here writes
#: with a verb at the start of the command, which is what this anchored pattern catches.
#: Alteon writes by *navigating a menu tree*: `/cfg/sys/ssnmp/wcomm` sets the SNMP write
#: community, and `/cfg/dump` prints the configuration. They differ by a leaf, and
#: neither starts with a verb — so without `/cfg/`, layer 3 fires on nothing Alteon can
#: send and the allow-list is the only control left on the one platform where a typo
#: costs the most.
#:
#: `dump` is the single exception, and it is a whole-word one: `/cfg/dumpfoo` is denied.
DENY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?:"
    r"conf(?:igure)?(?:\s+t(?:erminal)?)?"
    r"|write|wr|copy|reload|erase|delete|format|install|upgrade"
    r"|set\s|unset\s|edit\s|commit|rollback|clear\s|debug\s|monitor\s|request\s|test\s"
    r"|ping|traceroute|exec\s|execute\s"
    r"|diagnose\s(?!sys|hardware)"
    r"|no\s|shutdown|boot"
    r"|/cfg/(?!dump\b)"
    r"|end$"
    r")",
    re.IGNORECASE,
)


# ───────────────────────────── allow-list entries ───────────────────────────

#: A ``<placeholder>`` in an allow-list entry stands for one argument token. The token
#: charset is deliberately tight: no whitespace, no separators, nothing that could carry
#: a second command even if the injection guard were bypassed.
_TOKEN: Final[str] = r"[A-Za-z0-9_.:/@=-]+"  # noqa: S105 - a regex charset, not a secret

_PLACEHOLDER = re.compile(r"<[a-z_]+>")
_OPTIONAL = re.compile(r"\[([^\]]+)\]")


@dataclass(frozen=True, slots=True)
class CommandRule:
    """One allow-list entry.

    ``session_only`` marks a command that looks like a write to the deny-list but only
    changes the CLI session — paging, terminal width, scripting mode. SRS §8.1 item 2
    names these as the explicit exceptions; requiring the flag keeps each one a
    deliberate, reviewable decision.
    """

    pattern: str
    session_only: bool = False
    note: str = ""

    def compile(self) -> re.Pattern[str]:
        """Translate the entry into an anchored regex.

        Entries are tokenised on whitespace, which is safe because commands are
        normalised before matching: ``[word]`` becomes an optional literal, ``<arg>``
        becomes exactly one safe token, and everything else is matched literally.
        Anchoring at both ends is what stops a permitted prefix from carrying a
        forbidden tail.
        """
        parts: list[str] = []

        for token in self.pattern.split():
            if optional := _OPTIONAL.fullmatch(token):
                parts.append(rf"(?:\s+{re.escape(optional.group(1))})?")
            elif _PLACEHOLDER.fullmatch(token):
                parts.append(rf"\s+{_TOKEN}")
            else:
                parts.append(rf"\s+{re.escape(token)}")

        body = "".join(parts)
        if body.startswith(r"\s+"):  # the first token has no leading whitespace
            body = body[3:]

        return re.compile(f"^{body}$", re.IGNORECASE)


# ───────────────────────────── HTTP allow rules ─────────────────────────────


@dataclass(frozen=True, slots=True)
class HttpRule:
    """One permitted HTTP operation.

    ``method`` is ``GET`` for ordinary reads. A ``POST`` rule must justify itself: SRS
    §8.1 item 3 permits POST only for authentication and for vendor APIs that are
    POST-only by design, and ``reason`` records which case applies.
    """

    method: HttpMethod
    #: Matched against the request path as a prefix, after the path has been resolved —
    #: see `resolve_path`. A prefix is only a safe way to permit a subtree if nothing
    #: can climb back out of it.
    path_prefix: str
    reason: str = ""
    #: What the request must satisfy to be permitted, checked against the POST body or,
    #: for a GET, against the parsed query string.
    #:
    #: **Both, because some vendor APIs accept the same operation either way.** PAN-OS's
    #: XML API is the case that matters: `type`, `action` and `cmd` travel in a POST body
    #: or a GET query string interchangeably, and the API is fully functional over GET —
    #: `action=set`, `action=delete` and `type=commit` all work. This rule was applied to
    #: the body alone until 2026-09-29, so the POST rule refused a configuration write
    #: while the GET rule beside it permitted the identical operation.
    body_predicate: str | None = None


# ────────────────────────────── platform policy ─────────────────────────────


@dataclass(frozen=True, slots=True)
class PlatformPolicy:
    """The complete read-only contract for one platform (SRS §8.2)."""

    platform: str
    commands: tuple[CommandRule, ...] = ()
    http: tuple[HttpRule, ...] = ()
    #: FortiGate SSH must never pipe (SRS §8.2); other platforms legitimately do.
    forbid_pipe: bool = False

    #: This platform is **never contacted**. It is assessed from an uploaded export
    #: (FR-COL-11) and NetSecOps holds no credential for it.
    #:
    #: A flag rather than an inferred property of two empty tuples, because the two
    #: states look identical and mean opposite things: an empty allow-list that nobody
    #: meant is a policy somebody forgot to fill in, and `test_every_policy_declares_
    #: something` exists to catch exactly that. Setting this says the emptiness is the
    #: point — which is a stronger read-only guarantee than any list of reads, since
    #: there is no rule for `check_request` to match and therefore nothing that can be
    #: sent at all.
    offline_only: bool = False

    _compiled: list[tuple[CommandRule, re.Pattern[str]]] = field(
        default_factory=list, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "_compiled", [(rule, rule.compile()) for rule in self.commands])

    def match(self, command: str) -> CommandRule | None:
        for rule, pattern in self._compiled:
            if pattern.match(command):
                return rule
        return None

    def describe(self) -> list[str]:
        """Human-readable allow-list, for ``netsecops-cli audit-commands`` (SRS §8.1.7)."""
        if self.offline_only:
            return [
                "(nothing — this platform is never contacted; it is assessed from an "
                "uploaded export, and no credential for it is held)"
            ]

        lines: list[str] = []
        for command_rule in self.commands:
            suffix = "   [session-only]" if command_rule.session_only else ""
            lines.append(f"{command_rule.pattern}{suffix}")
        for http_rule in self.http:
            lines.append(f"{http_rule.method} {http_rule.path_prefix}")
        return lines


# ─────────────────────────────────── guard ──────────────────────────────────


def normalise(command: str) -> str:
    """Collapse whitespace so spacing cannot change whether a command matches."""
    return re.sub(r"\s+", " ", command).strip()


class PathTraversalError(ValueError):
    """A request path tried to climb out of the subtree it named."""


def resolve_path(path: str) -> str:
    """The path a server would act on, or a refusal.

    ``path_prefix`` permits a subtree, which is only safe if nothing can climb back out
    of it. Until 2026-09-29 the guard normalised the leading slash and no more, so
    ``/api/v2/cmdb/firewall/policy/../../monitor/system/os/reboot`` satisfied
    ``startswith('/api/v2/cmdb/firewall/policy')`` and was permitted — as was the
    percent-encoded form, because nothing decoded it before comparing.

    Nothing could construct such a path at the time: every entry in ``profiles.py`` is a
    literal constant. It mattered because it was about to stop being true — collecting
    Firepower and Barracuda means splicing a policy UUID or a service name **the device
    itself returned** into a path, and a hostile appliance answering with a name like
    ``../../admin`` is the whole attack. A guard whose promise holds only while its
    callers are careful is not defence in depth.

    Decoding is repeated to a fixed point rather than done once: ``%252e%252e`` decodes
    to ``%2e%2e`` and then to ``..``, and a single pass would hand the comparison a
    string the server would still resolve further.
    """
    raw, separator, query = path.partition("?")

    decoded = raw
    for _ in range(4):
        once = unquote(decoded)
        if once == decoded:
            break
        decoded = once
    else:
        # Still changing after four passes. No legitimate path is encoded that deeply,
        # and refusing beats guessing at what the server would finally see.
        raise PathTraversalError("path is encoded too many times to resolve safely")

    if "\\" in decoded:
        # A backslash is a separator on the far side of several vendor stacks and not
        # one here, so it is a way to write a segment this comparison cannot see.
        raise PathTraversalError("path contains a backslash")

    segments = decoded.split("/")
    if any(segment == ".." for segment in segments):
        # Refused rather than collapsed. `posixpath.normpath` would resolve this into a
        # path that then compares cleanly, which turns a request that was trying to
        # escape into one that quietly succeeds somewhere else — the caller should be
        # told its path was wrong, not silently rewritten.
        raise PathTraversalError("path contains a '..' segment")

    resolved = "/" + "/".join(s for s in segments if s not in {"", "."})
    if decoded.endswith("/") and not resolved.endswith("/"):
        resolved += "/"
    return resolved + separator + query


class ReadOnlyGuard:
    """Enforces a :class:`PlatformPolicy`. One instance per adapter.

    Every emitted command and request passes through ``check_command`` /
    ``check_request``. Adapters never talk to a transport directly; the session wrapper
    calls the guard first, so an adapter cannot forget.
    """

    def __init__(self, policy: PlatformPolicy) -> None:
        self.policy = policy

    # ── commands ────────────────────────────────────────────────────────

    def check_command(self, command: str) -> CommandRule:
        """Return the rule permitting ``command``, or raise :class:`ReadOnlyViolationError`."""
        # The separator check runs on the RAW string, before normalisation. normalise()
        # collapses newlines and carriage returns into spaces, which would erase the
        # exact evidence this layer exists to find — a newline is a command separator on
        # every CLI here.
        self._reject_separators(command)

        candidate = normalise(command)
        if not candidate:
            raise ReadOnlyViolationError(
                "Refusing to send an empty command.", platform=self.policy.platform
            )

        rule = self.policy.match(candidate)
        if rule is None:
            raise ReadOnlyViolationError(
                "Command is not on the read-only allow-list and was not sent.",
                platform=self.policy.platform,
                command=candidate,
            )

        # Layer 3: the deny-list still applies, unless this entry is a declared
        # session-only exception. This is what catches a mis-specified allow-list.
        if not rule.session_only and DENY_PATTERN.match(candidate):
            raise ReadOnlyViolationError(
                "Command matched the allow-list but is a write verb; the allow-list "
                "entry is wrong. Refusing to send it.",
                platform=self.policy.platform,
                command=candidate,
                matched_rule=rule.pattern,
            )

        return rule

    def _reject_separators(self, command: str) -> None:
        for separator in COMMAND_SEPARATORS:
            if separator in command:
                raise ReadOnlyViolationError(
                    "Command contains a separator or substitution and was not sent.",
                    platform=self.policy.platform,
                    command=command,
                    separator=separator,
                )
        if self.policy.forbid_pipe and PIPE in command:
            raise ReadOnlyViolationError(
                "This platform must not pipe command output.",
                platform=self.policy.platform,
                command=command,
            )

    def permits_command(self, command: str) -> bool:
        """Non-raising form, for tests and the conformance harness."""
        try:
            self.check_command(command)
        except ReadOnlyViolationError:
            return False
        return True

    # ── HTTP ────────────────────────────────────────────────────────────

    def check_request(
        self,
        method: str,
        path: str,
        *,
        body: object = None,
    ) -> HttpRule:
        """Validate an HTTP operation against the policy (SRS §8.1 item 3)."""
        verb = method.upper()

        if verb in {"PUT", "PATCH", "DELETE"}:
            raise ReadOnlyViolationError(
                f"{verb} is never permitted against a device.",
                platform=self.policy.platform,
                path="/" + path.lstrip("/"),
            )

        try:
            normalised_path = resolve_path("/" + path.lstrip("/"))
        except PathTraversalError as exc:
            # Refused before any rule is consulted, like the command-injection check:
            # a path that has to be untangled before it can be compared is not a path
            # this product meant to send.
            raise ReadOnlyViolationError(
                f"Request path was not sent: {exc}.",
                platform=self.policy.platform,
                method=verb,
                path="/" + path.lstrip("/"),
            ) from exc

        # What the request is asking for, wherever this API carries it. PAN-OS accepts
        # the same parameters as a POST body or a GET query string, so a predicate that
        # read only the body left the GET side of an identical operation unguarded.
        parameters = body if verb == "POST" else _query_parameters(normalised_path)

        for rule in self.policy.http:
            if rule.method != verb:
                continue
            if not normalised_path.startswith(rule.path_prefix):
                continue
            if rule.body_predicate and not _body_permitted(rule.body_predicate, parameters):
                continue
            return rule

        raise ReadOnlyViolationError(
            "Request is not on the read-only allow-list and was not sent.",
            platform=self.policy.platform,
            method=verb,
            path=normalised_path,
        )

    def permits_request(self, method: str, path: str, *, body: object = None) -> bool:
        try:
            self.check_request(method, path, body=body)
        except ReadOnlyViolationError:
            return False
        return True


# ───────────────────────── POST body predicates ─────────────────────────────
#
# The vendor APIs that are POST-only by design still have to prove the operation is a
# read. Each predicate below encodes one of the cases SRS §8.1 item 3 enumerates.


BodyPredicate = Callable[[object], bool]


def _body_permitted(predicate: str, body: object) -> bool:
    checker = _BODY_PREDICATES.get(predicate)
    return checker(body) if checker else False


def _checkpoint_show_only(body: object) -> bool:
    """Check Point Management API: the command must be a read or a session call."""
    if not isinstance(body, dict):
        return False
    command = str(body.get("command", "")).lower()
    return command.startswith("show-") or command in {"login", "logout", "keepalive"}


def _fortimanager_get_only(body: object) -> bool:
    """FortiManager JSON-RPC: ``method`` must be ``get``, or a login/logout ``exec``."""
    if not isinstance(body, dict):
        return False
    method = str(body.get("method", "")).lower()
    if method == "get":
        return True
    if method != "exec":
        return False
    # exec is permitted only for session management (SRS §8.2).
    urls = [str(item.get("url", "")).lower() for item in body.get("params", []) or []]
    return bool(urls) and all(u in {"/sys/login/user", "/sys/logout"} for u in urls)


def _panos_read_only(body: object) -> bool:
    """PAN-OS XML API: only the read ``type`` values, and ``op`` only for show commands."""
    if not isinstance(body, dict):
        return False

    api_type = str(body.get("type", "")).lower()
    if api_type == "keygen":
        return True
    if api_type == "op":
        cmd = str(body.get("cmd", "")).strip().lower()
        # <request><license><info/></license></request> is a read despite the verb,
        # and SRS §8.2 lists it as an explicit exception.
        return cmd.startswith("<show>") or cmd.startswith("<request><license><info")
    if api_type == "config":
        return str(body.get("action", "")).lower() in {"show", "get"}
    if api_type == "export":
        return str(body.get("category", "")).lower() in {"configuration", "certificate"}
    return False


def _query_parameters(path: str) -> dict[str, str] | None:
    """A GET's query string as the predicates expect to read it, or None.

    None where a key appears more than once, and a rule with a predicate then has
    nothing it can approve. Picking one value would be guessing: which of two `type=`
    parameters a server acts on is a property of that server's parser, so a guard that
    examined the first while PAN-OS read the second would have approved an operation it
    never looked at. This product composes no such request, so refusing costs nothing.
    """
    _base, _sep, query = path.partition("?")
    if not query:
        return {}
    parsed = parse_qs(query, keep_blank_values=True)
    if any(len(values) > 1 for values in parsed.values()):
        return None
    return {key: values[0] for key, values in parsed.items()}


def _auth_only(body: object) -> bool:
    """Token-generation endpoints (Cisco FMC/ISE): the path already constrains these."""
    return True


_BODY_PREDICATES: Final[dict[str, BodyPredicate]] = {
    "checkpoint_show_only": _checkpoint_show_only,
    "fortimanager_get_only": _fortimanager_get_only,
    "panos_read_only": _panos_read_only,
    "auth_only": _auth_only,
}
