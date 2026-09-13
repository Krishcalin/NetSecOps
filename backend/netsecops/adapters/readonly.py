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
#: ``diagnose`` carries a negative lookahead because FortiGate's ``diagnose sys`` and
#: ``diagnose hardware`` are read-only, while the rest of the ``diagnose`` tree is not.
DENY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?:"
    r"conf(?:igure)?(?:\s+t(?:erminal)?)?"
    r"|write|wr|copy|reload|erase|delete|format|install|upgrade"
    r"|set\s|unset\s|edit\s|commit|rollback|clear\s|debug\s|monitor\s|request\s|test\s"
    r"|ping|traceroute|exec\s|execute\s"
    r"|diagnose\s(?!sys|hardware)"
    r"|no\s|shutdown|boot"
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
    #: Matched against the request path as a prefix, after normalising the leading slash.
    path_prefix: str
    reason: str = ""
    #: For POST-only vendor APIs: the body must satisfy this to be permitted.
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
        normalised_path = "/" + path.lstrip("/")

        if verb in {"PUT", "PATCH", "DELETE"}:
            raise ReadOnlyViolationError(
                f"{verb} is never permitted against a device.",
                platform=self.policy.platform,
                path=normalised_path,
            )

        for rule in self.policy.http:
            if rule.method != verb:
                continue
            if not normalised_path.startswith(rule.path_prefix):
                continue
            if rule.body_predicate and not _body_permitted(rule.body_predicate, body):
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


def _auth_only(body: object) -> bool:
    """Token-generation endpoints (Cisco FMC/ISE): the path already constrains these."""
    return True


_BODY_PREDICATES: Final[dict[str, BodyPredicate]] = {
    "checkpoint_show_only": _checkpoint_show_only,
    "fortimanager_get_only": _fortimanager_get_only,
    "panos_read_only": _panos_read_only,
    "auth_only": _auth_only,
}
