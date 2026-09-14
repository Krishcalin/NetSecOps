"""Parser framework (FR-PARSE-01 … FR-PARSE-05).

A parser turns raw command output into an :class:`NormalisedConfig`. Three rules apply
to every one of them:

**Tolerance (FR-PARSE-03).** An unrecognised stanza is recorded in ``raw_unparsed`` and
never raises. Network configurations are enormous and vendor syntax drifts between
releases; a parser that failed on the first surprise would be useless in the field, and
silently dropping the stanza would hide what we missed.

**Provenance (FR-PARSE-04).** Every value records the artefact and line range it came
from, so a finding can show the offending configuration rather than asserting a
conclusion.

**Distinguish absent from false.** Leaving a field ``None`` means "not found" and makes
a check report *Not Evaluated*. Writing ``False`` means "found, and it is off". Blurring
the two produces confident, wrong findings.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ciscoconfparse2 import CiscoConfParse
from ciscoconfparse2.models_cisco import IOSCfgLine

from netsecops.core.logging import get_logger
from netsecops.core.redaction import redact_line
from netsecops.ncm.models import NormalisedConfig, Provenance

log = get_logger(__name__)


@dataclass(slots=True)
class ParseContext:
    """What a parser is working on, and where the results came from.

    ``artifact_id`` and ``command`` are carried so provenance can name the exact
    artefact; in unit tests they are None, which is fine — provenance line numbers are
    still recorded and are what the assertions check.
    """

    text: str
    artifact_id: str | None = None
    command: str | None = None
    lines: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.lines:
            self.lines = self.text.splitlines()

    def excerpt(self, line_start: int, line_end: int | None = None) -> str:
        """Redacted configuration text for a 1-based, inclusive line range.

        Redacted at the point of capture: an excerpt is copied into findings and
        tickets, so a secret that reached one would spread further than the config
        ever did (FR-COL-13).
        """
        end = line_end or line_start
        selected = self.lines[line_start - 1 : end]
        return "\n".join(redact_line(line)[0] for line in selected)

    def provenance(self, line_start: int, line_end: int | None = None) -> Provenance:
        return Provenance(
            artifact_id=self.artifact_id,
            command=self.command,
            line_start=line_start,
            line_end=line_end or line_start,
            excerpt=self.excerpt(line_start, line_end),
        )


class ParseResult:
    """An NCM under construction, with provenance recorded as values are set."""

    def __init__(self, context: ParseContext) -> None:
        self.context = context
        self.ncm = NormalisedConfig()
        self._consumed: set[int] = set()

    # ── recording ───────────────────────────────────────────────────────

    def record(self, path: str, *, line: int | None = None, line_end: int | None = None) -> None:
        """Note where the value at ``path`` came from (FR-PARSE-04)."""
        if line is None:
            return
        self.ncm.provenance.record(path, self.context.provenance(line, line_end))
        self.consume(line, line_end)

    def consume(self, line: int, line_end: int | None = None) -> None:
        """Mark lines as understood, so the rest can be reported as unparsed."""
        for n in range(line, (line_end or line) + 1):
            self._consumed.add(n)

    def finalise_unparsed(self, *, ignore: re.Pattern[str] | None = None) -> None:
        """Collect every line no rule claimed (FR-PARSE-03).

        This is the honesty mechanism: it makes parser coverage visible rather than
        letting unrecognised configuration disappear.
        """
        leftovers: list[str] = []
        for number, text in enumerate(self.context.lines, start=1):
            if number in self._consumed:
                continue
            stripped = text.strip()
            if not stripped or stripped == "!" or stripped.startswith("!"):
                continue
            if ignore is not None and ignore.match(stripped):
                continue
            leftovers.append(f"{number}: {redact_line(text)[0].strip()}")

        self.ncm.raw_unparsed = leftovers

    @property
    def consumed_lines(self) -> int:
        return len(self._consumed)


class ConfigParser(ABC):
    """Base for a device-configuration parser."""

    vendor: str = ""
    platform: str = ""

    #: Lines that are structurally meaningless and should not count as unparsed.
    IGNORE: re.Pattern[str] = re.compile(
        r"^(end|exit|Building configuration|Current configuration)"
    )

    @abstractmethod
    def parse(self, context: ParseContext) -> NormalisedConfig:
        """Produce an NCM. Must not raise on unexpected input (FR-PARSE-03)."""

    def parse_text(
        self, text: str, *, artifact_id: str | None = None, command: str | None = None
    ) -> NormalisedConfig:
        return self.parse(ParseContext(text=text, artifact_id=artifact_id, command=command))


class CiscoStyleParser(ConfigParser):
    """Shared helpers for indentation-structured Cisco configurations.

    ciscoconfparse2 supplies the hierarchy; these helpers add 1-based line numbers
    (operators count from one, the library counts from zero) and the None-versus-False
    discipline the NCM depends on.
    """

    syntax: str = "ios"

    def build(self, context: ParseContext) -> CiscoConfParse:
        return CiscoConfParse(context.lines, syntax=self.syntax)

    @staticmethod
    def line_number(obj: IOSCfgLine) -> int:
        """ciscoconfparse2 line numbers are 0-based; NCM provenance is 1-based."""
        return int(obj.linenum) + 1

    @staticmethod
    def family_range(obj: IOSCfgLine) -> tuple[int, int]:
        """The 1-based line span of a stanza and everything indented under it."""
        start = int(obj.linenum) + 1
        children = list(obj.all_children)
        end = (int(children[-1].linenum) + 1) if children else start
        return start, end

    @staticmethod
    def first(parse: CiscoConfParse, pattern: str) -> IOSCfgLine | None:
        matches = parse.find_objects(pattern)
        return matches[0] if matches else None

    @staticmethod
    def capture(obj: IOSCfgLine | None, pattern: str, group: int = 1) -> str | None:
        if obj is None:
            return None
        match = re.search(pattern, obj.text)
        return match.group(group) if match else None

    @staticmethod
    def capture_int(obj: IOSCfgLine | None, pattern: str, group: int = 1) -> int | None:
        value = CiscoStyleParser.capture(obj, pattern, group)
        try:
            return int(value) if value is not None else None
        except ValueError:
            return None

    @staticmethod
    def present(parse: CiscoConfParse, pattern: str) -> bool:
        return bool(parse.find_objects(pattern))


def timeout_to_seconds(minutes: str | int | None, seconds: str | int | None = 0) -> int | None:
    """Cisco writes timeouts as ``<minutes> <seconds>``; the NCM stores seconds."""
    if minutes is None:
        return None
    try:
        return int(minutes) * 60 + int(seconds or 0)
    except (TypeError, ValueError):
        return None


def first_known(*values: bool | None) -> bool | None:
    """The first value that is a real answer, treating ``False`` as one.

    Exists because ``a or b`` is the obvious spelling and is wrong for three-state
    fields: ``False or None`` is ``None``, so a source explicitly reporting a setting as
    *off* — which is usually the finding — comes through as "not determined" and the
    check reports Not Evaluated instead of Fail.

    That bug was written four times during Phase 5 alone, in four different parsers, by
    someone who knew about it: in ISE's MFA flag, FortiAuthenticator's LDAP TLS flag,
    tac_plus's default-service verdict and FreeRADIUS's ``start_tls``. It is a helper
    rather than a comment because the comment did not work.
    """
    for value in values:
        if value is not None:
            return value
    return None


def mask_secret(value: str) -> str:
    """Mask a credential found in configuration, keeping only its shape.

    Used for SNMP community *names*, which the NCM records so checks can compare them
    against known defaults without the real string ever being stored.
    """
    from netsecops.core.redaction import fingerprint

    return f"{value[:1]}***{len(value)}:{fingerprint(value)}"


KNOWN_DEFAULT_COMMUNITIES: frozenset[str] = frozenset(
    {"public", "private", "cisco", "admin", "secret", "community", "read", "write", "snmp"}
)


def is_default_community(value: str) -> bool:
    """Whether an SNMP community is a well-known default (Appendix B)."""
    return value.strip().lower() in KNOWN_DEFAULT_COMMUNITIES


__all__ = [
    "KNOWN_DEFAULT_COMMUNITIES",
    "CiscoStyleParser",
    "ConfigParser",
    "ParseContext",
    "ParseResult",
    "first_known",
    "is_default_community",
    "mask_secret",
    "timeout_to_seconds",
]
