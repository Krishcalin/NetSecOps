"""The check definition schema (FR-CHK-01, FR-CHK-03).

A check is data, not code. This module is the contract that makes that possible, and
two decisions in it shape everything downstream.

**Missing data is not a failure.** If the NCM field a check reads is ``None`` — the
parser never found it, or the command that would have supplied it failed — the result
is *Not Evaluated*, never *Fail* (FR-COL-08). A check that reported "Telnet is
disabled" on a configuration it could not read would be worse than no check at all: it
would be confidently wrong, and nobody would know. An empty *list* is different: it is
a real answer, so ``users[?weak_hash]`` returning ``[]`` means "none", and passes.

**Remediation is text, and only text.** SRS §8 forbids NetSecOps from changing a
device, so there is no field here that could ever be executed, and no schema change
should add one. If a check wants to fix something, the answer is no.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        """Contribution to the risk score (FR-CHK-09).

        The gaps are deliberately wide. A linear 5/4/3/2/1 lets a pile of Low findings
        outweigh a Critical one, which is precisely the arithmetic that makes a risk
        score stop meaning anything.
        """
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]


class Outcome(StrEnum):
    """The six states of FR-CHK-03."""

    PASS = "pass"  # noqa: S105 - a check outcome, not a credential
    FAIL = "fail"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"
    #: The data the check needed was not collected or not parsed (FR-COL-08).
    NOT_EVALUATED = "not_evaluated"
    #: The check itself was broken — a bad expression, an exception in Python logic.
    ERROR = "error"

    @property
    def is_finding(self) -> bool:
        """Whether this outcome should raise a finding."""
        return self in {Outcome.FAIL, Outcome.WARNING}

    @property
    def counts_toward_compliance(self) -> bool:
        """Whether this outcome belongs in a compliance percentage.

        Not Applicable and Not Evaluated must not be counted as passes. A device whose
        collection half-failed would otherwise score better than one fully assessed.
        """
        return self in {Outcome.PASS, Outcome.FAIL, Outcome.WARNING}


class LogicType(StrEnum):
    NCM = "ncm"
    REGEX = "regex"
    PYTHON = "python"


class MissingPolicy(StrEnum):
    """What to do when the data a check needs is absent.

    ``NOT_EVALUATED`` is the default and almost always right. The exceptions are real
    but narrow: a check for "is a syslog server configured" wants absence to *fail*,
    because absence is exactly the finding.
    """

    NOT_EVALUATED = "not_evaluated"
    FAIL = "fail"
    PASS = "pass"  # noqa: S105 - a missing-data policy, not a credential


class Assertion(BaseModel):
    """What must be true of the value the expression selected.

    Exactly one operator per assertion. A single assertion doing two things would make
    the failure message ambiguous, and the failure message is what an operator reads.
    """

    model_config = ConfigDict(extra="forbid")

    equals: Any = None
    not_equals: Any = None
    in_: list[Any] | None = Field(default=None, alias="in")
    not_in: list[Any] | None = None
    gt: float | None = None
    gte: float | None = None
    lt: float | None = None
    lte: float | None = None
    #: True when the selected collection must be empty, False when it must not be.
    empty: bool | None = None
    contains: Any = None
    not_contains: Any = None
    matches: str | None = None
    not_matches: str | None = None
    #: Every member of the collection must satisfy this comparison.
    all_equal: Any = None
    count_lte: int | None = None
    count_gte: int | None = None

    _OPERATORS = (
        "equals",
        "not_equals",
        "in_",
        "not_in",
        "gt",
        "gte",
        "lt",
        "lte",
        "empty",
        "contains",
        "not_contains",
        "matches",
        "not_matches",
        "all_equal",
        "count_lte",
        "count_gte",
    )

    @model_validator(mode="after")
    def _exactly_one_operator(self) -> Self:
        # `equals: false` and `equals: 0` are the whole point of several checks, so
        # "was it supplied" has to be asked of the model's fields, not of truthiness.
        supplied = [name for name in self._OPERATORS if name in self.model_fields_set]
        if len(supplied) != 1:
            raise ValueError(
                f"An assertion needs exactly one operator, got {len(supplied)}: "
                f"{supplied or 'none'}"
            )
        return self

    @model_validator(mode="after")
    def _regexes_compile(self) -> Self:
        for pattern in (self.matches, self.not_matches):
            if pattern is not None:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise ValueError(f"Invalid regular expression {pattern!r}: {exc}") from exc
        return self

    @property
    def operator(self) -> str:
        return next(name for name in self._OPERATORS if name in self.model_fields_set)

    def describe(self) -> str:
        """Human wording, used in the failure message an operator reads."""
        operator = self.operator
        value = getattr(self, operator)
        phrases = {
            "equals": f"be {value!r}",
            "not_equals": f"not be {value!r}",
            "in_": f"be one of {value!r}",
            "not_in": f"not be one of {value!r}",
            "gt": f"be greater than {value}",
            "gte": f"be at least {value}",
            "lt": f"be less than {value}",
            "lte": f"be at most {value}",
            "empty": "be empty" if value else "not be empty",
            "contains": f"contain {value!r}",
            "not_contains": f"not contain {value!r}",
            "matches": f"match /{value}/",
            "not_matches": f"not match /{value}/",
            "all_equal": f"have every entry equal to {value!r}",
            "count_lte": f"have at most {value} entr{'y' if value == 1 else 'ies'}",
            "count_gte": f"have at least {value} entr{'y' if value == 1 else 'ies'}",
        }
        return phrases[operator]


class Applicability(BaseModel):
    """Which devices a check applies to (FR-CHK-01).

    An empty field means "any". Narrowing is opt-in, because a check that silently
    applied to nothing would look like it was passing everywhere.
    """

    model_config = ConfigDict(extra="forbid")

    vendors: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    device_classes: list[str] = Field(default_factory=list)
    #: Inclusive lower and exclusive upper bounds on the device's software version.
    min_version: str | None = None
    max_version: str | None = None
    #: NCM paths that must resolve to something for this check to mean anything. A
    #: check on wireless settings applied to a switch is Not Applicable, not a pass.
    requires_features: list[str] = Field(default_factory=list)


class CheckLogic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: LogicType = LogicType.NCM

    #: JMESPath over the NCM, for ``type: ncm``.
    expression: str | None = None
    assert_: Assertion | None = Field(default=None, alias="assert")

    #: For ``type: regex``: a pattern applied to the redacted configuration text.
    pattern: str | None = None
    #: Whether the pattern matching or not matching is the passing condition.
    expect: Literal["present", "absent"] = "absent"

    #: For ``type: python``: the name a check function registered under.
    function: str | None = None

    #: NCM paths whose absence makes this check Not Evaluated rather than Fail.
    requires: list[str] = Field(default_factory=list)
    missing: MissingPolicy = MissingPolicy.NOT_EVALUATED

    #: NCM paths to look up in the snapshot's provenance map for evidence. Defaults to
    #: the expression when it is a plain dotted path.
    provenance: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _fields_match_the_type(self) -> Self:
        if self.type is LogicType.NCM:
            if not self.expression or self.assert_ is None:
                raise ValueError("An 'ncm' check needs both 'expression' and 'assert'.")
        elif self.type is LogicType.REGEX:
            if not self.pattern:
                raise ValueError("A 'regex' check needs 'pattern'.")
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"Invalid regular expression {self.pattern!r}: {exc}") from exc
        elif self.type is LogicType.PYTHON and not self.function:
            raise ValueError("A 'python' check needs 'function'.")
        return self

    def provenance_paths(self) -> list[str]:
        """Where to look for the configuration lines behind this result."""
        if self.provenance:
            return self.provenance
        if self.type is LogicType.NCM and self.expression and _IS_PLAIN_PATH.match(self.expression):
            return [self.expression]
        return []


#: A JMESPath expression that is just a dotted path, and so doubles as a provenance key.
_IS_PLAIN_PATH = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")


class References(BaseModel):
    """Where this check comes from (FR-CHK-05 framework mapping).

    Framework identifiers are attributes of the check rather than of a policy, so a
    compliance view can pivot by framework without the policy having to anticipate it.
    """

    model_config = ConfigDict(extra="forbid")

    cis: list[str] = Field(default_factory=list)
    nist_800_53: list[str] = Field(default_factory=list)
    pci_dss: list[str] = Field(default_factory=list)
    iso_27001: list[str] = Field(default_factory=list)
    cert_in: list[str] = Field(default_factory=list)
    cea: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)

    def frameworks(self) -> dict[str, list[str]]:
        """Non-empty framework mappings, for pivoting a compliance view."""
        return {
            name: value
            for name, value in self.model_dump().items()
            if value and name not in {"urls", "cve", "cwe"}
        }


#: Check ids look like `cisco-ios-telnet-disabled`: vendor-platform-subject, lowercase.
#: Stable, because a finding's identity is built from it and renaming one would orphan
#: every historical finding it produced.
CHECK_ID = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


class CheckDefinition(BaseModel):
    """One check, as loaded from ``checks/<vendor-or-common>/<id>.yaml``."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1)
    #: *Why* this matters. Without it a finding is an assertion the reader must take on
    #: trust, and the first question anyone asks of a failed check is "so what?".
    rationale: str = Field(min_length=1)
    severity: Severity

    applicability: Applicability = Field(default_factory=Applicability)
    logic: CheckLogic

    #: Text only. SRS §8: NetSecOps never changes a device, so this is never executed.
    remediation: str = Field(min_length=1)
    references: References = Field(default_factory=References)
    tags: list[str] = Field(default_factory=list)

    #: Bumped when the logic changes. Results record it, so a finding can be traced to
    #: the version of the check that produced it (FR-CHK-08).
    version: int = 1
    #: False for a check that ships disabled — one that is too noisy or too
    #: environment-specific to be on by default, but worth having available.
    enabled_by_default: bool = True

    @model_validator(mode="after")
    def _id_is_well_formed(self) -> Self:
        if not CHECK_ID.match(self.id):
            raise ValueError(
                f"Check id {self.id!r} must be lowercase words joined by hyphens, "
                "e.g. 'cisco-ios-telnet-disabled'."
            )
        return self

    @property
    def is_python(self) -> bool:
        return self.logic.type is LogicType.PYTHON


__all__ = [
    "CHECK_ID",
    "Applicability",
    "Assertion",
    "CheckDefinition",
    "CheckLogic",
    "LogicType",
    "MissingPolicy",
    "Outcome",
    "References",
    "Severity",
]
