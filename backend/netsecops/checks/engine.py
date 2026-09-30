"""Check evaluation (FR-CHK-01 … FR-CHK-03, FR-COL-08).

The engine turns a check definition and a snapshot into one :class:`CheckResult`. It
is deliberately free of the database and of HTTP, so a check can be evaluated in a unit
test, in the "test against device" dry run of FR-CHK-06, and by the job runner, with
identical behaviour.

Three rules govern every path through here:

**Absent is not false.** An NCM field that is ``None`` means the parser never found it.
The result is *Not Evaluated*, and it says which path was missing. A check that read a
half-parsed configuration and reported *Pass* would be the most damaging bug this
system could have, because it would look exactly like good news.

**An empty list is an answer.** ``users[?weak_hash]`` returning ``[]`` means there are
no weak users. Only ``None`` means "we do not know".

**A broken check is an Error, not a Fail.** A bad JMESPath expression or an exception
inside a Python check produces *Error* against that check alone. The other checks in
the policy still run — one malformed YAML file must not cost an entire assessment.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import jmespath
from jmespath.exceptions import JMESPathError
from packaging.version import InvalidVersion, Version

from netsecops.checks.schema import (
    Assertion,
    CheckDefinition,
    GoldenBlock,
    LogicType,
    MissingPolicy,
    Outcome,
    Severity,
)
from netsecops.core.logging import get_logger

log = get_logger(__name__)

#: Sentinel for "the expression selected nothing", which JMESPath also spells None.
MISSING = object()


@dataclass(frozen=True, slots=True)
class EvidenceLine:
    """One configuration line behind a result (FR-PARSE-04, FR-FIND-04)."""

    path: str
    line_start: int | None
    line_end: int | None
    #: Already redacted: provenance excerpts are redacted at capture in Phase 2.
    excerpt: str | None
    command: str | None = None


@dataclass(slots=True)
class CheckResult:
    check_id: str
    outcome: Outcome
    severity: Severity
    title: str
    #: One sentence saying what was found. This is the finding's description.
    message: str
    #: The value the expression selected, for the evidence block. Never raw config.
    observed: Any = None
    expected: str | None = None
    evidence: list[EvidenceLine] = field(default_factory=list)
    #: Why a check was skipped: the missing NCM path, or the applicability rule.
    reason: str | None = None
    check_version: int = 1
    duration_ms: int = 0

    @property
    def is_finding(self) -> bool:
        return self.outcome.is_finding


class DeviceContext:
    """What the engine knows about the device being assessed.

    Kept separate from the snapshot because applicability is about the *device*
    (vendor, class, version) while the logic is about its *configuration*.
    """

    def __init__(
        self,
        *,
        vendor: str | None = None,
        platform: str | None = None,
        device_class: str | None = None,
        version: str | None = None,
        hostname: str | None = None,
    ) -> None:
        self.vendor = (vendor or "").lower()
        self.platform = (platform or "").lower()
        self.device_class = (device_class or "").lower()
        self.version = version
        self.hostname = hostname

    @classmethod
    def from_ncm(cls, ncm: Mapping[str, Any], **overrides: Any) -> DeviceContext:
        device = ncm.get("device") or {}
        merged: dict[str, Any] = {
            "vendor": device.get("vendor"),
            "platform": device.get("platform"),
            "version": device.get("version"),
            "hostname": device.get("hostname"),
        }
        merged.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**merged)


#: Signature of a Python-implemented check (FR-CHK-02).
PythonCheck = Callable[["EvaluationContext"], "CheckResult | Outcome | tuple[Outcome, str]"]

_PYTHON_CHECKS: dict[str, PythonCheck] = {}


def python_check(name: str) -> Callable[[PythonCheck], PythonCheck]:
    """Register a Python check under ``name``, matching a YAML ``function:`` field.

    The metadata still lives in YAML (FR-CHK-02), so a Python check is discoverable,
    documented and framework-mapped exactly like a declarative one. Only the logic
    differs.
    """

    def register(function: PythonCheck) -> PythonCheck:
        if name in _PYTHON_CHECKS:
            raise ValueError(f"A Python check named {name!r} is already registered.")
        _PYTHON_CHECKS[name] = function
        return function

    return register


def registered_python_checks() -> dict[str, PythonCheck]:
    return dict(_PYTHON_CHECKS)


@dataclass(slots=True)
class EvaluationContext:
    """Everything a check may read. Python checks receive this."""

    check: CheckDefinition
    ncm: Mapping[str, Any]
    device: DeviceContext
    #: The redacted configuration, for regex checks. Never the original.
    config_text: str = ""
    provenance: Mapping[str, Any] = field(default_factory=dict)

    def select(self, expression: str) -> Any:
        """Run a JMESPath expression over the NCM."""
        return jmespath.search(expression, dict(self.ncm))

    def evidence_for(self, *paths: str) -> list[EvidenceLine]:
        return _evidence(self.provenance, paths)


# ────────────────────────────── applicability ───────────────────────────────


def _version_of(raw: str | None) -> Version | None:
    """Parse a device version leniently.

    Network versions are not PEP 440: `17.9(4a)`, `10.3(4a)`, `9.18(2)`, `15.2(7)E3`.
    The numeric prefix is the part version ranges are ever written against, so that is
    what is compared, and anything unparseable returns None rather than guessing.
    """
    if not raw:
        return None
    match = re.match(r"^(\d+(?:\.\d+)*)", raw.strip())
    if not match:
        return None
    try:
        return Version(match.group(1))
    except InvalidVersion:  # pragma: no cover - the regex already constrains this
        return None


def applies_to(check: CheckDefinition, device: DeviceContext, ncm: Mapping[str, Any]) -> str | None:
    """Return None if the check applies, or the reason it does not.

    Returning the reason rather than a bare bool is what lets a *Not Applicable* result
    say "this check is for firewalls" instead of leaving a blank in the report.
    """
    rules = check.applicability

    if rules.vendors and device.vendor not in {v.lower() for v in rules.vendors}:
        return f"This check applies to {', '.join(rules.vendors)}; the device is {device.vendor or 'unclassified'}."

    if rules.platforms and device.platform not in {p.lower() for p in rules.platforms}:
        return f"This check applies to {', '.join(rules.platforms)}; the device is {device.platform or 'unclassified'}."

    if rules.device_classes and device.device_class not in {
        c.lower() for c in rules.device_classes
    }:
        return (
            f"This check applies to {', '.join(rules.device_classes)} devices; "
            f"this one is {device.device_class or 'unclassified'}."
        )

    if rules.min_version or rules.max_version:
        current = _version_of(device.version)
        if current is None:
            # An unknown version cannot be excluded. Running the check and reporting
            # honestly beats silently skipping it, which would read as a pass.
            log.debug("check.version_unknown", check=check.id, version=device.version)
        else:
            low = _version_of(rules.min_version)
            high = _version_of(rules.max_version)
            if low is not None and current < low:
                return f"This check applies from version {rules.min_version}; the device runs {device.version}."
            if high is not None and current >= high:
                return f"This check applies below version {rules.max_version}; the device runs {device.version}."

    for feature in rules.requires_features:
        if jmespath.search(feature, dict(ncm)) in (None, [], {}):
            return f"The device does not have {feature.rsplit('.', 1)[-1]} configured."

    return None


# ─────────────────────────────── assertions ─────────────────────────────────


def _as_sequence(value: Any) -> Sequence[Any]:
    if value is None:
        return []
    if isinstance(value, str | bytes):
        return [value]
    if isinstance(value, Sequence):
        return value
    if isinstance(value, Iterable):
        return list(value)
    return [value]


def _comparable(value: Any) -> float | None:
    """Coerce to a number for the ordering operators, or None if it is not one.

    Booleans are excluded deliberately: `True > 0` is true in Python and meaningless
    in a check.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def evaluate_assertion(assertion: Assertion, value: Any) -> tuple[bool, str]:
    """Apply one assertion. Returns ``(passed, observed-description)``."""
    operator = assertion.operator
    expected = getattr(assertion, operator)

    match operator:
        case "equals":
            return value == expected, repr(value)
        case "not_equals":
            return value != expected, repr(value)
        case "in_":
            return value in expected, repr(value)
        case "not_in":
            return value not in expected, repr(value)
        case "gt" | "gte" | "lt" | "lte":
            number = _comparable(value)
            if number is None:
                return False, f"{value!r} (not a number)"
            passed = {
                "gt": number > expected,
                "gte": number >= expected,
                "lt": number < expected,
                "lte": number <= expected,
            }[operator]
            return passed, repr(value)
        case "empty":
            items = _as_sequence(value)
            is_empty = len(items) == 0
            return (is_empty == expected), f"{len(items)} entr{'y' if len(items) == 1 else 'ies'}"
        case "contains":
            return expected in _as_sequence(value), repr(value)
        case "not_contains":
            return expected not in _as_sequence(value), repr(value)
        case "matches":
            text = "" if value is None else str(value)
            return re.search(str(expected), text) is not None, repr(value)
        case "not_matches":
            text = "" if value is None else str(value)
            return re.search(str(expected), text) is None, repr(value)
        case "all_equal":
            items = _as_sequence(value)
            offenders = [item for item in items if item != expected]
            return not offenders, f"{len(offenders)} of {len(items)} differ"
        case "count_lte":
            items = _as_sequence(value)
            return len(items) <= expected, f"{len(items)} entr{'y' if len(items) == 1 else 'ies'}"
        case "count_gte":
            items = _as_sequence(value)
            return len(items) >= expected, f"{len(items)} entr{'y' if len(items) == 1 else 'ies'}"
        case _:  # pragma: no cover - the schema validator forbids this
            raise ValueError(f"Unknown assertion operator: {operator}")


# ───────────────────────────────── evidence ─────────────────────────────────


def _evidence(provenance: Mapping[str, Any], paths: Iterable[str]) -> list[EvidenceLine]:
    """Look up configuration lines for the given NCM paths.

    Provenance is stored keyed by exact path, but a check often reads a leaf whose
    provenance was recorded against its parent stanza (an interface, an ACL). So an
    exact hit is preferred, and a prefix match is the fallback rather than returning
    nothing — evidence at the wrong granularity still shows the operator the right
    part of their configuration.
    """
    entries: Mapping[str, Any] = provenance.get("entries", {}) if provenance else {}
    if not entries:
        return []

    found: list[EvidenceLine] = []
    seen: set[str] = set()

    for path in paths:
        keys = [path] if path in entries else sorted(k for k in entries if k.startswith(f"{path}."))
        if not keys:
            # The leaf has no provenance of its own; fall back to the nearest recorded
            # ancestor, e.g. `management.services.ssh` for `...ssh.version`.
            parts = path.split(".")
            while len(parts) > 1:
                parts.pop()
                ancestor = ".".join(parts)
                if ancestor in entries:
                    keys = [ancestor]
                    break

        for key in keys:
            if key in seen:
                continue
            seen.add(key)
            entry = entries[key] or {}
            found.append(
                EvidenceLine(
                    path=key,
                    line_start=entry.get("line_start"),
                    line_end=entry.get("line_end"),
                    excerpt=entry.get("excerpt"),
                    command=entry.get("command"),
                )
            )

    # A finding carrying fifty excerpts is not evidence, it is a haystack.
    return found[:10]


# ──────────────────────────────── evaluation ────────────────────────────────


def _missing_outcome(policy: MissingPolicy) -> Outcome:
    return {
        MissingPolicy.NOT_EVALUATED: Outcome.NOT_EVALUATED,
        MissingPolicy.FAIL: Outcome.FAIL,
        MissingPolicy.PASS: Outcome.PASS,
    }[policy]


def evaluate(
    check: CheckDefinition,
    ncm: Mapping[str, Any],
    *,
    device: DeviceContext | None = None,
    config_text: str = "",
    severity_override: Severity | None = None,
) -> CheckResult:
    """Evaluate one check against one snapshot. Never raises."""
    started = time.perf_counter()
    severity = severity_override or check.severity
    context = DeviceContext.from_ncm(ncm) if device is None else device
    provenance = ncm.get("provenance") or {}

    def finish(
        outcome: Outcome,
        message: str,
        *,
        observed: Any = None,
        expected: str | None = None,
        evidence: list[EvidenceLine] | None = None,
        reason: str | None = None,
    ) -> CheckResult:
        return CheckResult(
            check_id=check.id,
            outcome=outcome,
            severity=severity,
            title=check.title,
            message=message,
            observed=observed,
            expected=expected,
            evidence=evidence or [],
            reason=reason,
            check_version=check.version,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    try:
        if (reason := applies_to(check, context, ncm)) is not None:
            return finish(Outcome.NOT_APPLICABLE, reason, reason=reason)

        # Required data comes first: a check whose inputs are missing must report that,
        # not a verdict derived from their absence (FR-COL-08).
        for path in check.logic.requires:
            if jmespath.search(path, dict(ncm)) is None:
                message = (
                    f"Not evaluated: the configuration did not provide {path}. "
                    "The command that supplies it may have failed, or the parser did "
                    "not recognise this platform's syntax."
                )
                return finish(
                    _missing_outcome(check.logic.missing), message, reason=f"missing:{path}"
                )

        evaluation = EvaluationContext(
            check=check,
            ncm=ncm,
            device=context,
            config_text=config_text,
            provenance=provenance,
        )

        match check.logic.type:
            case LogicType.NCM:
                return _evaluate_ncm(check, evaluation, finish)
            case LogicType.REGEX:
                return _evaluate_regex(check, evaluation, finish)
            case LogicType.PYTHON:
                return _evaluate_python(check, evaluation, finish, severity)
            case LogicType.GOLDEN:
                return _evaluate_golden(check, evaluation, finish)

    except Exception as exc:
        # A broken check must never stop the policy: the other forty still have to run.
        log.warning("check.error", check=check.id, error=str(exc), error_type=type(exc).__name__)
        return finish(
            Outcome.ERROR,
            f"This check could not be evaluated: {type(exc).__name__}: {exc}",
            reason="error",
        )

    raise AssertionError("unreachable")  # pragma: no cover


_Finish = Callable[..., CheckResult]


def _evaluate_ncm(
    check: CheckDefinition, context: EvaluationContext, finish: _Finish
) -> CheckResult:
    logic = check.logic
    assert logic.expression is not None and logic.assert_ is not None  # noqa: S101 - schema-enforced

    try:
        value = context.select(logic.expression)
    except JMESPathError as exc:
        return finish(
            Outcome.ERROR,
            f"The check's expression is invalid: {exc}",
            reason="bad-expression",
        )

    # `None` means the parser did not find it; `[]` means it found none, which is an
    # answer. Conflating them is how a check comes to report confident nonsense.
    #
    # Every operator honours this, `empty`/`count_*` included. Excluding them (as this
    # did until the 2026-09-30 audit) let absent data satisfy `empty: true` — the parser
    # produced no `users` key, `_as_sequence(None)` is `[]`, so "no cleartext users"
    # read as a confident PASS over a device nothing was collected from. It also
    # overrode the check's own `missing:` policy: `aaa-server-redundancy` asks for
    # `not_evaluated` on absent data and got a FAIL. The check's declared policy decides
    # what absence means — a count check that wants absent-is-a-failure sets
    # `missing: fail` (ntp/syslog/management-acl already do).
    if value is None:
        message = (
            f"Not evaluated: the configuration did not state {logic.expression}. "
            "Absence here means the setting was not found, which is not the same as "
            "it being off."
        )
        return finish(
            _missing_outcome(logic.missing),
            message,
            reason=f"missing:{logic.expression}",
            evidence=context.evidence_for(*logic.provenance_paths()),
        )

    passed, observed = evaluate_assertion(logic.assert_, value)
    expected = f"{logic.expression} should {logic.assert_.describe()}"
    evidence = context.evidence_for(*logic.provenance_paths())

    if passed:
        return finish(
            Outcome.PASS,
            f"{check.title}: as expected ({observed}).",
            observed=value,
            expected=expected,
            evidence=evidence,
        )

    return finish(
        Outcome.FAIL,
        f"{logic.expression} is {observed}, but it should {logic.assert_.describe()}.",
        observed=value,
        expected=expected,
        evidence=evidence,
    )


#: Lines ignored when deciding whether a block's lines are adjacent. A comment or a
#: blank between two required lines is formatting, not a gap in the configuration, and
#: treating it as one would fail every device whose config has been tidied.
_NOISE = re.compile(r"^\s*(?:!|#|$)")


def _normalise(line: str) -> str:
    """Strip indentation and collapse runs of whitespace.

    Indentation is how IOS shows sub-mode and it is genuinely meaningful, but it is
    also inconsistent between releases and between what a device prints and what
    somebody pasted into a template. Comparing on the stripped text matches what an
    operator means by "this line is present"; a block that truly depends on nesting
    should use `match: regex` and say so explicitly.
    """
    return " ".join(line.split())


def _find(needle: str, lines: list[tuple[int, str]], *, regex: bool) -> list[int]:
    """Every line number matching one required line."""
    if regex:
        pattern = re.compile(needle)
        return [number for number, text in lines if pattern.search(text)]
    wanted = _normalise(needle)
    return [number for number, text in lines if _normalise(text) == wanted]


def _contiguous_run(block: GoldenBlock, lines: list[tuple[int, str]]) -> int | None:
    """The line number where the block's lines appear consecutively, or None.

    Blank lines and comments between them do not break the run — see `_NOISE`.
    """
    meaningful = [(number, text) for number, text in lines if not _NOISE.match(text)]
    span = len(block.lines)
    for start in range(len(meaningful) - span + 1):
        window = meaningful[start : start + span]
        if all(
            _find(wanted, [candidate], regex=block.match == "regex")
            for wanted, candidate in zip(block.lines, window, strict=True)
        ):
            return window[0][0]
    return None


def _evaluate_golden(
    check: CheckDefinition, context: EvaluationContext, finish: _Finish
) -> CheckResult:
    """Measure a configuration against a golden template (FR-DRIFT-04).

    **Every block is evaluated, not just up to the first failure.** A template exists
    to answer "how far is this device from the standard build", and stopping at the
    first missing line turns that into "at least one thing is wrong" — which sends
    somebody back for a second pass after each fix.

    **The message names what is missing or forbidden**, block by block. "Does not
    match the golden config" is not something anybody can act on.
    """
    logic = check.logic

    if not context.config_text:
        return finish(
            _missing_outcome(logic.missing),
            "Not evaluated: no configuration text was available to compare against the template.",
            reason="missing:config_text",
        )

    lines = list(enumerate(context.config_text.splitlines(), start=1))
    regex = False
    failures: list[str] = []
    evidence: list[EvidenceLine] = []
    passed_blocks = 0

    for block in logic.blocks:
        regex = block.match == "regex"

        if block.expect == "present":
            if block.contiguous:
                start = _contiguous_run(block, lines)
                if start is None:
                    failures.append(
                        f"{block.name}: the {len(block.lines)} lines are not present consecutively"
                    )
                    continue
                passed_blocks += 1
                evidence.append(
                    EvidenceLine(
                        path="config",
                        line_start=start,
                        line_end=start + len(block.lines) - 1,
                        excerpt=_normalise(block.lines[0]),
                    )
                )
                continue

            missing = [wanted for wanted in block.lines if not _find(wanted, lines, regex=regex)]
            if missing:
                shown = ", ".join(repr(line) for line in missing[:3])
                more = f" and {len(missing) - 3} more" if len(missing) > 3 else ""
                failures.append(f"{block.name}: missing {shown}{more}")
                continue
            passed_blocks += 1
            first = _find(block.lines[0], lines, regex=regex)[0]
            evidence.append(
                EvidenceLine(
                    path="config",
                    line_start=first,
                    line_end=first,
                    excerpt=_normalise(dict(lines)[first]),
                )
            )
            continue

        # expect == "absent"
        found = [
            (wanted, number)
            for wanted in block.lines
            for number in _find(wanted, lines, regex=regex)
        ]
        if found:
            shown = ", ".join(repr(wanted) for wanted, _ in found[:3])
            failures.append(f"{block.name}: found {shown} on {len(found)} line(s)")
            evidence.extend(
                EvidenceLine(
                    path="config",
                    line_start=number,
                    line_end=number,
                    excerpt=_normalise(dict(lines)[number]),
                )
                for _, number in found[:5]
            )
            continue
        passed_blocks += 1

    total = len(logic.blocks)
    expected = f"the configuration should satisfy all {total} block(s) of this template"

    if not failures:
        return finish(
            Outcome.PASS,
            f"{check.title}: all {total} block(s) of the template are satisfied.",
            observed={"blocks": total, "satisfied": total},
            expected=expected,
            evidence=evidence[:10],
        )

    return finish(
        Outcome.FAIL,
        f"{len(failures)} of {total} block(s) differ from the template — "
        + "; ".join(failures[:5])
        + ("; …" if len(failures) > 5 else "."),
        # Structured as well as in the message, so a report can count blocks rather
        # than parse prose.
        observed={
            "blocks": total,
            "satisfied": passed_blocks,
            "failed": [failure.split(":", 1)[0] for failure in failures],
        },
        expected=expected,
        evidence=evidence[:10],
    )


def _evaluate_regex(
    check: CheckDefinition, context: EvaluationContext, finish: _Finish
) -> CheckResult:
    logic = check.logic
    assert logic.pattern is not None  # noqa: S101 - schema-enforced

    if not context.config_text:
        return finish(
            _missing_outcome(logic.missing),
            "Not evaluated: no configuration text was available for this check.",
            reason="missing:config_text",
        )

    matches = [
        (number, line)
        for number, line in enumerate(context.config_text.splitlines(), start=1)
        if re.search(logic.pattern, line)
    ]
    present = bool(matches)
    passed = present if logic.expect == "present" else not present

    evidence = [
        # The text searched is the redacted copy, so an excerpt taken from it is safe
        # to put in a finding.
        EvidenceLine(path="config", line_start=number, line_end=number, excerpt=line.strip())
        for number, line in matches[:10]
    ]
    expected = (
        f"the configuration should contain /{logic.pattern}/"
        if logic.expect == "present"
        else f"the configuration should not contain /{logic.pattern}/"
    )

    if passed:
        return finish(
            Outcome.PASS, f"{check.title}: as expected.", expected=expected, evidence=evidence
        )

    message = (
        f"The configuration does not contain /{logic.pattern}/."
        if logic.expect == "present"
        else f"The configuration contains /{logic.pattern}/ on {len(matches)} line(s)."
    )
    return finish(
        Outcome.FAIL, message, observed=len(matches), expected=expected, evidence=evidence
    )


def _evaluate_python(
    check: CheckDefinition, context: EvaluationContext, finish: _Finish, severity: Severity
) -> CheckResult:
    function = _PYTHON_CHECKS.get(check.logic.function or "")
    if function is None:
        return finish(
            Outcome.ERROR,
            f"No Python check is registered under {check.logic.function!r}.",
            reason="unregistered",
        )

    produced = function(context)

    if isinstance(produced, CheckResult):
        # A Python check may build the whole result, which is what the complex ones
        # need: a rulebase analysis has evidence no declarative form could express.
        produced.check_id = check.id
        produced.severity = severity
        produced.check_version = check.version
        if not produced.title:
            produced.title = check.title
        return produced

    if isinstance(produced, tuple):
        outcome, message = produced
        return finish(outcome, message)

    return finish(produced, f"{check.title}: {produced.value}.")


def evaluate_all(
    checks: Iterable[CheckDefinition],
    ncm: Mapping[str, Any],
    *,
    device: DeviceContext | None = None,
    config_text: str = "",
    severity_overrides: Mapping[str, Severity] | None = None,
) -> list[CheckResult]:
    """Evaluate a policy's worth of checks against one snapshot."""
    overrides = severity_overrides or {}
    return [
        evaluate(
            check,
            ncm,
            device=device,
            config_text=config_text,
            severity_override=overrides.get(check.id),
        )
        for check in checks
    ]


__all__ = [
    "CheckResult",
    "DeviceContext",
    "EvaluationContext",
    "EvidenceLine",
    "applies_to",
    "evaluate",
    "evaluate_all",
    "evaluate_assertion",
    "python_check",
    "registered_python_checks",
]
