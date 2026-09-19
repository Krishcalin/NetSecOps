"""Feature-aware matching (FR-VUL-03).

    the engine uses NCM `features`/`management` to set confidence: Confirmed
    (version + feature match), Likely (version match, feature unknown), Not
    Affected (feature disabled), with explanation.

This is where everything else in the package finally produces an answer, and it is the
only module in Phase 6 whose output a human acts on: a Confirmed match is somebody
booking an outage window at 2am.

**Four verdicts, because three would force a lie.** Affected, not affected, and a third
state for every question the data cannot answer. The temptation is to drop the third and
round everything into one of the first two, and both roundings are damaging in ways that
compound:

* Rounding unknown down to *Not Affected* is silent. A device with no readable version,
  an advisory whose range nobody could parse, a Cisco train comparison that has no
  ordering — each disappears into a clean report, and nobody is ever told that the
  question went unasked.
* Rounding unknown up to *Confirmed* is loud and self-defeating. Flag every device
  running the product and the operator stops reading the vulnerability view within a
  week, taking the real findings with it.

So :class:`Confidence` has four members and `NOT_EVALUATED` is a first-class outcome
with a reason attached, not an error.

**The asymmetry that runs through the whole module.** Ruling a device *in* and ruling it
*out* need different amounts of evidence. To say "affected" it is enough that one
statement in the advisory matches. To say "not affected" every statement must have been
read and none may match — so an advisory carrying an unparsed range or an undefined
product id can raise a finding but can never clear one. :attr:`Advisory.fully_interpreted`
is what carries that, and :func:`match` refuses `NOT_AFFECTED` without it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import jmespath

from netsecops.core.logging import get_logger
from netsecops.ncm.models import NormalisedConfig
from netsecops.vuln.advisory import Advisory, AffectedProduct, ConstraintKind, FeatureCondition
from netsecops.vuln.cpe import hardware_cpe, same_product, software_cpe
from netsecops.vuln.versions import DeviceVersion, Ordering, compare, parse

log = get_logger(__name__)


class Confidence(StrEnum):
    """How sure the engine is, in FR-VUL-03's own vocabulary."""

    #: Version matches, and every condition the advisory states is satisfied.
    CONFIRMED = "confirmed"
    #: Version matches, but a stated condition could not be established — the parser
    #: never determined the feature either way.
    LIKELY = "likely"
    #: The advisory was fully understood and nothing in it applies to this device.
    NOT_AFFECTED = "not_affected"
    #: The question could not be asked. No version, an unreadable range, versions with
    #: no ordering between them. Never a synonym for safe.
    NOT_EVALUATED = "not_evaluated"


@dataclass(slots=True)
class Match:
    """One advisory weighed against one device.

    ``reasoning`` is not decoration. FR-VUL-03 requires an explanation, and a
    vulnerability finding that cannot say *why* is one an engineer will refuse to action
    and be right to.
    """

    advisory_id: str
    source: str
    #: Defaults to NOT_EVALUATED, and the default is load-bearing rather than
    #: incidental. A match is built before it is decided, so every early return and
    #: every path someone adds later inherits "we have not established this" unless it
    #: explicitly concludes otherwise. Defaulting to NOT_AFFECTED would make a forgotten
    #: branch silently clear a device; defaulting to CONFIRMED would make it cry wolf.
    #: Only "unknown" is safe to reach by accident.
    confidence: Confidence = Confidence.NOT_EVALUATED
    cve_ids: list[str] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)
    #: The advisory statement that matched, for tracing a disputed finding back.
    matched: AffectedProduct | None = None
    #: Releases the vendor named as fixed, for the upgrade-path view (FR-VUL-10).
    fixed_versions: list[str] = field(default_factory=list)

    @property
    def actionable(self) -> bool:
        """Whether this belongs in front of someone.

        NOT_EVALUATED is included deliberately: a device nobody could assess is a gap in
        coverage, and hiding it is how an estate develops blind spots that look like
        clean results.
        """
        return self.confidence is not Confidence.NOT_AFFECTED


def match(ncm: NormalisedConfig, advisory: Advisory, *, platform: str | None = None) -> Match:
    """Weigh one advisory against one device."""
    outcome = Match(
        advisory_id=advisory.advisory_id,
        source=advisory.source,
        cve_ids=list(advisory.cve_ids),
        fixed_versions=_fixed_versions(advisory),
    )

    platform = platform or ncm.device.platform
    device_version = parse(ncm.device.version, platform=platform)

    if device_version is None:
        # No version, or one this system cannot read. Every subsequent step needs it.
        outcome.confidence = Confidence.NOT_EVALUATED
        outcome.reasoning.append(
            f"This device reports no software version this system can read "
            f"({ncm.device.version!r}), so no advisory can be matched against it. "
            "Collect `show version` from it, or check the parser supports its format."
        )
        return outcome

    device_cpe = software_cpe(ncm, platform=platform)
    device_cpe_text = device_cpe.to_string() if device_cpe else None
    device_hardware = hardware_cpe(ncm)
    device_hardware_text = device_hardware.to_string() if device_hardware else None

    applicable = [
        entry
        for entry in advisory.affected
        if _names_this_device(entry, ncm, device_cpe_text, device_hardware_text)
    ]
    if not applicable:
        return _nothing_applies(outcome, advisory, ncm)

    # Weigh every statement about this product. One hit is enough to rule the device in;
    # ruling it out needs all of them to miss *and* the document to be fully understood.
    hits: list[AffectedProduct] = []
    unknowns: list[tuple[AffectedProduct, str]] = []

    for entry in applicable:
        if same_product(entry.cpe, device_hardware_text):
            # The statement is about the chassis, and the chassis is this one. There is
            # no software version to weigh: a flaw in a crypto accelerator or a
            # management port is not fixed by an upgrade, and NVD writes the version
            # component of a hardware CPE as `-` (NA) precisely to say so. Reading that
            # NA as an unreadable range — which is what happens if this falls through to
            # the version logic — turns an exact identity match into "cannot tell".
            hits.append(entry)
            continue

        verdict, why = _version_applies(device_version, entry, platform)
        if verdict is True:
            hits.append(entry)
        elif verdict is None:
            unknowns.append((entry, why))

    if hits:
        outcome.matched = hits[0]
        if same_product(hits[0].cpe, device_hardware_text):
            outcome.reasoning.append(
                f"{advisory.advisory_id} names this device's hardware "
                f"({ncm.device.model}) as affected. A chassis advisory does not depend "
                "on the software version, and no upgrade closes it."
            )
        else:
            outcome.reasoning.append(
                f"{ncm.device.version} falls within {hits[0].constraint.raw!r}, which "
                f"{advisory.advisory_id} names as affected."
            )
        return _apply_conditions(outcome, advisory, ncm)

    if unknowns:
        entry, why = unknowns[0]
        outcome.matched = entry
        outcome.confidence = Confidence.NOT_EVALUATED
        outcome.reasoning.append(why)
        return outcome

    return _nothing_applies(outcome, advisory, ncm, product_matched=True)


# ───────────────────────────── product identity ─────────────────────────────


def _names_this_device(
    entry: AffectedProduct,
    ncm: NormalisedConfig,
    device_cpe: str | None,
    device_hardware: str | None = None,
) -> bool:
    """Whether an advisory statement is about this device's product at all.

    The CPE is preferred where both sides have one: it is the vendor's own identifier,
    and comparing it avoids deciding whether "PAN-OS" and "Palo Alto Networks PAN-OS"
    are the same string. Falling back to vendor and product names is necessary because
    plenty of advisories carry no CPE.

    **A device is two products.** A firewall is an operating system and a chassis, and
    vendors scope advisories to either. Comparing only the software CPE meant a statement
    about the chassis failed identity on the CPE part alone — `h` against `o` — and an
    advisory naming this exact model was reported as naming no product matching this
    device. Where that advisory was fully interpreted, that verdict is *not affected*,
    which resolves an open finding: the hardware advisory closed the record of itself.

    Matching hardware is safe here because NVD's contextual "running on" entries never
    reach this point — `parse_nvd_feed` drops anything not marked `vulnerable: true`, so
    a hardware CPE that survives is one the publisher says is itself affected.

    The hardware arm is CPE-only, deliberately. Falling back to name comparison would
    weigh an advisory's product string against `model`, and model strings are written a
    dozen ways for one box; an over-eager match there attaches every chassis advisory to
    every device from that vendor.
    """
    if entry.cpe and device_hardware and same_product(entry.cpe, device_hardware):
        return True

    if entry.cpe and device_cpe:
        return same_product(entry.cpe, device_cpe)

    if not entry.identifiable:
        # A statement naming a product nobody could resolve. It cannot be matched to
        # this device, and it is also why the advisory is not `fully_interpreted` — so
        # it blocks a NOT_AFFECTED downstream rather than being silently ignored here.
        return False

    vendor = (ncm.device.vendor or "").strip().lower()
    entry_vendor = (entry.vendor or "").strip().lower()
    entry_product = (entry.product or "").strip().lower()
    platform = (ncm.device.platform or "").strip().lower()

    if entry_vendor and vendor and entry_vendor.split()[0] not in vendor:
        return False

    # `pan-os` against platform `panos`, `PAN-OS` against `panos`: compared with
    # separators removed, since vendors and this system punctuate differently.
    return _squash(entry_product) in _squash(platform) or _squash(platform) in _squash(
        entry_product
    )


def _squash(text: str) -> str:
    return "".join(character for character in text.lower() if character.isalnum())


# ────────────────────────────── version logic ───────────────────────────────


def _version_applies(
    device: DeviceVersion, entry: AffectedProduct, platform: str | None
) -> tuple[bool | None, str]:
    """Does this device's version fall inside the statement's range?

    Returns True, False, or None for "no ordering exists between these". The None case
    is the one that matters: two Cisco IOS versions in different trains are not
    comparable, and an engine that forced an answer would either raise a finding against
    a patched device or clear a vulnerable one.
    """
    constraint = entry.constraint

    if constraint.kind is ConstraintKind.UNPARSED:
        return None, (
            f"The advisory states its affected versions as {constraint.raw!r}, which "
            "this system cannot interpret. The device may or may not be in that range — "
            "read the advisory."
        )

    if constraint.kind is ConstraintKind.ALL:
        return True, ""

    if constraint.kind is ConstraintKind.EXACT:
        other = parse(constraint.version, platform=platform)
        if other is None:
            return None, (
                f"The advisory names version {constraint.version!r}, which this system "
                "cannot parse."
            )
        ordering = compare(device, other)
        if ordering is None:
            return None, _incomparable(device, other)
        return ordering is Ordering.EQUAL, ""

    # A range. Both bounds must be comparable for the answer to mean anything.
    if constraint.introduced is not None:
        lower = parse(constraint.introduced, platform=platform)
        if lower is None:
            return None, f"The advisory's lower bound {constraint.introduced!r} is unreadable."
        ordering = compare(device, lower)
        if ordering is None:
            return None, _incomparable(device, lower)
        if ordering is Ordering.LESS:
            return False, ""

    if constraint.fixed is not None:
        upper = parse(constraint.fixed, platform=platform)
        if upper is None:
            return None, f"The advisory's fixed release {constraint.fixed!r} is unreadable."
        ordering = compare(device, upper)
        if ordering is None:
            return None, _incomparable(device, upper)
        if ordering in (Ordering.GREATER, Ordering.EQUAL):
            # `fixed` is exclusive: the release containing the fix is not affected.
            return False, ""

    if constraint.last_affected is not None:
        upper = parse(constraint.last_affected, platform=platform)
        if upper is None:
            return None, (
                f"The advisory's last affected release {constraint.last_affected!r} is unreadable."
            )
        ordering = compare(device, upper)
        if ordering is None:
            return None, _incomparable(device, upper)
        if ordering is Ordering.GREATER:
            # Inclusive, and that is the whole point of the field: the named release is
            # affected, so only something strictly later is clear. Comparing this the way
            # `fixed` is compared would report every device on the last affected release
            # as patched — and NVD uses this bound precisely where no fix exists, so
            # those devices have nowhere to go.
            return False, ""

    return True, ""


def _incomparable(device: DeviceVersion, other: DeviceVersion) -> str:
    """Why two versions could not be ranked, in terms an operator can act on."""
    if device.train != other.train:
        return (
            f"{device.raw} and {other.raw} are on different Cisco release trains "
            f"({device.train or 'trunk'} and {other.train or 'trunk'}), which are "
            "maintained separately and have no ordering between them. Whether the fix "
            "reached this train has to be read from the advisory."
        )
    return f"{device.raw} and {other.raw} use different versioning schemes and cannot be compared."


# ──────────────────────────── feature conditions ────────────────────────────


def _apply_conditions(outcome: Match, advisory: Advisory, ncm: NormalisedConfig) -> Match:
    """Narrow a version hit by the advisory's stated conditions (FR-VUL-03).

    No conditions means the version match is the whole claim, and the verdict is
    Confirmed — which is how the great majority of advisories read.
    """
    if not advisory.conditions:
        outcome.confidence = Confidence.CONFIRMED
        return outcome

    document: dict[str, Any] = ncm.model_dump(mode="json")
    unknown: list[FeatureCondition] = []

    for condition in advisory.conditions:
        observed = jmespath.search(condition.path, document)

        if observed is None:
            # Absent is not false. The parser never established this, so the device is
            # not cleared by it — and not confirmed by it either.
            unknown.append(condition)
            continue

        if observed != condition.expected:
            outcome.confidence = Confidence.NOT_AFFECTED
            outcome.reasoning.append(
                f"The version matches, but {advisory.advisory_id} applies only where "
                f"{condition.description}. This device reports {condition.path} = "
                f"{observed!r}, so it is not affected."
            )
            return outcome

    if unknown:
        outcome.confidence = Confidence.LIKELY
        for condition in unknown:
            outcome.reasoning.append(
                f"{advisory.advisory_id} applies only where {condition.description}, and "
                f"nothing collected from this device establishes {condition.path} either "
                "way. Reported as likely rather than confirmed — check the device."
            )
        return outcome

    outcome.confidence = Confidence.CONFIRMED
    outcome.reasoning.append(
        "Every condition the advisory states is satisfied on this device: "
        + "; ".join(condition.description for condition in advisory.conditions)
        + "."
    )
    return outcome


# ───────────────────────────── the clean answer ─────────────────────────────


def _nothing_applies(
    outcome: Match,
    advisory: Advisory,
    ncm: NormalisedConfig,
    *,
    product_matched: bool = False,
) -> Match:
    """Nothing in the advisory matched — but is that an answer or a gap?

    Only an advisory that was understood end to end can clear a device. One carrying an
    unreadable range or a product id its own document never defined has statements
    nobody evaluated, and "none of the statements I could read applied to you" is not
    the same claim as "you are not affected".
    """
    if advisory.fully_interpreted:
        outcome.confidence = Confidence.NOT_AFFECTED
        outcome.reasoning.append(
            f"{ncm.device.version} is outside every version range {advisory.advisory_id} names."
            if product_matched
            else f"{advisory.advisory_id} names no product matching this device."
        )
        return outcome

    outcome.confidence = Confidence.NOT_EVALUATED
    outcome.reasoning.append(
        f"Nothing in {advisory.advisory_id} that this system could read applies to this "
        f"device, but {advisory.uninterpretable or len(advisory.notes_unparsed)} "
        "statement(s) in it could not be interpreted, so it cannot be ruled out: "
        + "; ".join(advisory.notes_unparsed[:2] or ["an affected-version range is unreadable"])
    )
    return outcome


def _fixed_versions(advisory: Advisory) -> list[str]:
    """The releases the vendor named as containing the fix (FR-VUL-10)."""
    versions: list[str] = []
    for entry in advisory.fixed:
        if entry.constraint.kind is ConstraintKind.EXACT and entry.constraint.version:
            versions.append(entry.constraint.version)
    return sorted(set(versions))


__all__ = ["Confidence", "Match", "match"]
