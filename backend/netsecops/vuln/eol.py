"""End-of-life and end-of-support detection (FR-VUL-05).

    The system SHALL detect End-of-Life / End-of-Support hardware and software
    using a maintained EoL dataset (vendor bulletins, `endoflife.date` API where
    available) and raise findings.

An unsupported release is a permanent, unfixable vulnerability: no advisory will ever
name it because the vendor has stopped looking, and no patch exists to apply. It is
often the most actionable thing on a device's page, because the remedy is a project
rather than a maintenance window and someone needs to start it early.

**Two dates, and the gap between them matters.** End-of-support (or end-of-security-
maintenance) is when fixes stop; end-of-life is when the vendor stops answering the
phone. A release past support but before EOL still runs, still has a contract, and no
longer receives security fixes â€” which is the state operators most often do not realise
they are in. They are tracked separately rather than collapsed into one date.

**The dataset's own quirk.** `endoflife.date` types these fields as *either* a date
*or* a boolean: `"eol": true` means "yes, and no date given", `"eol": false` means "not
yet". Code expecting a date either crashes on the boolean or, worse, drops the record â€”
and dropping a record that says `true` is dropping the strongest possible statement that
the release is dead. Both forms are read, and a field that is neither becomes
:data:`LifecycleStatus.UNKNOWN` rather than being treated as supported.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.vuln.versions import parse

log = get_logger(__name__)

#: How long before a support date to start warning. A quarter is the shortest notice on
#: which an upgrade project can realistically be funded and scheduled.
APPROACHING_DAYS = 90


class LifecycleStatus(StrEnum):
    """Where a release sits in its vendor's support lifecycle."""

    SUPPORTED = "supported"
    #: Support ends within :data:`APPROACHING_DAYS`. Still fixed today; needs a plan.
    APPROACHING_END_OF_SUPPORT = "approaching_end_of_support"
    #: Past end-of-support: the release still runs and no longer receives security
    #: fixes. The state operators most often do not know they are in.
    END_OF_SUPPORT = "end_of_support"
    #: Past end-of-life: unsupported entirely.
    END_OF_LIFE = "end_of_life"
    #: No dataset entry, or dates that could not be read. Never a synonym for supported.
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class EolRecord:
    """One release cycle's lifecycle dates, from one source."""

    vendor: str
    product: str
    #: The release train this covers â€” `9.18`, `17.9`, `R81.20`. Matched against a
    #: device version by prefix, since a device reports `9.18(4)` and the dataset
    #: tracks `9.18`.
    cycle: str
    source: str
    #: Security fixes stop. None when the dataset gave no date.
    support_ends: date | None = None
    #: Vendor support stops entirely.
    life_ends: date | None = None
    #: True where the dataset said "yes, ended" without giving a date.
    support_ended_undated: bool = False
    life_ended_undated: bool = False
    latest: str | None = None

    def status(self, *, today: date | None = None) -> LifecycleStatus:
        """Where this cycle sits today.

        Ordered worst-first: a release past EOL is also past support, and the more
        serious statement is the one worth reporting.
        """
        now = today or datetime.now(UTC).date()

        if self.life_ended_undated:
            return LifecycleStatus.END_OF_LIFE
        if self.life_ends and self.life_ends <= now:
            return LifecycleStatus.END_OF_LIFE

        if self.support_ended_undated:
            return LifecycleStatus.END_OF_SUPPORT
        if self.support_ends and self.support_ends <= now:
            return LifecycleStatus.END_OF_SUPPORT

        if self.support_ends and (self.support_ends - now).days <= APPROACHING_DAYS:
            return LifecycleStatus.APPROACHING_END_OF_SUPPORT

        if self.support_ends or self.life_ends:
            return LifecycleStatus.SUPPORTED

        # An entry exists but carries no usable date in either field. The cycle is
        # known; its lifecycle is not, and saying "supported" would invent the answer.
        return LifecycleStatus.UNKNOWN


@dataclass(frozen=True, slots=True)
class LifecycleAssessment:
    """What the dataset says about one device."""

    status: LifecycleStatus
    reasoning: str
    record: EolRecord | None = None

    @property
    def actionable(self) -> bool:
        """UNKNOWN is included: a device whose lifecycle nobody can establish is a gap
        in coverage, and filing it with the supported ones hides it."""
        return self.status is not LifecycleStatus.SUPPORTED


def parse_endoflife_date(
    payload: Any, *, vendor: str, product: str, source: str = "endoflife.date"
) -> list[EolRecord]:
    """Parse an `endoflife.date` product response.

    The API returns a list of cycles. Anything that is not a list of objects yields
    nothing rather than raising â€” this reads bytes fetched from a third party, and an
    error page must not abort a sync.
    """
    if not isinstance(payload, list):
        return []

    records: list[EolRecord] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        cycle = str(entry.get("cycle") or "").strip()
        if not cycle:
            continue

        support_date, support_ended = _date_or_flag(entry.get("support"))
        life_date, life_ended = _date_or_flag(entry.get("eol"))

        records.append(
            EolRecord(
                vendor=vendor,
                product=product,
                cycle=cycle,
                source=source,
                support_ends=support_date,
                life_ends=life_date,
                support_ended_undated=support_ended,
                life_ended_undated=life_ended,
                latest=str(entry.get("latest") or "") or None,
            )
        )

    log.info("vuln.eol_parsed", vendor=vendor, product=product, cycles=len(records))
    return records


def _date_or_flag(value: Any) -> tuple[date | None, bool]:
    """Read a field that is either a date, a boolean, or absent.

    Returns (date, ended_without_a_date). `True` is the strongest statement the dataset
    makes â€” "this is over" â€” and losing it because the field was not a string would
    discard exactly the records that matter most.
    """
    if value is True:
        return None, True
    if value is False or value is None:
        return None, False
    if isinstance(value, str) and value.strip():
        try:
            return date.fromisoformat(value.strip()), False
        except ValueError:
            log.debug("vuln.eol_unreadable_date", value=value)
            return None, False
    return None, False


def assess(
    version: str | None,
    records: list[EolRecord],
    *,
    platform: str | None = None,
    today: date | None = None,
) -> LifecycleAssessment:
    """Place a device's version in its product's lifecycle.

    Returns UNKNOWN rather than SUPPORTED wherever the answer cannot be established â€”
    no version, no matching cycle, or an entry with no usable dates. "We have no record
    of this release" and "this release is supported" are opposite operational states and
    must not render the same.
    """
    if not version or not version.strip():
        return LifecycleAssessment(
            LifecycleStatus.UNKNOWN,
            "This device reports no software version, so its support lifecycle cannot "
            "be looked up.",
        )

    if not records:
        return LifecycleAssessment(
            LifecycleStatus.UNKNOWN,
            f"No end-of-life data has been imported for this platform, so whether "
            f"{version} is still supported is unknown. Import an EoL bundle to answer it.",
        )

    record = _best_cycle(version, records, platform=platform)
    if record is None:
        return LifecycleAssessment(
            LifecycleStatus.UNKNOWN,
            f"{version} does not fall in any release cycle the imported end-of-life "
            f"data covers ({', '.join(sorted(r.cycle for r in records)[:8])}). It may be "
            "newer than the dataset, or the dataset may be incomplete.",
        )

    status = record.status(today=today)
    return LifecycleAssessment(status, _explain(record, status, version), record)


def _best_cycle(
    version: str, records: list[EolRecord], *, platform: str | None
) -> EolRecord | None:
    """The cycle a version belongs to.

    Longest matching prefix wins, so `9.18.4` picks the `9.18` cycle over a `9` one. The
    comparison goes through the version model rather than string matching, because
    `9.18(4)` and `9.18` are the same train spelled two ways and a string prefix would
    also match `9.1`.
    """
    parsed = parse(version, platform=platform)
    if parsed is None:
        return None

    best: EolRecord | None = None
    best_depth = -1

    for record in records:
        cycle = parse(record.cycle, platform=platform)
        if cycle is None:
            continue

        depth = len(cycle.release)
        prefix = parsed.release[:depth]
        if len(prefix) < depth:
            continue

        # Compare the cycle against the device's version truncated to the cycle's own
        # depth: `9.18.4` against cycle `9.18` compares (9,18) with (9,18).
        if prefix != cycle.release:
            continue
        if cycle.train is not None and cycle.train != parsed.train:
            continue

        if depth > best_depth:
            best, best_depth = record, depth

    return best


def _explain(record: EolRecord, status: LifecycleStatus, version: str) -> str:
    """Why this verdict, in terms someone can act on."""
    upgrade = f" The latest release in this cycle is {record.latest}." if record.latest else ""

    match status:
        case LifecycleStatus.END_OF_LIFE:
            when = f" on {record.life_ends}" if record.life_ends else ""
            return (
                f"{version} is in the {record.cycle} cycle, which reached end of life"
                f"{when}. It receives no fixes of any kind and no future advisory will "
                f"name it.{upgrade}"
            )
        case LifecycleStatus.END_OF_SUPPORT:
            when = f" on {record.support_ends}" if record.support_ends else ""
            return (
                f"{version} is in the {record.cycle} cycle, whose security maintenance "
                f"ended{when}. The device still runs and still boots; it no longer "
                f"receives security fixes.{upgrade}"
            )
        case LifecycleStatus.APPROACHING_END_OF_SUPPORT:
            return (
                f"{version} is in the {record.cycle} cycle, whose security maintenance "
                f"ends on {record.support_ends} â€” within {APPROACHING_DAYS} days. An "
                f"upgrade needs planning now rather than after the date.{upgrade}"
            )
        case LifecycleStatus.SUPPORTED:
            horizon = record.support_ends or record.life_ends
            return f"{version} is in the {record.cycle} cycle, supported until {horizon}."
        case _:
            return (
                f"{version} matches the {record.cycle} cycle, but the imported data "
                "carries no usable support or end-of-life date for it."
            )


__all__ = [
    "APPROACHING_DAYS",
    "EolRecord",
    "LifecycleAssessment",
    "LifecycleStatus",
    "assess",
    "parse_endoflife_date",
]
