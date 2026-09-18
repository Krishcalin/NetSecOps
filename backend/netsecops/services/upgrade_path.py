"""What would upgrading actually fix? (FR-VUL-10)

A vulnerability list tells an engineer they have forty CVEs. It does not tell them the
one thing they need in order to act: which single release closes the most of them. That
is the question this answers — for a device, every candidate fixed release its own
advisories name, and what each would and would not eliminate.

**The candidates come from the advisories, never from imagination.** Only versions some
advisory actually names as fixed are offered. Synthesising "try 17.9.5" because 17.9.4 is
fixed would recommend a release that may not exist, and an engineer who schedules an
outage for it does not get a second one.

**Three outcomes per CVE, not two.** Cisco IOS trains are the reason: `15.2(7)E3` and
`15.2(4)M5` are parallel, with independent fix schedules, and neither is later than the
other. Asked whether upgrading to one closes a CVE fixed in the other, the honest answer
is *cannot say* — so a CVE is `eliminated`, `remaining`, or `undetermined`, and the last
is never folded into either.

Folding it into `eliminated` would tell somebody a vulnerability is fixed when it is not.
Folding it into `remaining` is safer but still wrong, and wrong in a way that matters:
it makes a good upgrade look worse than it is and pushes the engineer toward a release
that fixes less.

**Ranking puts KEV first, then volume.** A release closing one vulnerability under active
exploitation beats one closing nine nobody has ever attacked, and the whole point of this
view is to make the next maintenance window count.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.logging import get_logger
from netsecops.db.models.inventory import Device
from netsecops.db.models.vulnerability import VulnAdvisory, VulnCve, VulnMatch
from netsecops.vuln.versions import Ordering, compare, parse

log = get_logger(__name__)

#: Confidences that mean "this device is affected". `not_affected` and `not_evaluated`
#: are excluded: an upgrade plan built on unevaluated advisories would credit a release
#: with fixing things nobody established were broken.
AFFECTED = ("confirmed", "likely")

#: Most candidate releases returned. An estate device can accumulate dozens of distinct
#: fixed versions across its advisories, and a list that long is not a decision aid.
MAX_CANDIDATES = 20


@dataclass(slots=True)
class UpgradeCandidate:
    """One release the device could move to, and what it would buy."""

    version: str
    #: CVEs this release demonstrably closes.
    eliminates: list[str] = field(default_factory=list)
    #: CVEs that would still be open afterwards.
    remaining: list[str] = field(default_factory=list)
    #: CVEs on a version train this release cannot be compared with — see the module
    #: docstring. Reported separately and never merged into the other two.
    undetermined: list[str] = field(default_factory=list)
    #: How many of the eliminated CVEs are known-exploited. The number that should drive
    #: the decision.
    kev_eliminated: int = 0
    advisories_closed: int = 0

    @property
    def rank(self) -> tuple[int, int, int]:
        """Sort key, best first. KEV outranks volume; ties break on fewest left open."""
        return (-self.kev_eliminated, -len(self.eliminates), len(self.remaining))

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "eliminates": sorted(self.eliminates),
            "remaining": sorted(self.remaining),
            "undetermined": sorted(self.undetermined),
            "eliminates_count": len(self.eliminates),
            "remaining_count": len(self.remaining),
            "undetermined_count": len(self.undetermined),
            "kev_eliminated": self.kev_eliminated,
            "advisories_closed": self.advisories_closed,
        }


@dataclass(slots=True)
class UpgradeReport:
    device_id: uuid.UUID
    hostname: str | None
    platform: str | None
    current_version: str | None
    #: Set when the device's own version could not be parsed. Every candidate is then
    #: reported without being filtered against it, and saying so is the difference
    #: between a caveated answer and a wrong one.
    current_version_unparsed: bool = False
    total_open_cves: int = 0
    candidates: list[UpgradeCandidate] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "device_id": str(self.device_id),
            "hostname": self.hostname,
            "platform": self.platform,
            "current_version": self.current_version,
            "current_version_unparsed": self.current_version_unparsed,
            "total_open_cves": self.total_open_cves,
            "candidates": [c.as_dict() for c in self.candidates],
        }


def _closes(candidate: str, fixed_versions: Sequence[str], platform: str | None) -> bool | None:
    """Would moving to ``candidate`` pick up the fix in ``fixed_versions``?

    Returns True, False, or **None for "cannot say"** — the third state the whole module
    is built around. None arises when the candidate and every fixed version sit on
    parallel trains, where neither is later and `compare` correctly refuses to rank them.
    """
    target = parse(candidate, platform=platform)
    if target is None:
        return None

    verdict: bool | None = False
    for raw in fixed_versions:
        fixed = parse(raw, platform=platform)
        if fixed is None:
            # An unparseable fixed version cannot rule the CVE out. It also must not rule
            # it *in*: the advisory said something this reader did not understand.
            verdict = None if verdict is False else verdict
            continue

        ordering = compare(target, fixed)
        if ordering is None:
            # Parallel trains. Not a no — an unknown, which outranks a no.
            verdict = None if verdict is False else verdict
            continue
        if ordering in (Ordering.EQUAL, Ordering.GREATER):
            # One fixed version reached is enough: the advisory is satisfied.
            return True

    return verdict


class UpgradePathService:
    """Answer "what would fixing X upgrade eliminate?" for one device (FR-VUL-10)."""

    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id

    async def for_device(self, device_id: uuid.UUID) -> UpgradeReport | None:
        device = (
            await self.session.execute(
                select(Device).where(Device.id == device_id, Device.org_id == self.org_id)
            )
        ).scalar_one_or_none()
        if device is None:
            return None

        rows = (
            await self.session.execute(
                select(VulnMatch, VulnAdvisory)
                .join(VulnAdvisory, VulnMatch.advisory_id == VulnAdvisory.id)
                .where(
                    VulnMatch.org_id == self.org_id,
                    VulnMatch.device_id == device_id,
                    VulnMatch.confidence.in_(AFFECTED),
                )
            )
        ).all()

        report = UpgradeReport(
            device_id=device.id,
            hostname=device.hostname,
            platform=device.platform,
            current_version=device.os_version,
        )
        if not rows:
            return report

        current = parse(device.os_version, platform=device.platform)
        report.current_version_unparsed = device.os_version is not None and current is None

        open_cves: set[str] = set()
        for match, _advisory in rows:
            open_cves.update(match.cve_ids or [])
        report.total_open_cves = len(open_cves)

        kev = await self._kev_ids(open_cves)

        # Candidates are every fixed version any affected advisory names, minus the ones
        # that are not actually a step forward from where the device already is.
        candidates: set[str] = set()
        for match, _advisory in rows:
            candidates.update(match.fixed_versions or [])

        built: list[UpgradeCandidate] = []
        for version in sorted(candidates):
            if current is not None:
                parsed = parse(version, platform=device.platform)
                # An equal-or-lower release is not an upgrade. A *parallel* one is kept:
                # moving between trains is a real migration an engineer may choose, and
                # dropping it would hide the only option that fixes some CVEs.
                if parsed is not None and compare(parsed, current) in (
                    Ordering.LESS,
                    Ordering.EQUAL,
                ):
                    continue

            candidate = UpgradeCandidate(version=version)
            for match, _advisory in rows:
                cves = list(match.cve_ids or [])
                closed = _closes(version, match.fixed_versions or [], device.platform)
                if closed is True:
                    candidate.eliminates.extend(cves)
                    candidate.advisories_closed += 1
                elif closed is False:
                    candidate.remaining.extend(cves)
                else:
                    candidate.undetermined.extend(cves)

            # A CVE is only eliminated when *every* advisory naming it is closed by this
            # release. One CVE routinely appears in several advisories — a vendor
            # re-issues, or the same flaw affects two components with different fix
            # trains — and upgrading past one of them leaves the others applying.
            #
            # So the states combine by severity of doubt rather than by order of
            # discovery: certainly-still-open beats cannot-say, which beats fixed.
            # Written the other way round (subtracting `remaining` from `eliminates`) a
            # release gets credited with a fix it only partly delivers, which is the
            # single most dangerous output this view could produce.
            fixed_by = set(candidate.eliminates)
            still_open = set(candidate.remaining)
            cannot_say = set(candidate.undetermined)

            candidate.remaining = sorted(still_open)
            candidate.undetermined = sorted(cannot_say - still_open)
            candidate.eliminates = sorted(fixed_by - still_open - cannot_say)
            candidate.kev_eliminated = sum(1 for cve in candidate.eliminates if cve in kev)

            if candidate.eliminates:
                built.append(candidate)

        built.sort(key=lambda c: c.rank)
        report.candidates = built[:MAX_CANDIDATES]

        log.info(
            "vuln.upgrade_path",
            device_id=str(device_id),
            candidates=len(report.candidates),
            open_cves=report.total_open_cves,
        )
        return report

    async def _kev_ids(self, cve_ids: set[str]) -> set[str]:
        if not cve_ids:
            return set()
        rows = (
            await self.session.execute(
                select(VulnCve.cve_id).where(
                    VulnCve.org_id == self.org_id,
                    VulnCve.cve_id.in_(sorted(cve_ids)),
                    VulnCve.kev.is_(True),
                )
            )
        ).scalars()
        return set(rows)


__all__ = ["AFFECTED", "MAX_CANDIDATES", "UpgradeCandidate", "UpgradePathService", "UpgradeReport"]
