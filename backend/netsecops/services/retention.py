"""Removing collected artefacts once they stop being worth their disk (FR-ADM-01).

`docs/deployment.md` has described a ninety-day artefact window since Phase 7 and based
its database sizing on one. Nothing enforced it. Artefacts are the fastest-growing table
in the schema — the raw output of every command, held twice, sealed and redacted — so a
deployment collecting daily grew without bound while its own documentation said it would
not. This is that window, enforced.

**What is removed, and what never is.**

Artefact *payloads* are removed. The collection row stays forever: it records that a
session happened, against which device, with which adapter, how long it took and whether
it was partial. That is metadata an auditor may want long after the command output stops
being useful, and it is a few hundred bytes against megabytes.

Snapshots are never touched, and the reason is a foreign key rather than a preference:
`check_results.snapshot_id` cascades, so deleting a snapshot would delete the assessment
history behind every finding it produced. Findings are documented as never purged
(DATA-02) and deleting the evidence under them would honour the letter of that and not
the point. The audit log is likewise untouched, and could not be purged from here anyway
— revision 0002 makes it append-only with a trigger.

**Disabled by default, because the alternative is deleting a customer's evidence because
they upgraded.** Retention is off until somebody sets a window. A product that starts
deleting data on upgrade, without being asked, has made that decision for an operator who
may be under a retention obligation they never told us about.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.logging import get_logger
from netsecops.db.models.audit import Setting
from netsecops.db.models.collection import Artifact, Collection

log = get_logger(__name__)

#: The setting that turns retention on. Absent or zero means keep everything.
ARTIFACT_RETENTION_KEY = "retention.artifact_days"

#: Collections purged per run. Retention is a background tidy-up, not a deadline: a
#: bounded batch keeps the transaction short and the table available, and a backlog
#: drains over a few nights rather than locking the busiest table for one long one.
BATCH = 500


@dataclass(frozen=True, slots=True)
class RetentionOutcome:
    """What one run did, in terms an operator can check against their expectation."""

    #: None when retention is switched off — distinct from 0 days, which nothing sets.
    window_days: int | None = None
    collections_purged: int = 0
    artifacts_removed: int = 0
    #: True when the batch limit was reached and more remain. The next run continues.
    more_remaining: bool = False

    @property
    def enabled(self) -> bool:
        return self.window_days is not None and self.window_days > 0

    def describe(self) -> str:
        if not self.enabled:
            return "Artefact retention is not configured; nothing was removed."
        more = " More remain and will be removed on the next run." if self.more_remaining else ""
        return (
            f"Removed {self.artifacts_removed} artefact(s) from "
            f"{self.collections_purged} collection(s) older than {self.window_days} days.{more}"
        )


async def artifact_window(session: AsyncSession) -> int | None:
    """The configured retention window in days, or None when retention is off.

    A malformed value disables retention rather than falling back to a default. The
    default would be a number nobody chose, applied to deleting evidence.
    """
    row = (
        await session.execute(select(Setting).where(Setting.key == ARTIFACT_RETENTION_KEY))
    ).scalar_one_or_none()
    if row is None:
        return None

    raw = row.value.get("days") if isinstance(row.value, dict) else row.value
    try:
        days = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        log.warning("retention.setting_unreadable", key=ARTIFACT_RETENTION_KEY, value=row.value)
        return None

    return days if days > 0 else None


class RetentionService:
    """Applies the artefact window. Touches nothing else."""

    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id

    async def purge_artifacts(self, *, now: datetime | None = None) -> RetentionOutcome:
        window = await artifact_window(self.session)
        if window is None:
            return RetentionOutcome()

        cutoff = (now or datetime.now(UTC)) - timedelta(days=window)

        # Collections old enough, whose artefacts are still here. Bounded, and ordered
        # oldest first so a backlog drains in the order the data stops being useful.
        due = (
            (
                await self.session.execute(
                    select(Collection.id)
                    .where(
                        Collection.org_id == self.org_id,
                        Collection.created_at < cutoff,
                        Collection.artifacts_purged_at.is_(None),
                    )
                    .order_by(Collection.created_at)
                    .limit(BATCH + 1)
                )
            )
            .scalars()
            .all()
        )

        more = len(due) > BATCH
        batch = list(due[:BATCH])
        if not batch:
            return RetentionOutcome(window_days=window)

        removed = int(
            (
                await self.session.execute(
                    select(func.count())
                    .select_from(Artifact)
                    .where(Artifact.collection_id.in_(batch))
                )
            ).scalar_one()
        )

        await self.session.execute(delete(Artifact).where(Artifact.collection_id.in_(batch)))
        # Marked in the same transaction as the delete. If these diverged, a collection
        # could lose its artefacts and still look unpurged — and the evidence view would
        # then report "this collection recorded no commands", which is a different and
        # alarming claim.
        await self.session.execute(
            update(Collection)
            .where(Collection.id.in_(batch))
            .values(artifacts_purged_at=now or datetime.now(UTC))
        )
        await self.session.flush()

        outcome = RetentionOutcome(
            window_days=window,
            collections_purged=len(batch),
            artifacts_removed=removed,
            more_remaining=more,
        )
        log.info(
            "retention.artifacts_purged",
            window_days=window,
            collections=outcome.collections_purged,
            artifacts=outcome.artifacts_removed,
            more_remaining=more,
        )
        return outcome


__all__ = [
    "ARTIFACT_RETENTION_KEY",
    "BATCH",
    "RetentionOutcome",
    "RetentionService",
    "artifact_window",
]
