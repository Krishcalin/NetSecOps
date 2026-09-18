"""Turning things that happen into notification events (FR-INT-01).

FR-INT-01 names eight triggers. They divide into two kinds, and the division is what
keeps this from being eight scattered call sites that drift apart.

**Four are already findings.** A drift finding, a host-key finding and a vulnerability
finding are written by five different services, and hooking each would mean five places to
forget. They are *derived* instead, by scanning new findings and mapping the finding kind
onto an event kind — so a service that starts writing findings tomorrow gets notifications
for free, and one that stops cannot silently take them away.

**Four are moments, not rows.** A job finishing, a credential being rejected, a feed sync
failing: none leaves a finding behind, so each is raised where it happens. There are four
such call sites and no more.

The ninth thing here is expiring exceptions, which is neither — it is a *deadline*, so it
is found by looking forward rather than by reacting. It is raised once per exception, on
the day it crosses the threshold, because an alert repeated every hour for a fortnight is
an alert nobody reads.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.db.models.audit import Setting
from netsecops.db.models.collection import Finding, FindingKind
from netsecops.db.models.inventory import Device
from netsecops.db.models.jobs import Job, JobStatus
from netsecops.db.models.policy import FindingException
from netsecops.db.models.vulnerability import VulnCve
from netsecops.integrations.events import Event, EventKind, EventSeverity, severity_of

WATERMARK_FINDINGS: Final[str] = "integrations.notify.watermark.findings"
WATERMARK_EXCEPTIONS: Final[str] = "integrations.notify.watermark.exceptions"

#: The same commit lag the SIEM forwarder uses, and for the same reason: a timestamp
#: watermark can otherwise step over a row that was still committing.
COMMIT_LAG: Final[timedelta] = timedelta(seconds=30)

#: How far ahead an exception's expiry is announced. A fortnight is long enough to renew
#: or remediate and short enough that the alert is still about something imminent.
EXPIRY_WINDOW: Final[timedelta] = timedelta(days=14)

#: Only these two are worth interrupting somebody for. Lower-severity findings are on the
#: findings page, where they belong.
NOTIFIED_SEVERITIES: Final[tuple[str, ...]] = ("critical", "high")

#: Finding kind to event kind. A kind absent here notifies as a plain finding.
BY_KIND: Final[dict[str, EventKind]] = {
    FindingKind.DRIFT.value: EventKind.DRIFT_DETECTED,
    FindingKind.HOSTKEY.value: EventKind.DEVICE_IDENTITY_CHANGED,
}


# ═══════════════════════════ moments, raised in place ════════════════════════


def job_event(job: Job) -> Event:
    """A job finished (FR-INT-01).

    A failure is `high` and a success is `info`, so the default subscription floor of
    `medium` delivers the failures and stays quiet about the successes — which is what
    somebody means when they subscribe a channel to "jobs".
    """
    failed = job.status in {JobStatus.FAILED.value, JobStatus.PARTIAL.value}
    return Event(
        kind=EventKind.JOB_FAILED if failed else EventKind.JOB_COMPLETED,
        severity=EventSeverity.HIGH if failed else EventSeverity.INFO,
        title=f"{job.job_type} job {job.status}",
        message=job.error_message or "",
        object_type="job",
        object_id=str(job.id),
        attributes={"jobType": job.job_type, "status": job.status},
    )


def credential_failure_event(device: Device, message: str) -> Event:
    """A device rejected every credential it was offered.

    Worth a notification rather than only a job outcome: a device that cannot be
    authenticated to is a device that is silently no longer being assessed, and its
    compliance percentage quietly stops meaning anything.
    """
    return Event(
        kind=EventKind.CREDENTIAL_FAILED,
        severity=EventSeverity.HIGH,
        title=f"Authentication failed on {device.hostname or device.mgmt_ip}",
        message=message,
        device_id=device.id,
        device_hostname=device.hostname,
        device_ip=str(device.mgmt_ip) if device.mgmt_ip else None,
        object_type="device",
        object_id=str(device.id),
    )


def feed_failure_event(feed: str, message: str) -> Event:
    """A feed could not be synchronised.

    High, not medium. A stale feed produces a *confident clean answer* rather than an
    obviously broken one, so silence here is exactly the wrong outcome.
    """
    return Event(
        kind=EventKind.FEED_SYNC_FAILED,
        severity=EventSeverity.HIGH,
        title=f"Feed sync failed: {feed}",
        message=message,
        object_type="feed",
        object_id=feed,
    )


# ═══════════════════════════ rows, found by scanning ═════════════════════════


async def _watermark(session: AsyncSession, org_id: int, key: str) -> str | None:
    row = (
        await session.execute(select(Setting).where(Setting.org_id == org_id, Setting.key == key))
    ).scalar_one_or_none()
    value = (row.value or {}).get("at") if row else None
    return str(value) if value else None


async def _set_watermark(session: AsyncSession, org_id: int, key: str, value: str) -> None:
    row = (
        await session.execute(select(Setting).where(Setting.org_id == org_id, Setting.key == key))
    ).scalar_one_or_none()
    if row is None:
        session.add(
            Setting(
                org_id=org_id,
                key=key,
                value={"at": value},
                description="How far notification scanning has reached. Managed automatically.",
            )
        )
    else:
        row.value = {"at": value}
    await session.flush()


async def _kev_ids(session: AsyncSession, org_id: int, cve_ids: set[str]) -> set[str]:
    if not cve_ids:
        return set()
    rows = (
        await session.execute(
            select(VulnCve.cve_id).where(
                VulnCve.org_id == org_id,
                VulnCve.cve_id.in_(sorted(cve_ids)),
                VulnCve.kev.is_(True),
            )
        )
    ).scalars()
    return set(rows)


async def scan(
    session: AsyncSession, *, org_id: int = 1, now: datetime | None = None, limit: int = 200
) -> list[Event]:
    """Every event derivable from state since the last scan.

    Advances its own watermarks, so an event is raised once. Called by the notification
    job immediately before it dispatches.
    """
    moment = now or datetime.now(UTC)
    events: list[Event] = []

    # ── new findings ────────────────────────────────────────────────────
    since = await _watermark(session, org_id, WATERMARK_FINDINGS)
    stmt = (
        select(Finding, Device)
        .join(Device, Finding.device_id == Device.id, isouter=True)
        .where(
            Finding.org_id == org_id,
            Finding.created_at <= moment - COMMIT_LAG,
            Finding.severity.in_(NOTIFIED_SEVERITIES),
        )
        .order_by(Finding.created_at)
        .limit(limit)
    )
    if since:
        stmt = stmt.where(Finding.created_at > datetime.fromisoformat(since))

    rows = list((await session.execute(stmt)).all())
    kev = await _kev_ids(
        session,
        org_id,
        {f.cve_id for f, _ in rows if f.kind == FindingKind.VULN.value and f.cve_id},
    )

    for finding, device in rows:
        kind = BY_KIND.get(finding.kind, EventKind.FINDING_OPENED)
        severity = severity_of(finding.severity)
        if finding.kind == FindingKind.VULN.value and finding.cve_id in kev:
            # "Being exploited right now" is a different page at 3am from "severe", so it
            # gets its own kind and is raised to critical whatever the CVSS said.
            kind = EventKind.KEV_MATCHED
            severity = EventSeverity.CRITICAL

        events.append(
            Event(
                kind=kind,
                severity=severity,
                title=finding.title,
                message=finding.description or "",
                occurred_at=finding.first_seen_at or finding.created_at,
                device_id=finding.device_id,
                device_hostname=device.hostname if device else None,
                device_ip=str(device.mgmt_ip) if device and device.mgmt_ip else None,
                object_type="finding",
                object_id=str(finding.id),
                attributes={
                    k: v
                    for k, v in {"checkId": finding.check_id, "cve": finding.cve_id}.items()
                    if v
                },
            )
        )

    if rows:
        await _set_watermark(
            session, org_id, WATERMARK_FINDINGS, rows[-1][0].created_at.isoformat()
        )

    # ── exceptions about to expire ──────────────────────────────────────
    events += await _expiring(session, org_id, moment)
    return events


async def _expiring(session: AsyncSession, org_id: int, moment: datetime) -> list[Event]:
    """Exceptions crossing the expiry window.

    Raised once each, tracked by a watermark on the expiry date rather than on when the
    scan ran — an exception does not cross the threshold twice, and re-announcing the same
    one every hour for a fortnight is how a channel gets muted.
    """
    horizon = moment + EXPIRY_WINDOW
    last = await _watermark(session, org_id, WATERMARK_EXCEPTIONS)
    floor = datetime.fromisoformat(last) if last else moment

    rows = list(
        (
            await session.execute(
                select(FindingException)
                .where(
                    FindingException.org_id == org_id,
                    FindingException.expires_at > floor,
                    FindingException.expires_at <= horizon,
                )
                .order_by(FindingException.expires_at)
            )
        ).scalars()
    )
    if not rows:
        return []

    await _set_watermark(session, org_id, WATERMARK_EXCEPTIONS, rows[-1].expires_at.isoformat())

    return [
        Event(
            kind=EventKind.EXCEPTION_EXPIRING,
            severity=EventSeverity.MEDIUM,
            title=f"Exception for {row.check_id} expires {row.expires_at:%Y-%m-%d}",
            message=row.justification or "",
            object_type="exception",
            object_id=str(row.id),
            attributes={"checkId": row.check_id, "expiresAt": row.expires_at.isoformat()},
        )
        for row in rows
    ]


__all__: list[str] = [
    "BY_KIND",
    "COMMIT_LAG",
    "EXPIRY_WINDOW",
    "NOTIFIED_SEVERITIES",
    "WATERMARK_EXCEPTIONS",
    "WATERMARK_FINDINGS",
    "credential_failure_event",
    "feed_failure_event",
    "job_event",
    "scan",
]
