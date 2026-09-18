"""Forwarding findings and audit events to a SIEM (FR-INT-02).

Batch-and-watermark rather than send-on-write. Emitting from every write path would put a
network call inside the transaction that created the finding — a slow or dead collector
would then slow or fail the assessment that found it, which inverts the priority: the
assessment is the product, the forwarding is a copy.

Two streams, because they have different shapes and different hazards.

**Audit records carry a monotonic bigint id**, so the watermark is exact: everything
above the last id forwarded, nothing else, no possibility of a gap.

**Findings do not.** They are UUID-keyed, so the watermark is a timestamp — and a
timestamp watermark has a real race. A row whose `created_at` is T can commit *after* a
batch that already advanced past T, and it is then never forwarded. Nothing downstream
would look wrong; the SIEM would simply never see that finding.

So the finding stream deliberately stays :data:`COMMIT_LAG` behind the present, and only
forwards rows old enough that any transaction which produced them has certainly
committed. The cost is that a finding reaches the SIEM half a minute later than it could.
The alternative is losing some of them silently, which is not a trade worth making for
thirty seconds.

**A SIEM outage is recorded, not retried into the ground.** If the send fails the
watermark does not advance, so the next run picks up where this one stopped — the events
are still in the database, and delivery resumes when the collector does.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.config import Settings
from netsecops.core.logging import get_logger
from netsecops.db.models.audit import AuditLog, Setting
from netsecops.db.models.collection import Finding
from netsecops.db.models.inventory import Device
from netsecops.integrations.events import Event, EventKind, EventSeverity, severity_of
from netsecops.integrations.syslog import SyslogFormat, SyslogForwarder, SyslogTarget

log = get_logger(__name__)

WATERMARK_AUDIT: Final[str] = "integrations.siem.watermark.audit"
WATERMARK_FINDINGS: Final[str] = "integrations.siem.watermark.findings"

#: How far behind the present the finding stream stays. See the module docstring — this
#: is the difference between a late event and a lost one.
COMMIT_LAG: Final[timedelta] = timedelta(seconds=30)

#: Most records of each stream forwarded in one run. Bounds memory and the time a single
#: batch holds a connection to the collector.
BATCH_LIMIT: Final[int] = 500

#: Audit actions worth a higher severity at the SIEM than the routine trail.
#:
#: Everything is forwarded; this only sets how loudly. A SOC correlating on the audit
#: stream wants `login.locked` to stand out from `device.created` without having to know
#: NetSecOps's vocabulary in advance.
ELEVATED: Final[dict[str, EventSeverity]] = {
    "login.locked": EventSeverity.HIGH,
    "login.failure": EventSeverity.MEDIUM,
    "token.reuse_detected": EventSeverity.CRITICAL,
    "mfa.challenge_failed": EventSeverity.MEDIUM,
    "mfa.disabled": EventSeverity.HIGH,
    "readonly.violation": EventSeverity.CRITICAL,
    "credential.used": EventSeverity.LOW,
    "password.reset": EventSeverity.MEDIUM,
    "role.granted": EventSeverity.MEDIUM,
}


@dataclass(slots=True)
class ForwardResult:
    audit_forwarded: int = 0
    findings_forwarded: int = 0
    #: Set when no target is configured, so a caller can tell "nothing to do" from
    #: "nothing happened".
    disabled: bool = False
    error: str | None = None

    @property
    def total(self) -> int:
        return self.audit_forwarded + self.findings_forwarded


def target_from(settings: Settings) -> SyslogTarget | None:
    """The configured collector, or None when forwarding is off."""
    if not settings.siem_syslog_host:
        return None
    return SyslogTarget(
        host=settings.siem_syslog_host,
        port=settings.siem_syslog_port,
        fmt=SyslogFormat(settings.siem_syslog_format),
        use_tls=settings.siem_syslog_tls,
        verify=settings.siem_syslog_verify,
        ca_file=settings.siem_syslog_ca_file,
    )


class SiemForwardingService:
    """Move new audit records and findings onto the wire."""

    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id

    # ── watermarks ──────────────────────────────────────────────────────

    async def _watermark(self, key: str) -> Any:
        row = (
            await self.session.execute(
                select(Setting).where(Setting.org_id == self.org_id, Setting.key == key)
            )
        ).scalar_one_or_none()
        return (row.value or {}).get("at") if row else None

    async def _set_watermark(self, key: str, value: Any) -> None:
        row = (
            await self.session.execute(
                select(Setting).where(Setting.org_id == self.org_id, Setting.key == key)
            )
        ).scalar_one_or_none()
        if row is None:
            self.session.add(
                Setting(
                    org_id=self.org_id,
                    key=key,
                    value={"at": value},
                    description="How far SIEM forwarding has reached. Managed automatically.",
                )
            )
        else:
            row.value = {"at": value}
        await self.session.flush()

    # ── conversion ──────────────────────────────────────────────────────

    def _audit_event(self, row: AuditLog) -> Event:
        action = row.action or "audit"
        return Event(
            kind=EventKind.AUDIT,
            signature=action,
            severity=ELEVATED.get(action, EventSeverity.INFO),
            title=action,
            message=f"{row.actor_username or 'system'} — {action} ({row.outcome})",
            occurred_at=row.ts,
            object_type=row.object_type,
            object_id=str(row.object_id) if row.object_id else None,
            attributes={
                k: str(v)
                for k, v in {
                    "actor": row.actor_username,
                    "outcome": row.outcome,
                    "auditId": row.id,
                }.items()
                if v is not None
            },
        )

    def _finding_event(self, finding: Finding, device: Device | None) -> Event:
        return Event(
            kind=EventKind.FINDING_OPENED,
            severity=severity_of(finding.severity),
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
                for k, v in {
                    "checkId": finding.check_id,
                    "cve": finding.cve_id,
                    "findingKind": finding.kind,
                    "status": finding.status,
                }.items()
                if v
            },
        )

    # ── the run ─────────────────────────────────────────────────────────

    async def forward(
        self,
        *,
        settings: Settings,
        forwarder: SyslogForwarder | None = None,
        limit: int = BATCH_LIMIT,
        now: datetime | None = None,
    ) -> ForwardResult:
        target = target_from(settings)
        if target is None and forwarder is None:
            return ForwardResult(disabled=True)

        sender = forwarder or SyslogForwarder(target)  # type: ignore[arg-type]
        moment = now or datetime.now(UTC)
        result = ForwardResult()

        # ── audit: exact, by monotonic id ───────────────────────────────
        last_id = int(await self._watermark(WATERMARK_AUDIT) or 0)
        audit_rows = list(
            (
                await self.session.execute(
                    select(AuditLog)
                    .where(AuditLog.org_id == self.org_id, AuditLog.id > last_id)
                    .order_by(AuditLog.id)
                    .limit(limit)
                )
            ).scalars()
        )

        # ── findings: lagged, by timestamp ──────────────────────────────
        since = await self._watermark(WATERMARK_FINDINGS)
        cutoff = moment - COMMIT_LAG
        stmt = (
            select(Finding, Device)
            .join(Device, Finding.device_id == Device.id, isouter=True)
            .where(Finding.org_id == self.org_id, Finding.created_at <= cutoff)
            .order_by(Finding.created_at)
            .limit(limit)
        )
        if since:
            stmt = stmt.where(Finding.created_at > datetime.fromisoformat(str(since)))
        finding_rows = list((await self.session.execute(stmt)).all())

        events = [self._audit_event(row) for row in audit_rows]
        events += [self._finding_event(f, d) for f, d in finding_rows]
        if not events:
            return result

        try:
            await sender.send(events)
        except Exception as exc:
            # The watermarks stay where they were, so nothing is lost: these records are
            # still in the database and the next run resumes from the same place.
            result.error = f"{type(exc).__name__}: {exc}"
            log.warning("integrations.siem_send_failed", error=result.error)
            return result

        if audit_rows:
            await self._set_watermark(WATERMARK_AUDIT, audit_rows[-1].id)
            result.audit_forwarded = len(audit_rows)
        if finding_rows:
            await self._set_watermark(
                WATERMARK_FINDINGS, finding_rows[-1][0].created_at.isoformat()
            )
            result.findings_forwarded = len(finding_rows)

        log.info(
            "integrations.siem_forwarded",
            audit=result.audit_forwarded,
            findings=result.findings_forwarded,
        )
        return result


__all__ = [
    "BATCH_LIMIT",
    "COMMIT_LAG",
    "ELEVATED",
    "WATERMARK_AUDIT",
    "WATERMARK_FINDINGS",
    "ForwardResult",
    "SiemForwardingService",
    "target_from",
]
