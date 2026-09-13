"""Wires device sessions into the tamper-evident audit log (FR-AUD-01, SRS §8.1.8).

SRS §8.1 item 8 promises customers can see exactly what NetSecOps executed on each
device. That promise is kept here: every command a session sends becomes an audit
record, in the same hash-chained log as everything else, so the record of what we did
to a device is as tamper-evident as the record of who logged in.

Device *output* is deliberately not recorded here. It routinely contains secrets, and
belongs in an encrypted artefact instead (FR-COL-03, FR-COL-13).
"""

from __future__ import annotations

import uuid
from typing import Any

from netsecops.adapters.session import CommandRecorder
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Principal
from netsecops.db.models.audit import AuditAction, AuditOutcome
from netsecops.services.audit import AuditService

log = get_logger(__name__)


class AuditingRecorder(CommandRecorder):
    """Writes every emitted command to the audit chain."""

    def __init__(
        self,
        audit: AuditService,
        *,
        actor: Principal | None = None,
        job_id: uuid.UUID | None = None,
        org_id: int = 1,
    ) -> None:
        self.audit = audit
        self.actor = actor
        self.job_id = job_id
        self.org_id = org_id

    async def record(
        self,
        *,
        command: str,
        device_id: uuid.UUID | None,
        succeeded: bool,
        duration_ms: int,
        detail: str | None = None,
    ) -> None:
        await self.audit.record(
            AuditAction.DEVICE_COMMAND,
            outcome=AuditOutcome.SUCCESS if succeeded else AuditOutcome.FAILURE,
            actor_id=self.actor.id if self.actor else None,
            actor_username=self.actor.username if self.actor else "scheduler",
            object_type="device",
            object_id=device_id,
            device_id=device_id,
            command_text=command,
            details={
                "duration_ms": duration_ms,
                "job_id": str(self.job_id) if self.job_id else None,
                "detail": detail,
            },
            org_id=self.org_id,
        )

    async def record_violation(
        self, *, command: str, device_id: uuid.UUID | None, reason: str, context: dict[str, Any]
    ) -> None:
        """A violation is a critical internal fault, not a device problem (FR-COL-04).

        It is recorded at ``DENIED`` so it stands out in the trail, and the notification
        rules in Phase 7 alert on this action specifically: it should never happen, and
        if it does, someone needs to know the same day.
        """
        log.critical(
            "readonly.violation_recorded",
            command=command,
            device_id=str(device_id) if device_id else None,
            reason=reason,
        )
        await self.audit.record(
            AuditAction.READONLY_VIOLATION,
            outcome=AuditOutcome.DENIED,
            actor_id=self.actor.id if self.actor else None,
            actor_username=self.actor.username if self.actor else "scheduler",
            object_type="device",
            object_id=device_id,
            device_id=device_id,
            command_text=command,
            details={
                "reason": reason,
                "job_id": str(self.job_id) if self.job_id else None,
                **context,
            },
            org_id=self.org_id,
        )
