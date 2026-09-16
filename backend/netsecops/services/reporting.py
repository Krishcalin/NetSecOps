"""Assembling reports, and freezing them (FR-RPT-02, FR-RPT-03).

Generation reads the estate as it is *now* and writes down what it saw. Nothing here
recomputes a stored report, and there is deliberately no code path that could: the only
function that touches `content` is `generate`, and it only ever writes a new row.

**Why the archive matters more than the rendering.** An operator asking "what is broken"
is served by the console, which is live and should be. An auditor asking "what did you
know on 31 March, and what did you do about it" cannot be served by a live view at all —
by the time they ask, the answer has changed. AlgoSec gets this right almost by accident,
because their analysis output *is* a dated report; it is the one architectural idea in
their product worth copying outright, and it is close to impossible to add afterwards.

**The severity ordering is duplicated here, deliberately.** `services/risk.py` weights
severities for scoring and `vuln_view.py` orders them for display; this orders them for
an archive. Sharing one constant would couple the frozen record to a live scoring
decision — reweighting Critical next year would change what March's report *says*,
which is the failure this module exists to prevent.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import NotFoundError, ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Principal, Scope
from netsecops.db.models.collection import Finding, FindingStatus
from netsecops.db.models.inventory import Device
from netsecops.db.models.policy import FindingException
from netsecops.db.models.reporting import Report, ReportStatus, ReportTemplate

log = get_logger(__name__)

#: Worst first, for the archive. See the module docstring on why this is not imported.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

#: What each template is for, in the words an operator would use to choose one. Served
#: by `GET /reports/templates` so the console never hard-codes a list that can drift
#: from what the service can actually assemble.
TEMPLATE_CATALOGUE: dict[ReportTemplate, dict[str, str]] = {
    ReportTemplate.EXECUTIVE_SUMMARY: {
        "title": "Executive summary",
        "audience": "Leadership",
        "description": (
            "Estate posture on one page: findings by severity, the devices carrying the "
            "most risk, and what could not be assessed."
        ),
    },
    ReportTemplate.DEVICE_DETAIL: {
        "title": "Device detail",
        "audience": "Engineer",
        "description": "Every finding on one device, with the configuration evidence behind it.",
    },
    ReportTemplate.GROUP_COMPLIANCE: {
        "title": "Group compliance",
        "audience": "Auditor",
        "description": "Pass, fail and not-evaluated counts per framework control, for a group.",
    },
    ReportTemplate.FIREWALL_RULEBASE: {
        "title": "Firewall rulebase review",
        "audience": "Firewall administrator",
        "description": "Shadowed and redundant rules, hygiene issues and NAT exposure.",
    },
    ReportTemplate.VULNERABILITY: {
        "title": "Vulnerability report",
        "audience": "Security analyst",
        "description": (
            "CVEs matched from collected software versions, with confidence and what "
            "could not be evaluated."
        ),
    },
    ReportTemplate.AAA_REVIEW: {
        "title": "AAA review",
        "audience": "Security analyst",
        "description": "RADIUS and TACACS+ posture, and what the servers and devices disagree about.",
    },
    ReportTemplate.DRIFT: {
        "title": "Configuration change report",
        "audience": "Change manager",
        "description": "What changed against the pinned baseline, security-relevant changes first.",
    },
    ReportTemplate.EXCEPTIONS_REGISTER: {
        "title": "Exceptions register",
        "audience": "Auditor",
        "description": (
            "Accepted risks with their justification, approver and expiry. The record an "
            "auditor asks for by name."
        ),
    },
    ReportTemplate.TREND: {
        "title": "Trend report",
        "audience": "Leadership",
        "description": "This report against an earlier one: what opened, what closed, what stayed.",
    },
}


def canonical_hash(content: dict[str, Any]) -> str:
    """SHA-256 over a canonical JSON serialisation.

    Sorted keys and fixed separators, so the same report hashes the same however the
    dict was built. Without that the hash would depend on insertion order and a
    recipient checking it would get spurious mismatches — a check that cries wolf is
    one nobody runs twice.
    """
    encoded = json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class ReportingService:
    """Generates reports and reads them back. Never edits one."""

    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id

    # ── generation ───────────────────────────────────────────────────────

    async def generate(
        self,
        template: ReportTemplate,
        *,
        actor: Principal,
        scope_device_id: uuid.UUID | None = None,
        scope_group_id: uuid.UUID | None = None,
        compare_to_id: uuid.UUID | None = None,
        title: str | None = None,
    ) -> Report:
        """Assemble a report and freeze it.

        The row is written `pending` first and only flipped to `ready` once content and
        its hash are both in hand. A crash halfway therefore leaves a row that is
        visibly incomplete rather than one that looks finished and is not — the state
        the CHECK constraint refuses to store.
        """
        if scope_device_id and scope_group_id:
            raise ValidationProblem(
                "A report is scoped to one device or one group, not both. Omit both for "
                "the whole estate."
            )

        report = Report(
            org_id=self.org_id,
            template=template.value,
            title=title or TEMPLATE_CATALOGUE[template]["title"],
            status=ReportStatus.PENDING.value,
            parameters={
                "scope_device_id": str(scope_device_id) if scope_device_id else None,
                "scope_group_id": str(scope_group_id) if scope_group_id else None,
                "compare_to_id": str(compare_to_id) if compare_to_id else None,
            },
            scope_device_id=scope_device_id,
            scope_group_id=scope_group_id,
            compare_to_id=compare_to_id,
            generated_by_id=actor.id,
        )
        self.session.add(report)
        await self.session.flush()

        try:
            content = await self._assemble(
                template,
                scope=actor.scope,
                scope_device_id=scope_device_id,
                scope_group_id=scope_group_id,
                compare_to_id=compare_to_id,
            )
        except Exception as exc:
            report.status = ReportStatus.FAILED.value
            report.error_message = str(exc) or exc.__class__.__name__
            await self.session.flush()
            log.warning("report.failed", template=template.value, error=str(exc))
            return report

        content["meta"] = {
            "template": template.value,
            "title": report.title,
            "generated_at": datetime.now(UTC).isoformat(),
            "generated_by": actor.username,
            # Stamped into the content, not only the row: a report exported to a file
            # and mailed onward keeps its own provenance.
            "scope": self._describe_scope(scope_device_id, scope_group_id),
        }

        report.content = content
        report.content_hash = canonical_hash(content)
        report.generated_at = datetime.now(UTC)
        report.status = ReportStatus.READY.value
        await self.session.flush()

        log.info(
            "report.generated",
            report_id=str(report.id),
            template=template.value,
            hash=report.content_hash[:12],
        )
        return report

    @staticmethod
    def _describe_scope(device_id: uuid.UUID | None, group_id: uuid.UUID | None) -> str:
        if device_id:
            return f"device:{device_id}"
        if group_id:
            return f"group:{group_id}"
        return "estate"

    # ── the templates ────────────────────────────────────────────────────

    async def _assemble(
        self,
        template: ReportTemplate,
        *,
        scope: Scope,
        scope_device_id: uuid.UUID | None,
        scope_group_id: uuid.UUID | None,
        compare_to_id: uuid.UUID | None,
    ) -> dict[str, Any]:
        match template:
            case ReportTemplate.EXECUTIVE_SUMMARY:
                return await self._executive_summary(scope)
            case ReportTemplate.EXCEPTIONS_REGISTER:
                return await self._exceptions_register(scope)
            case ReportTemplate.TREND:
                return await self._trend(scope, compare_to_id)
            case _:
                # Declared in the catalogue, not yet assembled. Refused loudly rather
                # than returned empty: an empty compliance report reads as a clean one.
                raise ValidationProblem(
                    f"The {template.value!r} template is not implemented yet. "
                    "`GET /reports/templates` marks which templates can be generated."
                )

    async def _findings(self, scope: Scope, *, kinds: Sequence[str] | None = None) -> list[Any]:
        stmt = (
            select(Finding, Device)
            .join(Device, Device.id == Finding.device_id)
            .where(Finding.status.in_(FindingStatus.active_values()))
        )
        if kinds:
            stmt = stmt.where(Finding.kind.in_(kinds))
        if not scope.unrestricted:
            from netsecops.services.inventory import InventoryService

            visible = await InventoryService(self.session).visible_device_ids(scope)
            stmt = stmt.where(Finding.device_id.in_(visible))
        return list((await self.session.execute(stmt)).all())

    async def _executive_summary(self, scope: Scope) -> dict[str, Any]:
        rows = await self._findings(scope)

        by_severity: dict[str, int] = dict.fromkeys(SEVERITY_ORDER, 0)
        by_kind: dict[str, int] = {}
        per_device: dict[str, dict[str, Any]] = {}

        for finding, device in rows:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_kind[finding.kind] = by_kind.get(finding.kind, 0) + 1
            entry = per_device.setdefault(
                str(device.id),
                {
                    "device_id": str(device.id),
                    "hostname": device.hostname,
                    "mgmt_ip": str(device.mgmt_ip),
                    "platform": device.platform,
                    "criticality": device.criticality,
                    "findings": 0,
                    "critical": 0,
                    "high": 0,
                },
            )
            entry["findings"] += 1
            if finding.severity in ("critical", "high"):
                entry[finding.severity] += 1

        # Worst first by Critical, then High, then total — the order an operator would
        # work the list in, frozen so the report does not reshuffle on re-read.
        ranked = sorted(
            per_device.values(),
            key=lambda d: (-d["critical"], -d["high"], -d["findings"], d["hostname"] or ""),
        )

        total_devices = int(
            (await self.session.execute(select(func.count()).select_from(Device))).scalar_one()
        )
        assessed = len(per_device)

        return {
            "totals": {
                "findings": len(rows),
                "devices_with_findings": assessed,
                "devices_total": total_devices,
                # Not "devices that are clean". A device with no findings may never
                # have been assessed, and the two must not read the same.
                "devices_without_findings": max(0, total_devices - assessed),
            },
            "by_severity": by_severity,
            "by_kind": by_kind,
            "top_devices": ranked[:10],
        }

    async def _exceptions_register(self, scope: Scope) -> dict[str, Any]:
        """Accepted risks, with who accepted them and when they lapse (FR-RPT-02).

        The report AlgoSec has no equivalent of: their only mechanism for accepting a
        risk is setting its severity to "Ignored", which is global, permanent and
        unattributed, and is indistinguishable in their output from a risk that never
        existed.
        """
        rows = (
            (
                await self.session.execute(
                    select(FindingException).order_by(FindingException.expires_at)
                )
            )
            .scalars()
            .all()
        )

        now = datetime.now(UTC)
        entries = []
        for row in rows:
            expires = row.expires_at
            entries.append(
                {
                    "check_id": row.check_id,
                    "scope": row.scope,
                    "device_id": str(row.device_id) if row.device_id else None,
                    "justification": row.justification,
                    "approver": row.approver,
                    "expires_at": expires.isoformat() if expires else None,
                    "status": row.status,
                    # Computed at generation and frozen. An exception that lapses in
                    # April was still live in March, and March's report must say so.
                    "expired_at_generation": bool(expires and expires < now),
                }
            )

        return {
            "totals": {
                "exceptions": len(entries),
                "expired": sum(1 for e in entries if e["expired_at_generation"]),
            },
            "exceptions": entries,
        }

    async def _trend(self, scope: Scope, compare_to_id: uuid.UUID | None) -> dict[str, Any]:
        """This report against an earlier one (FR-RPT-02).

        Reads the *earlier report's stored content*, not the estate as it was — which
        is the only way to make the comparison reproducible. Recomputing the old side
        from live data would give a different answer every time it ran.
        """
        if compare_to_id is None:
            raise ValidationProblem(
                "A trend report compares against an earlier report. Pass `compare_to_id`."
            )

        earlier = await self.get(compare_to_id)
        if earlier.status != ReportStatus.READY.value:
            raise ValidationProblem(
                f"Report {compare_to_id} is {earlier.status}, so there is nothing to "
                "compare against."
            )

        current = await self._executive_summary(scope)
        previous = earlier.content or {}

        def severity_delta(name: str) -> int:
            before = (previous.get("by_severity") or {}).get(name, 0)
            return current["by_severity"].get(name, 0) - before

        return {
            "compared_to": {
                "report_id": str(earlier.id),
                "generated_at": earlier.generated_at.isoformat() if earlier.generated_at else None,
                "content_hash": earlier.content_hash,
            },
            "current": current["totals"],
            "previous": previous.get("totals", {}),
            "by_severity": current["by_severity"],
            "severity_delta": {name: severity_delta(name) for name in SEVERITY_ORDER},
            "findings_delta": current["totals"]["findings"]
            - (previous.get("totals", {}).get("findings", 0)),
        }

    # ── reads ────────────────────────────────────────────────────────────

    async def get(self, report_id: uuid.UUID) -> Report:
        row = (
            await self.session.execute(
                select(Report).where(Report.org_id == self.org_id, Report.id == report_id)
            )
        ).scalar_one_or_none()
        if row is None:
            raise NotFoundError(f"No report {report_id}.")
        return row

    async def list_reports(
        self, *, template: str | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[list[Report], int]:
        stmt = select(Report).where(Report.org_id == self.org_id)
        if template:
            stmt = stmt.where(Report.template == template)

        total = int(
            (
                await self.session.execute(select(func.count()).select_from(stmt.subquery()))
            ).scalar_one()
        )
        rows = (
            (
                await self.session.execute(
                    stmt.order_by(Report.created_at.desc()).limit(limit).offset(offset)
                )
            )
            .scalars()
            .all()
        )
        return list(rows), total


__all__ = ["SEVERITY_ORDER", "TEMPLATE_CATALOGUE", "ReportingService", "canonical_hash"]
