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

**This service holds no `SecretVault`, and that is a design constraint rather than an
omission.** A report is an artefact that leaves the product — mailed, filed, attached to
a ticket — so it must be structurally incapable of carrying unredacted configuration.
Every evidence field it reads (`CheckResult.evidence`, `Snapshot.config_redacted`,
`Snapshot.ncm`) was redacted at capture. There is no decryption path in this module to
forget to avoid.

**A report that needs a scope and does not get one fails.** A "device detail" report
over the whole estate is not a device detail report, and a compliance report with no
framework is a list of checks. Falling back to the estate would produce a document that
answers a different question from the one its title claims — which is worse than no
document, because it is filed as though it answered the first.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.checks.loader import get_registry
from netsecops.checks.schema import Outcome
from netsecops.core.errors import NotFoundError, ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Principal, Scope
from netsecops.db.models.collection import Finding, FindingKind, FindingStatus, Snapshot
from netsecops.db.models.inventory import Device, DeviceGroup
from netsecops.db.models.policy import CheckResult, FindingException, RiskScore
from netsecops.db.models.reporting import Report, ReportStatus, ReportTemplate

log = get_logger(__name__)

#: Worst first, for the archive. See the module docstring on why this is not imported.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

#: Check outcomes, in the order a reader works down them. `not_evaluated` and `error`
#: are listed alongside the verdicts rather than folded into a "other" bucket: a check
#: that could not run is the single most common way a compliance number lies, and it
#: only stays visible if it has its own column everywhere.
OUTCOME_ORDER = (
    Outcome.FAIL.value,
    Outcome.WARNING.value,
    Outcome.PASS.value,
    Outcome.NOT_APPLICABLE.value,
    Outcome.NOT_EVALUATED.value,
    Outcome.ERROR.value,
)

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
        framework: str | None = None,
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
                "framework": framework,
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
                framework=framework,
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
        framework: str | None = None,
    ) -> dict[str, Any]:
        match template:
            case ReportTemplate.EXECUTIVE_SUMMARY:
                return await self._executive_summary(scope)
            case ReportTemplate.EXCEPTIONS_REGISTER:
                return await self._exceptions_register(scope)
            case ReportTemplate.TREND:
                return await self._trend(scope, compare_to_id)
            case ReportTemplate.DEVICE_DETAIL:
                return await self._device_detail(scope, scope_device_id)
            case ReportTemplate.GROUP_COMPLIANCE:
                return await self._group_compliance(scope, scope_group_id, framework)
            case ReportTemplate.FIREWALL_RULEBASE:
                return await self._firewall_rulebase(scope, scope_device_id)
            case ReportTemplate.VULNERABILITY:
                return await self._vulnerability(scope, scope_device_id)
            case ReportTemplate.AAA_REVIEW:
                return await self._aaa_review(scope)
            case ReportTemplate.DRIFT:
                return await self._drift(scope, scope_device_id)

        # Unreachable while every member of the enum is handled above; kept so that
        # adding a template without assembling it fails loudly rather than silently
        # producing an empty document.
        raise ValidationProblem(  # pragma: no cover - defensive
            f"The {template.value!r} template is not implemented yet. "
            "`GET /reports/templates` marks which templates can be generated."
        )

    # ── scope helpers ────────────────────────────────────────────────────

    async def _require_device(self, device_id: uuid.UUID | None, scope: Scope) -> Device:
        """Resolve the device a single-device report is about, or refuse.

        Refusing is the point. Defaulting to the estate would return a document whose
        title says "device detail" and whose body answers a different question.
        """
        if device_id is None:
            raise ValidationProblem(
                "This report is about one device. Pass `scope_device_id` — running it "
                "over the whole estate would answer a different question under the "
                "same title."
            )

        device = (
            await self.session.execute(
                select(Device).where(Device.org_id == self.org_id, Device.id == device_id)
            )
        ).scalar_one_or_none()
        if device is None:
            raise NotFoundError(f"No device {device_id}.")
        await self._assert_visible(device_id, scope)
        return device

    async def _require_group(self, group_id: uuid.UUID | None) -> DeviceGroup:
        if group_id is None:
            raise ValidationProblem("This report is about one device group. Pass `scope_group_id`.")
        group = (
            await self.session.execute(select(DeviceGroup).where(DeviceGroup.id == group_id))
        ).scalar_one_or_none()
        if group is None:
            raise NotFoundError(f"No device group {group_id}.")
        return group

    async def _assert_visible(self, device_id: uuid.UUID, scope: Scope) -> None:
        """A scoped principal must not generate a report about a device they cannot see.

        Without this a group-scoped auditor could name any device id and receive a
        frozen, downloadable document containing findings from outside their scope —
        and unlike a live view, that artefact keeps working after the scope is fixed.
        """
        if scope.unrestricted:
            return
        from netsecops.services.inventory import InventoryService

        visible = await InventoryService(self.session).visible_device_ids(scope)
        if device_id not in set(visible):
            raise NotFoundError(f"No device {device_id}.")

    async def _latest_snapshot(self, device: Device) -> Snapshot | None:
        return (
            await self.session.execute(
                select(Snapshot)
                .where(Snapshot.device_id == device.id)
                .order_by(Snapshot.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

    @staticmethod
    def _device_identity(device: Device) -> dict[str, Any]:
        """The fields that let a reader place the device without the console."""
        return {
            "device_id": str(device.id),
            "hostname": device.hostname,
            "mgmt_ip": str(device.mgmt_ip),
            "vendor": device.vendor,
            "platform": device.platform,
            "device_class": device.device_class,
            "criticality": device.criticality,
        }

    async def _active_findings(self, scope: Scope) -> Select[Any]:
        """The active-finding set this scope may see, as a statement to aggregate over.

        Returned unexecuted on purpose. The summary below wants five aggregates of this
        set and none of the rows, and the difference is the whole point: an estate-wide
        report used to `.all()` every active finding joined to its device — JSONB
        evidence, details and a duplicated device row apiece — and then count them in
        Python to produce a dozen integers and a top-ten list.
        """
        stmt = select(Finding).where(Finding.status.in_(FindingStatus.active_values()))
        if not scope.unrestricted:
            from netsecops.services.inventory import InventoryService

            visible = await InventoryService(self.session).visible_device_ids(scope)
            stmt = stmt.where(Finding.device_id.in_(visible))
        return stmt

    async def _executive_summary(self, scope: Scope) -> dict[str, Any]:
        """Counts and a worst-ten, computed by the database.

        Every figure here is an aggregate. Doing them in SQL keeps the memory this holds
        proportional to the *answer* — a dozen integers and ten rows — rather than to the
        estate, which is what a summary should cost.
        """
        base = await self._active_findings(scope)
        where = base.whereclause

        def aggregate(*columns: Any) -> Select[Any]:
            stmt = select(*columns).select_from(Finding)
            return stmt.where(where) if where is not None else stmt

        severity_rows = (
            await self.session.execute(
                aggregate(Finding.severity, func.count().label("n")).group_by(Finding.severity)
            )
        ).all()
        kind_rows = (
            await self.session.execute(
                aggregate(Finding.kind, func.count().label("n"))
                .group_by(Finding.kind)
                # Ordered so the report is reproducible. The Python version's ordering
                # was whatever the scan returned, which differed between two reports
                # over identical data.
                .order_by(func.count().desc(), Finding.kind)
            )
        ).all()

        # Zero-filled in the canonical order first, so a severity with no findings is
        # present and reads as none rather than as absent. A severity outside the
        # canonical list still lands, on the end, rather than being dropped.
        by_severity: dict[str, int] = dict.fromkeys(SEVERITY_ORDER, 0)
        for severity, count in severity_rows:
            by_severity[severity] = by_severity.get(severity, 0) + count
        by_kind: dict[str, int] = {str(kind): int(count) for kind, count in kind_rows}

        total_findings = sum(count for _, count in severity_rows)

        assessed = int(
            (
                await self.session.execute(aggregate(func.count(func.distinct(Finding.device_id))))
            ).scalar_one()
        )

        critical = func.count().filter(Finding.severity == "critical")
        high = func.count().filter(Finding.severity == "high")
        # Worst first by Critical, then High, then total — the order an operator would
        # work the list in, frozen so the report does not reshuffle on re-read. Ten rows
        # come back rather than every device in the estate.
        worst = (
            await self.session.execute(
                aggregate(
                    Device.id,
                    Device.hostname,
                    Device.mgmt_ip,
                    Device.platform,
                    Device.criticality,
                    func.count().label("findings"),
                    critical.label("critical"),
                    high.label("high"),
                )
                .join(Device, Device.id == Finding.device_id)
                .group_by(Device.id)
                .order_by(
                    critical.desc(),
                    high.desc(),
                    func.count().desc(),
                    func.coalesce(Device.hostname, ""),
                )
                .limit(10)
            )
        ).all()

        total_devices = int(
            (await self.session.execute(select(func.count()).select_from(Device))).scalar_one()
        )

        return {
            "totals": {
                "findings": total_findings,
                "devices_with_findings": assessed,
                "devices_total": total_devices,
                # Not "devices that are clean". A device with no findings may never
                # have been assessed, and the two must not read the same.
                "devices_without_findings": max(0, total_devices - assessed),
            },
            "by_severity": by_severity,
            "by_kind": by_kind,
            "top_devices": [
                {
                    "device_id": str(row.id),
                    "hostname": row.hostname,
                    "mgmt_ip": str(row.mgmt_ip),
                    "platform": row.platform,
                    "criticality": row.criticality,
                    "findings": row.findings,
                    "critical": row.critical,
                    "high": row.high,
                }
                for row in worst
            ],
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
            # Both sides come out of JSONB, so both are Any as far as the type checker is
            # concerned. Coerced rather than cast: a stored count that is not a number is
            # a corrupt report, and int() saying so is better than a delta that silently
            # concatenates strings.
            before = int((previous.get("by_severity") or {}).get(name, 0) or 0)
            return int(current["by_severity"].get(name, 0) or 0) - before

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

    async def _device_detail(self, scope: Scope, device_id: uuid.UUID | None) -> dict[str, Any]:
        """Every finding on one device, with the evidence behind it (FR-RPT-02).

        The evidence comes from `CheckResult.evidence`, which was redacted at capture.
        This service holds no vault, so there is no path by which raw configuration
        could reach a downloadable artefact.
        """
        device = await self._require_device(device_id, scope)
        snapshot = await self._latest_snapshot(device)

        findings = (
            (
                await self.session.execute(
                    select(Finding)
                    .where(
                        Finding.device_id == device.id,
                        Finding.status.in_(FindingStatus.active_values()),
                    )
                    .order_by(Finding.severity, Finding.last_seen_at.desc())
                )
            )
            .scalars()
            .all()
        )

        results = await self._latest_results(device, snapshot)
        by_outcome = dict.fromkeys(OUTCOME_ORDER, 0)
        for row in results:
            by_outcome[row.outcome] = by_outcome.get(row.outcome, 0) + 1

        risk = (
            await self.session.execute(
                select(RiskScore)
                .where(RiskScore.device_id == device.id)
                .order_by(RiskScore.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

        return {
            "device": self._device_identity(device),
            "assessment": {
                # Named "assessed_at", never "as of now": the newest snapshot may be
                # months old, and a report that hides that reads as current.
                "snapshot_id": str(snapshot.id) if snapshot else None,
                "assessed_at": snapshot.created_at.isoformat() if snapshot else None,
                "parser_platform": snapshot.parser_platform if snapshot else None,
                "parse_coverage": snapshot.parse_coverage if snapshot else None,
                "never_assessed": snapshot is None,
            },
            "risk": (
                {
                    "score": risk.score,
                    "components": risk.components,
                    "scored_at": risk.created_at.isoformat(),
                }
                if risk
                else None
            ),
            "totals": {
                "findings": len(findings),
                "checks_run": len(results),
                **{f"checks_{name}": by_outcome.get(name, 0) for name in OUTCOME_ORDER},
            },
            "findings": [
                {
                    "finding_id": str(f.id),
                    "kind": f.kind,
                    "check_id": f.check_id,
                    "cve_id": f.cve_id,
                    "title": f.title,
                    "severity": f.severity,
                    "status": f.status,
                    "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else None,
                    "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
                    "remediation": f.remediation,
                    "evidence": f.evidence,
                }
                for f in findings
            ],
            "checks": [
                {
                    "check_id": row.check_id,
                    "outcome": row.outcome,
                    "severity": row.severity,
                    "message": row.message,
                    # Why a check produced no verdict. Without it "not evaluated" is
                    # indistinguishable from "we did not bother".
                    "reason": row.reason,
                }
                for row in results
            ],
        }

    async def _latest_results(self, device: Device, snapshot: Snapshot | None) -> list[CheckResult]:
        """One result per check, from the most recent run against the latest snapshot.

        A snapshot can carry results from several jobs (the unique key is snapshot,
        check and job). Showing all of them would double-count a re-run, so the newest
        per check wins.
        """
        if snapshot is None:
            return []
        rows = (
            (
                await self.session.execute(
                    select(CheckResult)
                    .where(CheckResult.snapshot_id == snapshot.id)
                    .order_by(CheckResult.created_at.desc())
                )
            )
            .scalars()
            .all()
        )
        newest: dict[str, CheckResult] = {}
        for row in rows:
            newest.setdefault(row.check_id, row)
        return sorted(
            newest.values(),
            key=lambda r: (
                OUTCOME_ORDER.index(r.outcome) if r.outcome in OUTCOME_ORDER else 99,
                r.check_id,
            ),
        )

    async def _group_compliance(
        self, scope: Scope, group_id: uuid.UUID | None, framework: str | None
    ) -> dict[str, Any]:
        """Pass, fail and not-evaluated per framework control, for a group (FR-RPT-02).

        **The compliance percentage has an explicit denominator, and `not_evaluated` is
        not in it.** A control nobody could assess is not a control that passed, and
        the two must never be summed into one number — that single arithmetic decision
        is how compliance reports come to overstate posture. Both figures are reported:
        the percentage of *decided* controls that passed, and how many were never
        decided at all.
        """
        group = await self._require_group(group_id)
        if not framework:
            known = ", ".join(sorted(get_registry().frameworks()))
            raise ValidationProblem(
                "A compliance report is about one framework. Pass `framework` — "
                f"available: {known}."
            )

        registry = get_registry()
        mapped = registry.by_framework(framework)
        if not mapped:
            known = ", ".join(sorted(registry.frameworks()))
            raise ValidationProblem(
                f"No checks are mapped to {framework!r}. Known frameworks: {known}."
            )

        device_ids = await self._group_device_ids(group, scope)
        if not device_ids:
            raise ValidationProblem(
                f"Group {group.name!r} contains no devices you can see, so there is "
                "nothing to report on. An empty compliance report reads as a compliant "
                "one, which is why this is refused rather than returned."
            )

        check_ids = [d.id for d in mapped]
        rows = (
            (
                await self.session.execute(
                    select(CheckResult.check_id, CheckResult.outcome, func.count().label("n"))
                    .where(
                        CheckResult.check_id.in_(check_ids),
                        CheckResult.device_id.in_(device_ids),
                    )
                    .group_by(CheckResult.check_id, CheckResult.outcome)
                )
            )
            .tuples()
            .all()
        )

        tally: dict[str, dict[str, int]] = {}
        for check_id, outcome, count in rows:
            tally.setdefault(check_id, {})[outcome] = count

        by_control: dict[str, list[str]] = {}
        for definition in mapped:
            for control in definition.references.frameworks().get(framework, []):
                by_control.setdefault(control, []).append(definition.id)

        controls = []
        total_pass = total_fail = total_unevaluated = 0
        for control, ids in sorted(by_control.items()):
            passed = sum(tally.get(i, {}).get(Outcome.PASS.value, 0) for i in ids)
            failed = sum(tally.get(i, {}).get(Outcome.FAIL.value, 0) for i in ids)
            warned = sum(tally.get(i, {}).get(Outcome.WARNING.value, 0) for i in ids)
            skipped = sum(tally.get(i, {}).get(Outcome.NOT_EVALUATED.value, 0) for i in ids)
            errored = sum(tally.get(i, {}).get(Outcome.ERROR.value, 0) for i in ids)
            not_applicable = sum(tally.get(i, {}).get(Outcome.NOT_APPLICABLE.value, 0) for i in ids)
            # A control with no result at all is "never assessed", which is a third
            # state beside pass and fail and is the one a reader most needs to see.
            decided = passed + failed + warned
            controls.append(
                {
                    "control": control,
                    "checks": sorted(ids),
                    "passed": passed,
                    "failed": failed + warned,
                    "not_evaluated": skipped,
                    "errored": errored,
                    "not_applicable": not_applicable,
                    "never_assessed": decided == 0 and skipped == 0 and errored == 0,
                }
            )
            total_pass += passed
            total_fail += failed + warned
            total_unevaluated += skipped + errored

        decided_total = total_pass + total_fail
        return {
            "framework": framework,
            "group": {"group_id": str(group.id), "name": group.name, "path": group.path},
            "totals": {
                "devices": len(device_ids),
                "controls": len(controls),
                "passed": total_pass,
                "failed": total_fail,
                "not_evaluated": total_unevaluated,
                # Null rather than 100 when nothing was decided. A percentage over an
                # empty denominator is not "fully compliant", it is "no evidence".
                "compliance_percentage": (
                    round(100 * total_pass / decided_total) if decided_total else None
                ),
                "denominator": decided_total,
                "controls_never_assessed": sum(1 for c in controls if c["never_assessed"]),
            },
            "controls": controls,
        }

    async def _group_device_ids(self, group: DeviceGroup, scope: Scope) -> list[uuid.UUID]:
        """Devices in the group and every group beneath it, intersected with the scope."""
        from netsecops.db.models.inventory import DeviceGroupMember

        descendants = select(DeviceGroup.id).where(DeviceGroup.path.op("<@")(group.path))
        stmt = select(Device.id).where(
            Device.org_id == self.org_id,
            Device.id.in_(
                select(DeviceGroupMember.device_id).where(
                    DeviceGroupMember.group_id.in_(descendants)
                )
            ),
        )
        ids = list((await self.session.execute(stmt)).scalars().all())
        if scope.unrestricted:
            return ids

        from netsecops.services.inventory import InventoryService

        visible = set(await InventoryService(self.session).visible_device_ids(scope))
        return [i for i in ids if i in visible]

    async def _firewall_rulebase(self, scope: Scope, device_id: uuid.UUID | None) -> dict[str, Any]:
        """Shadowed and redundant rules, hygiene and NAT exposure (FR-RPT-02).

        Built from the stored snapshot's NCM, so it never touches a device and never
        needs the vault. The exposure caveats travel with the numbers: whether external
        zones were supplied or guessed changes what a NAT exposure finding *means*, and
        a frozen report is exactly where that context gets lost if it is not written
        down beside the count.
        """
        from netsecops.services.firewall_view import FirewallViewService

        device = await self._require_device(device_id, scope)
        snapshot = await self._latest_snapshot(device)
        if snapshot is None:
            raise ValidationProblem(
                f"{device.hostname or device.mgmt_ip} has no stored configuration, so "
                "there is no rulebase to analyse."
            )

        view = FirewallViewService(snapshot)
        if not view.has_rulebase:
            raise ValidationProblem(
                f"{device.hostname or device.mgmt_ip} has no firewall rulebase in its "
                "latest snapshot. Reporting zero shadowed rules for a device that has "
                "no rules would read as a clean rulebase."
            )

        payload = view.build()
        summary = payload.summary

        flagged = [
            {
                "order": rule.order,
                "name": rule.name,
                "action": rule.action,
                "enabled": rule.enabled,
                "issues": [
                    {
                        "issue": issue.issue,
                        "severity": issue.severity,
                        "message": issue.message,
                        "related_rule_order": issue.related_rule_order,
                    }
                    for issue in rule.issues
                ],
            }
            for rule in payload.rules
            if rule.issues
        ]

        return {
            "device": self._device_identity(device),
            "snapshot": {
                "snapshot_id": str(snapshot.id),
                "assessed_at": snapshot.created_at.isoformat(),
            },
            "totals": {
                "rules_total": summary.rules_total,
                "rules_enabled": summary.rules_enabled,
                "rules_analysed": summary.rules_analysed,
                "rules_with_issues": len(flagged),
                "relationships": summary.relationships,
                "policy_issues": summary.policy_issues,
                "hygiene_issues": summary.hygiene_issues,
                "nat_issues": summary.nat_issues,
            },
            "caveats": {
                # Each of these changes what the numbers mean, so they are part of the
                # frozen record rather than a footnote in the console.
                "analysis_truncated": summary.truncated,
                "exposure_analysed": summary.exposure_analysed,
                "external_zones_inferred": summary.external_zones_inferred,
                "zones": payload.zones,
            },
            "rules": flagged,
            "hygiene": [
                {
                    "issue": h.issue,
                    "severity": h.severity,
                    "name": h.name,
                    "message": h.message,
                }
                for h in payload.hygiene
            ],
            "nat_rules": [
                {
                    "order": n.order,
                    "name": n.name,
                    "original": n.original,
                    "translated": n.translated,
                    "service": n.service,
                    "direction": n.direction,
                    "issues": [
                        {"issue": i.issue, "severity": i.severity, "message": i.message}
                        for i in n.issues
                    ],
                }
                for n in payload.nat_rules
                if n.issues
            ],
        }

    async def _vulnerability(self, scope: Scope, device_id: uuid.UUID | None) -> dict[str, Any]:
        """CVEs matched from collected versions, and what could not be evaluated.

        `devices_unassessed` is carried into the totals deliberately. A vulnerability
        report whose headline is "12 CVEs" over an estate where forty devices were
        never assessed is not a posture statement, and the frozen artefact is the worst
        place for that qualifier to be missing.
        """
        from netsecops.services.vuln_view import VulnViewService

        view = VulnViewService(self.session)
        device = await self._require_device(device_id, scope) if device_id else None

        summary = await view.summary(scope=scope)
        rows, total = await view.list_vulnerabilities(
            scope=scope,
            device_id=device.id if device else None,
            # The archive takes the whole set, not a page of it. A report that silently
            # stopped at 50 rows would understate the estate for ever.
            limit=1000,
            offset=0,
        )

        return {
            "scope": self._device_identity(device) if device else {"scope": "estate"},
            "totals": {
                "vulnerabilities": total,
                "by_severity": summary.by_severity,
                "by_confidence": summary.by_confidence,
                "devices_affected": summary.devices_affected,
                "devices_unassessed": summary.devices_unassessed,
                "kev_count": summary.kev_count,
            },
            "caveats": {
                # Stated in the artefact because a null KEV flag is not "not on KEV",
                # and no CISA feed is ingested yet.
                "kev_feed_ingested": False,
                "kev_note": (
                    "No CISA KEV feed is ingested, so every KEV flag is unknown rather "
                    "than false. A CVE absent from the KEV count may still be on KEV."
                ),
                "truncated_at": 1000 if total > 1000 else None,
            },
            "vulnerabilities": [row.model_dump(mode="json") for row in rows],
        }

    async def _aaa_review(self, scope: Scope) -> dict[str, Any]:
        """RADIUS and TACACS+ posture, and what the servers and devices disagree about."""
        from netsecops.services.aaa_posture import AaaPostureService

        posture = await AaaPostureService(self.session).build(org_id=self.org_id)
        correlation = posture.correlation
        timeline = posture.certificates

        return {
            "totals": {
                # Null, not 0, when nothing could be assessed. An estate with no central
                # authentication and an estate nobody has looked at are opposite
                # problems that a zero would render identically.
                "coverage_percentage": posture.coverage_percentage,
                "devices_total": posture.devices_total,
                "devices_with_central_auth": posture.devices_with_central_auth,
                "devices_not_evaluated": posture.devices_not_evaluated,
                "servers": len(posture.servers),
                "open_findings": dict(posture.open_findings),
            },
            # The honest half of this report. Lifted to the top rather than left at the
            # bottom, because these say which conclusions were *not* drawn — and with
            # no AAA server collected, every device trivially appears on no client list.
            "caveats": {
                "limitations": list(posture.limitations),
                "correlation_limitations": list(correlation.limitations),
                "servers_examined": correlation.servers_examined,
                "registration_analysed": correlation.registration_analysed,
                # Client entries whose source masks the shared secret. Reuse is
                # unknowable for these, never "not reused" (FR-AAA-05).
                "secrets_not_exposable": correlation.secrets_not_exposable,
            },
            "accepted_protocols": [
                {"name": p.name, "weak": p.weak, "servers": list(p.servers)}
                for p in posture.accepted_protocols
            ],
            "weak_protocols_in_use": posture.weak_protocols_in_use,
            "transports": [{"kind": t.kind, "devices": t.devices} for t in posture.transports],
            "servers": [
                {
                    "device_id": str(s.device_id),
                    "hostname": s.hostname,
                    "product": s.product,
                    "clients": s.clients,
                    "identity_stores": s.identity_stores,
                    "weak_protocols": list(s.weak_protocols),
                    "admin_mfa_enabled": s.admin_mfa_enabled,
                    "snapshot_age_days": s.snapshot_age_days,
                    "certificates": s.certificates,
                }
                for s in posture.servers
            ],
            "certificates": {
                "total": timeline.total,
                "expired": timeline.expired,
                "expiring_soon": timeline.expiring_soon,
                "expiring_within_horizon": timeline.expiring_within_horizon,
                # Certificates with no parseable expiry. Not counted as valid.
                "undated": timeline.undated,
                "servers_without_certificates": list(timeline.servers_without_certificates),
                "entries": [
                    {
                        "device_id": str(e.device_id),
                        "device": e.device,
                        "name": e.name,
                        "subject": e.subject,
                        "issuer": e.issuer,
                        "self_signed": e.self_signed,
                        "usage": list(e.usage),
                        "expires_at": e.expires_at,
                        "days_remaining": e.days_remaining,
                    }
                    for e in timeline.entries
                ],
            },
            "correlation": {
                "counts": dict(correlation.counts),
                "orphaned_clients": [
                    {
                        "name": c.name,
                        "address": c.address,
                        "server": c.server,
                        "server_device_id": str(c.server_device_id),
                        # How stale the server's client list was. An orphan found from
                        # a six-month-old snapshot is a weaker claim than one from
                        # yesterday, and the report says which.
                        "server_snapshot_age_days": c.server_snapshot_age_days,
                    }
                    for c in correlation.orphaned_clients
                ],
                "unregistered_devices": [
                    {
                        "device_id": str(d.device_id),
                        "hostname": d.hostname,
                        "mgmt_ip": d.mgmt_ip,
                        "configured_for_aaa": d.configured_for_aaa,
                    }
                    for d in correlation.unregistered_devices
                ],
                "unknown_servers": [
                    {"address": s.address, "kind": s.kind, "used_by": list(s.used_by)}
                    for s in correlation.unknown_servers
                ],
                "reused_secrets": [
                    {"fingerprint": r.fingerprint, "used_by": list(r.used_by)}
                    for r in correlation.reused_secrets
                ],
            },
        }

    async def _drift(self, scope: Scope, device_id: uuid.UUID | None) -> dict[str, Any]:
        """What changed against the pinned baseline, security-relevant changes first.

        A device with no pinned baseline is reported as *unbaselined*, never as
        unchanged. Nothing to compare against and nothing changed look identical in a
        count and mean opposite things.
        """
        devices = (
            [await self._require_device(device_id, scope)]
            if device_id
            else await self._visible_devices(scope)
        )

        entries: list[dict[str, Any]] = []
        drifted = unbaselined = unassessed = 0

        for device in devices:
            baseline = (
                await self.session.execute(
                    select(Snapshot).where(
                        Snapshot.device_id == device.id, Snapshot.is_baseline.is_(True)
                    )
                )
            ).scalar_one_or_none()
            latest = await self._latest_snapshot(device)

            state = "in_sync"
            if latest is None:
                state = "never_assessed"
                unassessed += 1
            elif baseline is None:
                state = "no_baseline"
                unbaselined += 1
            elif baseline.normalized_hash != latest.normalized_hash:
                state = "drifted"
                drifted += 1

            finding = (
                (
                    await self.session.execute(
                        select(Finding).where(
                            Finding.device_id == device.id,
                            Finding.kind == FindingKind.DRIFT.value,
                            Finding.status.in_(FindingStatus.active_values()),
                        )
                    )
                )
                .scalars()
                .first()
            )

            if state == "in_sync" and finding is None:
                continue

            entries.append(
                {
                    **self._device_identity(device),
                    "state": state,
                    "baseline_pinned_at": (
                        baseline.baseline_pinned_at.isoformat()
                        if baseline and baseline.baseline_pinned_at
                        else None
                    ),
                    "latest_assessed_at": latest.created_at.isoformat() if latest else None,
                    "severity": finding.severity if finding else None,
                    "headline": finding.title if finding else None,
                    "changes": (finding.evidence or {}).get("semantic") if finding else None,
                }
            )

        entries.sort(
            key=lambda e: (
                SEVERITY_ORDER.index(e["severity"]) if e["severity"] in SEVERITY_ORDER else 99,
                e["hostname"] or "",
            )
        )

        return {
            "totals": {
                "devices_examined": len(devices),
                "drifted": drifted,
                # Not folded into "in sync". A device with no baseline has nothing to
                # drift from, which is a gap in the process rather than a clean result.
                "no_baseline": unbaselined,
                "never_assessed": unassessed,
                "in_sync": len(devices) - drifted - unbaselined - unassessed,
            },
            "devices": entries,
        }

    async def _visible_devices(self, scope: Scope) -> list[Device]:
        stmt = select(Device).where(Device.org_id == self.org_id)
        if not scope.unrestricted:
            from netsecops.services.inventory import InventoryService

            visible = await InventoryService(self.session).visible_device_ids(scope)
            stmt = stmt.where(Device.id.in_(visible))
        return list((await self.session.execute(stmt)).scalars().all())

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
