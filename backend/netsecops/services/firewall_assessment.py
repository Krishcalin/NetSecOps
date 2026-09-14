"""Turning rulebase analysis into stored findings (FR-FW-02 … FR-FW-05, FR-FIND-01).

The `firewall` package answers "what is wrong with this rulebase". This module is what
makes the answer persist: a `findings` row per problem, reopened when it comes back and
resolved when it goes away.

Three decisions shape it.

**Fingerprints are built from rule *names*, never rule numbers.** Inserting one rule at
the top of a rulebase renumbers everything below it. A fingerprint containing the order
would close every finding on the device and open an identical set the next morning,
destroying the first-seen dates that make a finding worth tracking. Names are stable
across exactly the edit that numbers are not. Where a rule has no name the parser has
already substituted a stable fallback.

**Absence is evidence here, unlike for checks.** A config check that does not run tells
you nothing, so its finding stays open. Rulebase analysis is different: it re-derives
every relationship from the whole rulebase on every snapshot, so a shadowing that is not
reported this time genuinely no longer exists. That makes closure by absence correct —
but only when the analysis actually ran. If the rulebase is empty because the platform
does not carry one, nothing is resolved, because "no rules parsed" and "no problems" are
different facts and only one of them is good news.

**Findings are capped, and the cap is visible.** A 5,000-rule rulebase can yield hundreds
of thousands of correlations. Writing a row for each would bury every other finding on
the device and make the findings table unusable. The counts are reported in full and a
bounded number of examples are stored, with a summary finding naming what was left out
rather than the truncation being silent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.logging import get_logger
from netsecops.db.models.collection import Finding, FindingKind, FindingStatus, Snapshot
from netsecops.db.models.inventory import Device
from netsecops.firewall import (
    NatReport,
    Relationship,
    analyse,
    examine_hygiene,
    examine_nat,
    examine_policy,
    external_zones_from,
    resolve_rulebase,
)
from netsecops.firewall.analysis import RELATIONSHIP_SEVERITY

log = get_logger(__name__)

#: How many findings of any one kind are written as individual rows. Beyond this the
#: count is still reported, as a single summary finding.
MAX_FINDINGS_PER_KIND = 50

#: Relationship kinds worth a finding. Correlation and generalisation are normal features
#: of a working rulebase — a specific exception above a general rule is *good* practice —
#: and writing a row for each would drown the shadowing findings that matter.
REPORTED_RELATIONSHIPS = (Relationship.SHADOWED, Relationship.REDUNDANT)


@dataclass(slots=True)
class FirewallAssessment:
    """What analysing one rulebase produced."""

    rules_analysed: int = 0
    findings_opened: int = 0
    findings_resolved: int = 0
    #: Every problem found, by kind, whether or not a row was written for it.
    counts: dict[str, int] = field(default_factory=dict)
    #: False when the snapshot carries no rulebase — which is not the same as a clean
    #: one, and stops anything being resolved on the strength of it.
    analysed: bool = False
    #: False when nobody told us which zones face the internet, so no exposure
    #: conclusions were drawn (FR-FW-04).
    exposure_analysed: bool = False
    duration_ms: int = 0


def _fingerprint(issue: str, *parts: str) -> str:
    """Stable identity for a rulebase finding.

    Deliberately excludes the rule order: see the module docstring. Names are lowercased
    so a rule renamed only in case does not present as a new problem.
    """
    tail = ":".join(part.strip().lower() for part in parts if part)
    return f"firewall:{issue}:{tail}" if tail else f"firewall:{issue}"


class FirewallAssessmentService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def assess(
        self,
        device: Device,
        snapshot: Snapshot,
        *,
        external_zones: list[str] | None = None,
    ) -> FirewallAssessment:
        """Analyse the snapshot's rulebase and store what it found.

        ``external_zones`` says which zones face untrusted networks. When it is not
        supplied the zone-naming heuristic is tried, and if that finds nothing the
        exposure analysis is skipped and said to be skipped — a guess here either
        invents exposure findings or hides real ones.
        """
        outcome = FirewallAssessment()
        firewall = (snapshot.ncm or {}).get("firewall") or {}

        if not firewall.get("security_rules"):
            # No rulebase. Not a clean rulebase — a switch has no firewall policy, and a
            # failed parse produces the same empty block. Nothing is resolved on this.
            log.info(
                "firewall_assessment.no_rulebase",
                device_id=str(device.id),
                platform=device.platform,
            )
            return outcome

        rules, resolver = resolve_rulebase(firewall)
        zones = external_zones if external_zones is not None else external_zones_from(firewall)

        analysis = analyse(rules)
        policy = examine_policy(rules)
        hygiene = examine_hygiene(resolver, rules)
        nat = examine_nat(firewall, rules, resolver, external_zones=zones)

        outcome.analysed = True
        outcome.rules_analysed = analysis.rules_analysed
        outcome.exposure_analysed = nat.exposure_analysed
        outcome.duration_ms = analysis.duration_ms

        seen: set[str] = set()

        for fingerprint, payload in self._collect(analysis, policy, hygiene, nat):
            seen.add(fingerprint)
            if await self._open(device, snapshot, fingerprint, payload):
                outcome.findings_opened += 1

        outcome.counts = {
            **analysis.total_by_kind,
            **policy.counts,
            **hygiene.counts,
            **nat.counts,
        }
        outcome.findings_resolved = await self._resolve_absent(device, seen)

        await self.session.flush()
        log.info(
            "firewall_assessment.completed",
            device_id=str(device.id),
            rules=outcome.rules_analysed,
            opened=outcome.findings_opened,
            resolved=outcome.findings_resolved,
            exposure_analysed=outcome.exposure_analysed,
        )
        return outcome

    # ── turning reports into finding payloads ───────────────────────────

    def _collect(
        self,
        analysis: Any,
        policy: Any,
        hygiene: Any,
        nat: NatReport,
    ) -> list[tuple[str, dict[str, Any]]]:
        """One flat list of (fingerprint, payload), capped per kind.

        The cap is applied per kind rather than overall so a rulebase with thousands of
        redundancies cannot crowd out its single critical exposure.
        """
        collected: list[tuple[str, dict[str, Any]]] = []
        per_kind: dict[str, int] = {}

        def take(kind: str) -> bool:
            count = per_kind.get(kind, 0)
            per_kind[kind] = count + 1
            return count < MAX_FINDINGS_PER_KIND

        for relationship in analysis.relationships:
            if relationship.kind not in REPORTED_RELATIONSHIPS:
                continue
            kind = relationship.kind.value
            if not take(kind):
                continue
            subject, cause = relationship.subject, relationship.cause
            collected.append(
                (
                    _fingerprint(kind, subject.name, cause.name),
                    {
                        "title": f"Rule '{subject.name}' is {kind}",
                        "description": relationship.describe(),
                        "severity": RELATIONSHIP_SEVERITY[relationship.kind],
                        "evidence": {
                            "subject_rule": subject.name,
                            "subject_order": subject.order,
                            "cause_rule": cause.name,
                            "cause_order": cause.order,
                            "shadows": list(relationship.subject_shadows),
                        },
                        "remediation": _RELATIONSHIP_REMEDIATION[relationship.kind],
                    },
                )
            )

        for finding in policy.findings:
            kind = finding.issue.value
            if not take(kind):
                continue
            collected.append(
                (
                    _fingerprint(kind, finding.rule_name),
                    {
                        "title": f"Rule '{finding.rule_name}': {kind.replace('_', ' ')}",
                        "description": finding.message,
                        "severity": finding.severity,
                        "evidence": {
                            "rule": finding.rule_name,
                            "order": finding.rule_order,
                            "threshold": finding.threshold,
                        },
                        "remediation": None,
                    },
                )
            )

        for finding in hygiene.findings:
            kind = finding.issue.value
            if not take(kind):
                continue
            collected.append(
                (
                    _fingerprint(kind, finding.name),
                    {
                        "title": f"{kind.replace('_', ' ').capitalize()}: {finding.name}",
                        "description": finding.message,
                        "severity": finding.severity,
                        "evidence": {"object": finding.name},
                        "remediation": None,
                    },
                )
            )

        for finding in nat.findings:
            kind = finding.issue.value
            if not take(kind):
                continue
            collected.append(
                (
                    # The security rule is part of the identity: the same NAT reachable
                    # through two different permits is two exposures, and closing one
                    # does not close the other.
                    _fingerprint(kind, finding.nat_name, finding.rule_name or ""),
                    {
                        "title": f"NAT '{finding.nat_name}': {kind.replace('_', ' ')}",
                        "description": finding.message,
                        "severity": finding.severity,
                        "evidence": {
                            "nat_rule": finding.nat_name,
                            "nat_order": finding.nat_order,
                            "security_rule": finding.rule_name,
                            "security_rule_order": finding.rule_order,
                        },
                        "remediation": None,
                    },
                )
            )

        for kind, total in per_kind.items():
            if total <= MAX_FINDINGS_PER_KIND:
                continue
            # The truncation is itself a finding. A rulebase with 4,000 redundancies has
            # one systemic problem, and silently storing the first fifty would understate
            # it while looking complete.
            collected.append(
                (
                    _fingerprint("truncated", kind),
                    {
                        "title": f"{total:,} '{kind.replace('_', ' ')}' problems in the rulebase",
                        "description": (
                            f"The analysis found {total:,} instances of "
                            f"'{kind.replace('_', ' ')}'. The first {MAX_FINDINGS_PER_KIND} "
                            "are recorded individually; the rest are not, because a "
                            "findings list that long is unreadable. At this volume the "
                            "count is the finding — the rulebase needs a review, not "
                            f"{total:,} separate fixes."
                        ),
                        "severity": "medium",
                        "evidence": {"issue": kind, "total": total},
                        "remediation": None,
                    },
                )
            )

        return collected

    # ── persistence ─────────────────────────────────────────────────────

    async def _open(
        self,
        device: Device,
        snapshot: Snapshot,
        fingerprint: str,
        payload: dict[str, Any],
    ) -> bool:
        """Create or refresh one finding. True when it is newly opened or reopened."""
        now = datetime.now(UTC)
        existing = (
            await self.session.execute(
                select(Finding).where(
                    Finding.device_id == device.id, Finding.fingerprint == fingerprint
                )
            )
        ).scalar_one_or_none()

        if existing is not None:
            was_closed = not FindingStatus(existing.status).is_active
            existing.title = payload["title"]
            existing.description = payload["description"]
            existing.severity = payload["severity"]
            existing.evidence = payload["evidence"]
            existing.snapshot_id = snapshot.id
            existing.last_seen_at = now
            existing.occurrences += 1
            if was_closed:
                existing.status = FindingStatus.REOPENED.value
                existing.resolved_at = None
            await self.session.flush()
            return was_closed

        self.session.add(
            Finding(
                org_id=device.org_id,
                device_id=device.id,
                kind=FindingKind.FIREWALL.value,
                fingerprint=fingerprint,
                title=payload["title"],
                description=payload["description"],
                severity=payload["severity"],
                status=FindingStatus.NEW.value,
                evidence=payload["evidence"],
                remediation=payload["remediation"],
                snapshot_id=snapshot.id,
                first_seen_at=now,
                last_seen_at=now,
            )
        )
        await self.session.flush()
        return True

    async def _resolve_absent(self, device: Device, seen: set[str]) -> int:
        """Close rulebase findings the current analysis did not produce.

        Only reached when the analysis ran over a real rulebase. Closure by absence is
        correct *here* precisely because every relationship is re-derived from the whole
        rulebase each time — the same reasoning that makes it wrong for a config check,
        which can simply not have run.
        """
        rows = (
            (
                await self.session.execute(
                    select(Finding).where(
                        Finding.device_id == device.id,
                        Finding.kind == FindingKind.FIREWALL.value,
                    )
                )
            )
            .scalars()
            .all()
        )

        now = datetime.now(UTC)
        resolved = 0
        for row in rows:
            if row.fingerprint in seen or not FindingStatus(row.status).is_active:
                continue
            row.status = FindingStatus.RESOLVED.value
            row.resolved_at = now
            resolved += 1

        if resolved:
            await self.session.flush()
        return resolved


_RELATIONSHIP_REMEDIATION: dict[Relationship, str] = {
    Relationship.SHADOWED: (
        "This rule can never match. Decide which behaviour is intended: if the traffic "
        "should be allowed, move this rule above the one covering it; if it should not, "
        "delete this rule so the rulebase says what it does."
    ),
    Relationship.REDUNDANT: (
        "Removing this rule does not change what the firewall permits or denies. Check "
        "the finding text first — a redundant rule can still be the only source of "
        "logging or inspection for its traffic, or the only thing holding a rule below "
        "it shut."
    ),
    Relationship.CORRELATED: (
        "The order between these rules decides the outcome. Confirm the current order "
        "is intended before either is moved."
    ),
    Relationship.GENERALISATION: (
        "Usually intentional: a specific exception above a general rule. No action is "
        "needed unless the exception was meant to be broader."
    ),
}


__all__ = [
    "MAX_FINDINGS_PER_KIND",
    "REPORTED_RELATIONSHIPS",
    "FirewallAssessment",
    "FirewallAssessmentService",
]
