"""Checking declared segmentation against what the estate actually does (FR-TOPO-07).

**Path-centrically**, which is the whole design and the thing that separates this from
reading a matrix off one firewall. The obvious implementation is to take each zone pair
and search every rulebase for a rule matching it; that is what a rule-centric tool does
and it is wrong in both directions.

It reports violations that do not exist: a permissive rule on one firewall means nothing
if a second firewall downstream denies the same traffic, and there is no path between
the two zones at all if nothing routes it. It also misses violations that do: no single
rule permits production to reach the card environment, and yet a packet gets there,
because the permit is assembled from one rule on the edge and another on the core.

So each cell of the matrix is evaluated by walking a packet, exactly as an operator
would ask it — through NAT, across hops, with each firewall consulted in turn.

Three properties this is arranged around.

**Not-verified is not a pass.** A cell whose path could not be traced — no device serves
the source, the route table was never collected, NAT could not be followed — is reported
as unverified, never as upheld. A segmentation matrix showing green for pairs nobody
could test is worse than no matrix: it is a compliance artefact asserting isolation that
was never checked, and somebody signs it.

**A `DENIED` intent is checked over the whole zone, not a sample address.** Proving a
negative about a zone pair means the whole address space, and the path engine already
evaluates ranges — `first_match_over_range` returns `mixed` where a rulebase treats part
of a range differently. Walking one representative address would prove nothing about the
other 65,000, while looking exactly as authoritative.

**Every prefix pair is walked, and the result says how many.** A zone is a list of
CIDRs, and a cell is upheld only if every prefix pair in it is. One combination behaving
differently from the rest is the interesting case, so it decides the cell rather than
being averaged away.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ConflictError, NotFoundError, ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.db.models.segmentation import (
    SegmentationExpectation,
    SegmentationRule,
    SegmentationZone,
)
from netsecops.topology.graph import TopologyGraph
from netsecops.topology.path import PathResult, PolicyVerdict, RoutingConfidence, walk

log = get_logger(__name__)

#: How many prefix pairs one cell will walk. A zone with twenty CIDRs against another
#: with twenty is four hundred full path walks for one cell, and a matrix of those is
#: not an interactive request. When the cap bites the cell says so rather than
#: presenting a partial check as a complete one.
MAX_PREFIX_PAIRS = 16


class CellStatus(StrEnum):
    """What one matrix cell came out as."""

    #: The estate does what the policy says.
    UPHELD = "upheld"
    #: The estate does something the policy forbids — or fails to do what it requires.
    VIOLATED = "violated"
    #: The path could not be traced far enough to say. Never a pass.
    UNVERIFIED = "unverified"


@dataclass(slots=True)
class CellResult:
    """One zone pair, evaluated."""

    rule_id: uuid.UUID
    source_zone: str
    destination_zone: str
    expectation: str
    protocol: str
    port: int
    status: CellStatus
    #: One sentence saying what was found and why it is or is not a violation.
    detail: str
    justification: str
    #: The prefix pairs actually walked, as "10.10.0.0/24 → 10.20.0.0/24".
    walked: list[str] = field(default_factory=list)
    #: Everything that makes this cell's answer narrower than it looks: a cap that bit,
    #: a NAT device the walk could not follow, a device with no route data.
    limitations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MatrixResult:
    cells: list[CellResult] = field(default_factory=list)
    upheld: int = 0
    violated: int = 0
    unverified: int = 0
    limitations: list[str] = field(default_factory=list)


def _prefix_pairs(source: SegmentationZone, destination: SegmentationZone) -> list[tuple[str, str]]:
    pairs = [(src, dst) for src in source.prefixes for dst in destination.prefixes]
    return pairs[:MAX_PREFIX_PAIRS]


def _verify_prefix(prefixes: list[str], zone_name: str) -> None:
    for prefix in prefixes:
        try:
            ipaddress.ip_network(prefix, strict=False)
        except ValueError as exc:
            raise ValidationProblem(
                f"Zone {zone_name!r} lists {prefix!r}, which is not an address or a CIDR "
                f"range: {exc}. A zone is defined by its addresses, so an unreadable one "
                "would make every rule touching this zone unverifiable."
            ) from None


def _judge(expectation: str, result: PathResult) -> tuple[CellStatus, str]:
    """One path answer against one expectation.

    The mapping is short and every line of it is a decision about what counts as
    evidence. The governing rule: only a *definitive* path answer can uphold or violate
    anything. `partially-allowed` means the permit speaks for the devices consulted and
    the path was not followed to the end — which is not proof of reachability, and
    certainly not proof of isolation.
    """
    routing, policy = result.routing, result.policy

    if expectation == SegmentationExpectation.DENIED:
        if policy is PolicyVerdict.BLOCKED:
            blocker = result.blocked_by
            where = f" at {blocker.hostname}" if blocker else ""
            return CellStatus.UPHELD, f"Traffic is denied{where}, as the policy requires."

        if policy is PolicyVerdict.ALLOWED and routing is RoutingConfidence.ROUTED:
            names = " → ".join(hop.hostname for hop in result.hops) or "no device"
            return (
                CellStatus.VIOLATED,
                f"Traffic reaches the destination and every firewall on the way permits "
                f"it ({names}). The policy says this must be blocked.",
            )

        if routing is RoutingConfidence.UNREACHABLE:
            # Nothing routes between them. That satisfies the intent, and it is worth
            # distinguishing from a firewall denying it: a routing gap is not a
            # control, and it disappears the day somebody adds a static route.
            return (
                CellStatus.UPHELD,
                "No device has a route between these zones, so the traffic cannot flow. "
                "Note this is a routing gap rather than a policy control — no firewall "
                "is denying it, and adding a route would remove the separation.",
            )

        if routing is RoutingConfidence.SAME_ZONE:
            return (
                CellStatus.VIOLATED,
                "These zones share an attached subnet, so traffic between them is not "
                "routed and no firewall can see it. Nothing can enforce this rule.",
            )

        return (
            CellStatus.UNVERIFIED,
            f"The path could not be traced far enough to say: routing is {routing.value} "
            f"and policy is {policy.value}. This is not evidence of separation.",
        )

    # ── expectation: ALLOWED ──────────────────────────────────────────────
    if policy is PolicyVerdict.ALLOWED and routing is RoutingConfidence.ROUTED:
        return CellStatus.UPHELD, "Traffic reaches the destination and is permitted."

    if policy is PolicyVerdict.BLOCKED:
        blocker = result.blocked_by
        where = (
            f"{blocker.hostname}" + (f" rule '{blocker.rule_name}'" if blocker.rule_name else "")
            if blocker
            else "a device on the path"
        )
        return (
            CellStatus.VIOLATED,
            f"{where} denies this traffic, but the policy requires it to be permitted.",
        )

    if routing is RoutingConfidence.UNREACHABLE:
        return (
            CellStatus.VIOLATED,
            "No device has a route between these zones, so the traffic cannot flow at "
            "all. The policy requires it to be permitted.",
        )

    return (
        CellStatus.UNVERIFIED,
        f"The path could not be traced to the end: routing is {routing.value} and policy "
        f"is {policy.value}. A permit on the devices consulted is not proof it gets "
        "through.",
    )


#: Worst first. A cell whose prefix pairs disagree takes the most serious of them,
#: because the interesting combination is the one that behaves differently and averaging
#: it away is how a matrix comes to show green over a hole.
_SEVERITY = {CellStatus.VIOLATED: 2, CellStatus.UNVERIFIED: 1, CellStatus.UPHELD: 0}


class SegmentationService:
    """Reads the declared policy and evaluates it against the live graph."""

    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id

    # ── the policy ────────────────────────────────────────────────────────

    async def zones(self) -> list[SegmentationZone]:
        rows = await self.session.execute(
            select(SegmentationZone)
            .where(SegmentationZone.org_id == self.org_id)
            .order_by(SegmentationZone.name)
        )
        return list(rows.scalars().all())

    async def zone(self, zone_id: uuid.UUID) -> SegmentationZone:
        found = await self.session.get(SegmentationZone, zone_id)
        if found is None or found.org_id != self.org_id:
            raise NotFoundError(f"No segmentation zone {zone_id}.")
        return found

    async def create_zone(
        self, *, name: str, prefixes: list[str], description: str | None = None
    ) -> SegmentationZone:
        if not prefixes:
            raise ValidationProblem(
                "A zone needs at least one address range. A zone with none can neither "
                "be reached nor be a source, so every rule touching it would be "
                "unverifiable."
            )
        _verify_prefix(prefixes, name)

        # Checked here rather than left to the unique constraint. While the policy was
        # written by script a duplicate was somebody's bug; from a form it is the most
        # ordinary mistake there is — a retried submit — and an IntegrityError surfaces
        # as a 500 with nothing a reader can act on.
        if any(zone.name == name for zone in await self.zones()):
            raise ConflictError(
                f"A zone called {name!r} already exists. Zone names are how every rule "
                "refers to address space, so two with one name would make the matrix "
                "ambiguous about which was meant."
            )

        zone = SegmentationZone(
            org_id=self.org_id, name=name, prefixes=prefixes, description=description
        )
        self.session.add(zone)
        await self.session.flush()
        return zone

    async def rules(self) -> list[SegmentationRule]:
        rows = await self.session.execute(
            select(SegmentationRule).where(SegmentationRule.org_id == self.org_id)
        )
        return list(rows.scalars().all())

    async def create_rule(
        self,
        *,
        source_zone_id: uuid.UUID,
        destination_zone_id: uuid.UUID,
        expectation: str,
        justification: str,
        protocol: str = "tcp",
        port: int = 443,
    ) -> SegmentationRule:
        if source_zone_id == destination_zone_id:
            raise ValidationProblem(
                "A zone cannot be segmented from itself. Traffic inside one zone does "
                "not cross a boundary, so there is nothing for a path walk to evaluate."
            )

        names = {zone.id: zone.name for zone in await self.zones()}
        for zone_id, label in ((source_zone_id, "source"), (destination_zone_id, "destination")):
            if zone_id not in names:
                raise NotFoundError(f"No segmentation zone {zone_id} to use as the {label}.")

        # One statement per pair and traffic, enforced here as well as by the unique
        # constraint. Two rules for the same pair and port would be two different claims
        # about one thing, and the matrix would show both — with no way to tell a reader
        # which the organisation actually means.
        for existing in await self.rules():
            if (
                existing.source_zone_id == source_zone_id
                and existing.destination_zone_id == destination_zone_id
                and existing.protocol == protocol
                and existing.port == port
            ):
                raise ConflictError(
                    f"{names[source_zone_id]} → {names[destination_zone_id]} on "
                    f"{protocol}/{port} is already declared as {existing.expectation!r}. "
                    "Withdraw that statement before making a different one, so the "
                    "change is a decision in the audit log rather than two rules "
                    "disagreeing."
                )

        rule = SegmentationRule(
            org_id=self.org_id,
            source_zone_id=source_zone_id,
            destination_zone_id=destination_zone_id,
            expectation=expectation,
            protocol=protocol,
            port=port,
            justification=justification,
        )
        self.session.add(rule)
        await self.session.flush()
        return rule

    async def delete_zone(self, zone_id: uuid.UUID) -> None:
        """Remove a zone, but only once nothing is declared about it.

        **The refusal is the point.** Both foreign keys are `ON DELETE CASCADE`, so the
        database would happily take a zone and every intent mentioning it — which means
        deleting one row could withdraw a dozen statements about what the organisation
        requires, with one audit entry naming the zone and none naming the policy that
        went with it. Somebody tidying up an unused zone would silently stop checking
        the thing the zone existed for.

        The cascade stays as a safety net against orphans. It is not the way out of
        here, and the rules have to be withdrawn deliberately first.
        """
        zone = await self.zone(zone_id)
        referencing = [
            rule
            for rule in await self.rules()
            if zone_id in (rule.source_zone_id, rule.destination_zone_id)
        ]
        if referencing:
            raise ConflictError(
                f"{zone.name!r} is named by {len(referencing)} declared intent(s), and "
                "removing it would withdraw every one of them. Withdraw the intents "
                "first, so each is a decision somebody made rather than a side effect."
            )

        await self.session.delete(zone)
        await self.session.flush()

    async def delete_rule(self, rule_id: uuid.UUID) -> None:
        """Withdraw one declared expectation.

        A hard delete, unlike a finding exception, which is retained with an expiry.
        The reason for the difference: an exception is a record that somebody accepted
        a risk and must survive for an auditor, whereas a segmentation rule is the
        policy itself — a withdrawn one is not history, it is a statement no longer
        made. What survives is the audit entry saying who withdrew it and when.
        """
        rule = await self.session.get(SegmentationRule, rule_id)
        if rule is None or rule.org_id != self.org_id:
            raise NotFoundError(f"No segmentation rule {rule_id}.")
        await self.session.delete(rule)
        await self.session.flush()

    # ── the evaluation ────────────────────────────────────────────────────

    async def evaluate(self, graph: TopologyGraph) -> MatrixResult:
        """Walk every declared cell and report what the estate actually does."""
        zones = {zone.id: zone for zone in await self.zones()}
        rules = await self.rules()

        matrix = MatrixResult()
        if not rules:
            matrix.limitations.append(
                "No segmentation policy has been declared, so there is nothing to check. "
                "An empty matrix is not a clean one."
            )
            return matrix

        for rule in sorted(
            rules, key=lambda r: (str(r.source_zone_id), str(r.destination_zone_id))
        ):
            source, destination = (
                zones.get(rule.source_zone_id),
                zones.get(rule.destination_zone_id),
            )
            if source is None or destination is None:  # pragma: no cover - FK prevents it
                continue
            matrix.cells.append(self._evaluate_cell(graph, rule, source, destination))

        matrix.upheld = sum(1 for c in matrix.cells if c.status is CellStatus.UPHELD)
        matrix.violated = sum(1 for c in matrix.cells if c.status is CellStatus.VIOLATED)
        matrix.unverified = sum(1 for c in matrix.cells if c.status is CellStatus.UNVERIFIED)

        if matrix.unverified:
            # Stated at the top, not only per cell. A reader scanning for red would
            # otherwise take the absence of it as a pass.
            matrix.limitations.append(
                f"{matrix.unverified} of {len(matrix.cells)} cells could not be verified. "
                "Those are not passes: the path could not be traced far enough to say "
                "anything about them either way."
            )

        log.info(
            "segmentation.matrix_evaluated",
            cells=len(matrix.cells),
            upheld=matrix.upheld,
            violated=matrix.violated,
            unverified=matrix.unverified,
        )
        return matrix

    def _evaluate_cell(
        self,
        graph: TopologyGraph,
        rule: SegmentationRule,
        source: SegmentationZone,
        destination: SegmentationZone,
    ) -> CellResult:
        pairs = _prefix_pairs(source, destination)
        total = len(source.prefixes) * len(destination.prefixes)

        cell = CellResult(
            rule_id=rule.id,
            source_zone=source.name,
            destination_zone=destination.name,
            expectation=rule.expectation,
            protocol=rule.protocol,
            port=rule.port,
            status=CellStatus.UNVERIFIED,
            detail="",
            justification=rule.justification,
        )

        if total > len(pairs):
            cell.limitations.append(
                f"These zones have {total} prefix combinations and {len(pairs)} were "
                "walked. The rest were not checked, so this cell speaks only for the "
                "combinations listed."
            )

        worst: tuple[int, CellStatus, str] | None = None

        for src_prefix, dst_prefix in pairs:
            cell.walked.append(f"{src_prefix} → {dst_prefix}")
            try:
                result = walk(
                    graph,
                    source=src_prefix,
                    destination=dst_prefix,
                    protocol=rule.protocol,
                    port=rule.port,
                )
            except ValidationProblem as exc:
                # A prefix the walk refuses — IPv6, or an address no device serves in a
                # way the endpoint parser rejects. Unverified, with the reason, rather
                # than failing the whole matrix on one bad row.
                status, detail = CellStatus.UNVERIFIED, str(exc)
            else:
                status, detail = _judge(rule.expectation, result)
                cell.limitations.extend(result.translation_unknown_at)

            ranked = (_SEVERITY[status], status, f"{src_prefix} → {dst_prefix}: {detail}")
            if worst is None or ranked[0] > worst[0]:
                worst = ranked

        if worst is not None:
            cell.status, cell.detail = worst[1], worst[2]
        else:  # pragma: no cover - a zone with no prefixes is refused at creation
            cell.detail = "This pair has no address ranges to walk."

        # UPHELD means "proven over what was walked". When the cap truncated the walk it
        # cannot speak for the unwalked combinations — a permit hiding in one of them
        # would be missed, so a DENIED cell reads as holding while a real hole exists
        # (and an ALLOWED cell hides a connectivity gap). A partial proof of a boundary
        # is not a proof, so it degrades to UNVERIFIED (2026-09-30 audit, invariant 2).
        if cell.status is CellStatus.UPHELD and total > len(pairs):
            cell.status = CellStatus.UNVERIFIED
            cell.detail = (
                f"{cell.detail} — but only {len(pairs)} of {total} prefix combinations "
                "were walked, so the boundary is not proven over the rest."
            )

        return cell


__all__ = ["MAX_PREFIX_PAIRS", "CellResult", "CellStatus", "MatrixResult", "SegmentationService"]
