"""Rulebase viewer and rule query endpoints (FR-FW-06, FR-FW-07).

All three routes are reads of a stored snapshot: nothing here touches a device, and
nothing here writes. That is what lets the viewer be opened against an old snapshot to
see what the rulebase looked like at the time of an incident, and what makes it safe to
give to an auditor.

Permissioned on ``snapshot:read`` rather than ``finding:read``: a rulebase *is*
configuration, and someone allowed to read a device's configuration can already see the
rules. Requiring a findings permission would leave an auditor able to read the raw
config but not the structured view of the same thing.
"""

from __future__ import annotations

import csv
import io
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from netsecops.api.deps import PrincipalDep, SessionDep, VaultDep, require, verify_csrf
from netsecops.core.errors import NotFoundError
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.schemas.firewall import (
    EstateDeviceRules,
    EstateRulesRead,
    RulebaseRead,
    RuleQueryRequest,
    RuleQueryResponse,
)
from netsecops.services.firewall_view import FirewallViewService, RulebaseFilter
from netsecops.services.inventory import InventoryService
from netsecops.services.snapshots import SnapshotService

log = get_logger(__name__)
router = APIRouter(tags=["firewall"])


async def _load(
    device_id: uuid.UUID,
    snapshot_id: uuid.UUID | None,
    session: SessionDep,
    vault: VaultDep,
    principal: PrincipalDep,
) -> FirewallViewService:
    """The device's snapshot, scoped to what the caller may see.

    Defaults to the latest snapshot. Naming one explicitly is what makes the viewer
    usable for "what did this look like on the day" â€” the rulebase that matters during
    an investigation is the one that was live then, not the one live now.
    """
    device = await InventoryService(session).get_device(device_id, scope=principal.scope)
    snapshots = SnapshotService(session, vault=vault)

    if snapshot_id is not None:
        snapshot = await snapshots.get(snapshot_id)
        if snapshot.device_id != device.id:
            # Not a 403: the snapshot may be perfectly visible to this caller, it just
            # belongs to a different device, and saying so is more useful than refusing.
            raise NotFoundError("That snapshot does not belong to this device.")
        return FirewallViewService(snapshot)

    latest = await snapshots.latest(device)
    if latest is None:
        raise NotFoundError(
            "This device has no configuration snapshot yet, so there is no rulebase "
            "to show. Run a collection first."
        )
    return FirewallViewService(latest)


@router.get(
    "/devices/{device_id}/firewall/rulebase",
    response_model=RulebaseRead,
    dependencies=[Depends(require(Permission.SNAPSHOT_READ))],
    summary="The device's rulebase with analysis attached to each rule (FR-FW-07)",
)
async def read_rulebase(
    device_id: uuid.UUID,
    session: SessionDep,
    vault: VaultDep,
    principal: PrincipalDep,
    snapshot_id: uuid.UUID | None = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    action: Annotated[str | None, Query(max_length=32)] = None,
    zone: Annotated[str | None, Query(max_length=128)] = None,
    issue: Annotated[str | None, Query(max_length=64)] = None,
    severity: Annotated[str | None, Query(max_length=16)] = None,
    include_disabled: bool = True,
    with_issues_only: bool = False,
) -> RulebaseRead:
    """Every rule, in evaluation order, with the problems the analysis found on it.

    The filters narrow what is *shown*; the whole rulebase is always analysed. Analysing
    only the filtered rules would change the answers â€” a rule is shadowed by its
    neighbours, and a rulebase filtered to one zone has none.
    """
    view = await _load(device_id, snapshot_id, session, vault, principal)
    return view.build(
        filters=RulebaseFilter(
            search=search,
            action=action,
            zone=zone,
            issue=issue,
            severity=severity,
            include_disabled=include_disabled,
            with_issues_only=with_issues_only,
        )
    )


#: How many devices one estate query will analyse. Every rulebase is analysed in full
#: to answer it â€” shadowing is a property of a whole policy, not of the rules that
#: matched â€” so this is a real cost, and the response says when it was hit rather than
#: quietly returning the first page as though it were the estate.
MAX_ESTATE_DEVICES = 100


@router.get(
    "/firewall/rules",
    response_model=EstateRulesRead,
    dependencies=[Depends(require(Permission.SNAPSHOT_READ))],
    summary="Rules matching one filter across the estate, grouped by device (FR-FW-07)",
)
async def list_estate_rules(
    session: SessionDep,
    vault: VaultDep,
    principal: PrincipalDep,
    search: Annotated[str | None, Query(max_length=200)] = None,
    action: Annotated[str | None, Query(max_length=32)] = None,
    zone: Annotated[str | None, Query(max_length=128)] = None,
    issue: Annotated[str | None, Query(max_length=64)] = None,
    severity: Annotated[str | None, Query(max_length=16)] = None,
    include_disabled: bool = True,
    with_issues_only: bool = False,
    limit: Annotated[int, Query(ge=1, le=MAX_ESTATE_DEVICES)] = 50,
) -> EstateRulesRead:
    """ "Show me every rule in the estate that does X" â€” previously unaskable.

    Every firewall route before this one was scoped to a single device, so a question
    about the estate meant opening each firewall in turn and applying the same filter by
    hand. `any_any_any` was already an issue key; there was simply no way to ask for it
    everywhere at once.

    **Grouped per device, and never merged into one sorted table.** A rule is shadowed
    because of where it sits, so order within a device is meaning. Sorting the estate's
    rules by severity â€” the obvious thing to do with a list like this â€” would destroy
    the only fact that makes half the issues on it true.

    **Devices that could not be searched are listed with the reason.** A device with no
    snapshot, or one whose snapshot carries no rulebase, appears in the response with
    `not_searched` set. Omitting them would turn "nothing in the estate matches" into a
    claim about devices nobody read â€” and a switch with no rulebase and a firewall whose
    policy failed to parse produce the same empty block, which is why the reason says so
    rather than asserting the device has no rules.
    """
    inventory = InventoryService(session)
    snapshots = SnapshotService(session, vault=vault)
    devices, total_visible = await inventory.list_devices(scope=principal.scope, limit=limit)

    filters = RulebaseFilter(
        search=search,
        action=action,
        zone=zone,
        issue=issue,
        severity=severity,
        include_disabled=include_disabled,
        with_issues_only=with_issues_only,
    )

    rows: list[EstateDeviceRules] = []
    matched_total = 0
    searched = 0

    for device in devices:
        row = EstateDeviceRules(
            device_id=device.id, hostname=device.hostname, platform=device.platform
        )

        snapshot = await snapshots.latest(device)
        if snapshot is None:
            row.not_searched = (
                "No configuration has been collected from this device, so its rules "
                "could not be searched."
            )
            rows.append(row)
            continue

        view = FirewallViewService(snapshot)
        row.snapshot_id = snapshot.id
        if not view.has_rulebase:
            # Deliberately not "this device has no matching rules". A switch legitimately
            # has no rulebase and a firewall whose policy failed to parse produces an
            # identical empty block; this response cannot tell them apart and does not
            # pretend to.
            row.not_searched = (
                "This snapshot carries no firewall rulebase â€” expected on a switch or "
                "router, and on a firewall meaning the policy was not collected or "
                "could not be parsed."
            )
            rows.append(row)
            continue

        built = view.build(filters=filters)
        searched += 1
        row.rules = built.rules
        row.matched = len(built.rules)
        row.rules_total = built.summary.rules_total
        row.rules_not_retrieved = built.summary.rules_not_retrieved
        row.truncated = built.summary.truncated
        matched_total += row.matched
        rows.append(row)

    not_searched = sum(1 for row in rows if row.not_searched)
    limitations: list[str] = []
    if not_searched:
        limitations.append(
            f"{not_searched} of {len(rows)} devices could not be searched. Each is "
            "listed with the reason, and no conclusion about the estate holds for them."
        )
    if total_visible > len(devices):
        limitations.append(
            f"Searched {len(devices)} of {total_visible} visible devices. Raise `limit` "
            "or narrow the inventory to cover the rest â€” this is not the whole estate."
        )
    if any(row.rules_not_retrieved for row in rows):
        limitations.append(
            "At least one rulebase arrived incomplete, so a device reporting no match "
            "may hold a matching rule among the ones that were never retrieved."
        )

    return EstateRulesRead(
        devices=rows,
        matched_total=matched_total,
        devices_searched=searched,
        devices_not_searched=not_searched,
        limitations=limitations,
    )


@router.post(
    "/devices/{device_id}/firewall/query",
    response_model=RuleQueryResponse,
    # Read-only, and still CSRF-checked: see the note on `POST /topology/path`. One rule
    # with no exceptions is cheaper to keep than one with a defensible exception.
    dependencies=[Depends(require(Permission.SNAPSHOT_READ)), Depends(verify_csrf)],
    summary="Which rule would match this packet (FR-FW-06)",
)
async def query_rulebase(
    device_id: uuid.UUID,
    request: RuleQueryRequest,
    session: SessionDep,
    vault: VaultDep,
    principal: PrincipalDep,
    snapshot_id: uuid.UUID | None = None,
) -> RuleQueryResponse:
    """Offline simulation over the stored rulebase â€” no packet is sent anywhere.

    The answer carries its own limitations: matching is over addresses, protocol and
    port only, so a rule the device would narrow by App-ID or User-ID may be reported as
    matching when it would not. A bare rule number without that caveat would be read as
    a guarantee.
    """
    view = await _load(device_id, snapshot_id, session, vault, principal)
    return view.query(request)


@router.get(
    "/devices/{device_id}/firewall/export",
    dependencies=[Depends(require(Permission.SNAPSHOT_READ))],
    summary="The rulebase and its analysis as CSV (FR-FW-07)",
    response_class=StreamingResponse,
)
async def export_rulebase(
    device_id: uuid.UUID,
    session: SessionDep,
    vault: VaultDep,
    principal: PrincipalDep,
    snapshot_id: uuid.UUID | None = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    action: Annotated[str | None, Query(max_length=32)] = None,
    zone: Annotated[str | None, Query(max_length=128)] = None,
    issue: Annotated[str | None, Query(max_length=64)] = None,
    severity: Annotated[str | None, Query(max_length=16)] = None,
    include_disabled: bool = True,
    with_issues_only: bool = False,
) -> StreamingResponse:
    """CSV of exactly what the viewer is showing, filters included.

    Exporting the whole rulebase regardless of the filter would be a different document
    from the one on screen, and the reason to export is usually to send on what you are
    looking at.
    """
    view = await _load(device_id, snapshot_id, session, vault, principal)
    payload = view.build(
        filters=RulebaseFilter(
            search=search,
            action=action,
            zone=zone,
            issue=issue,
            severity=severity,
            include_disabled=include_disabled,
            with_issues_only=with_issues_only,
        )
    )

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "order",
            "name",
            "enabled",
            "action",
            "source_zones",
            "destination_zones",
            "source",
            "destination",
            "services",
            "applications",
            "logging",
            "profiles",
            "hit_count",
            "unresolved_objects",
            "issues",
            "worst_severity",
        ]
    )

    for rule in payload.rules:
        writer.writerow(
            [
                rule.order,
                rule.name,
                "yes" if rule.enabled else "no",
                rule.action,
                "; ".join(rule.src_zones),
                "; ".join(rule.dst_zones),
                rule.source,
                rule.destination,
                rule.services,
                "; ".join(rule.applications),
                # Three states, spelled out. "no" and "unknown" mean different things and
                # a blank cell in a spreadsheet reads as "no" to everyone who opens it.
                {True: "yes", False: "no", None: "unknown"}[rule.logs],
                "; ".join(f"{k}={v}" for k, v in rule.profiles.items()),
                "" if rule.hit_count is None else rule.hit_count,
                "; ".join(rule.unresolved),
                "; ".join(f"{i.issue}: {i.message}" for i in rule.issues),
                rule.worst_severity,
            ]
        )

    log.info(
        "firewall.rulebase_exported",
        device_id=str(device_id),
        actor=principal.username,
        rules=len(payload.rules),
        of_total=payload.total,
    )

    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="rulebase-{device_id}.csv"',
        },
    )


__all__ = ["router"]
