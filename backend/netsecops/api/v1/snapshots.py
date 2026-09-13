"""Snapshot, artefact, diff and baseline endpoints (FR-DRIFT-01 … FR-DRIFT-03, FR-COL-11).

Everything here returns redacted output except one endpoint — ``GET /artifacts/{id}/raw``
— which requires ``config:view_unredacted`` and writes an audit record before returning
(SEC-09). Keeping the exception to a single route is what makes it reviewable.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, File, Query, UploadFile, status

from netsecops.api.deps import PrincipalDep, SessionDep, VaultDep, require, verify_csrf
from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.db.models.audit import AuditAction
from netsecops.db.models.collection import Finding, Snapshot
from netsecops.schemas.snapshots import (
    ArtifactDetail,
    ArtifactRead,
    CollectionRead,
    ConfigUploadResponse,
    DiffRead,
    DriftRead,
    PaginatedSnapshots,
    SemanticChangeRead,
    SnapshotDetail,
    SnapshotRead,
)
from netsecops.services.audit import AuditService
from netsecops.services.inventory import InventoryService
from netsecops.services.snapshots import DriftResult, SemanticChange, SnapshotService

log = get_logger(__name__)
router = APIRouter(tags=["snapshots"])

#: A configuration file larger than this is a mistake, not a switch (SEC-05). The
#: largest real running-configs — a fully populated chassis or a big ASA rulebase —
#: run to a few megabytes.
MAX_CONFIG_BYTES = 16 * 1024 * 1024


def snapshot_service(session: SessionDep, vault: VaultDep) -> SnapshotService:
    # The vault is injected, not built from global config inside the service: otherwise
    # tests would exercise a different decryption path than production does.
    return SnapshotService(session, vault=vault)


SnapshotDep = Annotated[SnapshotService, Depends(snapshot_service)]


def _semantic(changes: list[SemanticChange]) -> list[SemanticChangeRead]:
    return [SemanticChangeRead(path=c.path, description=c.describe()) for c in changes]


# ───────────────────────────── device views ─────────────────────────────


@router.get(
    "/devices/{device_id}/snapshots",
    response_model=PaginatedSnapshots,
    dependencies=[Depends(require(Permission.SNAPSHOT_READ))],
    summary="Configuration snapshot history for a device",
)
async def list_snapshots(
    device_id: uuid.UUID,
    snapshots: SnapshotDep,
    principal: PrincipalDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedSnapshots:
    device = await InventoryService(snapshots.session).get_device(device_id, scope=principal.scope)
    rows, total = await snapshots.list_for_device(device, limit=limit, offset=offset)
    return PaginatedSnapshots(
        data=[SnapshotRead.model_validate(s) for s in rows],
        meta={"total": total, "limit": limit, "offset": offset},
    )


@router.get(
    "/devices/{device_id}/drift",
    response_model=DriftRead,
    dependencies=[Depends(require(Permission.SNAPSHOT_READ))],
    summary="How the latest configuration differs from the pinned baseline",
)
async def device_drift(
    device_id: uuid.UUID, snapshots: SnapshotDep, principal: PrincipalDep
) -> DriftRead:
    device = await InventoryService(snapshots.session).get_device(device_id, scope=principal.scope)
    baseline = await snapshots.baseline(device)
    latest = await snapshots.latest(device)

    if latest is None:
        # No snapshot is not "no drift" — it is nothing to say. Reporting it as clean
        # would let a device that has never been collected look assessed.
        return DriftRead(
            device_id=device.id,
            baseline_snapshot_id=baseline.id if baseline else None,
            latest_snapshot_id=None,
            changed=False,
            severity=None,
            headline="This device has no configuration snapshot yet.",
        )

    drift = await snapshots.detect_drift(device, latest)
    finding = await snapshots.find_drift_finding(device)

    return _drift_response(device.id, baseline, latest, drift, finding)


def _drift_response(
    device_id: uuid.UUID,
    baseline: Snapshot | None,
    latest: Snapshot | None,
    drift: DriftResult,
    finding: Finding | None,
) -> DriftRead:
    headline = drift.headline
    if not drift.changed and baseline is None:
        headline = "No baseline is pinned for this device, so there is nothing to drift from."

    return DriftRead(
        device_id=device_id,
        baseline_snapshot_id=baseline.id if baseline else None,
        latest_snapshot_id=latest.id if latest else None,
        changed=drift.changed,
        severity=drift.severity.value if drift.changed else None,
        headline=headline,
        added=list(drift.diff.added) if drift.diff else [],
        removed=list(drift.diff.removed) if drift.diff else [],
        semantic=_semantic(drift.semantic),
        finding_id=finding.id if finding else None,
    )


@router.post(
    "/devices/{device_id}/configs",
    response_model=ConfigUploadResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Assess an uploaded configuration without touching the device (FR-COL-11)",
)
async def upload_config(
    device_id: uuid.UUID,
    snapshots: SnapshotDep,
    principal: PrincipalDep,
    file: Annotated[UploadFile, File(description="A device configuration export")],
) -> ConfigUploadResponse:
    device = await InventoryService(snapshots.session).get_device(device_id, scope=principal.scope)

    raw = await file.read()
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValidationProblem(
            f"The file is larger than {MAX_CONFIG_BYTES // (1024 * 1024)} MB.",
            size_bytes=len(raw),
        )
    if not raw.strip():
        raise ValidationProblem("The file is empty.")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        # Devices that write configurations in a legacy code page are common enough
        # that refusing them outright would be unhelpful; replacing the undecodable
        # bytes keeps the rest parseable.
        text = raw.decode("utf-8", errors="replace")

    result = await snapshots.ingest_config(
        device,
        config_text=text,
        filename=file.filename or "config.txt",
        actor=principal,
    )
    await snapshots.session.commit()

    return ConfigUploadResponse(
        snapshot_id=result.snapshot.id,
        collection_id=result.collection.id,
        artifact_id=result.artifact.id,
        deduplicated=result.deduplicated,
        parse_coverage=result.snapshot.parse_coverage,
        unparsed_count=result.snapshot.unparsed_count,
        drift=_drift_response(
            device.id,
            await snapshots.baseline(device),
            result.snapshot,
            result.drift,
            result.finding,
        ),
    )


@router.delete(
    "/devices/{device_id}/baseline",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Unpin a device's baseline",
)
async def clear_baseline(
    device_id: uuid.UUID, snapshots: SnapshotDep, principal: PrincipalDep
) -> None:
    device = await InventoryService(snapshots.session).get_device(device_id, scope=principal.scope)
    await snapshots.clear_baseline(device, actor=principal)
    await snapshots.session.commit()


# ──────────────────────────── snapshot views ────────────────────────────


@router.get(
    "/snapshots/{snapshot_id}",
    response_model=SnapshotDetail,
    dependencies=[Depends(require(Permission.SNAPSHOT_READ))],
    summary="A snapshot with its redacted configuration and NCM (IF-UI-04)",
)
async def get_snapshot(
    snapshot_id: uuid.UUID, snapshots: SnapshotDep, principal: PrincipalDep
) -> SnapshotDetail:
    snapshot = await snapshots.get(snapshot_id)
    # Scope is enforced through the owning device, not the snapshot: visibility is a
    # property of the device group, and checking it here keeps the one rule in one place.
    await InventoryService(snapshots.session).get_device(snapshot.device_id, scope=principal.scope)
    return SnapshotDetail.model_validate(snapshot)


@router.get(
    "/snapshots/{snapshot_id}/diff",
    response_model=DiffRead,
    dependencies=[Depends(require(Permission.SNAPSHOT_READ))],
    summary="Diff two snapshots, textually and semantically (FR-DRIFT-02, IF-UI-05)",
)
async def diff_snapshots(
    snapshot_id: uuid.UUID,
    snapshots: SnapshotDep,
    principal: PrincipalDep,
    against: Annotated[
        uuid.UUID | None,
        Query(description="The snapshot to compare against; defaults to the pinned baseline"),
    ] = None,
) -> DiffRead:
    after = await snapshots.get(snapshot_id)
    device = await InventoryService(snapshots.session).get_device(
        after.device_id, scope=principal.scope
    )

    if against is not None:
        before = await snapshots.get(against)
    else:
        baseline = await snapshots.baseline(device)
        if baseline is None:
            raise ValidationProblem(
                "This device has no pinned baseline, so there is nothing to diff "
                "against. Supply 'against' with a snapshot id."
            )
        before = baseline

    text_diff, semantic = await snapshots.diff(before, after)
    return DiffRead(
        from_snapshot_id=before.id,
        to_snapshot_id=after.id,
        changed=text_diff.changed,
        added=list(text_diff.added),
        removed=list(text_diff.removed),
        unified=text_diff.unified,
        before_lines=before.config_redacted.splitlines(),
        after_lines=after.config_redacted.splitlines(),
        semantic=_semantic(semantic),
    )


@router.post(
    "/snapshots/{snapshot_id}/baseline",
    response_model=SnapshotRead,
    dependencies=[Depends(require(Permission.DEVICE_WRITE)), Depends(verify_csrf)],
    summary="Pin this snapshot as the device's baseline (FR-DRIFT-03)",
)
async def pin_baseline(
    snapshot_id: uuid.UUID, snapshots: SnapshotDep, principal: PrincipalDep
) -> SnapshotRead:
    snapshot = await snapshots.get(snapshot_id)
    device = await InventoryService(snapshots.session).get_device(
        snapshot.device_id, scope=principal.scope
    )

    pinned = await snapshots.pin_baseline(snapshot, actor=principal)
    # Pinning re-declares what "correct" means for this device, so any open drift
    # finding measured against the old baseline is now answering a stale question.
    await snapshots.resolve_drift_finding(device)
    await snapshots.session.commit()

    return SnapshotRead.model_validate(pinned)


# ──────────────────────────── artefact views ────────────────────────────


@router.get(
    "/collections/{collection_id}",
    response_model=CollectionRead,
    dependencies=[Depends(require(Permission.SNAPSHOT_READ))],
    summary="One collection run against a device",
)
async def get_collection(
    collection_id: uuid.UUID, snapshots: SnapshotDep, principal: PrincipalDep
) -> CollectionRead:
    collection = await snapshots.get_collection(collection_id)
    await InventoryService(snapshots.session).get_device(
        collection.device_id, scope=principal.scope
    )
    return CollectionRead.model_validate(collection)


@router.get(
    "/collections/{collection_id}/artifacts",
    response_model=list[ArtifactRead],
    dependencies=[Depends(require(Permission.SNAPSHOT_READ))],
    summary="Every command issued in a collection, in order (FR-COL-03)",
)
async def list_artifacts(
    collection_id: uuid.UUID, snapshots: SnapshotDep, principal: PrincipalDep
) -> list[ArtifactRead]:
    collection = await snapshots.get_collection(collection_id)
    await InventoryService(snapshots.session).get_device(
        collection.device_id, scope=principal.scope
    )
    rows = await snapshots.artifacts_for(collection)
    return [ArtifactRead.model_validate(a) for a in rows]


@router.get(
    "/artifacts/{artifact_id}",
    response_model=ArtifactDetail,
    dependencies=[Depends(require(Permission.SNAPSHOT_READ))],
    summary="One command's output, with secrets replaced by placeholders (FR-COL-13)",
)
async def get_artifact(
    artifact_id: uuid.UUID, snapshots: SnapshotDep, principal: PrincipalDep
) -> ArtifactDetail:
    artifact = await snapshots.get_artifact(artifact_id)
    collection = await snapshots.get_collection(artifact.collection_id)
    await InventoryService(snapshots.session).get_device(
        collection.device_id, scope=principal.scope
    )

    return ArtifactDetail(
        **ArtifactRead.model_validate(artifact).model_dump(),
        response=artifact.response_redacted,
        redacted=True,
    )


@router.get(
    "/artifacts/{artifact_id}/raw",
    response_model=ArtifactDetail,
    dependencies=[Depends(require(Permission.CONFIG_VIEW_UNREDACTED))],
    summary="The unredacted original — separately permissioned and audited (SEC-09)",
)
async def get_artifact_raw(
    artifact_id: uuid.UUID, snapshots: SnapshotDep, principal: PrincipalDep
) -> ArtifactDetail:
    artifact = await snapshots.get_artifact(artifact_id)
    collection = await snapshots.get_collection(artifact.collection_id)
    device = await InventoryService(snapshots.session).get_device(
        collection.device_id, scope=principal.scope
    )

    plaintext = snapshots.open_artifact(artifact)

    # Audited before returning, and committed: a record written after the response is
    # a record that a crash can lose, which defeats the point of auditing this at all.
    await AuditService(snapshots.session).record(
        AuditAction.CONFIG_VIEWED_UNREDACTED,
        actor_id=principal.id,
        actor_username=principal.username,
        object_type="artifact",
        object_id=artifact.id,
        device_id=device.id,
        command_text=artifact.request_text,
        org_id=artifact.org_id,
    )
    await snapshots.session.commit()

    return ArtifactDetail(
        **ArtifactRead.model_validate(artifact).model_dump(),
        response=plaintext,
        redacted=False,
    )


__all__ = ["router"]
