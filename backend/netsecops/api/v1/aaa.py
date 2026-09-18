"""AAA posture endpoints (FR-AAA-05, FR-AAA-06).

Three routes, and the split between them is the important part.

``GET /aaa/posture`` and ``GET /aaa/correlation`` are **reads**. They re-derive the
answer from stored snapshots every time and write nothing, so an auditor can refresh
them freely and two people looking at once cannot interfere. Nothing here contacts a
device — the estate-wide picture is assembled from configuration already collected, and
§8 is not in play at any point.

``POST /aaa/assess`` is the **write**: it stores the correlation as findings so they
appear on each device's own page and acquire a first-seen date. It is separated from the
read deliberately. A dashboard load that quietly wrote findings would mean the act of
looking at the estate changed its finding history, and two operators opening the page
would race each other to open and resolve the same rows.

Permissioned on ``finding:read`` rather than ``snapshot:read``: this is analysis, not
configuration, and everything it returns is a conclusion about the estate.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from netsecops.api.deps import PrincipalDep, SessionDep, require, verify_csrf
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.schemas.aaa import AaaPostureRead, CorrelationRead
from netsecops.services.aaa_assessment import AaaAssessmentService
from netsecops.services.aaa_correlation import AaaCorrelationReport, AaaCorrelationService
from netsecops.services.aaa_posture import HORIZON_DAYS, SOON_DAYS, AaaPosture, AaaPostureService

log = get_logger(__name__)
router = APIRouter(prefix="/aaa", tags=["aaa"])


def _correlation(report: AaaCorrelationReport) -> CorrelationRead:
    return CorrelationRead.model_validate(
        {
            "orphaned_clients": [
                {
                    "name": client.name,
                    "address": client.address,
                    "server": client.server,
                    "server_device_id": client.server_device_id,
                    "server_snapshot_age_days": client.server_snapshot_age_days,
                }
                for client in report.orphaned_clients
            ],
            "unregistered_devices": [
                {
                    "device_id": device.device_id,
                    "hostname": device.hostname,
                    "mgmt_ip": device.mgmt_ip,
                    "configured_for_aaa": device.configured_for_aaa,
                }
                for device in report.unregistered_devices
            ],
            "unknown_servers": [
                # `used_by_ids` is deliberately not serialised: the UI shows labels, and
                # the ids exist only so the assessment can anchor a finding.
                {"address": server.address, "kind": server.kind, "used_by": server.used_by}
                for server in report.unknown_servers
            ],
            "reused_secrets": [
                {
                    "fingerprint": secret.fingerprint,
                    "used_by": secret.used_by,
                    "clients": secret.count,
                }
                for secret in report.reused_secrets
            ],
            "servers_examined": report.servers_examined,
            "secrets_not_exposable": report.secrets_not_exposable,
            "registration_analysed": report.registration_analysed,
        }
    )


def _posture(posture: AaaPosture) -> AaaPostureRead:
    timeline = posture.certificates
    return AaaPostureRead.model_validate(
        {
            "coverage_percentage": posture.coverage_percentage,
            "devices_total": posture.devices_total,
            "devices_with_central_auth": posture.devices_with_central_auth,
            "devices_not_evaluated": posture.devices_not_evaluated,
            "accepted_protocols": [
                {"name": p.name, "weak": p.weak, "servers": p.servers}
                for p in posture.accepted_protocols
            ],
            "transports": [{"kind": t.kind, "devices": t.devices} for t in posture.transports],
            "servers": [
                {
                    "device_id": s.device_id,
                    "hostname": s.hostname,
                    "product": s.product,
                    "clients": s.clients,
                    "identity_stores": s.identity_stores,
                    "weak_protocols": s.weak_protocols,
                    "admin_mfa_enabled": s.admin_mfa_enabled,
                    "snapshot_age_days": s.snapshot_age_days,
                    "certificates": s.certificates,
                }
                for s in posture.servers
            ],
            "certificates": {
                "entries": [
                    {
                        "device_id": entry.device_id,
                        "device": entry.device,
                        "name": entry.name,
                        "subject": entry.subject,
                        "issuer": entry.issuer,
                        "self_signed": entry.self_signed,
                        "usage": entry.usage,
                        "expires_at": entry.expires_at,
                        "days_remaining": entry.days_remaining,
                    }
                    for entry in timeline.entries
                ],
                "total": timeline.total,
                "expired": timeline.expired,
                "expiring_soon": timeline.expiring_soon,
                "expiring_within_horizon": timeline.expiring_within_horizon,
                "undated": timeline.undated,
                "servers_without_certificates": timeline.servers_without_certificates,
                "soon_days": SOON_DAYS,
                "horizon_days": HORIZON_DAYS,
            },
            "correlation": _correlation(posture.correlation),
            "open_findings": posture.open_findings,
            "limitations": posture.limitations,
            "generated_at": posture.generated_at,
        }
    )


@router.get(
    "/posture",
    response_model=AaaPostureRead,
    dependencies=[Depends(require(Permission.FINDING_READ))],
    summary="Estate-wide AAA posture (FR-AAA-06)",
)
async def read_posture(session: SessionDep, principal: PrincipalDep) -> AaaPostureRead:
    """Coverage, protocols, orphaned clients and the certificate expiry timeline.

    Derived from the latest snapshot of every device on every call. Nothing is cached,
    because a stale posture page is worse than a slow one: it is the page someone looks
    at to decide whether the estate is in a state they need to act on.
    """
    posture = await AaaPostureService(session).build()
    log.info(
        "aaa.posture_read",
        actor=principal.username,
        coverage=posture.coverage_percentage,
        servers=len(posture.servers),
    )
    return _posture(posture)


@router.get(
    "/correlation",
    response_model=CorrelationRead,
    dependencies=[Depends(require(Permission.FINDING_READ))],
    summary="AAA correlation across the estate (FR-AAA-05)",
)
async def read_correlation(session: SessionDep, principal: PrincipalDep) -> CorrelationRead:
    """The correlation on its own, for callers that do not need the whole posture."""
    report = await AaaCorrelationService(session).correlate()
    log.info("aaa.correlation_read", actor=principal.username, **report.counts)
    return _correlation(report)


@router.post(
    "/assess",
    response_model=CorrelationRead,
    dependencies=[Depends(require(Permission.FINDING_WRITE)), Depends(verify_csrf)],
    summary="Store the AAA correlation as per-device findings (FR-AAA-06)",
)
async def assess(session: SessionDep, principal: PrincipalDep) -> CorrelationRead:
    """Run the correlation and write its conclusions to the findings table.

    Separate from the read so that opening a dashboard never mutates finding history.
    Returns the same report the read returns, so a caller can act on the result without
    a second round trip.
    """
    report = await AaaCorrelationService(session).correlate()
    outcome = await AaaAssessmentService(session).store(report)
    log.info(
        "aaa.assessed",
        actor=principal.username,
        opened=outcome.findings_opened,
        resolved=outcome.findings_resolved,
        devices=outcome.devices_touched,
    )
    return _correlation(report)


__all__ = ["router"]
