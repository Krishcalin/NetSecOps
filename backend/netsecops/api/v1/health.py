"""Liveness, readiness and metrics endpoints (FR-JOB-06, NFR-OBS-01).

These are mounted at the application root rather than under ``/api/v1`` so orchestrators
and scrapers are not coupled to the API version (C-4 governs the business API).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Gauge, generate_latest
from sqlalchemy import text

from netsecops.api.deps import SessionDep, SettingsDep
from netsecops.core.logging import get_logger

log = get_logger(__name__)
router = APIRouter(tags=["health"])

# A dedicated registry keeps NetSecOps metrics out of the default global one, so a
# library that registers its own collectors cannot collide with ours.
REGISTRY = CollectorRegistry()

_info = Gauge(
    "netsecops_build_info",
    "Build and deployment information",
    ["version", "environment"],
    registry=REGISTRY,
)
_db_up = Gauge(
    "netsecops_database_up",
    "1 when the database answered its last readiness probe, 0 otherwise",
    registry=REGISTRY,
)

# Queue depth and collection success rate are required by FR-JOB-06; the collectors are
# declared here and populated once the job engine lands in Phase 1.
_queue_depth = Gauge(
    "netsecops_job_queue_depth", "Tasks waiting in the job queue", ["queue"], registry=REGISTRY
)
_active_sessions = Gauge(
    "netsecops_active_device_sessions", "Open read-only device sessions", registry=REGISTRY
)


@router.get("/healthz", summary="Liveness probe — is the process running?")
async def healthz(settings: SettingsDep) -> dict[str, Any]:
    from netsecops import __version__

    return {"status": "ok", "version": __version__, "environment": settings.env.value}


@router.get("/readyz", summary="Readiness probe — can the process serve traffic?")
async def readyz(session: SessionDep, response: Response, settings: SettingsDep) -> dict[str, Any]:
    """Readiness depends on the database; a failure returns 503 so traffic is withheld."""
    checks: dict[str, str] = {}

    try:
        await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
        _db_up.set(1)
    except Exception as exc:
        log.error("readyz.database_unavailable", error=str(exc))
        checks["database"] = "unavailable"
        _db_up.set(0)

    ready = all(v == "ok" for v in checks.values())
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {"status": "ready" if ready else "not_ready", "checks": checks}


@router.get("/metrics", summary="Prometheus metrics (NFR-OBS-01)")
async def metrics(settings: SettingsDep) -> Response:
    if not settings.metrics_enabled:
        return Response(status_code=status.HTTP_404_NOT_FOUND)

    from netsecops import __version__

    _info.labels(version=__version__, environment=settings.env.value).set(1)
    return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


def set_queue_depth(queue: str, depth: int) -> None:
    """Hook for the Phase 1 job engine."""
    _queue_depth.labels(queue=queue).set(depth)


def set_active_sessions(count: int) -> None:
    """Hook for the Phase 1 collector pool."""
    _active_sessions.set(count)
