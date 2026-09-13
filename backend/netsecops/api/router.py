"""API router aggregation (C-4 — everything business-facing lives under ``/api/v1``)."""

from __future__ import annotations

from fastapi import APIRouter

from netsecops.api.v1 import audit, auth, credentials, devices, jobs, snapshots, users

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(auth.router)
api_v1_router.include_router(users.router)
api_v1_router.include_router(audit.router)

# Phase 1 — inventory, credential vault, job engine
api_v1_router.include_router(devices.router)
api_v1_router.include_router(credentials.router)
api_v1_router.include_router(jobs.router)

# Phase 2 — snapshots, artefacts, diff, baselines
api_v1_router.include_router(snapshots.router)

# Routers added in later phases:
#   Phase 3 — checks, policies, findings, exceptions
#   Phase 4 — firewall
#   Phase 5 — aaa
#   Phase 6 — vulnerabilities
#   Phase 7 — discovery, reports, integrations, settings

__all__ = ["api_v1_router"]
