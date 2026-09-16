"""API router aggregation (C-4 — everything business-facing lives under ``/api/v1``)."""

from __future__ import annotations

from fastapi import APIRouter

from netsecops.api.v1 import (
    aaa,
    audit,
    auth,
    checks,
    credentials,
    devices,
    discovery,
    firewall,
    jobs,
    managers,
    snapshots,
    users,
    vulnerabilities,
)

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(auth.router)
api_v1_router.include_router(users.router)
api_v1_router.include_router(audit.router)

# `GET /devices/pending-review` is a *literal* sibling of `GET /devices/{device_id}`,
# and routes are matched in registration order. Registered after devices, the literal
# path is never reached: `pending-review` is parsed as a UUID, fails validation, and
# FastAPI returns 422 rather than trying the next route. So the managers router goes
# first, and `test_the_literal_route_is_not_shadowed_by_the_uuid_one` fails the build if
# this order is ever changed back.
api_v1_router.include_router(managers.router)

# Phase 1 — inventory, credential vault, job engine
api_v1_router.include_router(devices.router)
api_v1_router.include_router(credentials.router)
api_v1_router.include_router(jobs.router)

# Phase 2 — snapshots, artefacts, diff, baselines
api_v1_router.include_router(snapshots.router)

# Phase 3 — check library, policies, findings, exceptions, risk, compliance
api_v1_router.include_router(checks.router)

# Phase 4 — rulebase viewer and rule query. The manager-enumeration router is also
# Phase 4 but is registered above, for the routing reason noted there.
api_v1_router.include_router(firewall.router)

# Phase 5 — wireless and AAA. Every route here is estate-wide rather than per-device, so
# there is no literal/UUID collision to worry about and the order is free.
api_v1_router.include_router(aaa.router)

# Phase 6 — vulnerability findings, CVE detail and feed status. `/vulnerabilities/
# summary` and `/vulnerabilities/feeds` are literal siblings of `/vulnerabilities/
# {cve_id}`, and routes match in registration order — so both literals are declared
# before the parameterised route inside the module, and
# `test_literal_vulnerability_routes_are_not_shadowed` fails the build if that is
# reordered. Same trap as `/devices/pending-review` above; a CVE id is a plain string
# rather than a UUID, so the mistake would resolve to a 404 rather than a 422 and be
# correspondingly harder to notice.
api_v1_router.include_router(vulnerabilities.router)

# Phase 7 — discovery scopes and the review queue. Every path here is literal, so there
# is no shadowing order to preserve. Note there is no route that *starts* a run: the
# pacing loop FR-DISC-05 calls for does not exist yet, and an unpaced run is the port
# sweep SRS §1.2 forbids. `discovery.py` says so where someone would look for it.
api_v1_router.include_router(discovery.router)

# Routers added in later phases:
#   Phase 7 — reports, integrations, settings

__all__ = ["api_v1_router"]
