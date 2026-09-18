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
    notifications,
    reports,
    settings,
    snapshots,
    topology,
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

# Phase 7 — discovery scopes, runs and the review queue. Every path here is literal, so
# there is no shadowing order to preserve. Runs are started by POST to a scope's `/runs`
# sub-resource rather than to a top-level `/discovery/runs`, which is deliberate: a run
# cannot exist without the scope that says which addresses may be contacted, and nesting
# it makes a request that omits the scope unroutable rather than merely invalid.
api_v1_router.include_router(discovery.router)

# Phase 7 — reports. /reports/templates is a literal sibling of /reports/{report_id},
# which takes a UUID, so a mis-ordered declaration would 422 rather than 404 — louder
# than the CVE case above, but the literal still goes first inside the module.
api_v1_router.include_router(reports.router)

# Phase 8 — the layer-3 graph and path analysis. Every path here is literal, so there is
# no shadowing order to preserve. `/topology/path` is a POST that changes nothing: it
# takes a body because a packet is four correlated fields, and reads far better in an
# audit log as an object than as a query string.
api_v1_router.include_router(topology.router)

# Phase 7 — notification channels, subscriptions and the delivery queue (FR-INT-01).
# `/notifications/channels/{id}/test` is a literal sub-resource of a UUID path, so there
# is no literal/UUID sibling collision here.
api_v1_router.include_router(notifications.router)

# Phase 7 — platform settings (FR-ADM-01). `/settings/{key}` takes a free string, so a
# literal sibling added later would be shadowed silently; there are none today, and any
# addition belongs above this line.
api_v1_router.include_router(settings.router)

__all__ = ["api_v1_router"]
