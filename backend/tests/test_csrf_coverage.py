"""Every state-changing endpoint carries the CSRF check (SEC-03).

Written because the rule was being kept by hand and had already stopped being kept.
`api/v1/discovery.py` reached main with `verify_csrf` on none of its four state-changing
routes — including `POST /discovery/pending/{id}/approve`, which creates a device and
assigns it credentials. Every other router had it, so nothing looked wrong in review: the
omission is invisible unless you diff two routers side by side.

This is the same shape as `test_authz_matrix.py` and `test_profiles.py` — a structural
guard that fails the build rather than a convention people are asked to remember. A new
router with a POST and no CSRF dependency now cannot merge.

**Why the exemptions are exemptions.** `verify_csrf` implements double-submit: it
compares a cookie against a header. The three routes below run *before* the session
cookie exists, so there is nothing to double-submit and the check would reject every
legitimate sign-in. They are also the routes that issue the CSRF cookie in the first
place. Nothing else may be added to this set without the same argument.
"""

from __future__ import annotations

import pytest
from fastapi.routing import APIRoute

from netsecops.api.deps import verify_csrf

#: Methods that do not change state, so double-submit does not apply. `verify_csrf`
#: itself returns early on these; listing them keeps the assertion about intent rather
#: than about the dependency's internals.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

#: Routes that run before a session cookie exists (SEC-03).
EXEMPT: set[tuple[str, str]] = {
    # Establishes the session and sets the CSRF cookie. There is no prior cookie to
    # compare a header against.
    ("POST", "/api/v1/auth/login"),
    # The second leg of the same sign-in: the session is still not established until
    # the TOTP or recovery code is accepted.
    ("POST", "/api/v1/auth/mfa/verify"),
    # Presents the path-scoped refresh cookie, which a cross-site form post cannot
    # reach — the cookie is SameSite=strict and scoped to this path.
    ("POST", "/api/v1/auth/refresh"),
}


def _has_csrf(route: APIRoute) -> bool:
    """Whether `verify_csrf` appears anywhere in this route's dependency tree."""
    pending = list(route.dependant.dependencies)
    while pending:
        dependant = pending.pop()
        if dependant.call is verify_csrf:
            return True
        pending.extend(dependant.dependencies)
    return False


#: Where the v1 router is mounted. A route's own `path` already carries its router's
#: prefix — FastAPI applies that at decoration time — so this is the only piece missing.
API_PREFIX = "/api/v1"


def _api_routes(container) -> list[APIRoute]:
    """Every APIRoute under an app, however deeply the routers are nested.

    `app.routes` is not flat: an included router appears as an `_IncludedRouter` whose
    own routes hang off `original_router`. A single-level scan therefore finds *none* of
    them — and a coverage test that finds nothing passes. The first version of this file
    did exactly that and reported the rule as enforced across zero endpoints.
    """
    found: list[APIRoute] = []
    for route in getattr(container, "routes", []):
        if isinstance(route, APIRoute):
            found.append(route)
            continue
        found.extend(_api_routes(route))
        if (inner := getattr(route, "original_router", None)) is not None:
            found.extend(_api_routes(inner))
    return found


def _documented(app) -> set[tuple[str, str]]:
    """Every ``(method, path)`` the OpenAPI document publishes under the v1 prefix.

    The authoritative list, used to cross-check the walk above: OpenAPI is generated from
    the same routing table the server dispatches on, so a mismatch means the walk is
    wrong rather than the API being wrong.
    """
    return {
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        for method in operations
        if path.startswith(API_PREFIX)
    }


def _state_changing(app) -> list[tuple[str, str, APIRoute]]:
    documented = _documented(app)

    found: list[tuple[str, str, APIRoute]] = []
    for route in _api_routes(app):
        path = API_PREFIX + route.path
        for method in route.methods or set():
            # Intersected with the published document rather than filtered by string.
            # It drops the health endpoints, which are mounted at the root, and it means
            # a route whose full path this reconstructs incorrectly is *excluded* rather
            # than silently checked under a name nothing serves.
            if (method.upper(), path) in documented and method.upper() not in SAFE_METHODS:
                found.append((method.upper(), path, route))
    return found


class TestCsrfCoverage:
    def test_the_scan_actually_finds_endpoints(self, app) -> None:
        """Guards the guard.

        Every other assertion here is of the form "nothing is unprotected", which is
        trivially true of an empty list. This is the one that fails when the route walk
        stops working — and it did: nested routers made the first version find zero.
        """
        documented = _documented(app)
        expected = {(method, path) for method, path in documented if method not in SAFE_METHODS}
        scanned = {(method, path) for method, path, _ in _state_changing(app)}

        # Equality, not a threshold: every state-changing endpoint the API publishes is
        # one this scan reached. A count would keep passing while a whole router went
        # missing, which is the failure this file already had once.
        assert scanned == expected, (
            f"The route walk missed: {sorted(expected - scanned)}\n"
            f"and invented: {sorted(scanned - expected)}"
        )
        assert len(expected) > 40, f"Only {len(expected)} state-changing endpoints found"

    def test_every_state_changing_endpoint_is_protected(self, app) -> None:
        unprotected = [
            f"{method} {path}"
            for method, path, route in _state_changing(app)
            if (method, path) not in EXEMPT and not _has_csrf(route)
        ]

        assert not unprotected, (
            "These endpoints change state and carry no CSRF check (SEC-03):\n  "
            + "\n  ".join(sorted(unprotected))
            + "\n\nAdd `Depends(verify_csrf)` to the route's dependencies, or justify an "
            "entry in EXEMPT above — an exemption needs the same argument the three "
            "existing ones have: the route runs before a session cookie exists."
        )

    def test_the_exemptions_still_exist(self, app) -> None:
        """An exemption for a route that has been renamed is a hole nobody sees.

        The entry stops matching, the real route falls under the rule, and the list keeps
        claiming a justification for something that is no longer there.
        """
        declared = {(method, path) for method, path, _ in _state_changing(app)}

        assert EXEMPT <= declared, (
            f"These exemptions name routes that no longer exist: {sorted(EXEMPT - declared)}"
        )

    @pytest.mark.parametrize("method", sorted(SAFE_METHODS))
    def test_a_safe_method_is_not_required_to_carry_it(self, method: str) -> None:
        """Documents the boundary: the rule is about state change, not about verbs."""
        assert method in SAFE_METHODS
