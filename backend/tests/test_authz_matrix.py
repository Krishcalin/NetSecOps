"""Authorization matrix: every endpoint × every role (TEST-06).

Phase 0 acceptance requires these to pass. The matrix is written as data so that adding
an endpoint without deciding who may call it is a test failure, not an oversight — the
``test_every_endpoint_is_in_the_matrix`` guard enforces that as later phases add routes.

Each case asserts only that access is *granted or denied*, never that the handler
succeeds: a 404 for a missing record still proves the caller passed authorization.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import pytest
from httpx import AsyncClient

from netsecops.core.rbac import Role
from netsecops.db.models import User

ROLES = [Role.SUPER_ADMIN, Role.SECURITY_ANALYST, Role.NETWORK_ENGINEER, Role.AUDITOR]

#: Endpoints reachable without authentication at all.
PUBLIC_PATHS = {
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/mfa/verify"),
    ("POST", "/api/v1/auth/refresh"),
    ("GET", "/healthz"),
    ("GET", "/readyz"),
    ("GET", "/metrics"),
}

#: Endpoints any authenticated principal may call (they act on the caller's own account).
SELF_SERVICE_PATHS = {
    ("GET", "/api/v1/auth/me"),
    ("POST", "/api/v1/auth/logout"),
    ("POST", "/api/v1/auth/password"),
    ("POST", "/api/v1/auth/mfa/enroll"),
    ("POST", "/api/v1/auth/mfa/confirm"),
    ("DELETE", "/api/v1/auth/mfa"),
    ("GET", "/api/v1/auth/roles"),
    ("GET", "/api/v1/api-tokens"),
    ("POST", "/api/v1/api-tokens"),
    ("DELETE", "/api/v1/api-tokens/{token_id}"),
}


@dataclass(frozen=True)
class Case:
    method: str
    path: str
    #: Roles that must be allowed through authorization.
    allowed: frozenset[Role]
    body: dict | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.method, self.path)


_ADMIN_ONLY = frozenset({Role.SUPER_ADMIN})
_USER_READERS = frozenset({Role.SUPER_ADMIN})
_AUDIT_READERS = frozenset({Role.SUPER_ADMIN, Role.AUDITOR})

MATRIX: list[Case] = [
    # ── User administration ─────────────────────────────────────────────────
    Case("GET", "/api/v1/users", _USER_READERS),
    Case(
        "POST",
        "/api/v1/users",
        _USER_READERS,
        body={
            "username": "matrix_new",
            "email": "matrix_new@example.com",
            "password": "Valid-P4ssword!",
            "roles": [],
        },
    ),
    Case("GET", "/api/v1/users/{user_id}", _USER_READERS),
    Case("PATCH", "/api/v1/users/{user_id}", _USER_READERS, body={"full_name": "Changed"}),
    Case("DELETE", "/api/v1/users/{user_id}", _ADMIN_ONLY),
    Case("PUT", "/api/v1/users/{user_id}/roles", _ADMIN_ONLY, body={"roles": ["auditor"]}),
    Case("PUT", "/api/v1/users/{user_id}/scope", _ADMIN_ONLY, body={"device_group_ids": []}),
    Case(
        "POST",
        "/api/v1/users/{user_id}/password",
        _ADMIN_ONLY,
        body={"new_password": "Another-V4lid-Pass!"},
    ),
    # ── Audit log (FR-AUD-01) ───────────────────────────────────────────────
    Case("GET", "/api/v1/audit-log", _AUDIT_READERS),
    Case("GET", "/api/v1/audit-log/verify", _AUDIT_READERS),
    Case("GET", "/api/v1/audit-log/export", _AUDIT_READERS),
]

MATRIX_KEYS = {c.key for c in MATRIX} | PUBLIC_PATHS | SELF_SERVICE_PATHS


def _resolve(path: str, target: User) -> str:
    return path.replace("{user_id}", str(target.id)).replace("{token_id}", str(uuid.uuid4()))


@pytest.mark.authz
class TestEndpointCoverage:
    """Guard: no route may exist without an explicit authorization decision."""

    def test_every_endpoint_is_in_the_matrix(self, app) -> None:
        documented: set[tuple[str, str]] = set()
        for path, operations in app.openapi()["paths"].items():
            for method in operations:
                if method.upper() in {"HEAD", "OPTIONS", "TRACE"}:
                    continue
                documented.add((method.upper(), path))

        missing = documented - MATRIX_KEYS
        assert not missing, (
            "These endpoints have no authorization-matrix entry. Add them to MATRIX, "
            "PUBLIC_PATHS or SELF_SERVICE_PATHS in this file:\n  "
            + "\n  ".join(sorted(f"{m} {p}" for m, p in missing))
        )

    def test_matrix_has_no_stale_entries(self, app) -> None:
        documented: set[tuple[str, str]] = {
            (method.upper(), path)
            for path, operations in app.openapi()["paths"].items()
            for method in operations
        }
        stale = {c.key for c in MATRIX} - documented
        assert not stale, f"Matrix references endpoints that no longer exist: {sorted(stale)}"


@pytest.mark.authz
class TestRoleAccess:
    @pytest.mark.parametrize(
        "case", MATRIX, ids=lambda c: f"{c.method}_{c.path.strip('/').replace('/', '_')}"
    )
    @pytest.mark.parametrize("role", ROLES, ids=lambda r: r.value)
    async def test_role_access(
        self,
        client: AsyncClient,
        session,
        authenticate,
        case: Case,
        role: Role,
    ) -> None:
        from tests.conftest import make_user

        caller = await make_user(
            session, username=f"m_{role.value}_{uuid.uuid4().hex[:6]}", roles={role}
        )
        target = await make_user(session, username=f"t_{uuid.uuid4().hex[:8]}")
        authenticate(caller)

        response = await client.request(case.method, _resolve(case.path, target), json=case.body)

        if role in case.allowed:
            assert response.status_code != 403, (
                f"{role.value} should be permitted to {case.method} {case.path} "
                f"but got 403: {response.text[:200]}"
            )
        else:
            assert response.status_code == 403, (
                f"{role.value} must NOT be permitted to {case.method} {case.path} "
                f"but got {response.status_code}"
            )


@pytest.mark.authz
class TestUnauthenticatedAccess:
    @pytest.mark.parametrize(
        "case", MATRIX, ids=lambda c: f"{c.method}_{c.path.strip('/').replace('/', '_')}"
    )
    async def test_protected_endpoints_reject_anonymous_callers(
        self, client: AsyncClient, session, case: Case
    ) -> None:
        from tests.conftest import make_user

        target = await make_user(session, username=f"anon_t_{uuid.uuid4().hex[:8]}")
        response = await client.request(case.method, _resolve(case.path, target), json=case.body)
        assert response.status_code == 401

    @pytest.mark.parametrize(
        "path",
        sorted(p for _, p in PUBLIC_PATHS if p.startswith("/health") or p.startswith("/ready")),
    )
    async def test_probes_are_public(self, client: AsyncClient, path: str) -> None:
        assert (await client.get(path)).status_code in {200, 503}


@pytest.mark.authz
class TestSelfService:
    @pytest.mark.parametrize("role", ROLES, ids=lambda r: r.value)
    async def test_every_role_can_read_its_own_profile(
        self, client: AsyncClient, session, authenticate, role: Role
    ) -> None:
        from tests.conftest import make_user

        caller = await make_user(session, username=f"self_{role.value}", roles={role})
        authenticate(caller)

        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 200
        assert response.json()["username"] == caller.username


@pytest.mark.authz
class TestServiceAccountScoping:
    """FR-AUTH-07 — a token's scopes cap what it can reach."""

    async def test_token_without_the_scope_is_denied(
        self, client: AsyncClient, session, authenticate
    ) -> None:
        from netsecops.core.rbac import Permission
        from tests.conftest import make_user

        owner = await make_user(session, username="svc_owner", roles={Role.SUPER_ADMIN})
        authenticate(owner, token_scopes={Permission.DEVICE_READ})

        assert (await client.get("/api/v1/users")).status_code == 403

    async def test_token_with_the_scope_is_allowed(
        self, client: AsyncClient, session, authenticate
    ) -> None:
        from netsecops.core.rbac import Permission
        from tests.conftest import make_user

        owner = await make_user(session, username="svc_owner2", roles={Role.SUPER_ADMIN})
        authenticate(owner, token_scopes={Permission.USER_READ})

        assert (await client.get("/api/v1/users")).status_code == 200
