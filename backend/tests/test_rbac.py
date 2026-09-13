"""RBAC model tests (FR-AUTH-05)."""

from __future__ import annotations

import uuid

import pytest

from netsecops.core.rbac import (
    GROUP_SCOPED_ROLES,
    ROLE_DESCRIPTIONS,
    ROLE_PERMISSIONS,
    Permission,
    Principal,
    Role,
    Scope,
    permissions_for_roles,
)


def _principal(*roles: Role, scope: Scope | None = None, **kwargs) -> Principal:
    return Principal(
        id=uuid.uuid4(),
        username="test",
        roles=frozenset(roles),
        scope=scope or Scope.all(),
        **kwargs,
    )


class TestRoleDefinitions:
    def test_every_role_has_permissions_and_a_description(self) -> None:
        for role in Role:
            assert role in ROLE_PERMISSIONS, f"{role} has no permission set"
            assert ROLE_DESCRIPTIONS.get(role), f"{role} has no description"

    def test_super_admin_holds_every_permission(self) -> None:
        assert ROLE_PERMISSIONS[Role.SUPER_ADMIN] == frozenset(Permission)

    @pytest.mark.parametrize("role", [Role.AUDITOR, Role.NETWORK_ENGINEER])
    def test_read_only_roles_cannot_write(self, role: Role) -> None:
        """Auditor and Network Engineer must hold no mutating permission."""
        write_permissions = {p for p in Permission if p.value.split(":")[1] != "read"}
        # job:execute, config:view_unredacted and report:generate are all non-read.
        assert not (ROLE_PERMISSIONS[role] & write_permissions)

    def test_network_engineer_cannot_touch_credentials_or_checks(self) -> None:
        """SRS §2.3 — the device owner explicitly cannot change checks or credentials."""
        granted = ROLE_PERMISSIONS[Role.NETWORK_ENGINEER]
        assert Permission.CREDENTIAL_READ not in granted
        assert Permission.CREDENTIAL_WRITE not in granted
        assert Permission.CHECK_WRITE not in granted

    def test_only_auditor_and_super_admin_read_the_audit_log(self) -> None:
        holders = {r for r in Role if Permission.AUDIT_READ in ROLE_PERMISSIONS[r]}
        assert holders == {Role.AUDITOR, Role.SUPER_ADMIN}

    def test_unredacted_config_is_restricted(self) -> None:
        """SEC-09 — viewing unredacted config is a privilege, not a default."""
        holders = {r for r in Role if Permission.CONFIG_VIEW_UNREDACTED in ROLE_PERMISSIONS[r]}
        assert holders == {Role.SUPER_ADMIN, Role.SECURITY_ANALYST}

    def test_analyst_can_run_assessments(self) -> None:
        assert Permission.JOB_EXECUTE in ROLE_PERMISSIONS[Role.SECURITY_ANALYST]

    def test_auditor_cannot_run_assessments(self) -> None:
        assert Permission.JOB_EXECUTE not in ROLE_PERMISSIONS[Role.AUDITOR]


class TestPrincipalPermissions:
    def test_permissions_union_across_roles(self) -> None:
        principal = _principal(Role.AUDITOR, Role.NETWORK_ENGINEER)
        assert Permission.AUDIT_READ in principal.permissions
        assert Permission.DEVICE_READ in principal.permissions

    def test_has_requires_all(self) -> None:
        principal = _principal(Role.AUDITOR)
        assert principal.has(Permission.AUDIT_READ, Permission.DEVICE_READ)
        assert not principal.has(Permission.AUDIT_READ, Permission.DEVICE_WRITE)

    def test_has_any_requires_one(self) -> None:
        principal = _principal(Role.AUDITOR)
        assert principal.has_any(Permission.DEVICE_WRITE, Permission.AUDIT_READ)
        assert not principal.has_any(Permission.DEVICE_WRITE, Permission.CHECK_WRITE)

    def test_roleless_principal_has_nothing(self) -> None:
        assert _principal().permissions == frozenset()

    def test_is_super_admin(self) -> None:
        assert _principal(Role.SUPER_ADMIN).is_super_admin
        assert not _principal(Role.SECURITY_ANALYST).is_super_admin


class TestTokenScopes:
    """FR-AUTH-07 — a token narrows its owner's permissions, never widens them."""

    def test_token_scopes_intersect_role_permissions(self) -> None:
        principal = _principal(
            Role.SECURITY_ANALYST,
            token_scopes=frozenset({Permission.DEVICE_READ, Permission.FINDING_READ}),
        )
        assert principal.permissions == {Permission.DEVICE_READ, Permission.FINDING_READ}

    def test_token_cannot_grant_beyond_the_role(self) -> None:
        principal = _principal(
            Role.AUDITOR,
            token_scopes=frozenset({Permission.USER_WRITE, Permission.DEVICE_READ}),
        )
        assert Permission.USER_WRITE not in principal.permissions
        assert Permission.DEVICE_READ in principal.permissions

    def test_super_admin_token_is_still_capped_by_its_scopes(self) -> None:
        principal = _principal(Role.SUPER_ADMIN, token_scopes=frozenset({Permission.DEVICE_READ}))
        assert principal.permissions == {Permission.DEVICE_READ}


class TestScope:
    def test_unrestricted_allows_every_group(self) -> None:
        assert Scope.all().allows_group(uuid.uuid4())

    def test_restricted_allows_only_assigned_groups(self) -> None:
        allowed, denied = uuid.uuid4(), uuid.uuid4()
        scope = Scope(unrestricted=False, device_group_ids=frozenset({allowed}))

        assert scope.allows_group(allowed)
        assert not scope.allows_group(denied)

    def test_restricted_denies_ungrouped_objects(self) -> None:
        """A device in no group must not leak to a group-scoped role."""
        scope = Scope(unrestricted=False, device_group_ids=frozenset({uuid.uuid4()}))
        assert not scope.allows_group(None)

    def test_group_scoped_roles_are_the_expected_set(self) -> None:
        assert GROUP_SCOPED_ROLES == {Role.NETWORK_ENGINEER, Role.AUDITOR, Role.API_SERVICE}


class TestPermissionsForRoles:
    def test_empty_roles_grant_nothing(self) -> None:
        assert permissions_for_roles(frozenset()) == frozenset()

    def test_matches_principal_computation(self) -> None:
        roles = {Role.AUDITOR, Role.NETWORK_ENGINEER}
        assert permissions_for_roles(roles) == _principal(*roles).permissions
