"""Role-based access control (FR-AUTH-05).

Five roles from SRS §2.3 map to a flat permission set. Endpoints declare the permission
they need rather than the roles they accept, so adding a role never requires editing
every route.

Permissions for later phases are declared here up front. That is deliberate: TEST-06
requires an authorization matrix covering *every* endpoint × role, and building the
vocabulary once keeps the matrix honest as routes land phase by phase.

Object-level scoping (Network Engineer and Auditor see only their assigned Device Groups)
is expressed by :class:`Scope`, which resolves to "all" for the unrestricted roles.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final


class Role(StrEnum):
    """The five user classes in SRS §2.3."""

    SUPER_ADMIN = "super_admin"
    SECURITY_ANALYST = "security_analyst"
    NETWORK_ENGINEER = "network_engineer"
    AUDITOR = "auditor"
    API_SERVICE = "api_service"


class Permission(StrEnum):
    # Platform administration
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    ROLE_READ = "role:read"
    ROLE_WRITE = "role:write"
    API_TOKEN_READ = "api_token:read"  # noqa: S105 - permission name
    API_TOKEN_WRITE = "api_token:write"  # noqa: S105 - permission name
    SETTINGS_READ = "settings:read"
    SETTINGS_WRITE = "settings:write"
    AUDIT_READ = "audit:read"
    INTEGRATION_READ = "integration:read"
    INTEGRATION_WRITE = "integration:write"

    # Inventory (Phase 1)
    DEVICE_READ = "device:read"
    DEVICE_WRITE = "device:write"
    CREDENTIAL_READ = "credential:read"
    CREDENTIAL_WRITE = "credential:write"
    DISCOVERY_READ = "discovery:read"
    DISCOVERY_WRITE = "discovery:write"

    # Assessment (Phases 1-3)
    JOB_READ = "job:read"
    JOB_EXECUTE = "job:execute"
    CHECK_READ = "check:read"
    CHECK_WRITE = "check:write"
    POLICY_READ = "policy:read"
    POLICY_WRITE = "policy:write"

    # Results (Phases 3-6)
    FINDING_READ = "finding:read"
    FINDING_WRITE = "finding:write"
    EXCEPTION_WRITE = "exception:write"
    VULN_READ = "vuln:read"
    VULN_WRITE = "vuln:write"
    SNAPSHOT_READ = "snapshot:read"

    #: SEC-09 — viewing unredacted configuration is a distinct, audited privilege.
    CONFIG_VIEW_UNREDACTED = "config:view_unredacted"

    # Reporting (Phase 7)
    REPORT_READ = "report:read"
    REPORT_GENERATE = "report:generate"


_READ_ONLY: Final[frozenset[Permission]] = frozenset(
    {
        Permission.DEVICE_READ,
        Permission.JOB_READ,
        Permission.CHECK_READ,
        Permission.POLICY_READ,
        Permission.FINDING_READ,
        Permission.VULN_READ,
        Permission.SNAPSHOT_READ,
        Permission.REPORT_READ,
        Permission.DISCOVERY_READ,
    }
)

_ANALYST: Final[frozenset[Permission]] = _READ_ONLY | frozenset(
    {
        Permission.DEVICE_WRITE,
        Permission.CREDENTIAL_READ,
        Permission.CREDENTIAL_WRITE,
        Permission.DISCOVERY_WRITE,
        Permission.JOB_EXECUTE,
        Permission.CHECK_WRITE,
        Permission.POLICY_WRITE,
        Permission.FINDING_WRITE,
        Permission.EXCEPTION_WRITE,
        Permission.VULN_WRITE,
        Permission.REPORT_GENERATE,
        Permission.CONFIG_VIEW_UNREDACTED,
    }
)

#: Network Engineer owns devices but must not touch checks or credentials (SRS §2.3).
_NETWORK_ENGINEER: Final[frozenset[Permission]] = frozenset(
    {
        Permission.DEVICE_READ,
        Permission.JOB_READ,
        Permission.FINDING_READ,
        Permission.VULN_READ,
        Permission.SNAPSHOT_READ,
        Permission.CHECK_READ,
        Permission.POLICY_READ,
        Permission.REPORT_READ,
        Permission.DISCOVERY_READ,
    }
)

#: Auditor additionally sees the audit trail, but cannot execute anything.
_AUDITOR: Final[frozenset[Permission]] = _READ_ONLY | frozenset({Permission.AUDIT_READ})

ROLE_PERMISSIONS: Final[dict[Role, frozenset[Permission]]] = {
    Role.SUPER_ADMIN: frozenset(Permission),
    Role.SECURITY_ANALYST: _ANALYST,
    Role.NETWORK_ENGINEER: _NETWORK_ENGINEER,
    Role.AUDITOR: _AUDITOR,
    # A service account's effective permissions are the intersection of this ceiling and
    # the scopes minted into its token (FR-AUTH-07).
    Role.API_SERVICE: _READ_ONLY | frozenset({Permission.JOB_EXECUTE, Permission.FINDING_WRITE}),
}

#: Roles whose visibility is limited to assigned Device Groups (FR-AUTH-05).
GROUP_SCOPED_ROLES: Final[frozenset[Role]] = frozenset(
    {Role.NETWORK_ENGINEER, Role.AUDITOR, Role.API_SERVICE}
)

ROLE_DESCRIPTIONS: Final[dict[Role, str]] = {
    Role.SUPER_ADMIN: "Platform owner: users, roles, settings, vault policy, integrations.",
    Role.SECURITY_ANALYST: "Primary user: inventory, assessments, findings, reports.",
    Role.NETWORK_ENGINEER: "Device owner: read findings and config for assigned groups.",
    Role.AUDITOR: "Compliance/management: read-only dashboards, reports and audit trail.",
    Role.API_SERVICE: "Machine user for SIEM/ITSM integrations, scoped by token.",
}


@dataclass(frozen=True, slots=True)
class Scope:
    """Object-level visibility for a principal (FR-AUTH-05).

    ``unrestricted`` means every device group. Otherwise ``device_group_ids`` lists the
    group subtrees the principal may see; queries filter on it.
    """

    unrestricted: bool = False
    device_group_ids: frozenset[uuid.UUID] = field(default_factory=frozenset)

    @classmethod
    def all(cls) -> Scope:
        return cls(unrestricted=True)

    def allows_group(self, group_id: uuid.UUID | None) -> bool:
        if self.unrestricted:
            return True
        if group_id is None:
            return False
        return group_id in self.device_group_ids


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller: a user session or an API service account."""

    id: uuid.UUID
    username: str
    roles: frozenset[Role]
    scope: Scope
    is_service_account: bool = False
    token_id: uuid.UUID | None = None
    #: For service accounts: the scopes minted into the token, capping its permissions.
    token_scopes: frozenset[Permission] | None = None

    @property
    def permissions(self) -> frozenset[Permission]:
        granted: frozenset[Permission] = frozenset()
        for role in self.roles:
            granted |= ROLE_PERMISSIONS.get(role, frozenset())
        if self.token_scopes is not None:
            granted &= self.token_scopes
        return granted

    def has(self, *permissions: Permission) -> bool:
        """True only if *every* requested permission is held."""
        return set(permissions).issubset(self.permissions)

    def has_any(self, *permissions: Permission) -> bool:
        return bool(set(permissions) & self.permissions)

    @property
    def is_super_admin(self) -> bool:
        return Role.SUPER_ADMIN in self.roles


def permissions_for_roles(roles: frozenset[Role] | set[Role]) -> frozenset[Permission]:
    granted: frozenset[Permission] = frozenset()
    for role in roles:
        granted |= ROLE_PERMISSIONS.get(role, frozenset())
    return granted
