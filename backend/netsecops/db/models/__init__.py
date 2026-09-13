"""ORM models.

Every model must be imported here so that Alembic autogenerate and
``Base.metadata.create_all`` see the complete schema (C-5).
"""

from netsecops.db.models.audit import (
    GENESIS_HASH,
    AuditAction,
    AuditLog,
    AuditOutcome,
    Setting,
)
from netsecops.db.models.inventory import (
    Credential,
    CredentialAssignment,
    CredentialType,
    Criticality,
    Device,
    DeviceClass,
    DeviceGroup,
    DeviceGroupMember,
    DeviceStatus,
    DeviceTag,
    Site,
    Tag,
    Vendor,
)
from netsecops.db.models.jobs import (
    DeviceJobStatus,
    ErrorClass,
    Job,
    JobDevice,
    JobStatus,
    JobType,
    Schedule,
)
from netsecops.db.models.user import (
    ApiToken,
    LoginAttempt,
    MFASecret,
    PasswordHistory,
    RefreshToken,
    User,
    UserDeviceGroupScope,
    UserRole,
)

__all__ = [
    "GENESIS_HASH",
    "ApiToken",
    "AuditAction",
    "AuditLog",
    "AuditOutcome",
    "Credential",
    "CredentialAssignment",
    "CredentialType",
    "Criticality",
    "Device",
    "DeviceClass",
    "DeviceGroup",
    "DeviceGroupMember",
    "DeviceJobStatus",
    "DeviceStatus",
    "DeviceTag",
    "ErrorClass",
    "Job",
    "JobDevice",
    "JobStatus",
    "JobType",
    "LoginAttempt",
    "MFASecret",
    "PasswordHistory",
    "RefreshToken",
    "Schedule",
    "Setting",
    "Site",
    "Tag",
    "User",
    "UserDeviceGroupScope",
    "UserRole",
    "Vendor",
]
