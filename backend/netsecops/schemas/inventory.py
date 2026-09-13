"""Inventory and credential request/response models (SEC-04).

FR-CRED-03 is enforced structurally here: there is no response model with a field that
could carry secret material. ``CredentialRead`` exposes the name, type and metadata,
and nothing else — a future contributor cannot accidentally serialise a secret because
there is nowhere for it to go.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

from netsecops.db.models.inventory import (
    CredentialType,
    Criticality,
    DeviceClass,
    DeviceStatus,
    Vendor,
)

# ──────────────────────────────── devices ───────────────────────────────────


class DeviceBase(BaseModel):
    hostname: str | None = Field(default=None, max_length=255)
    fqdn: str | None = Field(default=None, max_length=255)
    vendor: Vendor = Vendor.UNKNOWN
    platform: str | None = Field(
        default=None,
        max_length=64,
        description="Must match a platform with a read-only policy (see netsecops-cli audit-commands)",
    )
    device_class: DeviceClass = DeviceClass.UNKNOWN
    site_id: uuid.UUID | None = None
    criticality: Criticality = Criticality.MEDIUM
    notes: str | None = None
    ssh_port: int = Field(default=22, ge=1, le=65535)
    https_port: int = Field(default=443, ge=1, le=65535)
    connect_timeout: int | None = Field(default=None, ge=1, le=600)
    command_timeout: int | None = Field(default=None, ge=1, le=3600)
    allow_expert: bool = Field(
        default=False,
        description="Check Point Gaia only: permit whitelisted expert-mode reads (SRS §8.2)",
    )
    allow_sudo_read: bool = Field(
        default=False,
        description="Linux AAA hosts only: permit `sudo -n cat` of config files (SRS §8.2)",
    )


class DeviceCreate(DeviceBase):
    mgmt_ip: IPvAnyAddress
    group_ids: list[uuid.UUID] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class DeviceUpdate(BaseModel):
    mgmt_ip: IPvAnyAddress | None = None
    hostname: str | None = Field(default=None, max_length=255)
    fqdn: str | None = Field(default=None, max_length=255)
    vendor: Vendor | None = None
    platform: str | None = Field(default=None, max_length=64)
    device_class: DeviceClass | None = None
    site_id: uuid.UUID | None = None
    criticality: Criticality | None = None
    status: DeviceStatus | None = None
    notes: str | None = None
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    https_port: int | None = Field(default=None, ge=1, le=65535)
    connect_timeout: int | None = Field(default=None, ge=1, le=600)
    command_timeout: int | None = Field(default=None, ge=1, le=3600)
    allow_expert: bool | None = None
    allow_sudo_read: bool | None = None
    group_ids: list[uuid.UUID] | None = None
    tags: list[str] | None = None


class DeviceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    mgmt_ip: str
    hostname: str | None
    fqdn: str | None
    vendor: str
    platform: str | None
    device_class: str
    criticality: str
    status: str
    site_id: uuid.UUID | None
    parent_device_id: uuid.UUID | None

    serial_number: str | None
    os_version: str | None
    model: str | None
    facts: dict[str, Any]

    last_collected_at: datetime | None
    last_seen_at: datetime | None
    #: Present so an operator can compare it against the device (FR-COL-10).
    host_key_fingerprint: str | None

    ssh_port: int
    https_port: int
    allow_expert: bool
    allow_sudo_read: bool
    notes: str | None

    created_at: datetime
    updated_at: datetime

    @field_validator("mgmt_ip", mode="before")
    @classmethod
    def _stringify_ip(cls, v: object) -> object:
        """asyncpg returns INET as an ipaddress object; the API contract is a string."""
        return str(v) if v is not None else v


class DeviceDetail(DeviceRead):
    group_ids: list[uuid.UUID] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    credential_names: list[str] = Field(default_factory=list)


class PaginatedDevices(BaseModel):
    data: list[DeviceRead]
    meta: dict[str, int]


# ───────────────────────────── device groups ────────────────────────────────


class DeviceGroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    parent_id: uuid.UUID | None = None
    description: str | None = None


class DeviceGroupMove(BaseModel):
    parent_id: uuid.UUID | None = None


class DeviceGroupRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    parent_id: uuid.UUID | None
    #: The ltree materialised path. Exposed because it makes the hierarchy obvious
    #: to an API consumer building a tree without n+1 requests.
    path: str
    created_at: datetime


class SiteCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    description: str | None = None
    location: str | None = Field(default=None, max_length=255)


class SiteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    location: str | None


class TagRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    colour: str | None


# ─────────────────────────────── CSV import ─────────────────────────────────


class ImportRowResult(BaseModel):
    line: int
    valid: bool
    action: str = Field(description="create, update, or error")
    errors: list[str] = Field(default_factory=list)
    mgmt_ip: str | None = None


class ImportPreviewResponse(BaseModel):
    """FR-INV-02 — what *would* happen, before anything is written."""

    ok: bool
    creates: int
    updates: int
    invalid: int
    rows: list[ImportRowResult]


class ImportApplyResponse(BaseModel):
    created: int
    updated: int


# ─────────────────────────────── credentials ────────────────────────────────


class CredentialCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    credential_type: CredentialType
    description: str | None = None
    #: Both halves; the service decides which fields are secret and seals only those.
    #: Unknown field names are rejected, so a secret cannot land in searchable metadata.
    secret_data: dict[str, str] = Field(
        description="Type-specific fields, e.g. {'username': 'ro', 'password': '...'}"
    )


class CredentialUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=150)
    description: str | None = None
    secret_data: dict[str, str] | None = Field(
        default=None, description="Only the fields being rotated need to be supplied"
    )


class CredentialRead(BaseModel):
    """FR-CRED-03 — no field here can carry secret material, by construction."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    credential_type: str
    #: The non-secret half only: usernames, SNMPv3 protocol names, key comments.
    #:
    #: Serialization-only alias, deliberately. A plain ``alias="metadata"`` would make
    #: Pydantic read ``obj.metadata`` when validating from the ORM — which on a
    #: declarative model is SQLAlchemy's MetaData object, not this column.
    metadata_: dict[str, Any] = Field(default_factory=dict, serialization_alias="metadata")
    key_id: str
    last_used_at: datetime | None
    last_tested_at: datetime | None
    last_test_succeeded: bool | None
    created_at: datetime


class CredentialAssignmentCreate(BaseModel):
    device_id: uuid.UUID | None = None
    group_id: uuid.UUID | None = None
    priority: int = Field(default=100, ge=0, le=10_000)


class CredentialAssignmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    credential_id: uuid.UUID
    device_id: uuid.UUID | None
    group_id: uuid.UUID | None
    priority: int


class CredentialTestRequest(BaseModel):
    device_id: uuid.UUID


class CredentialTestResponse(BaseModel):
    """FR-CRED-05 — login plus one trivial read, nothing more."""

    succeeded: bool
    device_id: uuid.UUID
    detail: str | None = None
    command: str | None = Field(
        default=None, description="The single read command issued, for transparency"
    )
    host_key_fingerprint: str | None = None


class PaginatedCredentials(BaseModel):
    data: list[CredentialRead]
    meta: dict[str, int]
