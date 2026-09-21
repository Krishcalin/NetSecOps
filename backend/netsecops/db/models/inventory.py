"""Inventory and credential-vault tables (FR-INV-01…08, FR-CRED-01…07)."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netsecops.db.base import Base, OrgMixin, TimestampMixin, UUIDPrimaryKeyMixin
from netsecops.db.types import LtreePath


class Vendor(StrEnum):
    CISCO = "cisco"
    PALOALTO = "paloalto"
    FORTINET = "fortinet"
    CHECKPOINT = "checkpoint"
    LINUX = "linux"
    UNKNOWN = "unknown"


class DeviceClass(StrEnum):
    """SRS §1.3 device classes."""

    FIREWALL = "firewall"
    SWITCH = "switch"
    ROUTER = "router"
    WIRELESS_AP = "wireless_ap"
    WIRELESS_CONTROLLER = "wireless_controller"
    MANAGER = "manager"
    AAA_SERVER = "aaa_server"
    UNKNOWN = "unknown"


class Criticality(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DeviceStatus(StrEnum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    #: Discovered but not yet approved for assessment (FR-DISC-04).
    PENDING_REVIEW = "pending_review"


class CredentialType(StrEnum):
    """FR-CRED-01."""

    SSH_PASSWORD = "ssh_password"  # noqa: S105
    SSH_KEY = "ssh_key"
    ENABLE_SECRET = "enable_secret"  # noqa: S105
    API_KEY = "api_key"
    API_USERNAME_PASSWORD = "api_username_password"  # noqa: S105
    SNMP_V2C = "snmp_v2c"
    SNMP_V3 = "snmp_v3"
    CHECKPOINT_API = "checkpoint_api"
    JUMP_HOST = "jump_host"


# ────────────────────────────── organisation ────────────────────────────────


class Site(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    __tablename__ = "sites"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_sites_org_id_name"),)

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    location: Mapped[str | None] = mapped_column(String(255))


class DeviceGroup(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """Hierarchical group (FR-INV-03), e.g. Site → Zone → Function.

    ``path`` is the materialised ltree path from the root, built from the sanitised
    UUIDs of the ancestors. Storing it means the scope check in FR-AUTH-05 — "is this
    device in a subtree the caller may see?" — is one indexed containment query.
    """

    __tablename__ = "device_groups"
    __table_args__ = (
        UniqueConstraint("org_id", "parent_id", "name", name="uq_device_groups_parent_name"),
        Index("ix_device_groups_path", "path", postgresql_using="gist"),
    )

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("device_groups.id", ondelete="CASCADE"), index=True
    )
    path: Mapped[str] = mapped_column(LtreePath, nullable=False)

    parent: Mapped[DeviceGroup | None] = relationship(remote_side="DeviceGroup.id")

    @staticmethod
    def label_for(group_id: uuid.UUID) -> str:
        """ltree labels permit only [A-Za-z0-9_], so a UUID's hyphens are stripped."""
        return "g" + group_id.hex


class Tag(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    __tablename__ = "tags"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_tags_org_id_name"),)

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    colour: Mapped[str | None] = mapped_column(String(16))


class DeviceTag(Base, OrgMixin):
    __tablename__ = "device_tags"

    device_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True
    )
    tag_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True
    )


class DeviceGroupMember(Base, OrgMixin):
    """A device may belong to several groups (FR-INV-03)."""

    __tablename__ = "device_group_members"

    device_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True
    )
    group_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("device_groups.id", ondelete="CASCADE"), primary_key=True
    )


# ──────────────────────────────── devices ───────────────────────────────────


class Device(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """A target device (FR-INV-01).

    Credentials are never stored here — only assignments pointing at vault records.
    """

    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("org_id", "mgmt_ip", name="uq_devices_org_id_mgmt_ip"),
        Index("ix_devices_vendor_platform", "vendor", "platform"),
        Index("ix_devices_status", "status"),
    )

    mgmt_ip: Mapped[str] = mapped_column(INET, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    fqdn: Mapped[str | None] = mapped_column(String(255))

    vendor: Mapped[str] = mapped_column(String(32), nullable=False, default=Vendor.UNKNOWN)
    #: Matches a key in ``adapters.policies.POLICIES`` once the device is classified.
    platform: Mapped[str | None] = mapped_column(String(64))
    device_class: Mapped[str] = mapped_column(
        String(32), nullable=False, default=DeviceClass.UNKNOWN
    )

    site_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("sites.id", ondelete="SET NULL"), index=True
    )
    owner_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    criticality: Mapped[str] = mapped_column(String(16), nullable=False, default=Criticality.MEDIUM)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default=DeviceStatus.ACTIVE)

    #: A manager (Panorama, FortiManager, FMC, SMS) that owns this device (FR-INV-04).
    parent_device_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), index=True
    )

    #: Facts refreshed after each successful collection (FR-INV-05).
    facts: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    serial_number: Mapped[str | None] = mapped_column(String(128), index=True)
    os_version: Mapped[str | None] = mapped_column(String(128))
    model: Mapped[str | None] = mapped_column(String(128))
    last_collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # ── Trust-on-first-use pins (FR-COL-10) ─────────────────────────────
    host_key_fingerprint: Mapped[str | None] = mapped_column(String(128))
    tls_cert_fingerprint: Mapped[str | None] = mapped_column(String(128))

    # ── Per-device access overrides ─────────────────────────────────────
    ssh_port: Mapped[int] = mapped_column(Integer, nullable=False, default=22)
    https_port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)
    connect_timeout: Mapped[int | None] = mapped_column(Integer)
    command_timeout: Mapped[int | None] = mapped_column(Integer)
    jump_host_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL")
    )

    #: Check Point Gaia expert-mode reads, off unless explicitly enabled (SRS §8.2).
    allow_expert: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    #: Linux AAA hosts: permit `sudo -n cat` for root-only config files (SRS §8.2).
    allow_sudo_read: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    notes: Mapped[str | None] = mapped_column(Text)

    groups: Mapped[list[DeviceGroupMember]] = relationship(
        cascade="all, delete-orphan", lazy="selectin"
    )
    tags: Mapped[list[DeviceTag]] = relationship(cascade="all, delete-orphan", lazy="selectin")
    credential_assignments: Mapped[list[CredentialAssignment]] = relationship(
        back_populates="device",
        cascade="all, delete-orphan",
        lazy="selectin",
        foreign_keys="CredentialAssignment.device_id",
    )

    @property
    def policy_platform(self) -> str | None:
        """The read-only allow-list to enforce against, honouring per-device escapes.

        **This is a policy key and nothing else.** `checkpoint_gaia_expert` and
        `linux_aaa_sudo` widen which *commands* may be sent (ADR-002: expert mode is a
        root shell, enabled per device to bound the blast radius). They are not different
        configuration formats, different collection profiles or different check targets.

        It was called `effective_platform` and used as all four, which broke a device the
        moment somebody enabled the option:

        * as a parser key, `get_parser("checkpoint_gaia_expert")` raises, so the device
          could no longer store a snapshot at all;
        * as the check-applicability platform, the shipped library writes
          `platforms: [checkpoint_gaia]` and applicability is an exact set membership
          test — so every Check Point check reported Not Applicable and the gateway was
          assessed to zero findings. Existing findings stayed open, because only a PASS
          resolves one, but nothing new was ever evaluated.

        Anything that parses, collects, assesses or displays uses `platform`.
        """
        if self.platform == "checkpoint_gaia" and self.allow_expert:
            return "checkpoint_gaia_expert"
        if self.platform == "linux_aaa" and self.allow_sudo_read:
            return "linux_aaa_sudo"
        return self.platform


# ────────────────────────────── credentials ─────────────────────────────────


class Credential(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """Vault record (FR-CRED-01/02/03).

    Secret material lives only in ``encrypted_blob``, sealed with AES-256-GCM under a
    per-record data key and bound to this row's id. No API ever returns it.
    """

    __tablename__ = "credentials"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_credentials_org_id_name"),)

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    credential_type: Mapped[str] = mapped_column(String(32), nullable=False)

    #: Non-secret half: username, SNMPv3 auth/priv protocol names, key comment.
    #: Anything here may be shown in the UI, so nothing secret may be put here.
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    #: Envelope-encrypted secret payload. AAD is this row's id (DATA-01).
    encrypted_blob: Mapped[bytes] = mapped_column(nullable=False)
    #: Master key id the data key is wrapped under, for rotation reporting.
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)

    #: When set, the secret is fetched from an external manager at use time and
    #: ``encrypted_blob`` holds only the reference (FR-CRED-06).
    external_ref: Mapped[str | None] = mapped_column(String(512))

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_test_succeeded: Mapped[bool | None] = mapped_column(Boolean)

    assignments: Mapped[list[CredentialAssignment]] = relationship(
        back_populates="credential", cascade="all, delete-orphan"
    )


class CredentialAssignment(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """Binds a credential to a device or a group, with fallback ordering (FR-CRED-04).

    Exactly one of ``device_id`` / ``group_id`` is set. Device-level assignments
    override inherited group ones; within a level, ``priority`` orders the fallback
    list so a rotated credential can be tried before the previous one.
    """

    __tablename__ = "credential_assignments"
    __table_args__ = (
        UniqueConstraint(
            "credential_id", "device_id", "group_id", name="uq_credential_assignment_target"
        ),
        Index("ix_credential_assignments_device", "device_id", "priority"),
        Index("ix_credential_assignments_group", "group_id", "priority"),
    )

    credential_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("credentials.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE")
    )
    group_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("device_groups.id", ondelete="CASCADE")
    )
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)

    credential: Mapped[Credential] = relationship(back_populates="assignments", lazy="selectin")
    device: Mapped[Device | None] = relationship(
        back_populates="credential_assignments", foreign_keys=[device_id]
    )
