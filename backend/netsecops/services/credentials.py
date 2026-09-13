"""Credential vault (FR-CRED-01 … FR-CRED-07).

Two rules govern everything here:

- **Secrets are write-only over the API.** ``CredentialService`` returns ORM rows whose
  ``encrypted_blob`` never leaves this module in plaintext; only :meth:`open_secret`
  decrypts, and only the collector calls it (FR-CRED-03).
- **Every use is audited, the secret never is.** FR-CRED-07 wants a record of which
  credential was used against which device, by which job — and explicitly not the
  secret itself.
"""

from __future__ import annotations

import builtins
import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.crypto import SecretVault, build_vault
from netsecops.core.errors import ConflictError, NotFoundError, ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Principal
from netsecops.db.models.audit import AuditAction, AuditOutcome
from netsecops.db.models.inventory import (
    Credential,
    CredentialAssignment,
    CredentialType,
    Device,
    DeviceGroup,
    DeviceGroupMember,
)
from netsecops.services.audit import AuditService

log = get_logger(__name__)


#: Which fields each credential type requires, and which of them are secret.
#: Non-secret fields are stored in ``metadata`` and shown in the UI; secret fields are
#: sealed. Getting this table wrong is how a password ends up in a JSONB column, so it
#: is data rather than scattered conditionals.
SECRET_FIELDS: dict[CredentialType, tuple[str, ...]] = {
    CredentialType.SSH_PASSWORD: ("password",),
    CredentialType.SSH_KEY: ("private_key", "passphrase"),
    CredentialType.ENABLE_SECRET: ("secret",),
    CredentialType.API_KEY: ("api_key",),
    CredentialType.API_USERNAME_PASSWORD: ("password",),
    CredentialType.SNMP_V2C: ("community",),
    CredentialType.SNMP_V3: ("auth_key", "priv_key"),
    CredentialType.CHECKPOINT_API: ("password",),
    CredentialType.JUMP_HOST: ("password", "private_key", "passphrase"),
}

PUBLIC_FIELDS: dict[CredentialType, tuple[str, ...]] = {
    CredentialType.SSH_PASSWORD: ("username",),
    CredentialType.SSH_KEY: ("username", "key_comment"),
    CredentialType.ENABLE_SECRET: (),
    CredentialType.API_KEY: ("header_name",),
    CredentialType.API_USERNAME_PASSWORD: ("username",),
    CredentialType.SNMP_V2C: (),
    CredentialType.SNMP_V3: ("username", "auth_protocol", "priv_protocol", "security_level"),
    CredentialType.CHECKPOINT_API: ("username", "domain"),
    CredentialType.JUMP_HOST: ("username", "host", "port"),
}

REQUIRED_FIELDS: dict[CredentialType, tuple[str, ...]] = {
    CredentialType.SSH_PASSWORD: ("username", "password"),
    CredentialType.SSH_KEY: ("username", "private_key"),
    CredentialType.ENABLE_SECRET: ("secret",),
    CredentialType.API_KEY: ("api_key",),
    CredentialType.API_USERNAME_PASSWORD: ("username", "password"),
    CredentialType.SNMP_V2C: ("community",),
    CredentialType.SNMP_V3: ("username", "security_level"),
    CredentialType.CHECKPOINT_API: ("username", "password"),
    CredentialType.JUMP_HOST: ("username", "host"),
}


@dataclass(frozen=True, slots=True)
class ResolvedCredential:
    """A credential chosen for a device, with the reason it was chosen.

    ``source`` is "device" or "group": FR-CRED-04 makes device assignments override
    inherited group ones, and a collector log that says which applied is the difference
    between a five-minute and a two-hour diagnosis.
    """

    credential: Credential
    source: str
    priority: int
    group_id: uuid.UUID | None = None


class CredentialService:
    def __init__(self, session: AsyncSession, *, vault: SecretVault | None = None) -> None:
        self.session = session
        self._vault = vault
        self.audit = AuditService(session)

    @property
    def vault(self) -> SecretVault:
        if self._vault is None:
            self._vault = build_vault()
        return self._vault

    # ─────────────────────────────── create ─────────────────────────────

    async def create(
        self,
        *,
        name: str,
        credential_type: CredentialType,
        secret_data: dict[str, Any],
        description: str | None = None,
        actor: Principal,
        org_id: int = 1,
    ) -> Credential:
        """Seal a new credential.

        ``secret_data`` carries both halves; this method decides which fields are
        secret and seals only those, so a caller cannot accidentally place a password
        in the searchable metadata.
        """
        await self._assert_name_free(name, org_id)
        self._validate_fields(credential_type, secret_data)

        secret_part = {
            key: secret_data[key]
            for key in SECRET_FIELDS.get(credential_type, ())
            if secret_data.get(key) is not None
        }
        public_part = {
            key: secret_data[key]
            for key in PUBLIC_FIELDS.get(credential_type, ())
            if secret_data.get(key) is not None
        }

        credential = Credential(
            org_id=org_id,
            name=name,
            description=description,
            credential_type=credential_type.value,
            metadata_=public_part,
            # Placeholder: the real seal needs the row id as AAD (DATA-01), which only
            # exists after the flush below.
            encrypted_blob=b"",
            key_id="",
            created_by_id=actor.id,
        )
        self.session.add(credential)
        await self.session.flush()

        credential.encrypted_blob = self.vault.seal(json.dumps(secret_part), aad=str(credential.id))
        credential.key_id = self.vault.current_key_id()
        await self.session.flush()

        await self.audit.record(
            AuditAction.CREDENTIAL_CREATED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="credential",
            object_id=credential.id,
            # Field *names* only — never values (FR-CRED-07).
            details={
                "name": name,
                "type": credential_type.value,
                "secret_fields": sorted(secret_part),
            },
        )
        return credential

    def _validate_fields(self, credential_type: CredentialType, data: dict[str, Any]) -> None:
        missing = [
            field for field in REQUIRED_FIELDS.get(credential_type, ()) if not data.get(field)
        ]
        if missing:
            raise ValidationProblem(
                f"Credential type '{credential_type.value}' requires: {', '.join(missing)}.",
                missing_fields=missing,
            )

        known = set(SECRET_FIELDS.get(credential_type, ())) | set(
            PUBLIC_FIELDS.get(credential_type, ())
        )
        if unexpected := sorted(set(data) - known):
            # Refusing unknown fields stops a secret being smuggled into metadata under
            # a name this module does not recognise as secret.
            raise ValidationProblem(
                f"Unexpected field(s) for '{credential_type.value}': {', '.join(unexpected)}.",
                unexpected_fields=unexpected,
                accepted_fields=sorted(known),
            )

    # ─────────────────────────────── read ───────────────────────────────

    async def get(self, credential_id: uuid.UUID) -> Credential:
        credential = (
            await self.session.execute(select(Credential).where(Credential.id == credential_id))
        ).scalar_one_or_none()
        if credential is None:
            raise NotFoundError("Credential not found.")
        return credential

    async def list(
        self,
        *,
        search: str | None = None,
        credential_type: CredentialType | None = None,
        limit: int = 50,
        offset: int = 0,
        org_id: int = 1,
    ) -> tuple[Sequence[Credential], int]:
        stmt = select(Credential).where(Credential.org_id == org_id)
        count_stmt = select(func.count()).select_from(Credential).where(Credential.org_id == org_id)

        if search:
            pattern = f"%{search}%"
            condition = or_(Credential.name.ilike(pattern), Credential.description.ilike(pattern))
            stmt, count_stmt = stmt.where(condition), count_stmt.where(condition)

        if credential_type is not None:
            condition = Credential.credential_type == credential_type.value
            stmt, count_stmt = stmt.where(condition), count_stmt.where(condition)

        total = int((await self.session.execute(count_stmt)).scalar_one())
        rows = (
            (await self.session.execute(stmt.order_by(Credential.name).limit(limit).offset(offset)))
            .scalars()
            .all()
        )
        return rows, total

    def open_secret(self, credential: Credential) -> dict[str, Any]:
        """Decrypt a credential's secret half.

        The only path from ciphertext to plaintext. Callers are the collector and the
        credential test; nothing in the API layer may call this.
        """
        if not credential.encrypted_blob:
            return {}
        raw = self.vault.open(credential.encrypted_blob, aad=str(credential.id))
        opened: dict[str, Any] = json.loads(raw.decode("utf-8"))
        return opened

    # ────────────────────────────── update ──────────────────────────────

    async def update(
        self,
        credential: Credential,
        *,
        actor: Principal,
        name: str | None = None,
        description: str | None = None,
        secret_data: dict[str, Any] | None = None,
    ) -> Credential:
        changes: list[str] = []

        if name is not None and name != credential.name:
            await self._assert_name_free(name, credential.org_id, exclude_id=credential.id)
            credential.name = name
            changes.append("name")

        if description is not None and description != credential.description:
            credential.description = description
            changes.append("description")

        if secret_data:
            credential_type = CredentialType(credential.credential_type)
            # Merge over the existing secret so a caller may rotate one field without
            # resupplying the rest.
            merged = {**self.open_secret(credential), **credential.metadata_, **secret_data}
            self._validate_fields(credential_type, merged)

            secret_part = {
                key: merged[key]
                for key in SECRET_FIELDS.get(credential_type, ())
                if merged.get(key) is not None
            }
            public_part = {
                key: merged[key]
                for key in PUBLIC_FIELDS.get(credential_type, ())
                if merged.get(key) is not None
            }

            credential.encrypted_blob = self.vault.seal(
                json.dumps(secret_part), aad=str(credential.id)
            )
            credential.key_id = self.vault.current_key_id()
            credential.metadata_ = public_part
            changes.append("secret")

        if changes:
            await self.session.flush()
            await self.audit.record(
                AuditAction.CREDENTIAL_UPDATED,
                actor_id=actor.id,
                actor_username=actor.username,
                object_type="credential",
                object_id=credential.id,
                details={"changed": changes},
            )
        return credential

    async def delete(self, credential: Credential, *, actor: Principal) -> None:
        assignments = int(
            (
                await self.session.execute(
                    select(func.count())
                    .select_from(CredentialAssignment)
                    .where(CredentialAssignment.credential_id == credential.id)
                )
            ).scalar_one()
        )
        if assignments:
            raise ConflictError(
                "This credential is still assigned to devices or groups. "
                "Remove the assignments first.",
                assignments=assignments,
            )

        name = credential.name
        await self.session.delete(credential)
        await self.session.flush()

        await self.audit.record(
            AuditAction.CREDENTIAL_DELETED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="credential",
            object_id=credential.id,
            details={"name": name},
        )

    # ──────────────────────────── assignment ────────────────────────────

    async def assign(
        self,
        credential: Credential,
        *,
        device_id: uuid.UUID | None = None,
        group_id: uuid.UUID | None = None,
        priority: int = 100,
        actor: Principal,
    ) -> CredentialAssignment:
        if (device_id is None) == (group_id is None):
            raise ValidationProblem(
                "An assignment targets exactly one of a device or a device group."
            )

        existing = (
            await self.session.execute(
                select(CredentialAssignment).where(
                    CredentialAssignment.credential_id == credential.id,
                    CredentialAssignment.device_id == device_id,
                    CredentialAssignment.group_id == group_id,
                )
            )
        ).scalar_one_or_none()

        if existing is not None:
            existing.priority = priority
            await self.session.flush()
            return existing

        assignment = CredentialAssignment(
            org_id=credential.org_id,
            credential_id=credential.id,
            device_id=device_id,
            group_id=group_id,
            priority=priority,
        )
        self.session.add(assignment)
        await self.session.flush()

        await self.audit.record(
            AuditAction.CREDENTIAL_UPDATED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="credential",
            object_id=credential.id,
            details={
                "assigned_to": "device" if device_id else "group",
                "target_id": str(device_id or group_id),
                "priority": priority,
            },
        )
        return assignment

    async def unassign(self, assignment_id: uuid.UUID, *, actor: Principal) -> None:
        assignment = (
            await self.session.execute(
                select(CredentialAssignment).where(CredentialAssignment.id == assignment_id)
            )
        ).scalar_one_or_none()
        if assignment is None:
            raise NotFoundError("Credential assignment not found.")

        credential_id = assignment.credential_id
        await self.session.delete(assignment)
        await self.session.flush()

        await self.audit.record(
            AuditAction.CREDENTIAL_UPDATED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="credential",
            object_id=credential_id,
            details={"unassigned": str(assignment_id)},
        )

    async def resolve_for_device(self, device: Device) -> Sequence[ResolvedCredential]:
        """Build the ordered credential fallback list for a device (FR-CRED-04).

        Device-level assignments come first, then group-level ones inherited from every
        group the device belongs to — including ancestors, since a credential set on
        "Site A" should apply to "Site A → Core" without being reassigned.
        Within a level, lower ``priority`` is tried first.
        """
        resolved: builtins.list[ResolvedCredential] = []

        device_rows = (
            (
                await self.session.execute(
                    select(CredentialAssignment)
                    .where(CredentialAssignment.device_id == device.id)
                    .order_by(CredentialAssignment.priority)
                )
            )
            .scalars()
            .all()
        )
        for row in device_rows:
            resolved.append(
                ResolvedCredential(
                    credential=await self.get(row.credential_id),
                    source="device",
                    priority=row.priority,
                )
            )

        group_ids = await self._ancestor_group_ids(device)
        if group_ids:
            group_rows = (
                (
                    await self.session.execute(
                        select(CredentialAssignment)
                        .where(CredentialAssignment.group_id.in_(group_ids))
                        .order_by(CredentialAssignment.priority)
                    )
                )
                .scalars()
                .all()
            )
            seen = {r.credential.id for r in resolved}
            for row in group_rows:
                if row.credential_id in seen:
                    continue  # a device-level assignment already covers this credential
                seen.add(row.credential_id)
                resolved.append(
                    ResolvedCredential(
                        credential=await self.get(row.credential_id),
                        source="group",
                        priority=row.priority,
                        group_id=row.group_id,
                    )
                )

        return resolved

    async def _ancestor_group_ids(self, device: Device) -> Sequence[uuid.UUID]:
        """Every group the device is in, plus all of their ancestors.

        ltree's containment operator does the ancestor walk in the database: a group's
        path contains its ancestors' paths as prefixes.
        """
        direct = (
            (
                await self.session.execute(
                    select(DeviceGroupMember.group_id).where(
                        DeviceGroupMember.device_id == device.id
                    )
                )
            )
            .scalars()
            .all()
        )
        if not direct:
            return []

        paths = (
            (await self.session.execute(select(DeviceGroup.path).where(DeviceGroup.id.in_(direct))))
            .scalars()
            .all()
        )
        if not paths:
            return list(direct)

        # `@>` is "is an ancestor of (or equal to)". Every group whose path is a prefix
        # of one of the device's group paths is an ancestor of that group.
        conditions = [DeviceGroup.path.op("@>")(path) for path in paths]
        ancestors = (
            (await self.session.execute(select(DeviceGroup.id).where(or_(*conditions))))
            .scalars()
            .all()
        )
        return list(ancestors)

    # ────────────────────────────── usage ───────────────────────────────

    async def record_use(
        self,
        credential: Credential,
        *,
        device: Device,
        succeeded: bool,
        job_id: uuid.UUID | None = None,
        actor: Principal | None = None,
        detail: str | None = None,
    ) -> None:
        """FR-CRED-07 — record that a credential was used, never what it contains."""
        credential.last_used_at = datetime.now(UTC)

        await self.audit.record(
            AuditAction.CREDENTIAL_USED,
            outcome=AuditOutcome.SUCCESS if succeeded else AuditOutcome.FAILURE,
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "scheduler",
            object_type="credential",
            object_id=credential.id,
            device_id=device.id,
            details={
                "credential_name": credential.name,
                "device": str(device.mgmt_ip),
                "job_id": str(job_id) if job_id else None,
                "outcome": detail,
            },
        )

    async def record_test(
        self,
        credential: Credential,
        *,
        device: Device,
        succeeded: bool,
        actor: Principal,
        detail: str | None = None,
    ) -> None:
        credential.last_tested_at = datetime.now(UTC)
        credential.last_test_succeeded = succeeded
        await self.session.flush()

        await self.audit.record(
            AuditAction.CREDENTIAL_TESTED,
            outcome=AuditOutcome.SUCCESS if succeeded else AuditOutcome.FAILURE,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="credential",
            object_id=credential.id,
            device_id=device.id,
            details={"device": str(device.mgmt_ip), "detail": detail},
        )

    # ────────────────────────────── helpers ─────────────────────────────

    async def _assert_name_free(
        self, name: str, org_id: int, *, exclude_id: uuid.UUID | None = None
    ) -> None:
        stmt = select(Credential).where(Credential.org_id == org_id, Credential.name == name)
        if exclude_id is not None:
            stmt = stmt.where(Credential.id != exclude_id)
        if (await self.session.execute(stmt)).scalar_one_or_none() is not None:
            raise ConflictError(f"A credential named '{name}' already exists.")
