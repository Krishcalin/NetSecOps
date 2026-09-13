"""Policy, custom-check and exception management (FR-CHK-05 … FR-CHK-07)."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.checks.loader import CheckRegistry, explain_validation_error, get_registry
from netsecops.checks.policy_packs import get_packs
from netsecops.checks.schema import CheckDefinition, LogicType, Severity
from netsecops.core.errors import ConflictError, NotFoundError, ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Principal
from netsecops.db.models.audit import AuditAction
from netsecops.db.models.inventory import DeviceGroup
from netsecops.db.models.policy import (
    CustomCheck,
    ExceptionScope,
    ExceptionStatus,
    FindingException,
    Policy,
    PolicyAssignment,
    PolicyCheck,
)
from netsecops.services.audit import AuditService

log = get_logger(__name__)


class PolicyService:
    def __init__(self, session: AsyncSession, *, registry: CheckRegistry | None = None) -> None:
        self.session = session
        self._registry = registry
        self.audit = AuditService(session)

    @property
    def registry(self) -> CheckRegistry:
        if self._registry is None:
            self._registry = get_registry()
        return self._registry

    # ───────────────────────────── seeding ──────────────────────────────

    async def seed_packs(self, *, org_id: int = 1, make_default: bool = True) -> list[Policy]:
        """Install shipped policy packs that are not present yet.

        Idempotent, and deliberately non-destructive: an existing policy is left exactly
        as the operator has it, even if the pack has since changed. Overwriting would
        silently discard a disabled check or a severity override — the customisations
        most worth keeping, because someone thought about them.
        """
        installed: list[Policy] = []

        for loaded in get_packs():
            pack = loaded.pack
            existing = (
                await self.session.execute(
                    select(Policy).where(Policy.org_id == org_id, Policy.source == pack.source)
                )
            ).scalar_one_or_none()

            if existing is not None:
                if existing.version < pack.version:
                    log.info(
                        "policy.pack_newer_than_installed",
                        pack=pack.source,
                        installed=existing.version,
                        available=pack.version,
                    )
                continue

            policy = Policy(
                org_id=org_id,
                name=pack.name,
                description=pack.description,
                source=pack.source,
                version=pack.version,
                frameworks=pack.frameworks,
                enabled=True,
            )
            self.session.add(policy)
            await self.session.flush()

            known = set(self.registry.ids)
            for entry in pack.checks:
                if entry.id not in known:
                    # Already logged at pack load; skipped here so the policy does not
                    # carry a reference the engine will only warn about every run.
                    continue
                self.session.add(
                    PolicyCheck(
                        org_id=org_id,
                        policy_id=policy.id,
                        check_id=entry.id,
                        enabled=entry.enabled,
                        severity_override=entry.severity,
                        notes=entry.notes,
                    )
                )

            # Refreshed so `policy.entries` is populated. A relationship on a row that
            # was added rather than queried is unloaded, and touching one under async
            # SQLAlchemy raises MissingGreenlet rather than lazily loading.
            await self.session.flush()
            await self.session.refresh(policy, ["entries"])

            installed.append(policy)
            log.info("policy.pack_installed", pack=pack.source, checks=len(policy.entries))

        if make_default and installed:
            has_default = (
                await self.session.execute(
                    select(Policy).where(Policy.org_id == org_id, Policy.is_default.is_(True))
                )
            ).scalar_one_or_none()
            if has_default is None:
                installed[0].is_default = True

        await self.session.flush()
        return installed

    # ───────────────────────────── policies ─────────────────────────────

    async def list_policies(self, *, org_id: int = 1) -> Sequence[Policy]:
        return (
            (
                await self.session.execute(
                    select(Policy).where(Policy.org_id == org_id).order_by(Policy.name)
                )
            )
            .scalars()
            .all()
        )

    async def get(self, policy_id: uuid.UUID) -> Policy:
        policy = (
            await self.session.execute(select(Policy).where(Policy.id == policy_id))
        ).scalar_one_or_none()
        if policy is None:
            raise NotFoundError("Policy not found.")
        return policy

    async def create(
        self,
        *,
        name: str,
        check_ids: Sequence[str],
        actor: Principal,
        description: str | None = None,
        frameworks: Sequence[str] | None = None,
        org_id: int = 1,
    ) -> Policy:
        clash = (
            await self.session.execute(
                select(Policy).where(Policy.org_id == org_id, Policy.name == name)
            )
        ).scalar_one_or_none()
        if clash is not None:
            raise ConflictError(f"A policy named {name!r} already exists.")

        known = set(self.registry.ids) | await self._custom_check_ids(org_id)
        unknown = sorted(set(check_ids) - known)
        if unknown:
            raise ValidationProblem(
                f"These checks do not exist: {', '.join(unknown)}.",
                unknown_checks=unknown,
            )

        policy = Policy(
            org_id=org_id,
            name=name,
            description=description,
            source="custom",
            frameworks=list(frameworks or []),
        )
        self.session.add(policy)
        await self.session.flush()

        for check_id in check_ids:
            self.session.add(PolicyCheck(org_id=org_id, policy_id=policy.id, check_id=check_id))
        await self.session.flush()
        await self.session.refresh(policy, ["entries"])

        await self.audit.record(
            AuditAction.SETTINGS_CHANGED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="policy",
            object_id=policy.id,
            details={"created": name, "checks": len(check_ids)},
            org_id=org_id,
        )
        return policy

    async def set_check(
        self,
        policy: Policy,
        check_id: str,
        *,
        actor: Principal,
        enabled: bool | None = None,
        severity_override: Severity | None = None,
    ) -> PolicyCheck:
        """Enable, disable or re-grade one check within a policy (FR-CHK-06)."""
        entry = (
            await self.session.execute(
                select(PolicyCheck).where(
                    PolicyCheck.policy_id == policy.id, PolicyCheck.check_id == check_id
                )
            )
        ).scalar_one_or_none()

        if entry is None:
            if check_id not in set(self.registry.ids) | await self._custom_check_ids(policy.org_id):
                raise ValidationProblem(f"No check with id {check_id!r} exists.")
            entry = PolicyCheck(org_id=policy.org_id, policy_id=policy.id, check_id=check_id)
            self.session.add(entry)

        if enabled is not None:
            entry.enabled = enabled
        if severity_override is not None:
            entry.severity_override = severity_override.value

        await self.session.flush()

        await self.audit.record(
            AuditAction.SETTINGS_CHANGED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="policy_check",
            object_id=entry.id,
            details={
                "policy": policy.name,
                "check": check_id,
                "enabled": entry.enabled,
                "severity_override": entry.severity_override,
            },
            org_id=policy.org_id,
        )
        return entry

    async def assign(
        self, policy: Policy, group_id: uuid.UUID, *, actor: Principal
    ) -> PolicyAssignment:
        group = (
            await self.session.execute(select(DeviceGroup).where(DeviceGroup.id == group_id))
        ).scalar_one_or_none()
        if group is None:
            raise NotFoundError("Device group not found.")

        existing = (
            await self.session.execute(
                select(PolicyAssignment).where(
                    PolicyAssignment.policy_id == policy.id,
                    PolicyAssignment.device_group_id == group_id,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing

        assignment = PolicyAssignment(
            org_id=policy.org_id, policy_id=policy.id, device_group_id=group_id
        )
        self.session.add(assignment)
        await self.session.flush()

        await self.audit.record(
            AuditAction.SETTINGS_CHANGED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="policy_assignment",
            object_id=assignment.id,
            details={"policy": policy.name, "group": group.name},
            org_id=policy.org_id,
        )
        return assignment

    async def set_default(self, policy: Policy, *, actor: Principal) -> Policy:
        """Make this the policy for devices no assignment covers.

        The previous default is unset first. Enforced here rather than by a partial
        unique index because "there can be only one" is friendlier applied silently
        than returned as a conflict the operator has to resolve themselves.
        """
        current = (
            (
                await self.session.execute(
                    select(Policy).where(
                        Policy.org_id == policy.org_id,
                        Policy.is_default.is_(True),
                        Policy.id != policy.id,
                    )
                )
            )
            .scalars()
            .all()
        )

        for other in current:
            other.is_default = False

        policy.is_default = True
        await self.session.flush()

        await self.audit.record(
            AuditAction.SETTINGS_CHANGED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="policy",
            object_id=policy.id,
            details={"default": True, "replaced": [p.name for p in current]},
            org_id=policy.org_id,
        )
        return policy

    # ─────────────────────────── custom checks ──────────────────────────

    async def _custom_check_ids(self, org_id: int) -> set[str]:
        rows = (
            (
                await self.session.execute(
                    select(CustomCheck.check_id).where(CustomCheck.org_id == org_id)
                )
            )
            .scalars()
            .all()
        )
        return set(rows)

    async def create_custom_check(
        self, definition: dict[str, Any], *, actor: Principal, org_id: int = 1
    ) -> CustomCheck:
        """Store an operator-authored check (FR-CHK-06).

        Validated against the same schema as the shipped library, and refused if it
        declares Python logic: accepting a function name from a web form would let a
        user invoke any registered callable, and accepting code would be worse.
        """
        try:
            parsed = CheckDefinition.model_validate(definition)
        except ValidationError as exc:
            # This is operator input from a web form, so a schema failure is a 422 with
            # the field names — not a 500 with a stack trace. The message is the same
            # one the YAML loader gives, because it is the same schema and the author
            # should not have to learn two vocabularies.
            raise ValidationProblem(
                f"The check definition is not valid: {explain_validation_error(exc)}",
                errors=[
                    {"field": ".".join(str(p) for p in e["loc"]), "message": e["msg"]}
                    for e in exc.errors()
                ],
            ) from exc

        if parsed.logic.type is LogicType.PYTHON:
            raise ValidationProblem(
                "Custom checks may use 'ncm' or 'regex' logic. Python checks are part "
                "of the shipped library because their code is reviewed with the "
                "product."
            )

        if parsed.id in set(self.registry.ids):
            raise ConflictError(
                f"{parsed.id!r} is the id of a shipped check. Choose another id, or "
                "override the shipped check's severity within a policy instead."
            )

        clash = (
            await self.session.execute(
                select(CustomCheck).where(
                    CustomCheck.org_id == org_id, CustomCheck.check_id == parsed.id
                )
            )
        ).scalar_one_or_none()
        if clash is not None:
            raise ConflictError(f"A custom check with id {parsed.id!r} already exists.")

        row = CustomCheck(
            org_id=org_id,
            check_id=parsed.id,
            definition=parsed.model_dump(mode="json", by_alias=True),
            created_by_id=actor.id,
        )
        self.session.add(row)
        await self.session.flush()

        await self.audit.record(
            AuditAction.SETTINGS_CHANGED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="custom_check",
            object_id=row.id,
            details={"check": parsed.id, "severity": parsed.severity.value},
            org_id=org_id,
        )
        return row

    async def list_custom_checks(self, *, org_id: int = 1) -> Sequence[CustomCheck]:
        return (
            (
                await self.session.execute(
                    select(CustomCheck)
                    .where(CustomCheck.org_id == org_id)
                    .order_by(CustomCheck.check_id)
                )
            )
            .scalars()
            .all()
        )

    # ───────────────────────────── exceptions ───────────────────────────

    async def create_exception(
        self,
        *,
        check_id: str,
        justification: str,
        expires_at: datetime,
        actor: Principal,
        scope: ExceptionScope = ExceptionScope.DEVICE,
        device_id: uuid.UUID | None = None,
        device_group_id: uuid.UUID | None = None,
        approver: str | None = None,
        org_id: int = 1,
    ) -> FindingException:
        """Suppress a finding, with a reason and an end date (FR-CHK-07)."""
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= datetime.now(UTC):
            raise ValidationProblem(
                "The expiry date is in the past. An exception needs a date by which "
                "the decision will be revisited."
            )

        if scope is ExceptionScope.DEVICE and device_id is None:
            raise ValidationProblem("A device-scoped exception needs a device_id.")
        if scope is ExceptionScope.GROUP and device_group_id is None:
            raise ValidationProblem("A group-scoped exception needs a device_group_id.")

        known = set(self.registry.ids) | await self._custom_check_ids(org_id)
        if check_id not in known:
            raise ValidationProblem(f"No check with id {check_id!r} exists.")

        row = FindingException(
            org_id=org_id,
            check_id=check_id,
            scope=scope.value,
            device_id=device_id if scope is ExceptionScope.DEVICE else None,
            device_group_id=device_group_id if scope is ExceptionScope.GROUP else None,
            justification=justification,
            approver=approver,
            expires_at=expires_at,
            status=ExceptionStatus.ACTIVE.value,
            created_by_id=actor.id,
        )
        self.session.add(row)
        await self.session.flush()

        await self.audit.record(
            AuditAction.EXCEPTION_CREATED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="exception",
            object_id=row.id,
            device_id=device_id,
            details={
                "check": check_id,
                "scope": scope.value,
                "expires_at": expires_at.isoformat(),
                "approver": approver,
            },
            org_id=org_id,
        )
        log.info(
            "exception.created", check=check_id, scope=scope.value, expires=expires_at.isoformat()
        )
        return row

    async def revoke_exception(
        self, exception_id: uuid.UUID, *, actor: Principal
    ) -> FindingException:
        row = (
            await self.session.execute(
                select(FindingException).where(FindingException.id == exception_id)
            )
        ).scalar_one_or_none()
        if row is None:
            raise NotFoundError("Exception not found.")

        row.status = ExceptionStatus.REVOKED.value
        row.revoked_at = datetime.now(UTC)
        await self.session.flush()

        await self.audit.record(
            AuditAction.SETTINGS_CHANGED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="exception",
            object_id=row.id,
            details={"revoked": True, "check": row.check_id},
            org_id=row.org_id,
        )
        return row

    async def list_exceptions(
        self, *, org_id: int = 1, active_only: bool = False
    ) -> Sequence[FindingException]:
        stmt = select(FindingException).where(FindingException.org_id == org_id)
        if active_only:
            stmt = stmt.where(
                FindingException.status == ExceptionStatus.ACTIVE.value,
                FindingException.expires_at > datetime.now(UTC),
            )
        rows = (
            (await self.session.execute(stmt.order_by(FindingException.expires_at))).scalars().all()
        )
        return rows

    async def count_policies(self, *, org_id: int = 1) -> int:
        return int(
            (
                await self.session.execute(
                    select(func.count()).select_from(Policy).where(Policy.org_id == org_id)
                )
            ).scalar_one()
        )


__all__ = ["PolicyService"]
