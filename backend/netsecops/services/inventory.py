"""Inventory management (FR-INV-01 … FR-INV-08).

Two things here deserve attention beyond ordinary CRUD:

- **Scope filtering.** Every list and fetch takes a :class:`Scope`. FR-AUTH-05 restricts
  Network Engineers and Auditors to their assigned Device Groups, and the only way to
  make that reliable is to apply it in the query rather than trusting each caller.
- **Group paths.** ``device_groups.path`` is an ltree materialised path. Moving a group
  has to rewrite its whole subtree, so that lives in one place here rather than being
  re-derived by callers.
"""

from __future__ import annotations

import builtins
import csv
import io
import ipaddress
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sqlalchemy import Select, false, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ConflictError, NotFoundError, ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Principal, Scope
from netsecops.db.models.audit import AuditAction
from netsecops.db.models.inventory import (
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
from netsecops.services.audit import AuditService

log = get_logger(__name__)


@dataclass(slots=True)
class ImportRow:
    """One CSV row, with whatever is wrong with it (FR-INV-02)."""

    line: int
    data: dict[str, str]
    errors: builtins.list[str] = field(default_factory=list)
    #: Set when the row would update an existing device rather than create one.
    existing_id: uuid.UUID | None = None

    @property
    def valid(self) -> bool:
        return not self.errors


@dataclass(slots=True)
class ImportPreview:
    """The dry-run result FR-INV-02 requires before anything is written."""

    rows: builtins.list[ImportRow]

    @property
    def creates(self) -> int:
        return sum(1 for r in self.rows if r.valid and r.existing_id is None)

    @property
    def updates(self) -> int:
        return sum(1 for r in self.rows if r.valid and r.existing_id is not None)

    @property
    def invalid(self) -> int:
        return sum(1 for r in self.rows if not r.valid)

    @property
    def ok(self) -> bool:
        return self.invalid == 0


CSV_COLUMNS = (
    "mgmt_ip",
    "hostname",
    "vendor",
    "platform",
    "device_class",
    "site",
    "criticality",
    "groups",
    "tags",
    "notes",
)


class InventoryService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.audit = AuditService(session)

    # ─────────────────────────────── devices ────────────────────────────

    async def get_device(self, device_id: uuid.UUID, *, scope: Scope | None = None) -> Device:
        device = (
            await self.session.execute(select(Device).where(Device.id == device_id))
        ).scalar_one_or_none()
        if device is None:
            raise NotFoundError("Device not found.")

        if scope is not None and not await self._scope_allows(device, scope):
            # Deliberately "not found", not "forbidden": telling a caller a device
            # exists but is out of their scope is itself a disclosure.
            raise NotFoundError("Device not found.")
        return device

    async def list_devices(
        self,
        *,
        scope: Scope,
        search: str | None = None,
        vendor: Vendor | None = None,
        platform: str | None = None,
        device_class: DeviceClass | None = None,
        criticality: Criticality | None = None,
        status: DeviceStatus | None = None,
        site_id: uuid.UUID | None = None,
        group_id: uuid.UUID | None = None,
        tag: str | None = None,
        limit: int = 50,
        offset: int = 0,
        org_id: int = 1,
    ) -> tuple[Sequence[Device], int]:
        stmt: Select[tuple[Device]] = select(Device).where(Device.org_id == org_id)

        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(
                or_(
                    Device.hostname.ilike(pattern),
                    Device.fqdn.ilike(pattern),
                    Device.serial_number.ilike(pattern),
                    func.text(Device.mgmt_ip).ilike(pattern),
                )
            )
        if vendor is not None:
            stmt = stmt.where(Device.vendor == vendor.value)
        if platform is not None:
            stmt = stmt.where(Device.platform == platform)
        if device_class is not None:
            stmt = stmt.where(Device.device_class == device_class.value)
        if criticality is not None:
            stmt = stmt.where(Device.criticality == criticality.value)
        if status is not None:
            stmt = stmt.where(Device.status == status.value)
        if site_id is not None:
            stmt = stmt.where(Device.site_id == site_id)

        if group_id is not None:
            stmt = stmt.where(Device.id.in_(await self._device_ids_in_subtree(group_id)))
        if tag is not None:
            stmt = stmt.where(
                Device.id.in_(
                    select(DeviceTag.device_id)
                    .join(Tag, Tag.id == DeviceTag.tag_id)
                    .where(Tag.name == tag)
                )
            )

        stmt = await self._apply_scope(stmt, scope)

        total = int(
            (
                await self.session.execute(select(func.count()).select_from(stmt.subquery()))
            ).scalar_one()
        )
        rows = (
            (
                await self.session.execute(
                    stmt.order_by(Device.hostname, Device.mgmt_ip).limit(limit).offset(offset)
                )
            )
            .scalars()
            .all()
        )
        return rows, total

    async def create_device(
        self,
        *,
        mgmt_ip: str,
        actor: Principal,
        hostname: str | None = None,
        fqdn: str | None = None,
        vendor: Vendor = Vendor.UNKNOWN,
        platform: str | None = None,
        device_class: DeviceClass = DeviceClass.UNKNOWN,
        site_id: uuid.UUID | None = None,
        criticality: Criticality = Criticality.MEDIUM,
        group_ids: Iterable[uuid.UUID] = (),
        tags: Iterable[str] = (),
        notes: str | None = None,
        org_id: int = 1,
        **extra: Any,
    ) -> Device:
        self._validate_ip(mgmt_ip)
        await self._assert_ip_free(mgmt_ip, org_id)
        if platform:
            self._validate_platform(platform)

        device = Device(
            org_id=org_id,
            mgmt_ip=mgmt_ip,
            hostname=hostname,
            fqdn=fqdn,
            vendor=vendor.value,
            platform=platform,
            device_class=device_class.value,
            site_id=site_id,
            criticality=criticality.value,
            notes=notes,
            **extra,
        )
        self.session.add(device)
        await self.session.flush()

        await self._set_groups(device, group_ids)
        await self._set_tags(device, tags, org_id)
        await self.session.flush()
        await self.session.refresh(device)

        await self.audit.record(
            AuditAction.DEVICE_CREATED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="device",
            object_id=device.id,
            device_id=device.id,
            details={"mgmt_ip": mgmt_ip, "hostname": hostname, "vendor": vendor.value},
        )
        return device

    async def update_device(
        self,
        device: Device,
        *,
        actor: Principal,
        group_ids: Iterable[uuid.UUID] | None = None,
        tags: Iterable[str] | None = None,
        **fields: Any,
    ) -> Device:
        changes: dict[str, Any] = {}

        for name, value in fields.items():
            if value is None or not hasattr(device, name):
                continue
            current = getattr(device, name)
            new = value.value if hasattr(value, "value") else value

            if name == "mgmt_ip" and str(new) != str(current):
                self._validate_ip(str(new))
                await self._assert_ip_free(str(new), device.org_id, exclude_id=device.id)
            if name == "platform" and new:
                self._validate_platform(str(new))

            if str(new) != str(current):
                changes[name] = {"from": str(current), "to": str(new)}
                setattr(device, name, new)

        if group_ids is not None:
            await self._set_groups(device, group_ids)
            changes["groups"] = sorted(str(g) for g in group_ids)
        if tags is not None:
            await self._set_tags(device, tags, device.org_id)
            changes["tags"] = sorted(tags)

        if changes:
            await self.session.flush()
            await self.session.refresh(device)
            await self.audit.record(
                AuditAction.DEVICE_UPDATED,
                actor_id=actor.id,
                actor_username=actor.username,
                object_type="device",
                object_id=device.id,
                device_id=device.id,
                details={"changes": changes},
            )
        return device

    async def archive_device(self, device: Device, *, actor: Principal) -> Device:
        """Archiving keeps history; deleting destroys it. Prefer archiving."""
        device.status = DeviceStatus.ARCHIVED.value
        await self.session.flush()

        await self.audit.record(
            AuditAction.DEVICE_UPDATED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="device",
            object_id=device.id,
            device_id=device.id,
            details={"archived": True},
        )
        return device

    async def delete_device(self, device: Device, *, actor: Principal) -> None:
        mgmt_ip, device_id = str(device.mgmt_ip), device.id
        await self.session.delete(device)
        await self.session.flush()

        await self.audit.record(
            AuditAction.DEVICE_DELETED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="device",
            object_id=device_id,
            details={"mgmt_ip": mgmt_ip},
        )

    async def record_facts(self, device: Device, facts: dict[str, Any]) -> Device:
        """Refresh device facts after a successful collection (FR-INV-05)."""
        from datetime import UTC, datetime

        device.facts = {**device.facts, **facts}
        for column, key in (
            ("hostname", "hostname"),
            ("serial_number", "serial"),
            ("os_version", "version"),
            ("model", "model"),
        ):
            if value := facts.get(key):
                setattr(device, column, str(value))

        device.last_collected_at = datetime.now(UTC)
        device.last_seen_at = device.last_collected_at
        await self.session.flush()
        return device

    # ──────────────────────────── device groups ─────────────────────────

    async def create_group(
        self,
        *,
        name: str,
        actor: Principal,
        parent_id: uuid.UUID | None = None,
        description: str | None = None,
        org_id: int = 1,
    ) -> DeviceGroup:
        parent = await self.get_group(parent_id) if parent_id else None

        group = DeviceGroup(
            org_id=org_id,
            name=name,
            description=description,
            parent_id=parent_id,
            path="pending",  # replaced below: the path is built from the row's own id
        )
        self.session.add(group)
        await self.session.flush()

        group.path = self._path_for(group, parent)
        await self.session.flush()

        await self.audit.record(
            AuditAction.DEVICE_UPDATED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="device_group",
            object_id=group.id,
            details={"created": name, "parent_id": str(parent_id) if parent_id else None},
        )
        return group

    async def get_group(self, group_id: uuid.UUID) -> DeviceGroup:
        group = (
            await self.session.execute(select(DeviceGroup).where(DeviceGroup.id == group_id))
        ).scalar_one_or_none()
        if group is None:
            raise NotFoundError("Device group not found.")
        return group

    async def list_groups(self, *, org_id: int = 1) -> Sequence[DeviceGroup]:
        return (
            (
                await self.session.execute(
                    select(DeviceGroup)
                    .where(DeviceGroup.org_id == org_id)
                    .order_by(DeviceGroup.path)
                )
            )
            .scalars()
            .all()
        )

    async def move_group(
        self, group: DeviceGroup, *, new_parent_id: uuid.UUID | None, actor: Principal
    ) -> DeviceGroup:
        """Re-parent a group and rewrite its subtree's paths.

        Every descendant's path embeds its ancestors, so a move is not a single-row
        update. Doing it anywhere but here would leave paths silently inconsistent and
        break scope checks in a way no error message would explain.
        """
        if new_parent_id == group.id:
            raise ValidationProblem("A group cannot be its own parent.")

        new_parent = await self.get_group(new_parent_id) if new_parent_id else None
        if new_parent is not None and new_parent.path.startswith(f"{group.path}."):
            raise ValidationProblem("A group cannot be moved beneath its own descendant.")

        old_path = group.path
        group.parent_id = new_parent_id
        group.path = self._path_for(group, new_parent)

        descendants = (
            (
                await self.session.execute(
                    select(DeviceGroup).where(DeviceGroup.path.op("<@")(old_path))
                )
            )
            .scalars()
            .all()
        )
        for descendant in descendants:
            if descendant.id == group.id:
                continue
            descendant.path = group.path + descendant.path[len(old_path) :]

        await self.session.flush()
        await self.audit.record(
            AuditAction.DEVICE_UPDATED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="device_group",
            object_id=group.id,
            details={"moved": {"from": old_path, "to": group.path}},
        )
        return group

    @staticmethod
    def _path_for(group: DeviceGroup, parent: DeviceGroup | None) -> str:
        label = DeviceGroup.label_for(group.id)
        return f"{parent.path}.{label}" if parent else label

    async def _device_ids_in_subtree(self, group_id: uuid.UUID) -> Select[tuple[uuid.UUID]]:
        """Devices in a group or any group beneath it."""
        group = await self.get_group(group_id)
        return select(DeviceGroupMember.device_id).where(
            DeviceGroupMember.group_id.in_(
                select(DeviceGroup.id).where(DeviceGroup.path.op("<@")(group.path))
            )
        )

    # ──────────────────────────── sites and tags ────────────────────────

    async def create_site(
        self,
        *,
        name: str,
        actor: Principal,
        description: str | None = None,
        location: str | None = None,
        org_id: int = 1,
    ) -> Site:
        existing = (
            await self.session.execute(select(Site).where(Site.org_id == org_id, Site.name == name))
        ).scalar_one_or_none()
        if existing is not None:
            raise ConflictError(f"A site named '{name}' already exists.")

        site = Site(org_id=org_id, name=name, description=description, location=location)
        self.session.add(site)
        await self.session.flush()
        return site

    async def list_sites(self, *, org_id: int = 1) -> Sequence[Site]:
        return (
            (
                await self.session.execute(
                    select(Site).where(Site.org_id == org_id).order_by(Site.name)
                )
            )
            .scalars()
            .all()
        )

    async def list_tags(self, *, org_id: int = 1) -> Sequence[Tag]:
        return (
            (await self.session.execute(select(Tag).where(Tag.org_id == org_id).order_by(Tag.name)))
            .scalars()
            .all()
        )

    # ───────────────────────────── CSV import ───────────────────────────

    async def preview_import(self, content: str, *, org_id: int = 1) -> ImportPreview:
        """Validate a CSV without writing anything (FR-INV-02).

        Import is all-or-nothing on validity: a half-imported inventory is worse than a
        rejected one, because nobody knows which half.
        """
        try:
            reader = csv.DictReader(io.StringIO(content))
            fieldnames = reader.fieldnames or []
        except csv.Error as exc:
            raise ValidationProblem(f"The file is not valid CSV: {exc}") from exc

        if "mgmt_ip" not in fieldnames:
            raise ValidationProblem(
                "The CSV must have a 'mgmt_ip' column.", expected_columns=list(CSV_COLUMNS)
            )

        rows: builtins.list[ImportRow] = []
        seen_ips: set[str] = set()

        for line, raw in enumerate(reader, start=2):  # line 1 is the header
            data = {k: (v or "").strip() for k, v in raw.items() if k}
            row = ImportRow(line=line, data=data)

            mgmt_ip = data.get("mgmt_ip", "")
            if not mgmt_ip:
                row.errors.append("mgmt_ip is required")
            else:
                valid_ip = True
                try:
                    ipaddress.ip_address(mgmt_ip)
                except ValueError:
                    row.errors.append(f"'{mgmt_ip}' is not a valid IP address")
                    valid_ip = False

                if mgmt_ip in seen_ips:
                    row.errors.append("duplicate mgmt_ip within this file")
                seen_ips.add(mgmt_ip)

                # Only look the device up once the value is known to be an IP: the
                # column is INET, and the driver rejects a malformed parameter before
                # the query runs — turning a reportable row error into a 500.
                if valid_ip:
                    existing = (
                        await self.session.execute(
                            select(Device).where(Device.org_id == org_id, Device.mgmt_ip == mgmt_ip)
                        )
                    ).scalar_one_or_none()
                    if existing is not None:
                        row.existing_id = existing.id

            self._validate_enum(row, "vendor", Vendor)
            self._validate_enum(row, "device_class", DeviceClass)
            self._validate_enum(row, "criticality", Criticality)

            if platform := data.get("platform"):
                try:
                    self._validate_platform(platform)
                except ValidationProblem as exc:
                    row.errors.append(str(exc))

            rows.append(row)

        if not rows:
            raise ValidationProblem("The CSV contained no data rows.")

        return ImportPreview(rows=rows)

    async def apply_import(
        self, preview: ImportPreview, *, actor: Principal, org_id: int = 1
    ) -> dict[str, int]:
        if not preview.ok:
            raise ValidationProblem(
                "The import has validation errors; nothing was written.",
                invalid_rows=preview.invalid,
            )

        created = updated = 0

        for row in preview.rows:
            data = row.data
            site_id = await self._site_id_for(data.get("site"), org_id)
            groups = await self._group_ids_for(data.get("groups"), org_id)
            tags = [t.strip() for t in (data.get("tags") or "").split("|") if t.strip()]

            common: dict[str, Any] = {
                "hostname": data.get("hostname") or None,
                "vendor": Vendor(data["vendor"]) if data.get("vendor") else Vendor.UNKNOWN,
                "platform": data.get("platform") or None,
                "device_class": (
                    DeviceClass(data["device_class"])
                    if data.get("device_class")
                    else DeviceClass.UNKNOWN
                ),
                "criticality": (
                    Criticality(data["criticality"])
                    if data.get("criticality")
                    else Criticality.MEDIUM
                ),
                "site_id": site_id,
                "notes": data.get("notes") or None,
            }

            if row.existing_id is not None:
                device = await self.get_device(row.existing_id)
                await self.update_device(device, actor=actor, group_ids=groups, tags=tags, **common)
                updated += 1
            else:
                await self.create_device(
                    mgmt_ip=data["mgmt_ip"],
                    actor=actor,
                    group_ids=groups,
                    tags=tags,
                    org_id=org_id,
                    **common,
                )
                created += 1

        log.info("inventory.import_applied", created=created, updated=updated)
        return {"created": created, "updated": updated}

    @staticmethod
    def _validate_enum(row: ImportRow, column: str, enum: type[StrEnum]) -> None:
        value = row.data.get(column)
        if not value:
            return
        allowed = sorted(member.value for member in enum)
        if value not in allowed:
            row.errors.append(f"{column} '{value}' is not one of: {', '.join(allowed)}")

    async def _site_id_for(self, name: str | None, org_id: int) -> uuid.UUID | None:
        if not name:
            return None
        site = (
            await self.session.execute(select(Site).where(Site.org_id == org_id, Site.name == name))
        ).scalar_one_or_none()
        if site is None:
            site = Site(org_id=org_id, name=name)
            self.session.add(site)
            await self.session.flush()
        return site.id

    async def _group_ids_for(self, raw: str | None, org_id: int) -> builtins.list[uuid.UUID]:
        """Resolve ``A|B`` group names, creating any that do not exist yet."""
        names = [n.strip() for n in (raw or "").split("|") if n.strip()]
        ids: builtins.list[uuid.UUID] = []

        for name in names:
            group = (
                await self.session.execute(
                    select(DeviceGroup).where(
                        DeviceGroup.org_id == org_id,
                        DeviceGroup.name == name,
                        DeviceGroup.parent_id.is_(None),
                    )
                )
            ).scalar_one_or_none()

            if group is None:
                group = DeviceGroup(org_id=org_id, name=name, path="pending")
                self.session.add(group)
                await self.session.flush()
                group.path = DeviceGroup.label_for(group.id)
                await self.session.flush()

            ids.append(group.id)
        return ids

    # ────────────────────────────── helpers ─────────────────────────────

    async def _apply_scope(
        self, stmt: Select[tuple[Device]], scope: Scope
    ) -> Select[tuple[Device]]:
        """Restrict a device query to the groups a principal may see (FR-AUTH-05)."""
        if scope.unrestricted:
            return stmt
        if not scope.device_group_ids:
            # A group-scoped principal with no groups sees nothing, rather than
            # everything — failing closed is the only safe reading.
            return stmt.where(false())

        paths = (
            (
                await self.session.execute(
                    select(DeviceGroup.path).where(DeviceGroup.id.in_(list(scope.device_group_ids)))
                )
            )
            .scalars()
            .all()
        )
        if not paths:
            return stmt.where(false())

        visible_groups = select(DeviceGroup.id).where(
            or_(*[DeviceGroup.path.op("<@")(path) for path in paths])
        )
        return stmt.where(
            Device.id.in_(
                select(DeviceGroupMember.device_id).where(
                    DeviceGroupMember.group_id.in_(visible_groups)
                )
            )
        )

    async def visible_device_ids(self, scope: Scope) -> list[uuid.UUID]:
        """Every device id a principal may see (FR-AUTH-05).

        For queries over objects that hang off a device — findings, check results —
        which need the same restriction but are not device rows themselves. Scoping is
        applied here rather than by each caller so there is one implementation of the
        group hierarchy walk to get wrong.
        """
        stmt = await self._apply_scope(select(Device), scope)
        return list((await self.session.execute(stmt.with_only_columns(Device.id))).scalars().all())

    async def _scope_allows(self, device: Device, scope: Scope) -> bool:
        if scope.unrestricted:
            return True
        stmt = await self._apply_scope(select(Device).where(Device.id == device.id), scope)
        return (await self.session.execute(stmt)).scalar_one_or_none() is not None

    async def _set_groups(self, device: Device, group_ids: Iterable[uuid.UUID]) -> None:
        wanted = set(group_ids)

        # Queried rather than read from device.groups: on a freshly flushed row the
        # relationship is unloaded, and touching it would emit lazy IO mid-transaction.
        current = (
            (
                await self.session.execute(
                    select(DeviceGroupMember).where(DeviceGroupMember.device_id == device.id)
                )
            )
            .scalars()
            .all()
        )
        existing = {m.group_id for m in current}

        for member in [m for m in current if m.group_id not in wanted]:
            await self.session.delete(member)
        for group_id in wanted - existing:
            await self.get_group(group_id)  # 404s rather than a foreign-key error
            self.session.add(
                DeviceGroupMember(org_id=device.org_id, device_id=device.id, group_id=group_id)
            )

    async def _set_tags(self, device: Device, names: Iterable[str], org_id: int) -> None:
        wanted = {n.strip() for n in names if n.strip()}

        current_rows = (
            (
                await self.session.execute(
                    select(Tag)
                    .join(DeviceTag, DeviceTag.tag_id == Tag.id)
                    .where(DeviceTag.device_id == device.id)
                )
            )
            .scalars()
            .all()
        )
        current = {t.name: t for t in current_rows}

        for name, tag in current.items():
            if name not in wanted:
                link = (
                    await self.session.execute(
                        select(DeviceTag).where(
                            DeviceTag.device_id == device.id, DeviceTag.tag_id == tag.id
                        )
                    )
                ).scalar_one_or_none()
                if link is not None:
                    await self.session.delete(link)

        for name in wanted - set(current):
            # Tags are created on first use rather than requiring a separate step: an
            # operator adding "dmz" to a device means the tag to exist.
            existing_tag = (
                await self.session.execute(
                    select(Tag).where(Tag.org_id == org_id, Tag.name == name)
                )
            ).scalar_one_or_none()

            if existing_tag is None:
                existing_tag = Tag(org_id=org_id, name=name)
                self.session.add(existing_tag)
                await self.session.flush()

            self.session.add(DeviceTag(org_id=org_id, device_id=device.id, tag_id=existing_tag.id))

    @staticmethod
    def _validate_ip(value: str) -> None:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValidationProblem(f"'{value}' is not a valid IP address.") from exc

    @staticmethod
    def _validate_platform(platform: str) -> None:
        """Reject a platform this installation cannot actually do anything with.

        A device we cannot describe is a device we must not touch (SRS §8.1), and
        catching it at creation is far kinder than failing mid-collection — which is what
        this used to do for five of the platforms it accepted. It checked only that a
        read-only *policy* existed, and a policy is the narrowest of the three things a
        platform needs: an allow-list says what may be sent, a collection profile says
        what to send, and a parser says how to read the answer.

        `cisco_iosxr`, `cisco_ftd_fmc` and `linux_aaa` had the first and neither of the
        others, so a device onboarded as one of them passed validation and then failed
        at its first collection. `checkpoint_gaia_expert` and `linux_aaa_sudo` are not
        platforms at all — they are per-device escapes derived from
        `Device.policy_platform`, and setting one directly produces a device whose base
        platform is a policy key.

        Manager platforms are the exception and are accepted: a FortiManager is
        enumerated for the devices it manages rather than collected from, so it has no
        collection profile by design.
        """
        from netsecops.adapters.children import INTERPRETERS
        from netsecops.adapters.policies import POLICIES
        from netsecops.adapters.profiles import PROFILES

        if platform not in POLICIES:
            raise ValidationProblem(
                f"Unknown platform '{platform}'. No read-only policy is defined for it.",
                known_platforms=sorted(POLICIES),
            )

        usable = sorted(set(PROFILES) | set(INTERPRETERS))
        if platform not in usable:
            raise ValidationProblem(
                f"'{platform}' has a read-only policy but nothing that can collect from "
                "it: no collection profile and no manager enumerator. A device set to it "
                "would pass validation here and fail at its first collection.",
                known_platforms=usable,
            )

    async def _assert_ip_free(
        self, mgmt_ip: str, org_id: int, *, exclude_id: uuid.UUID | None = None
    ) -> None:
        stmt = select(Device).where(Device.org_id == org_id, Device.mgmt_ip == mgmt_ip)
        if exclude_id is not None:
            stmt = stmt.where(Device.id != exclude_id)
        if (await self.session.execute(stmt)).scalar_one_or_none() is not None:
            raise ConflictError(f"A device with management IP {mgmt_ip} already exists.")
