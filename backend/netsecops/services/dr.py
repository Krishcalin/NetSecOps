"""Disaster-recovery sets: CRUD, and the HA-fact resolver that suggests them.

The suggestions are the interesting half. A device's parsed configuration records its HA
peer as a string — a hostname or an address it was told to replicate — and this service
resolves that string against the rest of the inventory to *propose* a set. It never
creates one: the string is self-reported and the match is by name, and collapsing two
devices that are not actually a pair would hide a real second firewall from every path
walk. A person confirms the pairing; the resolver only saves them the discovery.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ConflictError, NotFoundError, ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.db.models.dr import DrRole, DrSet, DrSetMember
from netsecops.db.models.inventory import Device, DeviceStatus
from netsecops.schemas.dr import (
    DrMemberInput,
    DrMemberRead,
    DrSetRead,
    DrSuggestionMember,
    DrSuggestionRead,
)

log = get_logger(__name__)

#: HA role strings, lower-cased, that mean "this device is the one carrying traffic".
#: Vendors disagree on the word, so the set is generous; anything outside it is treated
#: as a standby for the purpose of a *suggestion*, which a person then confirms.
_PRIMARY_ROLE_WORDS = frozenset({"active", "primary", "master", "primary-active"})


class DrService:
    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id

    # ── reads ───────────────────────────────────────────────────────────────

    async def list_sets(self) -> list[DrSetRead]:
        rows = await self.session.execute(
            select(DrSet).where(DrSet.org_id == self.org_id).order_by(DrSet.name)
        )
        sets = list(rows.scalars().all())
        names = await self._hostnames({m.device_id for s in sets for m in s.members})
        return [self._to_read(s, names) for s in sets]

    async def get_set(self, dr_set_id: uuid.UUID) -> DrSetRead:
        found = await self._require(dr_set_id)
        names = await self._hostnames({m.device_id for m in found.members})
        return self._to_read(found, names)

    async def _require(self, dr_set_id: uuid.UUID) -> DrSet:
        found = await self.session.get(DrSet, dr_set_id)
        if found is None or found.org_id != self.org_id:
            raise NotFoundError(f"No DR set {dr_set_id}.")
        return found

    # ── writes ──────────────────────────────────────────────────────────────

    async def create_set(
        self, *, name: str, members: list[DrMemberInput], description: str | None = None
    ) -> DrSetRead:
        primaries = [m for m in members if m.role is DrRole.PRIMARY]
        if len(primaries) != 1:
            raise ValidationProblem(
                "A DR set has exactly one primary. The logical device is built from the "
                "primary's configuration, so a set with none has nothing to analyse and "
                f"one with two is ambiguous. This set names {len(primaries)}."
            )

        device_ids = [m.device_id for m in members]
        if len(set(device_ids)) != len(device_ids):
            raise ValidationProblem("A device appears more than once in this DR set.")

        known = await self._devices(device_ids)
        missing = [str(d) for d in device_ids if d not in known]
        if missing:
            raise NotFoundError(f"No such device(s) in this organisation: {', '.join(missing)}.")

        await self._assert_unattached(device_ids)

        if await self._name_taken(name):
            raise ConflictError(
                f"A DR set called {name!r} already exists. Names are how a set is "
                "referred to in reports, so two with one name would be ambiguous."
            )

        dr_set = DrSet(org_id=self.org_id, name=name, description=description)
        dr_set.members = [
            DrSetMember(org_id=self.org_id, device_id=m.device_id, role=m.role.value)
            for m in members
        ]
        self.session.add(dr_set)
        await self.session.flush()

        names = {d.id: d.hostname for d in known.values()}
        return self._to_read(dr_set, names)

    async def delete_set(self, dr_set_id: uuid.UUID) -> DrSetRead:
        found = await self._require(dr_set_id)
        names = await self._hostnames({m.device_id for m in found.members})
        read = self._to_read(found, names)
        await self.session.delete(found)
        await self.session.flush()
        return read

    # ── suggestions from HA facts ─────────────────────────────────────────────

    async def suggestions(self) -> list[DrSuggestionRead]:
        rows = await self.session.execute(
            select(Device.id, Device.hostname, Device.mgmt_ip, Device.facts).where(
                Device.org_id == self.org_id,
                Device.status != DeviceStatus.ARCHIVED.value,
            )
        )
        devices = list(rows.all())

        by_name: dict[str, uuid.UUID] = {}
        role_of: dict[uuid.UUID, str] = {}
        hostname_of: dict[uuid.UUID, str | None] = {}
        for device_id, hostname, mgmt_ip, facts in devices:
            hostname_of[device_id] = hostname
            ha = (facts or {}).get("ha") or {}
            role_of[device_id] = str(ha.get("role") or "").strip().lower()
            if hostname:
                lowered = hostname.strip().lower()
                by_name.setdefault(lowered, device_id)
                by_name.setdefault(lowered.split(".", 1)[0], device_id)
            if mgmt_ip:
                by_name.setdefault(str(mgmt_ip), device_id)

        attached = await self._attached_device_ids()

        suggestions: list[DrSuggestionRead] = []
        seen: set[frozenset[uuid.UUID]] = set()
        for device_id, _hostname, _mgmt, facts in devices:
            if device_id in attached:
                continue
            ha = (facts or {}).get("ha") or {}
            if not ha.get("enabled"):
                continue
            peer = str(ha.get("peer") or "").strip()
            if not peer:
                continue
            peer_id, how = _resolve(peer, by_name)
            if peer_id is None or peer_id == device_id or peer_id in attached:
                continue
            pair = frozenset({device_id, peer_id})
            if pair in seen:
                continue
            seen.add(pair)
            suggestions.append(
                self._suggest(device_id, peer_id, peer, how, role_of, hostname_of)
            )
        return suggestions

    def _suggest(
        self,
        reporter_id: uuid.UUID,
        peer_id: uuid.UUID,
        peer_string: str,
        how: str,
        role_of: dict[uuid.UUID, str],
        hostname_of: dict[uuid.UUID, str | None],
    ) -> DrSuggestionRead:
        # Whichever device calls itself active/primary is the primary. If neither does,
        # the reporting device is proposed as primary and the reason says the guess is
        # the person's to settle.
        if role_of.get(reporter_id) in _PRIMARY_ROLE_WORDS:
            primary_id, standby_id = reporter_id, peer_id
            basis = f"{_name(reporter_id, hostname_of)} reports HA role active"
        elif role_of.get(peer_id) in _PRIMARY_ROLE_WORDS:
            primary_id, standby_id = peer_id, reporter_id
            basis = f"{_name(peer_id, hostname_of)} reports HA role active"
        else:
            primary_id, standby_id = reporter_id, peer_id
            basis = "neither device reports an active role, so the primary is a guess"

        reason = (
            f"{_name(reporter_id, hostname_of)} reports HA peer {peer_string!r}, "
            f"matched to {_name(peer_id, hostname_of)} by {how}; {basis}."
        )
        return DrSuggestionRead(
            members=[
                DrSuggestionMember(
                    device_id=primary_id,
                    hostname=hostname_of.get(primary_id),
                    role=DrRole.PRIMARY.value,
                ),
                DrSuggestionMember(
                    device_id=standby_id,
                    hostname=hostname_of.get(standby_id),
                    role=DrRole.STANDBY.value,
                ),
            ],
            reason=reason,
        )

    # ── helpers ───────────────────────────────────────────────────────────────

    async def _devices(self, device_ids: list[uuid.UUID]) -> dict[uuid.UUID, Device]:
        rows = await self.session.execute(
            select(Device).where(Device.org_id == self.org_id, Device.id.in_(device_ids))
        )
        return {d.id: d for d in rows.scalars().all()}

    async def _hostnames(self, device_ids: set[uuid.UUID]) -> dict[uuid.UUID, str | None]:
        if not device_ids:
            return {}
        rows = await self.session.execute(
            select(Device.id, Device.hostname).where(Device.id.in_(device_ids))
        )
        return {device_id: hostname for device_id, hostname in rows.all()}

    async def _assert_unattached(self, device_ids: list[uuid.UUID]) -> None:
        rows = await self.session.execute(
            select(DrSetMember.device_id).where(DrSetMember.device_id.in_(device_ids))
        )
        taken = [str(row[0]) for row in rows.all()]
        if taken:
            raise ConflictError(
                "These devices already belong to a DR set, and a device can be in only "
                f"one: {', '.join(taken)}. Remove them from the other set first."
            )

    async def _attached_device_ids(self) -> set[uuid.UUID]:
        rows = await self.session.execute(select(DrSetMember.device_id))
        return {row[0] for row in rows.all()}

    async def _name_taken(self, name: str) -> bool:
        rows = await self.session.execute(
            select(DrSet.id).where(DrSet.org_id == self.org_id, DrSet.name == name)
        )
        return rows.first() is not None

    @staticmethod
    def _to_read(dr_set: DrSet, names: dict[uuid.UUID, str | None]) -> DrSetRead:
        return DrSetRead(
            id=dr_set.id,
            name=dr_set.name,
            description=dr_set.description,
            members=[
                DrMemberRead(
                    device_id=m.device_id, hostname=names.get(m.device_id), role=m.role
                )
                # Primary first, then standbys by id for a stable order.
                for m in sorted(
                    dr_set.members, key=lambda m: (m.role != DrRole.PRIMARY.value, str(m.device_id))
                )
            ],
        )


def _resolve(peer: str, by_name: dict[str, uuid.UUID]) -> tuple[uuid.UUID | None, str]:
    lowered = peer.strip().lower()
    if (device_id := by_name.get(lowered)) is not None:
        return device_id, "hostname" if not _looks_like_ip(lowered) else "address"
    short = lowered.split(".", 1)[0]
    if (device_id := by_name.get(short)) is not None:
        return device_id, "short hostname"
    return None, ""


def _looks_like_ip(value: str) -> bool:
    return value.replace(".", "").isdigit() or ":" in value


def _name(device_id: uuid.UUID, hostname_of: dict[uuid.UUID, str | None]) -> str:
    return hostname_of.get(device_id) or str(device_id)


__all__ = ["DrService"]
