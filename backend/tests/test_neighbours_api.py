"""A device's CDP/LLDP table, through the API (FR-TOPO-01).

`test_neighbours.py` proves the parsers against vendor output. This proves the layer
between them and the console: that a snapshot's JSON becomes a neighbour list, that each
entry is matched against the *current* inventory rather than the one that existed when
the snapshot was taken, and — the part that carries the weight — that an empty list
arrives with the reason it is empty.

**Why the matching lives here and not in the parser.** What a device said is fixed at
collection time. Whether this estate contains a device by that name changes every time
somebody onboards one, so a match baked into the snapshot would freeze an answer that
should move. The tests below onboard a device *after* the snapshot exists and expect the
neighbour to resolve.

**Why a wrong match is worse than none.** An unresolved neighbour is the edge of the
managed estate, which is a useful thing to see. A neighbour resolved to the wrong device
draws a cable between two boxes that are not connected, confidently — so the ambiguous
short-name case asserts that nothing is matched at all.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.collection import Snapshot
from netsecops.db.models.inventory import DeviceClass, DeviceStatus, Vendor
from netsecops.services.inventory import InventoryService
from tests.conftest import make_user


def url(device_id: uuid.UUID | str) -> str:
    return f"/api/v1/devices/{device_id}/neighbours"


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="neighbour_analyst", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
async def signed_in(session: AsyncSession, authenticate):
    user = await make_user(session, username="neighbour_api", roles={Role.SECURITY_ANALYST})
    await session.commit()
    authenticate(user)
    return user


def entry(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "protocol": "cdp",
        "local_interface": "GigabitEthernet0/1",
        "remote_device": "core-sw01",
        "remote_interface": "GigabitEthernet1/0/24",
        "remote_address": "10.0.0.2",
        "platform": "cisco WS-C3850-24T",
        "capabilities": ["Switch", "IGMP"],
    }
    base.update(over)
    return base


def ncm(
    neighbours: list[dict[str, Any]],
    *,
    cdp: bool | None = True,
    lldp: bool | None = True,
) -> dict[str, Any]:
    return {
        "ncm_version": "1.1",
        "features": {"cdp": cdp, "lldp": lldp},
        "l2": {"neighbours": neighbours},
    }


async def add_device(
    session: AsyncSession,
    actor: Principal,
    *,
    hostname: str,
    mgmt_ip: str,
    ncm_body: dict[str, Any] | None = None,
    status: str = DeviceStatus.ACTIVE.value,
    created_at: dt.datetime | None = None,
):
    device = await InventoryService(session).create_device(
        mgmt_ip=mgmt_ip,
        actor=actor,
        hostname=hostname,
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
        status=status,
    )
    if ncm_body is not None:
        await add_snapshot(session, device.id, ncm_body, created_at=created_at)
    return device


async def add_snapshot(
    session: AsyncSession,
    device_id: uuid.UUID,
    ncm_body: dict[str, Any],
    *,
    created_at: dt.datetime | None = None,
) -> None:
    digest = uuid.uuid4().hex
    snapshot = Snapshot(
        org_id=1,
        device_id=device_id,
        ncm=ncm_body,
        ncm_version="1.1",
        config_hash=digest,
        normalized_hash=digest,
        config_redacted="! switch",
    )
    if created_at is not None:
        snapshot.created_at = created_at
    session.add(snapshot)
    await session.flush()


class TestTheTableReachesTheConsole:
    async def test_entries_are_returned_with_their_protocol(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        device = await add_device(
            session,
            actor,
            hostname="access-sw01",
            mgmt_ip="10.0.0.1",
            ncm_body=ncm([entry(), entry(protocol="lldp", local_interface="Gi0/2")]),
        )
        await session.commit()

        body = (await client.get(url(device.id))).json()

        # Two entries, not one: the protocols are deliberately not merged, because they
        # disagree about the same link often enough that collapsing them loses which
        # one saw what.
        assert len(body["neighbours"]) == 2
        assert {n["protocol"] for n in body["neighbours"]} == {"cdp", "lldp"}

    async def test_the_fields_survive_the_round_trip(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        device = await add_device(
            session, actor, hostname="access-sw01", mgmt_ip="10.0.0.1", ncm_body=ncm([entry()])
        )
        await session.commit()

        found = (await client.get(url(device.id))).json()["neighbours"][0]

        assert found["local_interface"] == "GigabitEthernet0/1"
        assert found["remote_interface"] == "GigabitEthernet1/0/24"
        assert found["platform"] == "cisco WS-C3850-24T"
        assert found["capabilities"] == ["Switch", "IGMP"]

    async def test_only_the_latest_snapshot_is_read(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        # A cable that was moved last month is not where the cable is. The older
        # snapshot's neighbour must not appear alongside the current one.
        old = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
        new = dt.datetime(2026, 6, 1, tzinfo=dt.UTC)
        device = await add_device(
            session,
            actor,
            hostname="access-sw01",
            mgmt_ip="10.0.0.1",
            ncm_body=ncm([entry(remote_device="old-core")]),
            created_at=old,
        )
        await add_snapshot(
            session, device.id, ncm([entry(remote_device="new-core")]), created_at=new
        )
        await session.commit()

        body = (await client.get(url(device.id))).json()

        assert [n["remote_device"] for n in body["neighbours"]] == ["new-core"]


class TestWhyAnEmptyListIsEmpty:
    """The four causes that look identical in a list of none.

    Only one of them means "this device has no neighbours", and reporting the others as
    though they did is this codebase's named failure mode.
    """

    async def test_no_snapshot_reports_no_snapshot(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        device = await add_device(session, actor, hostname="new-sw", mgmt_ip="10.0.0.9")
        await session.commit()

        body = (await client.get(url(device.id))).json()

        # Null, not an error and not an empty-but-collected answer: nothing has been
        # asked of this device, which is different from it having nothing to say.
        assert body["snapshot_id"] is None
        assert body["neighbours"] == []

    async def test_the_protocol_state_is_carried(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        device = await add_device(
            session,
            actor,
            hostname="access-sw01",
            mgmt_ip="10.0.0.1",
            ncm_body=ncm([], cdp=False, lldp=True),
        )
        await session.commit()

        body = (await client.get(url(device.id))).json()

        # "LLDP is on and nothing answered" is a finding on a switch with uplinks.
        # "CDP is off" is not. Without these two fields they are the same empty table.
        assert (body["cdp_enabled"], body["lldp_enabled"]) == (False, True)

    async def test_an_undetermined_protocol_stays_undetermined(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        # Null must not collapse to false. A platform whose configuration does not state
        # the setting would otherwise be reported as having the protocol disabled, which
        # is a claim nobody made.
        device = await add_device(
            session,
            actor,
            hostname="access-sw01",
            mgmt_ip="10.0.0.1",
            ncm_body=ncm([], cdp=None, lldp=None),
        )
        await session.commit()

        body = (await client.get(url(device.id))).json()

        assert (body["cdp_enabled"], body["lldp_enabled"]) == (None, None)

    async def test_a_snapshot_predating_the_commands_is_not_an_error(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        # Every snapshot collected before this slice shipped has no `l2.neighbours` key
        # at all. Reading one must not fail.
        device = await add_device(
            session, actor, hostname="old-sw", mgmt_ip="10.0.0.1", ncm_body={"ncm_version": "1.0"}
        )
        await session.commit()

        response = await client.get(url(device.id))

        assert response.status_code == 200
        assert response.json()["neighbours"] == []


class TestMatchingAgainstTheInventory:
    async def test_a_hostname_match_carries_the_device(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        core = await add_device(session, actor, hostname="core-sw01", mgmt_ip="10.0.0.2")
        device = await add_device(
            session, actor, hostname="access-sw01", mgmt_ip="10.0.0.1", ncm_body=ncm([entry()])
        )
        await session.commit()

        found = (await client.get(url(device.id))).json()["neighbours"][0]

        assert found["device_id"] == str(core.id)
        assert found["matched_by"] == "hostname"

    async def test_an_fqdn_falls_back_to_the_short_name(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        # IOS advertises an FQDN and the inventory frequently holds the short name. This
        # is the common case, not an edge one, and without the fallback almost nothing
        # in a domain-joined estate resolves.
        core = await add_device(session, actor, hostname="core-sw01", mgmt_ip="10.0.0.2")
        device = await add_device(
            session,
            actor,
            hostname="access-sw01",
            mgmt_ip="10.0.0.1",
            ncm_body=ncm([entry(remote_device="core-sw01.example.local")]),
        )
        await session.commit()

        found = (await client.get(url(device.id))).json()["neighbours"][0]

        assert found["device_id"] == str(core.id)
        assert found["matched_by"] == "short-hostname"

    async def test_an_ambiguous_short_name_matches_nothing(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        # Two sites both running a `core-sw01`. Resolving to whichever sorted first
        # draws a cable between two boxes in different buildings — a wrong answer given
        # confidently, which is worse than an unmanaged one that asks a human.
        await add_device(session, actor, hostname="core-sw01.site-a", mgmt_ip="10.0.0.2")
        await add_device(session, actor, hostname="core-sw01.site-b", mgmt_ip="10.0.0.3")
        device = await add_device(
            session,
            actor,
            hostname="access-sw01",
            mgmt_ip="10.0.0.1",
            ncm_body=ncm([entry(remote_device="core-sw01.site-c", remote_address=None)]),
        )
        await session.commit()

        found = (await client.get(url(device.id))).json()["neighbours"][0]

        assert found["device_id"] is None
        assert found["matched_by"] is None

    async def test_an_address_match_when_the_name_is_unknown(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        # NX-OS device IDs carry a chassis serial and some devices advertise no name at
        # all. The management address is the last resort, and it is a weaker claim —
        # which is why `matched_by` says which one was used.
        core = await add_device(session, actor, hostname="core-sw01", mgmt_ip="10.0.0.2")
        device = await add_device(
            session,
            actor,
            hostname="access-sw01",
            mgmt_ip="10.0.0.1",
            ncm_body=ncm([entry(remote_device=None)]),
        )
        await session.commit()

        found = (await client.get(url(device.id))).json()["neighbours"][0]

        assert found["device_id"] == str(core.id)
        assert found["matched_by"] == "address"

    async def test_matching_follows_the_inventory_not_the_snapshot(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        # The snapshot is taken first and the neighbour is onboarded afterwards. A match
        # computed at parse time and stored would still report this as unmanaged.
        device = await add_device(
            session, actor, hostname="access-sw01", mgmt_ip="10.0.0.1", ncm_body=ncm([entry()])
        )
        await session.commit()
        assert (await client.get(url(device.id))).json()["neighbours"][0]["device_id"] is None

        core = await add_device(session, actor, hostname="core-sw01", mgmt_ip="10.0.0.2")
        await session.commit()

        found = (await client.get(url(device.id))).json()["neighbours"][0]
        assert found["device_id"] == str(core.id)

    async def test_an_archived_device_is_not_matched(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        # Decommissioned hardware is not part of the estate. Matching to it would draw
        # the current network through a box that has been removed from the rack — the
        # same exclusion the graph makes, for the same reason.
        await add_device(
            session,
            actor,
            hostname="core-sw01",
            mgmt_ip="10.0.0.2",
            status=DeviceStatus.ARCHIVED.value,
        )
        device = await add_device(
            session, actor, hostname="access-sw01", mgmt_ip="10.0.0.1", ncm_body=ncm([entry()])
        )
        await session.commit()

        found = (await client.get(url(device.id))).json()["neighbours"][0]

        assert found["device_id"] is None

    async def test_the_counts_split_managed_from_not(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        await add_device(session, actor, hostname="core-sw01", mgmt_ip="10.0.0.2")
        device = await add_device(
            session,
            actor,
            hostname="access-sw01",
            mgmt_ip="10.0.0.1",
            ncm_body=ncm(
                [
                    entry(),
                    entry(
                        local_interface="Gi0/5",
                        remote_device="SEP001A2B3C4D5E",
                        remote_address="10.30.10.55",
                    ),
                ]
            ),
        )
        await session.commit()

        body = (await client.get(url(device.id))).json()

        # A phone is not a gap to chase. The split is what lets the console say "4 of 11
        # are managed" without inviting the other seven to be read as a work queue.
        assert (body["matched"], body["unmanaged"]) == (1, 1)
