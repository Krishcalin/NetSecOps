"""Operational command output supplied by upload (FR-COL-11).

**The gap this closes.** `ParseContext.artifact` is read in twelve places across six
parsers: the version, model and serial every CVE match depends on, the protocol-learned
routes the topology graph is built from, ACL hit counts, a controller's access points,
and CDP/LLDP neighbours. None of it is in a running configuration. A live collection
gathers it alongside; an upload could not — so an air-gapped estate, which is precisely
what FR-COL-11 exists for, had every one of those capabilities dead and nothing saying
so. An empty neighbour list on an uploaded switch reads exactly like a switch with CDP
turned off.

Two properties carry this file.

**The allow-list is the gate.** An upload is still this product taking a device's output
into its store, so a filename is not a reason to hold something SRS §8.1 promises is
never gathered. `cat /etc/shadow.txt` is refused on a Cisco device for the same reason
the collector would never send it.

**A configuration that has not changed does not mean nothing has changed.** The snapshot
is de-duplicated on the configuration hash, and supporting output is deliberately not in
that hash — a routing table reconverges on its own, and folding it in would make every
collection of an unchanged device look like drift. The consequence was that re-uploading
a stored configuration *with* a capture attached parsed the neighbours and threw them
away. That is the single most important test here, because it fails silently: the panel
stays empty and the upload reports success.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ValidationProblem
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.collection import Artifact, ArtifactKind
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.services.inventory import InventoryService
from netsecops.services.snapshots import (
    SnapshotService,
    SupportingCapture,
    command_from_filename,
    resolve_supporting_command,
)
from tests.conftest import make_user

CONFIG = """\
hostname access-sw01
!
interface GigabitEthernet0/1
 description uplink
!
line vty 0 4
 transport input ssh
!
"""

CDP = """\
-------------------------
Device ID: core-sw01
Entry address(es):
  IP address: 10.0.0.2
Platform: cisco WS-C3850-24T,  Capabilities: Switch IGMP
Interface: GigabitEthernet0/1,  Port ID (outgoing port): GigabitEthernet1/0/24
Holdtime : 143 sec
"""


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="upload_analyst", roles={Role.SUPER_ADMIN})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
async def signed_in(session: AsyncSession, authenticate):
    user = await make_user(session, username="upload_api", roles={Role.SUPER_ADMIN})
    await session.commit()
    authenticate(user)
    return user


async def make_device(session: AsyncSession, actor: Principal, *, mgmt_ip: str = "10.0.0.1"):
    return await InventoryService(session).create_device(
        mgmt_ip=mgmt_ip,
        actor=actor,
        hostname="access-sw01",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )


def files(config: str = CONFIG, **captures: str) -> list[tuple[str, tuple[str, bytes, str]]]:
    """A multipart body: the configuration, plus a capture per keyword.

    Keyword names carry underscores, which is exactly the spelling an operator gets from
    saving a file on a machine that dislikes spaces — so the tests exercise it rather
    than only the tidy form.
    """
    parts: list[tuple[str, tuple[str, bytes, str]]] = [
        ("file", ("config.txt", config.encode(), "text/plain"))
    ]
    for name, text in captures.items():
        parts.append(("artifacts", (f"{name}.txt", text.encode(), "text/plain")))
    return parts


# ───────────────────────── reading the filename ─────────────────────────


class TestTheFilenameNamesTheCommand:
    @pytest.mark.parametrize(
        "filename",
        [
            "show cdp neighbors detail.txt",
            "show_cdp_neighbors_detail.txt",
            "show cdp neighbors detail.log",
            "show_cdp_neighbors_detail.out",
        ],
    )
    def test_both_spellings_and_the_usual_extensions(self, filename: str) -> None:
        assert resolve_supporting_command(filename, "cisco_ios") == "show cdp neighbors detail"

    def test_hyphens_are_left_alone(self) -> None:
        # `show radius-server`, `show run-config commands` and
        # `get router info routing-table all` are real allow-list entries whose hyphens
        # are part of the command. Treating `-` like `_` breaks every one of them.
        assert resolve_supporting_command("show radius-server.txt", "cisco_nxos") == (
            "show radius-server"
        )

    def test_a_path_is_reduced_to_its_name(self) -> None:
        # Browsers send a bare name, but scripted uploads and some clients send a path.
        assert command_from_filename("captures/sw01/show version.txt")[0] == "show version"

    def test_an_unknown_command_is_refused(self) -> None:
        with pytest.raises(ValidationProblem):
            resolve_supporting_command("show tech-support.txt", "cisco_ios")

    def test_something_that_is_not_a_show_command_is_refused(self) -> None:
        # The allow-list is the gate, not the extension and not the operator's word for
        # it. This is the case that makes the gate worth having.
        with pytest.raises(ValidationProblem):
            resolve_supporting_command("cat /etc/shadow.txt", "cisco_ios")

    def test_a_session_only_command_is_refused(self) -> None:
        # `terminal length 0` sets paging and produces no output. A file claiming to be
        # its result is a mistake, and accepting it would store an artefact that means
        # nothing.
        with pytest.raises(ValidationProblem):
            resolve_supporting_command("terminal length 0.txt", "cisco_ios")

    def test_a_command_approved_for_another_platform_is_refused(self) -> None:
        # `show cdp neighbors detail` is on the IOS and NX-OS lists. `show ap summary`
        # is not on the ASA's, and a per-platform gate is the only one that can say so.
        with pytest.raises(ValidationProblem):
            resolve_supporting_command("show ap summary.txt", "cisco_asa")

    def test_an_unknown_platform_is_a_refusal_not_a_free_pass(self) -> None:
        with pytest.raises(ValidationProblem):
            resolve_supporting_command("show version.txt", "not_a_platform")


# ────────────────────────── through the API ─────────────────────────────


class TestTheUploadCarriesThem:
    async def test_neighbours_reach_the_ncm(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        device = await make_device(session, actor)
        await session.commit()

        response = await client.post(
            f"/api/v1/devices/{device.id}/configs",
            files=files(show_cdp_neighbors_detail=CDP),
        )

        assert response.status_code == 201
        assert response.json()["supporting_commands"] == ["show cdp neighbors detail"]

        neighbours = (await client.get(f"/api/v1/devices/{device.id}/neighbours")).json()
        assert [n["local_interface"] for n in neighbours["neighbours"]] == [
            "GigabitEthernet0/1"
        ]

    async def test_the_configuration_alone_still_works(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        # The whole existing estate uploads this way. Adding an optional field must not
        # make the old call shape a client error.
        device = await make_device(session, actor)
        await session.commit()

        response = await client.post(f"/api/v1/devices/{device.id}/configs", files=files())

        assert response.status_code == 201
        assert response.json()["supporting_commands"] == []

    async def test_a_capture_is_stored_as_its_own_artefact(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        device = await make_device(session, actor)
        await session.commit()

        body = (
            await client.post(
                f"/api/v1/devices/{device.id}/configs",
                files=files(show_cdp_neighbors_detail=CDP),
            )
        ).json()

        rows = (
            (
                await session.execute(
                    select(Artifact).where(Artifact.collection_id == uuid.UUID(body["collection_id"]))
                )
            )
            .scalars()
            .all()
        )

        # Two: the configuration and the capture. The evidence trail has to be able to
        # say which NCM field came from which file.
        assert len(rows) == 2
        capture = next(row for row in rows if row.request_text == "show cdp neighbors detail")
        # UPLOAD, not COMMAND. The output is real and nothing was sent to a device to
        # get it; a trail that cannot tell those apart lets an offline assessment be
        # read as a live one.
        assert capture.kind == ArtifactKind.UPLOAD.value

    async def test_a_misnamed_capture_rejects_the_whole_upload(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        # Refused before anything is stored, so the operator fixes the name and retries
        # rather than being left with a half-ingested collection.
        device = await make_device(session, actor)
        await session.commit()

        response = await client.post(
            f"/api/v1/devices/{device.id}/configs",
            files=files(show_tech_support=CDP),
        )

        assert response.status_code == 422
        assert "show_tech_support.txt" in response.text

    async def test_two_files_claiming_one_command_are_refused(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        # The parser reads one output per command. Taking whichever arrived last would
        # make the result depend on upload order, which nobody can see.
        device = await make_device(session, actor)
        await session.commit()

        response = await client.post(
            f"/api/v1/devices/{device.id}/configs",
            files=[
                ("file", ("config.txt", CONFIG.encode(), "text/plain")),
                ("artifacts", ("show cdp neighbors detail.txt", CDP.encode(), "text/plain")),
                ("artifacts", ("show_cdp_neighbors_detail.txt", CDP.encode(), "text/plain")),
            ],
        )

        assert response.status_code == 422

    async def test_an_empty_capture_is_skipped_not_refused(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        # `show cdp neighbors detail` on a switch with CDP off legitimately returns
        # nothing. Rejecting the upload over it would punish the honest case.
        device = await make_device(session, actor)
        await session.commit()

        response = await client.post(
            f"/api/v1/devices/{device.id}/configs",
            files=files(show_cdp_neighbors_detail="   \n"),
        )

        assert response.status_code == 201
        assert response.json()["supporting_commands"] == []


class TestAnUnchangedConfigurationIsNotUnchangedKnowledge:
    """The trap, and the reason this slice is more than a new form field.

    The snapshot de-duplicates on the configuration hash. Supporting output is not in
    that hash on purpose. So the second upload below has an identical configuration, and
    the naive de-duplication parsed its neighbours and discarded them — reporting
    success while the panel stayed empty.
    """

    async def test_adding_a_capture_to_a_stored_configuration_updates_the_ncm(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        device = await make_device(session, actor)
        await session.commit()

        first = await client.post(f"/api/v1/devices/{device.id}/configs", files=files())
        assert first.json()["deduplicated"] is False

        second = await client.post(
            f"/api/v1/devices/{device.id}/configs",
            files=files(show_cdp_neighbors_detail=CDP),
        )

        # Still the same configuration, so still de-duplicated — that part was right.
        assert second.json()["deduplicated"] is True
        assert second.json()["snapshot_id"] == first.json()["snapshot_id"]

        # And the neighbours are now there, which is the part that was not.
        neighbours = (await client.get(f"/api/v1/devices/{device.id}/neighbours")).json()
        assert len(neighbours["neighbours"]) == 1

    async def test_re_uploading_the_same_pair_changes_nothing_but_the_counter(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        # The other half: the refresh must be conditional. Rewriting the NCM on every
        # identical upload would touch rows nothing changed in.
        device = await make_device(session, actor)
        await session.commit()

        payload: dict[str, Any] = {"files": files(show_cdp_neighbors_detail=CDP)}
        first = (
            await client.post(f"/api/v1/devices/{device.id}/configs", **payload)
        ).json()
        second = (
            await client.post(
                f"/api/v1/devices/{device.id}/configs", files=files(show_cdp_neighbors_detail=CDP)
            )
        ).json()

        assert second["snapshot_id"] == first["snapshot_id"]
        assert second["deduplicated"] is True

        neighbours = (await client.get(f"/api/v1/devices/{device.id}/neighbours")).json()
        # Not two. Appending on every re-upload would double the estate's cabling.
        assert len(neighbours["neighbours"]) == 1


class TestTheServiceContract:
    async def test_a_bad_filename_costs_nothing(
        self, session: AsyncSession, actor: Principal, vault
    ) -> None:
        # Refused before a Collection or an artefact exists. The transaction would roll
        # a later refusal back anyway, so this asserts the ordering in the code rather
        # than the behaviour of the transaction around it: the two come apart the moment
        # anybody calls this service outside a request.
        device = await make_device(session, actor)
        await session.commit()
        service = SnapshotService(session, vault=vault)

        with pytest.raises(ValidationProblem):
            await service.ingest_config(
                device,
                config_text=CONFIG,
                filename="config.txt",
                actor=actor,
                supporting=[SupportingCapture(filename="reload.txt", text="x")],
            )

        assert (
            await session.execute(select(Artifact).where(Artifact.org_id == device.org_id))
        ).first() is None
