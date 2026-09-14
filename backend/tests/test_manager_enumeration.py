"""Manager child enumeration and the approval gate (FR-INV-04, FR-DISC-06).

FR-INV-04 permits a manager to auto-populate the inventory *with user approval*. Almost
everything worth testing here is about taking that seriously:

**The approval has to have teeth.** An imported device lands as `pending_review`, and
that status only means anything because job targeting excludes it.
`test_a_pending_device_is_never_targeted_by_a_job` is the assertion that makes the rest
of this feature honest — without it, importing four hundred firewalls from a Panorama
would put every one of them into the next scheduled job, connecting to devices nobody
chose to assess.

**Nothing is deleted.** A manager that omits a device because of an API error, a
permissions change or a domain filter looks exactly like one that no longer manages it.
Archiving on that basis would drop devices from assessment at the moment the manager is
misbehaving, so a disappearance is surfaced and never acted on.

**Re-enumerating must not duplicate.** Matching prefers the serial number, because it is
the only identifier that survives a device being re-addressed — which is precisely the
event that would otherwise create a second record, a second risk score and a second set
of findings for one box.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.adapters.children import (
    UnsupportedManagerError,
    enumerate_children,
    supports_enumeration,
)
from netsecops.core.errors import ValidationProblem
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device
from netsecops.db.models.inventory import DeviceClass, DeviceStatus, Vendor
from netsecops.services.inventory import InventoryService
from netsecops.services.manager_enumeration import ManagerEnumerationService
from tests.conftest import make_user

FIXTURES = Path(__file__).parent / "fixtures/managers"
PANORAMA = (FIXTURES / "panorama_devices.xml").read_text(encoding="utf-8")
FORTIMANAGER = (FIXTURES / "fortimanager_devices.json").read_text(encoding="utf-8")
CHECKPOINT = (FIXTURES / "checkpoint_gateways.json").read_text(encoding="utf-8")


# ═══════════════════════ reading each manager's shape ════════════════════════


class TestPanorama:
    def test_every_managed_firewall_is_reported(self) -> None:
        children = enumerate_children("panos", PANORAMA)
        assert [c.hostname for c in children] == [
            "fw-branch-london",
            "fw-branch-frankfurt",
            "fw-dc-primary",
            "fw-awaiting-provisioning",
        ]

    def test_identity_and_version_are_carried(self) -> None:
        child = enumerate_children("panos", PANORAMA)[0]

        assert child.serial_number == "001901234501"
        assert child.mgmt_ip == "10.10.1.1"
        assert child.os_version == "11.0.2"
        assert child.model == "PA-460"
        assert child.platform == "panos"
        assert child.vendor == "paloalto"

    def test_a_disconnected_firewall_is_reported_not_filtered(self) -> None:
        """Frequently the interesting one: a firewall that stopped checking in is either
        decommissioned and still racked, or live and unmanaged. Filtering would hide
        exactly that case."""
        children = {c.hostname: c for c in enumerate_children("panos", PANORAMA)}

        assert children["fw-dc-primary"].reachable is False
        assert children["fw-branch-london"].reachable is True

    def test_the_device_group_is_kept(self) -> None:
        """So the import can mirror an estate the operator has already organised."""
        children = {c.hostname: c for c in enumerate_children("panos", PANORAMA)}
        assert children["fw-branch-london"].group == "EMEA-Branches"

    def test_a_firewall_with_no_address_is_still_reported(self) -> None:
        children = {c.hostname: c for c in enumerate_children("panos", PANORAMA)}
        assert children["fw-awaiting-provisioning"].mgmt_ip is None

    def test_malformed_xml_yields_nothing_rather_than_raising(self) -> None:
        """A manager that returned something unreadable must not fail the job it was
        part of."""
        assert enumerate_children("panos", "<response><devices>") == []

    def test_an_entity_expansion_is_refused_rather_than_expanded(self) -> None:
        """A manager's response is attacker-influenced input like any other device
        output, and this runs on a worker with network access to the whole estate."""
        bomb = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE response [<!ENTITY a "xxxxxxxxxx">'
            '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
            "<response><result><devices><entry><hostname>&b;</hostname></entry>"
            "</devices></result></response>"
        )
        assert enumerate_children("panos", bomb) == []


class TestFortiManager:
    def test_every_managed_fortigate_is_reported(self) -> None:
        children = enumerate_children("fortimanager", FORTIMANAGER)
        assert [c.hostname for c in children] == [
            "FGT-branch-oslo",
            "FGT-branch-bergen",
            "FGT-dc-cluster",
        ]

    def test_the_firmware_is_recombined_from_three_integers(self) -> None:
        """`os_ver` 7, `mr` 2, `patch` 5 is FortiOS 7.2.5. Passing `os_ver` through alone
        would give every FortiGate a version of "7", and the vulnerability matcher would
        then match every 7.x advisory against all of them."""
        children = {c.hostname: c for c in enumerate_children("fortimanager", FORTIMANAGER)}

        assert children["FGT-branch-oslo"].os_version == "7.2.5"
        assert children["FGT-branch-bergen"].os_version == "7.0.12"
        assert children["FGT-dc-cluster"].os_version == "7.4.1"

    def test_children_are_fortios_devices_not_fortimanager_ones(self) -> None:
        """The manager's platform is not its children's. Importing them as
        `fortimanager` would apply the wrong checks and the wrong parser."""
        assert all(
            c.platform == "fortios" for c in enumerate_children("fortimanager", FORTIMANAGER)
        )

    def test_connection_status_one_is_up_and_anything_else_is_not(self) -> None:
        children = {c.hostname: c for c in enumerate_children("fortimanager", FORTIMANAGER)}
        assert children["FGT-branch-oslo"].reachable is True
        assert children["FGT-branch-bergen"].reachable is False

    def test_an_absent_connection_status_stays_unknown(self) -> None:
        """Absent is not false: only `1` is a positive statement that a device is up."""
        payload = json.dumps({"result": [{"data": [{"name": "FGT-x", "ip": "10.0.0.1"}]}]})
        assert enumerate_children("fortimanager", payload)[0].reachable is None

    def test_the_adom_is_kept_as_the_group(self) -> None:
        children = {c.hostname: c for c in enumerate_children("fortimanager", FORTIMANAGER)}
        assert children["FGT-dc-cluster"].group == "Datacentre"

    def test_malformed_json_yields_nothing_rather_than_raising(self) -> None:
        assert enumerate_children("fortimanager", '{"result": [') == []


class TestCheckPoint:
    def test_gateways_and_clusters_are_reported(self) -> None:
        children = enumerate_children("checkpoint_mgmt", CHECKPOINT)
        assert "cp-gw-edge-01" in {c.hostname for c in children}
        assert "cp-cluster-dc" in {c.hostname for c in children}

    def test_the_management_server_and_log_server_are_not_imported(self) -> None:
        """A management server lists *itself* and its log servers alongside the
        gateways. Importing those creates a device that can never be collected from and
        a collection failure that never resolves."""
        names = {c.hostname for c in enumerate_children("checkpoint_mgmt", CHECKPOINT)}

        assert "cp-mgmt-primary" not in names
        assert "cp-log-server" not in names

    def test_an_unfamiliar_gateway_type_is_included_rather_than_dropped(self) -> None:
        """The deny-list is the safe direction: an extra proposal costs a click, and a
        missing one is a firewall nobody assesses. A new appliance type in a future
        release must surface for a human rather than vanish."""
        names = {c.hostname for c in enumerate_children("checkpoint_mgmt", CHECKPOINT)}
        assert "cp-gw-newtype" in names

    def test_children_are_gaia_devices(self) -> None:
        """A gateway runs Gaia. Its policy lives on the management server, but the
        device itself is collected from as a Gaia box."""
        assert all(
            c.platform == "checkpoint_gaia"
            for c in enumerate_children("checkpoint_mgmt", CHECKPOINT)
        )

    def test_the_uid_stands_in_for_a_serial(self) -> None:
        """Check Point exposes no serial here, and the UID is stable within this
        management server — which is the scope that matters for matching."""
        child = next(
            c
            for c in enumerate_children("checkpoint_mgmt", CHECKPOINT)
            if c.hostname == "cp-gw-edge-01"
        )
        assert child.serial_number == "aa000001-0000-0000-0000-000000000001"

    def test_reachability_is_unknown_rather_than_assumed(self) -> None:
        """The API does not report it on this call. Claiming every gateway is up because
        nothing said otherwise is the absent-is-not-false mistake in a new place."""
        assert all(c.reachable is None for c in enumerate_children("checkpoint_mgmt", CHECKPOINT))


class TestTheRegistry:
    def test_an_unsupported_platform_raises_with_the_supported_ones(self) -> None:
        with pytest.raises(UnsupportedManagerError, match="fortimanager"):
            enumerate_children("cisco_ios", "{}")

    @pytest.mark.parametrize("platform", ["panos", "panorama", "fortimanager", "checkpoint_mgmt"])
    def test_supported_managers(self, platform: str) -> None:
        assert supports_enumeration(platform)

    @pytest.mark.parametrize("platform", ["cisco_ios", "fortios", None])
    def test_a_managed_device_is_not_itself_a_manager(self, platform: str | None) -> None:
        assert not supports_enumeration(platform)

    def test_every_enumeration_request_is_on_the_platforms_allow_list(self) -> None:
        """SRS §8.2. This is the one place the product reaches for a device-facing call
        outside a collection profile, so it is held to the same standard: the request
        must already be approved in `policies.py`, where a reviewer reads it.
        """
        from netsecops.adapters.children import ENUMERATION_REQUESTS
        from netsecops.adapters.policies import get_policy
        from netsecops.adapters.readonly import ReadOnlyGuard

        for platform, (method, path, body) in ENUMERATION_REQUESTS.items():
            # Panorama shares the PAN-OS API and its allow-list.
            policy_platform = "panos" if platform == "panorama" else platform
            guard = ReadOnlyGuard(get_policy(policy_platform))

            assert guard.permits_request(method, path, body=body), (
                f"{platform}: enumeration issues {method} {path} with body {body}, "
                f"which the platform's rules in policies.py do not permit."
            )


# ═════════════════════ importing, and the approval gate ══════════════════════


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="mgr_analyst", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
async def panorama(session: AsyncSession, actor: Principal) -> Device:
    return await InventoryService(session).create_device(
        mgmt_ip="10.100.0.10",
        actor=actor,
        hostname="panorama-01",
        vendor=Vendor.PALOALTO,
        platform="panos",
        device_class=DeviceClass.MANAGER,
    )


class TestPreview:
    async def test_it_writes_nothing(
        self, session: AsyncSession, panorama: Device, actor: Principal
    ) -> None:
        """The whole point of the split: a human sees what would change before it does."""
        service = ManagerEnumerationService(session)
        preview = await service.preview(panorama, PANORAMA)

        assert preview.counts["reported"] == 4
        assert await service.pending(panorama) == []

    async def test_new_devices_are_proposed(self, session: AsyncSession, panorama: Device) -> None:
        preview = await ManagerEnumerationService(session).preview(panorama, PANORAMA)

        assert {p.child.hostname for p in preview.new} == {
            "fw-branch-london",
            "fw-branch-frankfurt",
            "fw-dc-primary",
        }

    async def test_a_device_with_no_address_is_unimportable_and_says_why(
        self, session: AsyncSession, panorama: Device
    ) -> None:
        preview = await ManagerEnumerationService(session).preview(panorama, PANORAMA)

        unimportable = preview.unimportable
        assert len(unimportable) == 1
        assert unimportable[0].child.hostname == "fw-awaiting-provisioning"
        assert "no management address" in (unimportable[0].reason or "")

    async def test_a_device_already_in_inventory_is_known_not_new(
        self, session: AsyncSession, panorama: Device, actor: Principal
    ) -> None:
        """Adopting an existing device is better than refusing its address and far
        better than creating a duplicate."""
        await InventoryService(session).create_device(
            mgmt_ip="10.10.1.1",
            actor=actor,
            hostname="fw-branch-london",
            vendor=Vendor.PALOALTO,
            platform="panos",
            device_class=DeviceClass.FIREWALL,
        )

        preview = await ManagerEnumerationService(session).preview(panorama, PANORAMA)
        known = {p.child.hostname for p in preview.known}
        assert known == {"fw-branch-london"}

    async def test_a_non_manager_is_refused_with_an_explanation(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        firewall = await InventoryService(session).create_device(
            mgmt_ip="10.10.9.9",
            actor=actor,
            hostname="just-a-firewall",
            vendor=Vendor.PALOALTO,
            platform="panos",
            device_class=DeviceClass.FIREWALL,
        )

        with pytest.raises(ValidationProblem, match="not recorded as a manager"):
            await ManagerEnumerationService(session).preview(firewall, PANORAMA)


class TestImport:
    async def test_only_the_approved_devices_are_created(
        self, session: AsyncSession, panorama: Device, actor: Principal
    ) -> None:
        """The approval. A call that imported everything it enumerated would turn one
        API response into an estate nobody chose."""
        service = ManagerEnumerationService(session)
        preview = await service.preview(panorama, PANORAMA)

        result = await service.import_children(
            panorama, preview, identities=["001901234501"], actor=actor
        )

        assert result.counts["created"] == 1
        pending = await service.pending(panorama)
        assert [d.hostname for d in pending] == ["fw-branch-london"]

    async def test_imported_devices_are_pending_review_and_attributed(
        self, session: AsyncSession, panorama: Device, actor: Principal
    ) -> None:
        service = ManagerEnumerationService(session)
        preview = await service.preview(panorama, PANORAMA)
        await service.import_children(panorama, preview, identities=["001901234501"], actor=actor)

        device = (await service.pending(panorama))[0]
        assert device.status == DeviceStatus.PENDING_REVIEW.value
        assert device.parent_device_id == panorama.id
        assert device.device_class == DeviceClass.FIREWALL.value
        assert device.serial_number == "001901234501"
        assert device.os_version == "11.0.2"
        assert device.facts["manager_hostname"] == "panorama-01"

    async def test_approving_an_identity_not_in_the_preview_is_an_error(
        self, session: AsyncSession, panorama: Device, actor: Principal
    ) -> None:
        """The list the human approved is no longer the list being acted on, and they
        should see that rather than have it silently resolved."""
        service = ManagerEnumerationService(session)
        preview = await service.preview(panorama, PANORAMA)

        with pytest.raises(ValidationProblem, match="not in the enumeration"):
            await service.import_children(
                panorama, preview, identities=["999999999999"], actor=actor
            )

    async def test_an_unimportable_device_is_skipped_not_created(
        self, session: AsyncSession, panorama: Device, actor: Principal
    ) -> None:
        service = ManagerEnumerationService(session)
        preview = await service.preview(panorama, PANORAMA)

        result = await service.import_children(
            panorama, preview, identities=["001901234504"], actor=actor
        )

        assert result.counts["created"] == 0
        assert result.skipped == ["001901234504"]

    async def test_re_enumerating_adopts_rather_than_duplicating(
        self, session: AsyncSession, panorama: Device, actor: Principal
    ) -> None:
        service = ManagerEnumerationService(session)

        first = await service.preview(panorama, PANORAMA)
        await service.import_children(panorama, first, identities=["001901234501"], actor=actor)

        second = await service.preview(panorama, PANORAMA)
        result = await service.import_children(
            panorama, second, identities=["001901234501"], actor=actor
        )

        assert result.counts["created"] == 0
        assert len(await service.pending(panorama)) == 1

    async def test_a_re_addressed_device_is_matched_on_its_serial(
        self, session: AsyncSession, panorama: Device, actor: Principal
    ) -> None:
        """The event that would otherwise duplicate a device — and two records for one
        box means two risk scores and two sets of findings for the same firewall."""
        service = ManagerEnumerationService(session)
        preview = await service.preview(panorama, PANORAMA)
        await service.import_children(panorama, preview, identities=["001901234501"], actor=actor)

        moved = PANORAMA.replace("10.10.1.1", "10.11.1.1")
        again = await service.preview(panorama, moved)

        assert {p.child.hostname for p in again.known} == {"fw-branch-london"}
        assert "fw-branch-london" not in {p.child.hostname for p in again.new}

    async def test_adopting_does_not_reset_an_approved_device_to_pending(
        self, session: AsyncSession, panorama: Device, actor: Principal
    ) -> None:
        """Someone approved this device. A later enumeration must not quietly withdraw
        it from assessment."""
        service = ManagerEnumerationService(session)
        preview = await service.preview(panorama, PANORAMA)
        await service.import_children(panorama, preview, identities=["001901234501"], actor=actor)

        device = (await service.pending(panorama))[0]
        await service.approve(device, actor=actor)

        again = await service.preview(panorama, PANORAMA)
        await service.import_children(panorama, again, identities=["001901234501"], actor=actor)

        await session.refresh(device)
        assert device.status == DeviceStatus.ACTIVE.value

    async def test_adopting_never_overwrites_the_working_management_address(
        self, session: AsyncSession, panorama: Device, actor: Principal
    ) -> None:
        """The address in inventory is the one shown to work; the manager's may be a
        different interface entirely."""
        service = ManagerEnumerationService(session)
        preview = await service.preview(panorama, PANORAMA)
        await service.import_children(panorama, preview, identities=["001901234501"], actor=actor)
        device = (await service.pending(panorama))[0]

        moved = PANORAMA.replace("10.10.1.1", "10.11.1.1")
        again = await service.preview(panorama, moved)
        await service.import_children(panorama, again, identities=["001901234501"], actor=actor)

        await session.refresh(device)
        assert str(device.mgmt_ip) == "10.10.1.1"


class TestDisappearance:
    async def test_a_device_the_manager_stops_reporting_is_surfaced(
        self, session: AsyncSession, panorama: Device, actor: Principal
    ) -> None:
        service = ManagerEnumerationService(session)
        preview = await service.preview(panorama, PANORAMA)
        await service.import_children(panorama, preview, identities=["001901234501"], actor=actor)

        # Serial, hostname *and* address all change: matching falls back to the address,
        # so leaving it would make the device look merely renamed rather than gone.
        without = (
            PANORAMA.replace("001901234501", "001901239999")
            .replace("fw-branch-london", "fw-something-else")
            .replace("10.10.1.1", "10.19.9.9")
        )
        again = await service.preview(panorama, without)

        assert len(again.disappeared) == 1
        assert again.disappeared[0]["hostname"] == "fw-branch-london"

    async def test_it_is_not_archived_automatically(
        self, session: AsyncSession, panorama: Device, actor: Principal
    ) -> None:
        """A manager that omits a device because of an API error, a permissions change
        or a domain filter looks exactly like one that no longer manages it. Archiving on
        that basis removes devices from assessment when the manager is misbehaving."""
        service = ManagerEnumerationService(session)
        preview = await service.preview(panorama, PANORAMA)
        await service.import_children(panorama, preview, identities=["001901234501"], actor=actor)
        device = (await service.pending(panorama))[0]

        await service.preview(panorama, "<response><result><devices/></result></response>")

        await session.refresh(device)
        assert device.status != DeviceStatus.ARCHIVED.value


class TestTheApprovalGate:
    async def test_a_pending_device_is_never_targeted_by_a_job(
        self, session: AsyncSession, panorama: Device, actor: Principal
    ) -> None:
        """The assertion that makes this whole feature honest.

        `pending_review` is only an approval gate because job targeting excludes it.
        Without this, importing four hundred firewalls from a Panorama would put every
        one of them into the next scheduled job — connecting to devices nobody chose.
        """
        from netsecops.services.jobs import JobScope, JobService

        service = ManagerEnumerationService(session)
        preview = await service.preview(panorama, PANORAMA)
        await service.import_children(panorama, preview, identities=["001901234501"], actor=actor)
        device = (await service.pending(panorama))[0]

        targeted = await JobService(session).resolve_scope(
            JobScope(device_ids=(device.id,)), principal_scope=actor.scope
        )
        assert [d.id for d in targeted] == []

    async def test_approving_admits_it_to_assessment(
        self, session: AsyncSession, panorama: Device, actor: Principal
    ) -> None:
        from netsecops.services.jobs import JobScope, JobService

        service = ManagerEnumerationService(session)
        preview = await service.preview(panorama, PANORAMA)
        await service.import_children(panorama, preview, identities=["001901234501"], actor=actor)
        device = (await service.pending(panorama))[0]

        await service.approve(device, actor=actor)

        targeted = await JobService(session).resolve_scope(
            JobScope(device_ids=(device.id,)), principal_scope=actor.scope
        )
        assert [d.id for d in targeted] == [device.id]

    async def test_approving_something_not_awaiting_review_is_refused(
        self, session: AsyncSession, panorama: Device, actor: Principal
    ) -> None:
        with pytest.raises(ValidationProblem, match="not awaiting review"):
            await ManagerEnumerationService(session).approve(panorama, actor=actor)

    async def test_an_ordinary_active_device_is_still_targeted(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The exclusion must not catch anything else: every existing device is active,
        and a gate that quietly stopped assessing them would be far worse than no gate."""
        from netsecops.services.jobs import JobScope, JobService

        device = await InventoryService(session).create_device(
            mgmt_ip="10.10.5.5",
            actor=actor,
            hostname="ordinary",
            vendor=Vendor.CISCO,
            platform="cisco_ios",
            device_class=DeviceClass.SWITCH,
        )

        targeted = await JobService(session).resolve_scope(
            JobScope(device_ids=(device.id,)), principal_scope=actor.scope
        )
        assert [d.id for d in targeted] == [device.id]
