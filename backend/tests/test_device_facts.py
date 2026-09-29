"""Device facts reach the device row (FR-INV-05).

**The defect this pins was total, not partial.** `InventoryService.record_facts` was
written, documented against FR-INV-05, and called by nothing — not the collection
runner, not the offline upload, not a test. Found on 2026-09-29 by asking why the
vulnerability engine had produced no rows: all 653 devices in the estate had
`os_version = NULL`, while 622 of their snapshots carried a version in the parsed NCM.

The chain that breaks is worth stating in full, because every link fails quietly:

1. nothing copies the NCM's version onto `Device.os_version`;
2. `software_cpe()` returns None without a version — deliberately, because a wildcard
   version matches every advisory ever published;
3. no CPE means no feed match, no KEV hit, no EoL check;
4. the device renders as having no vulnerabilities, which is what a *clean* device looks
   like.

So the product's entire FR-VUL half was structurally incapable of producing a finding,
and the symptom was indistinguishable from good news.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.services.inventory import InventoryService
from netsecops.services.snapshots import SnapshotService, SupportingCapture
from netsecops.vuln.cpe import software_cpe
from tests.conftest import make_user

IOS_CONFIG = """\
version 15.2
!
hostname edge-sw-01
!
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.252
!
line vty 0 4
 transport input ssh
!
end
"""

SHOW_VERSION = """\
Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3
Processor board ID FOC1234X56Y
cisco WS-C2960X-48FPD-L (APM86XXX) processor
"""


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="facts_actor", roles={Role.SUPER_ADMIN})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def make_device(session: AsyncSession, actor: Principal, ip: str = "10.0.0.1"):
    return await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=actor,
        hostname="placeholder",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )


class TestAnUploadUpdatesTheDevice:
    async def test_the_version_reaches_the_device_row(
        self, session: AsyncSession, actor: Principal, vault
    ) -> None:
        device = await make_device(session, actor)
        assert device.os_version is None

        await SnapshotService(session, vault=vault).ingest_config(
            device, config_text=IOS_CONFIG, filename="edge-sw-01.cfg", actor=actor
        )

        assert device.os_version == "15.2"

    def test_and_that_is_what_makes_a_cpe_possible(self) -> None:
        """The link in the chain that made the whole engine inert.

        Stated as a property of `software_cpe` rather than inferred: without a version
        it returns None *by design*, because a wildcard version would match every
        advisory ever published for the platform.
        """
        from netsecops.ncm.models import DeviceFacts, NormalisedConfig

        without = NormalisedConfig(device=DeviceFacts(platform="cisco_ios"))
        with_version = NormalisedConfig(
            device=DeviceFacts(platform="cisco_ios", version="15.2(7)E3")
        )

        assert software_cpe(without) is None
        assert software_cpe(with_version) is not None

    async def test_a_supporting_capture_supplies_what_the_config_cannot(
        self, session: AsyncSession, actor: Principal, vault
    ) -> None:
        # The reason FR-COL-11 gained supporting captures. A running configuration says
        # `version 15.2`; `show version` says `15.2(7)E3`, which is the string an
        # advisory is written against.
        device = await make_device(session, actor, ip="10.0.0.2")

        await SnapshotService(session, vault=vault).ingest_config(
            device,
            config_text=IOS_CONFIG,
            filename="edge-sw-01.cfg",
            actor=actor,
            supporting=[SupportingCapture(filename="show version.txt", text=SHOW_VERSION)],
        )

        assert device.os_version == "15.2(7)E3"
        assert device.serial_number == "FOC1234X56Y"

    async def test_an_upload_does_not_claim_the_device_was_contacted(
        self, session: AsyncSession, actor: Principal, vault
    ) -> None:
        """Facts and contact are different claims.

        The facts are real — they came from the device's own configuration. But nothing
        was sent to it, and `last_collected_at` means "we talked to this device". Setting
        it here would report an unreachable appliance as recently collected, which is
        the reading `topology.py` already works around by keying on the snapshot.
        """
        device = await make_device(session, actor, ip="10.0.0.3")

        await SnapshotService(session, vault=vault).ingest_config(
            device, config_text=IOS_CONFIG, filename="x.cfg", actor=actor
        )

        assert device.os_version == "15.2"
        assert device.last_collected_at is None

    async def test_a_live_collection_does_claim_it(
        self, session: AsyncSession, actor: Principal, vault
    ) -> None:
        # The other half of the same distinction: `create_snapshot` defaults to
        # `contacted=True`, which is what the collection runner uses.
        device = await make_device(session, actor, ip="10.0.0.4")

        await SnapshotService(session, vault=vault).create_snapshot(
            device, config_text=IOS_CONFIG, platform="cisco_ios"
        )

        assert device.last_collected_at is not None

    async def test_re_uploading_an_unchanged_config_still_updates_the_facts(
        self, session: AsyncSession, actor: Principal, vault
    ) -> None:
        """The case the estate is actually in.

        650 configurations are already stored. Re-uploading one with `show version`
        attached is de-duplicated on the configuration hash — so if facts were recorded
        only when a *new* snapshot is written, the second upload would change nothing
        and the device would stay unassessable.
        """
        device = await make_device(session, actor, ip="10.0.0.5")
        snapshots = SnapshotService(session, vault=vault)

        await snapshots.ingest_config(
            device, config_text=IOS_CONFIG, filename="x.cfg", actor=actor
        )
        assert device.os_version == "15.2"

        result = await snapshots.ingest_config(
            device,
            config_text=IOS_CONFIG,
            filename="x.cfg",
            actor=actor,
            supporting=[SupportingCapture(filename="show version.txt", text=SHOW_VERSION)],
        )

        assert result.deduplicated is True
        assert device.os_version == "15.2(7)E3"


class TestRecordFactsItself:
    async def test_it_does_not_overwrite_a_fact_with_nothing(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        # A parser that could not read the model must not erase one an earlier
        # collection established. Absent means "no new information", not "no model".
        device = await make_device(session, actor, ip="10.0.0.6")
        inventory = InventoryService(session)

        await inventory.record_facts(device, {"model": "WS-C2960X", "version": "15.2"})
        await inventory.record_facts(device, {"version": "15.3"})

        assert device.model == "WS-C2960X"
        assert device.os_version == "15.3"

    async def test_the_raw_facts_are_kept_alongside_the_columns(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        # The columns are the four a query filters on; `facts` keeps whatever else the
        # parser learned, so adding a fifth later needs no migration.
        device = await make_device(session, actor, ip="10.0.0.7")

        await InventoryService(session).record_facts(
            device, {"version": "15.2", "uptime_s": 9000}
        )

        assert device.facts["uptime_s"] == 9000
