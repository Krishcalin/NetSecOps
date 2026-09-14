"""Cross-estate AAA correlation (FR-AAA-05).

Every other analysis in this product looks at one device. This one's whole subject is
the disagreement *between* devices, which changes the shape of the failures: a bug here
is not a wrong finding on one switch, it is a wrong statement about the estate.

Three of those are pinned below, because each would be believed:

**"No secret reuse" when the secrets were never visible.** ISE and FortiAuthenticator
return `********`. Counting those as unique would report a clean estate on the strength
of data nobody has.

**"Every device is unregistered" when no AAA server has been collected.** With no server
snapshots, every device trivially appears on no client list. That is the absence of the
question, not the answer to it.

**Coverage of 0% when nothing was assessable.** Zero and "we could not tell" look
identical on a dashboard and lead to opposite actions.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device
from netsecops.db.models.collection import Snapshot
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.services.aaa_correlation import AaaCorrelationService, summarise
from netsecops.services.inventory import InventoryService
from tests.conftest import make_user


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="aaa_analyst", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def add_device(
    session: AsyncSession,
    actor: Principal,
    *,
    ip: str,
    hostname: str,
    platform: str = "cisco_ios",
    device_class: DeviceClass = DeviceClass.SWITCH,
    vendor: Vendor = Vendor.CISCO,
) -> Device:
    return await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=actor,
        hostname=hostname,
        vendor=vendor,
        platform=platform,
        device_class=device_class,
    )


async def snapshot(
    session: AsyncSession,
    device: Device,
    ncm: dict[str, Any],
    *,
    age_days: int = 0,
) -> Snapshot:
    digest = sha256(f"{device.id}{ncm}{age_days}".encode()).hexdigest()
    row = Snapshot(
        org_id=device.org_id,
        device_id=device.id,
        ncm=ncm,
        config_redacted="",
        config_hash=digest,
        normalized_hash=digest,
    )
    session.add(row)
    await session.flush()

    if age_days:
        row.created_at = datetime.now(UTC) - timedelta(days=age_days)
        await session.flush()
    return row


def client(name: str, address: str, *, fingerprint: str | None = None, secret: bool = True):
    return {
        "name": name,
        "address": address,
        "secret_configured": secret,
        "secret_fingerprint": fingerprint,
    }


def server_ncm(product: str, clients: list[dict[str, Any]]) -> dict[str, Any]:
    return {"device": {}, "aaa_server": {"product": product, "clients": clients}}


def client_ncm(servers: list[dict[str, Any]]) -> dict[str, Any]:
    return {"device": {}, "aaa": {"servers": servers}}


# ═══════════════ devices an AAA server knows and we do not ═══════════════════


class TestOrphanedClients:
    async def test_a_switch_on_ise_and_not_in_inventory_is_found(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The highest-value output here: it finds *devices*, not problems on devices we
        already knew about. A switch authenticating against ISE and absent from
        inventory is assessed by nothing, and the compliance percentage is measured over
        an estate that does not include it."""
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        known = await add_device(session, actor, ip="198.51.100.31", hostname="core-sw-01")

        await snapshot(
            session,
            ise,
            server_ncm(
                "ise",
                [
                    client("core-sw-01", "198.51.100.31"),
                    client("branch-sw-99", "10.77.0.9"),
                ],
            ),
        )
        await snapshot(session, known, client_ncm([]))

        report = await AaaCorrelationService(session).correlate()

        assert [o.name for o in report.orphaned_clients] == ["branch-sw-99"]
        assert report.orphaned_clients[0].server == "ise-01"

    async def test_a_client_matched_by_hostname_is_not_orphaned(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The AAA server's address for a device is often a loopback, not the management
        address in inventory. Matching on address alone would report half the estate as
        orphaned."""
        ise = await add_device(
            session, actor, ip="10.100.0.51", hostname="ise-02", platform="cisco_ise"
        )
        await add_device(session, actor, ip="198.51.100.40", hostname="edge-rtr-01")

        await snapshot(session, ise, server_ncm("ise", [client("edge-rtr-01", "10.255.0.1")]))

        report = await AaaCorrelationService(session).correlate()
        assert report.orphaned_clients == []

    async def test_addresses_are_compared_as_addresses(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """`10.0.0.1` and `10.0.0.1/32` are one host. Every estate writes them
        inconsistently, and string comparison would report the same box twice — once as
        an orphan and once as unregistered."""
        ise = await add_device(
            session, actor, ip="10.100.0.52", hostname="ise-03", platform="cisco_ise"
        )
        await add_device(session, actor, ip="198.51.100.60", hostname="sw-cidr")

        await snapshot(session, ise, server_ncm("ise", [client("whatever", "198.51.100.60/32")]))

        report = await AaaCorrelationService(session).correlate()
        assert report.orphaned_clients == []

    async def test_a_stale_server_snapshot_is_flagged_rather_than_trusted(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """A device added to inventory last week looks identical to one nobody ever
        added, if the server's client list is two months old. The report says which."""
        ise = await add_device(
            session, actor, ip="10.100.0.53", hostname="ise-04", platform="cisco_ise"
        )
        await snapshot(session, ise, server_ncm("ise", [client("ghost", "10.88.0.1")]), age_days=60)

        report = await AaaCorrelationService(session).correlate()

        assert report.orphaned_clients[0].server_snapshot_age_days >= 59
        assert any("more than 30 days old" in note for note in report.limitations)


# ════════════════════ the reverse, and the gate on it ════════════════════════


class TestUnregisteredDevices:
    async def test_a_device_on_no_client_list_is_reported(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        ise = await add_device(
            session, actor, ip="10.100.0.54", hostname="ise-05", platform="cisco_ise"
        )
        await add_device(session, actor, ip="198.51.100.31", hostname="core-sw-01")
        lonely = await add_device(session, actor, ip="198.51.100.32", hostname="forgotten-sw")

        await snapshot(session, ise, server_ncm("ise", [client("core-sw-01", "198.51.100.31")]))
        await snapshot(session, lonely, client_ncm([]))

        report = await AaaCorrelationService(session).correlate()

        assert [d.hostname for d in report.unregistered_devices] == ["forgotten-sw"]

    async def test_nothing_is_claimed_when_no_aaa_server_was_collected(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The catastrophic false positive this gate exists to prevent.

        With no server snapshots every device trivially appears on no client list, so an
        ungated analysis reports the entire estate as unregistered — a page of confident
        findings produced by the absence of data.
        """
        await add_device(session, actor, ip="198.51.100.33", hostname="sw-a")
        await add_device(session, actor, ip="198.51.100.34", hostname="sw-b")

        report = await AaaCorrelationService(session).correlate()

        assert report.registration_analysed is False
        assert report.unregistered_devices == []
        assert any("cannot tell which devices are registered" in n for n in report.limitations)

    async def test_the_aaa_server_itself_is_not_reported_as_unregistered(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """A RADIUS server is not a client of itself."""
        ise = await add_device(
            session, actor, ip="10.100.0.55", hostname="ise-06", platform="cisco_ise"
        )
        await snapshot(session, ise, server_ncm("ise", [client("sw", "10.1.1.1")]))

        report = await AaaCorrelationService(session).correlate()
        assert "ise-06" not in [d.hostname for d in report.unregistered_devices]

    async def test_a_manager_is_not_expected_on_a_client_list(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """A Panorama authenticates its administrators, not itself. Reporting it would
        be a finding nobody can action."""
        ise = await add_device(
            session, actor, ip="10.100.0.56", hostname="ise-07", platform="cisco_ise"
        )
        await add_device(
            session,
            actor,
            ip="10.100.0.57",
            hostname="panorama-01",
            platform="panos",
            device_class=DeviceClass.MANAGER,
            vendor=Vendor.PALOALTO,
        )
        await snapshot(session, ise, server_ncm("ise", [client("sw", "10.1.1.2")]))

        report = await AaaCorrelationService(session).correlate()
        assert "panorama-01" not in [d.hostname for d in report.unregistered_devices]

    async def test_a_device_configured_for_aaa_but_unregistered_is_marked(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The contradiction worth surfacing: this switch is *trying* to authenticate
        against a server that has never heard of it, so every login against it is
        failing over to the local account."""
        ise = await add_device(
            session, actor, ip="10.100.0.58", hostname="ise-08", platform="cisco_ise"
        )
        misconfigured = await add_device(
            session, actor, ip="198.51.100.35", hostname="pointing-at-nothing"
        )

        await snapshot(session, ise, server_ncm("ise", [client("other", "10.2.2.2")]))
        await snapshot(
            session,
            misconfigured,
            client_ncm([{"type": "radius", "host": "10.100.0.58", "key_configured": True}]),
        )

        report = await AaaCorrelationService(session).correlate()
        entry = next(d for d in report.unregistered_devices if d.hostname == "pointing-at-nothing")
        assert entry.configured_for_aaa is True


# ════════════════════════ servers nobody assesses ════════════════════════════


class TestUnknownServers:
    async def test_an_aaa_server_not_in_inventory_is_reported(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """A RADIUS server nobody assesses is a single point of compromise for every
        credential on the network."""
        switch = await add_device(session, actor, ip="198.51.100.36", hostname="sw-c")
        await snapshot(
            session,
            switch,
            client_ncm([{"type": "radius", "host": "10.200.0.9", "key_configured": True}]),
        )

        report = await AaaCorrelationService(session).correlate()

        assert [u.address for u in report.unknown_servers] == ["10.200.0.9"]
        assert report.unknown_servers[0].used_by == ["sw-c"]

    async def test_devices_sharing_an_unknown_server_are_grouped(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """One entry naming forty switches is one piece of work; forty entries is a
        page nobody reads."""
        for index, name in enumerate(("sw-d", "sw-e", "sw-f")):
            device = await add_device(session, actor, ip=f"198.51.100.4{index}", hostname=name)
            await snapshot(
                session,
                device,
                client_ncm([{"type": "tacacs", "host": "10.200.0.10"}]),
            )

        report = await AaaCorrelationService(session).correlate()

        assert len(report.unknown_servers) == 1
        assert sorted(report.unknown_servers[0].used_by) == ["sw-d", "sw-e", "sw-f"]

    async def test_a_server_that_is_in_inventory_is_not_reported(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        await add_device(
            session, actor, ip="10.100.0.60", hostname="radius-01", platform="freeradius"
        )
        switch = await add_device(session, actor, ip="198.51.100.50", hostname="sw-g")
        await snapshot(session, switch, client_ncm([{"type": "radius", "host": "10.100.0.60"}]))

        report = await AaaCorrelationService(session).correlate()
        assert report.unknown_servers == []


# ═══════════════════════ shared-secret reuse ═════════════════════════════════


class TestSecretReuse:
    async def test_a_key_shared_across_devices_is_reported(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """One key across the estate means one disclosure is the whole estate. Only
        FreeRADIUS and tac_plus expose the real key, which is why this is answerable at
        all — and it is answered without NetSecOps ever holding the secret."""
        radius = await add_device(
            session, actor, ip="10.100.0.61", hostname="radius-02", platform="freeradius"
        )
        await snapshot(
            session,
            radius,
            server_ncm(
                "freeradius",
                [
                    client("sw-1", "10.1.0.1", fingerprint="aaaa1111"),
                    client("sw-2", "10.1.0.2", fingerprint="aaaa1111"),
                    client("sw-3", "10.1.0.3", fingerprint="aaaa1111"),
                    client("partner", "10.1.0.9", fingerprint="bbbb2222"),
                ],
            ),
        )

        report = await AaaCorrelationService(session).correlate()

        assert len(report.reused_secrets) == 1
        reuse = report.reused_secrets[0]
        assert reuse.fingerprint == "aaaa1111"
        assert reuse.count == 3
        assert "bbbb2222" not in [r.fingerprint for r in report.reused_secrets]

    async def test_reuse_is_detected_across_two_different_servers(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The same key configured on a RADIUS server and a TACACS+ server. One
        fingerprint function across every parser is what makes this visible."""
        radius = await add_device(
            session, actor, ip="10.100.0.62", hostname="radius-03", platform="freeradius"
        )
        tacacs = await add_device(
            session, actor, ip="10.100.0.63", hostname="tacacs-01", platform="tac_plus"
        )
        await snapshot(
            session,
            radius,
            server_ncm("freeradius", [client("sw-x", "10.3.0.1", fingerprint="cccc")]),
        )
        await snapshot(
            session,
            tacacs,
            server_ncm("tac_plus", [client("sw-y", "10.3.0.2", fingerprint="cccc")]),
        )

        report = await AaaCorrelationService(session).correlate()

        assert len(report.reused_secrets) == 1
        assert sorted(report.reused_secrets[0].used_by) == ["radius-03/sw-x", "tacacs-01/sw-y"]

    async def test_a_masked_secret_is_unknown_not_unique(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The honesty requirement FR-AAA-05 states explicitly. ISE returns `********`
        for every device; counting those as unique would report a clean estate on the
        strength of data nobody has."""
        ise = await add_device(
            session, actor, ip="10.100.0.64", hostname="ise-09", platform="cisco_ise"
        )
        await snapshot(
            session,
            ise,
            server_ncm(
                "ise",
                [
                    client("sw-p", "10.4.0.1", fingerprint=None),
                    client("sw-q", "10.4.0.2", fingerprint=None),
                ],
            ),
        )

        report = await AaaCorrelationService(session).correlate()

        assert report.reused_secrets == []
        assert report.secrets_not_exposable == 2
        assert any("not absent" in note for note in report.limitations)


# ════════════════════════════ coverage ═══════════════════════════════════════


class TestCoverage:
    async def test_coverage_counts_devices_with_central_authentication(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        central = await add_device(session, actor, ip="198.51.100.70", hostname="sw-central")
        local = await add_device(session, actor, ip="198.51.100.71", hostname="sw-local")

        await snapshot(session, central, client_ncm([{"type": "radius", "host": "10.100.0.61"}]))
        await snapshot(session, local, client_ncm([]))

        report = await AaaCorrelationService(session).correlate()

        assert report.coverage.devices_total == 2
        assert report.coverage.devices_with_central_auth == 1
        assert report.coverage.percentage == 50

    async def test_an_uncollected_device_is_excluded_from_the_denominator(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """A device nobody has collected from has not been shown to lack central
        authentication. Counting it as a failure would make the percentage a measure of
        collection coverage rather than of AAA coverage."""
        central = await add_device(session, actor, ip="198.51.100.72", hostname="sw-h")
        await add_device(session, actor, ip="198.51.100.73", hostname="never-collected")

        await snapshot(session, central, client_ncm([{"type": "radius", "host": "10.9.9.9"}]))

        report = await AaaCorrelationService(session).correlate()

        assert report.coverage.devices_total == 2
        assert report.coverage.devices_not_evaluated == 1
        assert report.coverage.percentage == 100

    async def test_coverage_is_unknown_rather_than_zero_when_nothing_is_assessable(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """0% and "we could not tell" look identical on a dashboard and lead to opposite
        actions: one sends someone to configure AAA, the other to fix collection."""
        await add_device(session, actor, ip="198.51.100.74", hostname="sw-i")

        report = await AaaCorrelationService(session).correlate()

        assert report.coverage.percentage is None
        assert any("no honest denominator" in note for note in report.limitations)

    async def test_an_empty_estate_does_not_divide_by_zero(self, session: AsyncSession) -> None:
        report = await AaaCorrelationService(session).correlate()

        assert report.coverage.percentage is None
        assert report.counts["orphaned_clients"] == 0


class TestTheSummary:
    async def test_it_carries_the_limitations_rather_than_only_the_counts(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The dashboard renders this. A summary of counts alone would show zeros that
        mean "not analysed" as though they meant "nothing wrong"."""
        await add_device(session, actor, ip="198.51.100.75", hostname="sw-j")

        summary = summarise(await AaaCorrelationService(session).correlate())

        assert summary["registration_analysed"] is False
        assert summary["limitations"]
        assert summary["coverage_percentage"] is None
