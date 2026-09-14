"""The estate-wide AAA posture dashboard (FR-AAA-06).

A posture dashboard fails in a particular direction: towards looking clean. Every panel
on it is a count, and every count has a way of reaching zero because nobody collected
the data rather than because there is nothing to report. The tests here are mostly about
that — each one pins a case where the honest answer and the flattering answer differ.

The four panels FR-AAA-06 names are coverage, protocols, orphaned clients and the
certificate expiry timeline. Orphans come straight from the correlation and are tested
in ``test_aaa_correlation.py``; this file covers the other three and the assembly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.collection import Finding, FindingKind, FindingStatus
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.services.aaa_posture import AaaPostureService
from tests.conftest import make_user
from tests.test_aaa_correlation import add_device, client, client_ncm, server_ncm, snapshot


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="posture_analyst", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


def in_days(days: int) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


def certificate(name: str, *, not_after: str | None, **extra: Any) -> dict[str, Any]:
    return {"name": name, "not_after": not_after, **extra}


def with_certificates(ncm: dict[str, Any], certificates: list[dict[str, Any]]) -> dict[str, Any]:
    return {**ncm, "certificates": certificates}


# ═════════════════════════════ coverage ═════════════════════════════════════


class TestCoverage:
    async def test_coverage_is_a_percentage_of_devices_we_could_assess(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        central = await add_device(session, actor, ip="198.51.100.1", hostname="sw-a")
        local = await add_device(session, actor, ip="198.51.100.2", hostname="sw-b")
        await snapshot(session, central, client_ncm([{"type": "radius", "host": "10.100.0.60"}]))
        await snapshot(session, local, client_ncm([]))

        posture = await AaaPostureService(session).build()

        assert posture.devices_total == 2
        assert posture.devices_with_central_auth == 1
        assert posture.coverage_percentage == 50

    async def test_coverage_is_unknown_rather_than_zero_when_nothing_was_assessable(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """0% and "we have not looked" send an operator to two different places. One is
        a project to roll out TACACS+; the other is a broken collector."""
        await add_device(session, actor, ip="198.51.100.3", hostname="sw-c")

        posture = await AaaPostureService(session).build()

        assert posture.devices_total == 1
        assert posture.devices_not_evaluated == 1
        assert posture.coverage_percentage is None


# ════════════════════════ protocols the servers accept ══════════════════════


class TestProtocols:
    async def test_protocols_are_aggregated_across_servers_with_the_weak_ones_first(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The reason to open this panel is the weak entries. Sorting alphabetically
        would put EAP-TLS above MS-CHAPv1 and make the panel decoration."""
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        radius = await add_device(
            session, actor, ip="10.100.0.51", hostname="radius-01", platform="freeradius"
        )
        await snapshot(
            session,
            ise,
            {
                **server_ncm("ise", [client("sw-a", "198.51.100.1")]),
                "aaa_server": {
                    "product": "ise",
                    "clients": [client("sw-a", "198.51.100.1")],
                    "allowed_protocols": ["EAP-TLS", "MS-CHAPv1", "PEAP"],
                },
            },
        )
        await snapshot(
            session,
            radius,
            {
                "device": {},
                "aaa_server": {
                    "product": "freeradius",
                    "clients": [client("sw-b", "198.51.100.2")],
                    "allowed_protocols": ["EAP-TLS", "PAP"],
                },
            },
        )

        posture = await AaaPostureService(session).build()
        names = [p.name for p in posture.accepted_protocols]

        assert set(posture.weak_protocols_in_use) == {"MS-CHAPv1", "PAP"}
        assert names[:2] == ["MS-CHAPv1", "PAP"], "weak protocols must sort first"
        # And each protocol names the servers that accept it, so the fix has an address.
        eap = next(p for p in posture.accepted_protocols if p.name == "EAP-TLS")
        assert eap.weak is False
        assert eap.servers == ["ise-01", "radius-01"]

    async def test_an_empty_protocol_panel_says_why_when_servers_exist(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """A server that exposed no protocol set produces an empty panel that looks
        identical to a server accepting nothing. Only one of those is good news."""
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        await snapshot(session, ise, server_ncm("ise", [client("sw-a", "198.51.100.1")]))

        posture = await AaaPostureService(session).build()

        assert posture.accepted_protocols == []
        assert any("protocols panel" in note for note in posture.limitations)


class TestTransports:
    async def test_devices_are_counted_by_the_kind_of_server_they_point_at(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        for index, servers in enumerate(
            (
                [{"type": "radius", "host": "10.100.0.60"}],
                [{"type": "radius", "host": "10.100.0.60"}],
                [{"type": "tacacs+", "host": "10.100.0.61"}],
            )
        ):
            device = await add_device(
                session, actor, ip=f"198.51.100.1{index}", hostname=f"sw-{index}"
            )
            await snapshot(session, device, client_ncm(servers))

        posture = await AaaPostureService(session).build()

        assert [(t.kind, t.devices) for t in posture.transports] == [("radius", 2), ("tacacs+", 1)]

    async def test_a_device_pointing_at_two_kinds_counts_once_for_each(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """A switch doing RADIUS for 802.1X and TACACS+ for administration is one device
        in two rows, not two devices — but it must appear in both, or the panel
        under-reports whichever it is counted as."""
        device = await add_device(session, actor, ip="198.51.100.20", hostname="sw-dual")
        await snapshot(
            session,
            device,
            client_ncm(
                [
                    {"type": "radius", "host": "10.100.0.60"},
                    {"type": "radius", "host": "10.100.0.62"},
                    {"type": "tacacs+", "host": "10.100.0.61"},
                ]
            ),
        )

        posture = await AaaPostureService(session).build()

        assert {t.kind: t.devices for t in posture.transports} == {"radius": 1, "tacacs+": 1}


# ═══════════════════════ certificate expiry timeline ════════════════════════


class TestCertificateTimeline:
    async def test_certificates_are_bucketed_by_how_soon_they_stop_working(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        await snapshot(
            session,
            ise,
            with_certificates(
                server_ncm("ise", [client("sw-a", "198.51.100.1")]),
                [
                    certificate("expired", not_after=in_days(-10)),
                    certificate("urgent", not_after=in_days(9)),
                    certificate("planned", not_after=in_days(70)),
                    certificate("distant", not_after=in_days(900)),
                ],
            ),
        )

        timeline = (await AaaPostureService(session).build()).certificates

        assert timeline.total == 4
        assert timeline.expired == 1
        assert timeline.expiring_soon == 1
        # The 90-day horizon includes the 30-day bucket: an operator planning a quarter
        # needs one number for "certificates I must deal with this quarter".
        assert timeline.expiring_within_horizon == 2
        assert [entry.name for entry in timeline.entries] == [
            "expired",
            "urgent",
            "planned",
            "distant",
        ]

    async def test_an_undated_certificate_is_counted_and_listed_last(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """Dropping it would shorten the timeline, and a shorter timeline reads as
        better news. Sorting it first would bury the certificate expiring on Friday."""
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        await snapshot(
            session,
            ise,
            with_certificates(
                server_ncm("ise", [client("sw-a", "198.51.100.1")]),
                [
                    certificate("pxgrid", not_after="unknown"),
                    certificate("campus-eap", not_after=in_days(20)),
                ],
            ),
        )

        posture = await AaaPostureService(session).build()
        timeline = posture.certificates

        assert timeline.total == 2
        assert timeline.undated == 1
        assert [entry.name for entry in timeline.entries] == ["campus-eap", "pxgrid"]
        # And it is not silently counted as expiring or expired.
        assert timeline.expired == 0
        assert timeline.expiring_soon == 1
        assert any("could not interpret" in note for note in posture.limitations)

    async def test_a_server_that_contributed_no_certificate_is_named(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """This is the difference between "nothing expiring" and "nothing collected".
        An AAA server whose certificate endpoint returned 403 produces an empty timeline
        that looks exactly like a healthy one."""
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        await snapshot(session, ise, server_ncm("ise", [client("sw-a", "198.51.100.1")]))

        posture = await AaaPostureService(session).build()

        assert posture.certificates.total == 0
        assert posture.certificates.servers_without_certificates == ["ise-01"]
        assert any("blind to those servers" in note for note in posture.limitations)

    async def test_each_entry_names_the_device_it_is_on(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """A timeline of certificate names with no devices is a list nobody can action:
        'campus-eap expires Friday' is only useful with somewhere to go and fix it."""
        ise = await add_device(
            session, actor, ip="10.100.0.50", hostname="ise-01", platform="cisco_ise"
        )
        await snapshot(
            session,
            ise,
            with_certificates(
                server_ncm("ise", [client("sw-a", "198.51.100.1")]),
                [certificate("campus-eap", not_after=in_days(20), usage=["EAP Authentication"])],
            ),
        )

        entry = (await AaaPostureService(session).build()).certificates.entries[0]

        assert entry.device == "ise-01"
        assert entry.device_id == str(ise.id)
        assert entry.usage == ["EAP Authentication"]


# ══════════════════════════ servers and findings ════════════════════════════


class TestServers:
    async def test_each_server_is_summarised_with_what_it_could_not_tell_us(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """`admin_mfa_enabled` is three-valued on purpose. FreeRADIUS and tac_plus have
        no such concept, and rendering their None as "no" would invent a finding on
        every open-source AAA server in the estate."""
        radius = await add_device(
            session, actor, ip="10.100.0.51", hostname="radius-01", platform="freeradius"
        )
        await snapshot(
            session,
            radius,
            {
                "device": {},
                "aaa_server": {
                    "product": "freeradius",
                    "clients": [client("sw-a", "198.51.100.1")],
                    "identity_stores": [{"name": "ldap", "type": "ldap"}],
                    "allowed_protocols": ["PAP", "EAP-TLS"],
                },
            },
        )

        summary = (await AaaPostureService(session).build()).servers[0]

        assert summary.product == "freeradius"
        assert summary.clients == 1
        assert summary.identity_stores == 1
        assert summary.weak_protocols == ["PAP"]
        assert summary.admin_mfa_enabled is None
        assert summary.snapshot_age_days == 0

    async def test_a_device_that_is_not_an_aaa_server_is_not_listed_as_one(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        switch = await add_device(session, actor, ip="198.51.100.30", hostname="sw-z")
        await snapshot(session, switch, client_ncm([{"type": "radius", "host": "10.100.0.60"}]))

        posture = await AaaPostureService(session).build()

        assert posture.servers == []
        assert any("device-side view only" in note for note in posture.limitations)


class TestOpenFindings:
    async def test_only_active_aaa_findings_are_counted(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """A resolved finding counted here would mean the number on the dashboard never
        goes down, which is the fastest way to teach people to ignore it."""
        device = await add_device(session, actor, ip="198.51.100.40", hostname="sw-f")
        now = datetime.now(UTC)
        for index, (kind, severity, status) in enumerate(
            (
                (FindingKind.AAA, "high", FindingStatus.NEW),
                (FindingKind.AAA, "high", FindingStatus.RESOLVED),
                (FindingKind.AAA, "medium", FindingStatus.REOPENED),
                (FindingKind.CONFIG, "critical", FindingStatus.NEW),
            )
        ):
            session.add(
                Finding(
                    org_id=device.org_id,
                    device_id=device.id,
                    kind=kind.value,
                    fingerprint=f"test:{index}",
                    title="t",
                    severity=severity,
                    status=status.value,
                    evidence={},
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
        await session.flush()

        posture = await AaaPostureService(session).build()

        assert posture.open_findings == {"high": 1, "medium": 1}


class TestAssembly:
    async def test_the_dashboard_and_the_correlation_agree(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The posture carries the correlation report itself rather than recomputing its
        numbers. Two analyses of the same estate that disagree by one is the kind of
        thing nobody can debug from a screenshot."""
        ise = await add_device(
            session,
            actor,
            ip="10.100.0.50",
            hostname="ise-01",
            platform="cisco_ise",
            device_class=DeviceClass.AAA_SERVER,
            vendor=Vendor.CISCO,
        )
        await snapshot(session, ise, server_ncm("ise", [client("ghost", "10.88.0.1")]))

        posture = await AaaPostureService(session).build()

        assert posture.correlation.servers_examined == 1
        assert [c.name for c in posture.correlation.orphaned_clients] == ["ghost"]
        assert posture.correlation.registration_analysed is True
