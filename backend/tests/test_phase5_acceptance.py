"""Phase 5 acceptance (SRS §12).

    AAA coverage report correct against fixture lab.

The other AAA tests build their NCM by hand, which is the right thing for a unit test
and the wrong thing for this one: a correlation assembled from dictionaries written to
suit the assertion proves the arithmetic and nothing about whether the parsers feed it
what it expects. So the estate here is built the way a real one is — the shipped fixture
configurations, through the shipped parsers, into snapshots, and out through the
correlation and posture services.

**The lab.** Nine devices. Four are AAA servers (ISE, FortiAuthenticator, FreeRADIUS,
tac_plus), four are collected network devices, and one is in inventory with nothing
collected from it — that last one exists because it is the only way to tell a coverage
denominator that excludes the unknown from one that quietly counts it as a failure.
One of the four, `radsec-gw-01`, is deliberately in inventory under a hostname that
differs from the name its RADIUS server knows it by; see the note on that row.

**Every expected number below was read off the fixtures by hand, not off a previous run
of this code.** That distinction is the whole value of the file. `campus_radius.json`
and `campus_tacplus.conf` really do share one shared secret across two different
products; ISE really does list a `branch-sw-99` that nothing put in inventory. If a
refactor changes one of these numbers, the question is which of the two is now wrong,
and the fixtures are the tiebreaker.

What is deliberately *not* asserted: the exact expired-certificate count. The fixture
dates are absolute, so `fac-eap-server` expires in May 2027 and would silently move
between buckets as the wall clock advances, turning a real assertion into a time bomb.
The certificates are pinned by which bucket they belong to for reasons that cannot
change — a 2025 date is permanently in the past — and by the timeline's blind spots,
which are what FR-AAA-06 actually rests on.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, User
from netsecops.db.models.collection import Snapshot
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser
from netsecops.services.aaa_correlation import AaaCorrelationService, summarise
from netsecops.services.aaa_posture import AaaPostureService
from netsecops.services.inventory import InventoryService
from tests.conftest import make_user

FIXTURES = Path(__file__).parent / "fixtures"

POSTURE = "/api/v1/aaa/posture"
CORRELATION = "/api/v1/aaa/correlation"

#: The key `campus_radius.json` and `campus_tacplus.conf` share, written out here so the
#: reuse assertions are checkable against the fixture without opening it.
SHARED_KEY = "SharedEstateKey2026"

#: Every real shared secret the lab contains. `radsec` is one of them and is deliberately
#: absent: it is also a substring of the client name `radsec-peer`, which the response
#: legitimately carries, so asserting on it would fail for the wrong reason.
LAB_SECRETS = (SHARED_KEY, "P4rtnerUniqueKey!", "WlcOwnKey!2026")


# ═══════════════════════════════ the lab ═════════════════════════════════════


class LabDevice:
    """One device in the fixture lab: inventory row plus the artefact collected from it.

    `fixture` is None for the device nobody has collected from. It is not an oversight
    in the lab — it is the case the coverage denominator has to get right.
    """

    def __init__(
        self,
        hostname: str,
        ip: str,
        platform: str,
        fixture: str | None,
        *,
        vendor: Vendor = Vendor.CISCO,
        device_class: DeviceClass = DeviceClass.SWITCH,
    ) -> None:
        self.hostname = hostname
        self.ip = ip
        self.platform = platform
        self.fixture = fixture
        self.vendor = vendor
        self.device_class = device_class


#: The estate. Management addresses are chosen so that the correlation has something
#: true to say in both directions: `10.100.5.30` and `10.100.5.60` are in inventory
#: because devices point at them, while `10.100.5.31` and `10.100.5.70` deliberately are
#: not, and so must surface as AAA servers nobody assesses.
LAB = [
    LabDevice("core-sw-01", "198.51.100.31", "cisco_ios", "cisco/ios/17.9/hardened_switch.cfg"),
    LabDevice(
        "campus-wlc-01",
        "10.100.0.30",
        "cisco_wlc_aireos",
        "cisco/wlc/8.10/campus_wlc.txt",
        device_class=DeviceClass.WIRELESS_CONTROLLER,
    ),
    LabDevice(
        "wlc-9800-01",
        "10.100.0.31",
        "cisco_iosxe",
        "cisco/ios/17.9/wlc_9800.cfg",
        device_class=DeviceClass.WIRELESS_CONTROLLER,
    ),
    LabDevice(
        "ise-pan-01",
        "10.100.5.10",
        "cisco_ise",
        "cisco/ise/3.2/ise_deployment.json",
        device_class=DeviceClass.AAA_SERVER,
    ),
    LabDevice(
        "fac-campus-01",
        "10.100.5.11",
        "fortiauthenticator",
        "fortinet/fortiauthenticator/6.5/campus_fac.json",
        vendor=Vendor.FORTINET,
        device_class=DeviceClass.AAA_SERVER,
    ),
    LabDevice(
        "radius-01",
        "10.100.5.60",
        "freeradius",
        "linux/freeradius/3.0/campus_radius.json",
        vendor=Vendor.LINUX,
        device_class=DeviceClass.AAA_SERVER,
    ),
    LabDevice(
        "tacacs-01",
        "10.100.5.30",
        "tac_plus",
        "linux/tacplus/campus_tacplus.conf",
        vendor=Vendor.LINUX,
        device_class=DeviceClass.AAA_SERVER,
    ),
    # In inventory under a name that matches no client entry anywhere, at an address
    # that matches one exactly: FreeRADIUS calls 10.100.0.55 `radsec-peer`, the CMDB
    # calls it `radsec-gw-01`. Nothing else in the lab separates matching by address
    # from matching by name, and an estate where the two agree on every device is not
    # an estate anyone has. Without this row, deleting the address comparison entirely
    # leaves every assertion in this file green.
    LabDevice("radsec-gw-01", "10.100.0.55", "cisco_ios", "cisco/ios/15.2/weak_switch.cfg"),
    # In inventory, never collected from. Coverage must set it aside rather than count
    # it as a device without central authentication.
    LabDevice("branch-sw-42", "10.77.0.42", "cisco_ios", None),
]


async def build_lab(session: AsyncSession, actor: Principal) -> dict[str, Device]:
    """Create every lab device and snapshot the fixture through its real parser."""
    inventory = InventoryService(session)
    devices: dict[str, Device] = {}

    for entry in LAB:
        device = await inventory.create_device(
            mgmt_ip=entry.ip,
            actor=actor,
            hostname=entry.hostname,
            vendor=entry.vendor,
            platform=entry.platform,
            device_class=entry.device_class,
        )
        devices[entry.hostname] = device

        if entry.fixture is None:
            continue

        text = (FIXTURES / entry.fixture).read_text(encoding="utf-8")
        ncm = get_parser(entry.platform).parse(ParseContext(text=text))
        digest = sha256(f"{device.id}{entry.fixture}".encode()).hexdigest()
        session.add(
            Snapshot(
                org_id=device.org_id,
                device_id=device.id,
                ncm=ncm.model_dump(mode="json"),
                # The acceptance criterion is about the correlation, and the correlation
                # reads the NCM only. Storing empty redacted text keeps this test from
                # depending on the redaction pipeline it does not exercise.
                config_redacted="",
                config_hash=digest,
                normalized_hash=digest,
            )
        )

    await session.flush()
    return devices


@pytest.fixture
async def analyst_user(session: AsyncSession) -> User:
    return await make_user(session, username="phase5_analyst", roles={Role.SECURITY_ANALYST})


@pytest.fixture
async def actor(analyst_user: User) -> Principal:
    return Principal(
        id=analyst_user.id,
        username=analyst_user.username,
        roles=analyst_user.role_set,
        scope=Scope.all(),
    )


@pytest.fixture
async def lab(session: AsyncSession, actor: Principal) -> dict[str, Device]:
    return await build_lab(session, actor)


# ═════════════════════ the criterion, one assertion at a time ════════════════


class TestPhase5Acceptance:
    async def test_coverage_counts_the_estate_correctly(
        self, session: AsyncSession, lab: dict[str, Device]
    ) -> None:
        """Nine devices, eight assessable, four centrally authenticated.

        The denominator is the point. `branch-sw-42` has no snapshot, so nothing can say
        whether it uses central authentication; counting it as a failure would report
        4/9 = 44% and send someone to fix a device that may already be compliant.
        Counting only what was assessable reports 4/8 = 50%.

        The four AAA servers are in the denominator and not in the numerator, which is
        correct rather than merely convenient: ISE authenticates its administrators
        against itself, and a `aaa.servers` list that is empty because the box is the
        server is still an empty list. The number to watch if this ever looks wrong is
        `devices_with_central_auth`, not the percentage.
        """
        report = await AaaCorrelationService(session).correlate()
        coverage = report.coverage

        assert coverage.devices_total == 9
        assert coverage.devices_not_evaluated == 1, "only branch-sw-42 was never collected"
        assert coverage.devices_with_central_auth == 4, (
            "core-sw-01, campus-wlc-01, wlc-9800-01, radsec-gw-01"
        )

        assert coverage.percentage == 50
        assert coverage.percentage != round(100 * 4 / 9), (
            "the uncollected device must be excluded from the denominator, not counted "
            "as a device without central authentication"
        )

    async def test_the_servers_that_answered_are_the_ones_counted(
        self, session: AsyncSession, lab: dict[str, Device]
    ) -> None:
        """All four AAA products contributed a client list.

        `servers_examined` gates every registration conclusion below it, so a parser
        regression that silently stopped filling `aaa_server.clients` would not produce
        wrong orphan counts — it would produce an analysis that declines to run. This
        asserts it ran.
        """
        report = await AaaCorrelationService(session).correlate()

        assert report.servers_examined == 4, "ISE, FortiAuthenticator, FreeRADIUS, tac_plus"
        assert report.registration_analysed is True

    async def test_devices_the_servers_know_and_inventory_does_not(
        self, session: AsyncSession, lab: dict[str, Device]
    ) -> None:
        """Five orphaned clients, named.

        This is the half of FR-AAA-05 that finds devices rather than problems on devices
        already known, so it is asserted by name: a count alone would survive the
        analysis matching the wrong client against the wrong inventory row.

        Two exclusions carry the weight here. `core-sw-01` is on three of the four
        servers' client lists and is in inventory under that same name, so name matching
        alone would suppress it. `radsec-peer` is in inventory only as the address
        10.100.0.55 under a different hostname, so **only** address matching can suppress
        it — which is what makes this assertion able to fail if that comparison is lost.
        """
        report = await AaaCorrelationService(session).correlate()
        orphans = {client.name for client in report.orphaned_clients}

        assert orphans == {
            "branch-sw-99",  # ISE
            "fortigate-edge",  # FortiAuthenticator
            "decommissioned-ap",  # FortiAuthenticator
            "branch-rtr-07",  # FreeRADIUS
            "partner-nas",  # FreeRADIUS
        }
        assert "radsec-peer" not in orphans, (
            "10.100.0.55 is in inventory as radsec-gw-01; an orphan here means the "
            "comparison fell back to hostnames and is blind to renamed devices"
        )
        assert len(report.orphaned_clients) == 5, "one row per (server, client) pair"

        # Every orphan names the server that knows it, or the report is unactionable.
        assert {client.server for client in report.orphaned_clients} == {
            "ise-pan-01",
            "fac-campus-01",
            "radius-01",
        }

    async def test_devices_inventory_knows_and_the_servers_do_not(
        self, session: AsyncSession, lab: dict[str, Device]
    ) -> None:
        """The reverse direction, and the distinction inside it.

        `wlc-9800-01` configures a RADIUS server and appears on no client list, which is
        a contradiction — something is authenticating, or failing to, against a server
        that has never heard of it. `branch-sw-42` is merely unknown. Both are reported;
        `configured_for_aaa` is what separates a live misconfiguration from a gap in
        collection, and a UI that lost that flag would page someone about the wrong one.

        The four AAA servers must not appear here at all: a RADIUS server is not expected
        on its own client list.
        """
        report = await AaaCorrelationService(session).correlate()
        unregistered = {device.hostname: device for device in report.unregistered_devices}

        assert set(unregistered) == {"wlc-9800-01", "branch-sw-42"}
        assert unregistered["wlc-9800-01"].configured_for_aaa is True
        assert unregistered["branch-sw-42"].configured_for_aaa is False

    async def test_aaa_servers_nobody_assesses(
        self, session: AsyncSession, lab: dict[str, Device]
    ) -> None:
        """Three addresses the estate authenticates against that are not in inventory.

        A RADIUS server nobody collects from is a single point of compromise for every
        credential that crosses it. `10.100.5.30` and `10.100.5.60` are the control: both
        are pointed at by lab devices and both *are* in inventory, so their absence from
        this list is what shows the check is comparing rather than listing.
        """
        report = await AaaCorrelationService(session).correlate()
        unknown = {server.address: server for server in report.unknown_servers}

        assert set(unknown) == {"10.100.5.31", "10.100.5.70", "10.100.5.32"}
        assert unknown["10.100.5.31"].used_by == ["core-sw-01"]
        assert unknown["10.100.5.70"].used_by == ["campus-wlc-01"]
        assert unknown["10.100.5.32"].kind == "radius"

        for collected in ("10.100.5.30", "10.100.5.60"):
            assert collected not in unknown, "this one is in inventory and is assessed"

    async def test_one_shared_secret_spans_two_different_products(
        self, session: AsyncSession, lab: dict[str, Device]
    ) -> None:
        """The reuse the fixtures were built to contain.

        `campus_radius.json` and `campus_tacplus.conf` configure the same key, so the
        fingerprint appears on both a FreeRADIUS and a tac_plus server. One disclosure is
        four devices, and finding that requires comparing across servers rather than
        within one — which is why this is correlation and not a per-device check.
        """
        report = await AaaCorrelationService(session).correlate()

        assert len(report.reused_secrets) == 1
        reuse = report.reused_secrets[0]

        assert reuse.used_by == [
            "radius-01/branch-rtr-07",
            "radius-01/campus-wlc-01",
            "radius-01/core-sw-01",
            "tacacs-01/core-sw-01",
        ]
        assert reuse.count == 4
        assert len(reuse.server_ids) == 2, "the finding must anchor to both servers"

        # The digest is a fingerprint, never the key. FR-COL-13 depends on this, and it
        # is one substitution away from being false — a "fingerprint" that was the key
        # would correlate exactly as well and would put every shared secret in the estate
        # into the API response.
        assert SHARED_KEY not in reuse.fingerprint
        assert all(character in "0123456789abcdef" for character in reuse.fingerprint)

    async def test_masked_secrets_are_unknown_rather_than_unique(
        self, session: AsyncSession, lab: dict[str, Device]
    ) -> None:
        """Six clients whose secret their server will not show.

        ISE and FortiAuthenticator both return `********`, so reuse is unanswerable for
        their clients. Counting those six as "not reused" would report a clean estate on
        the strength of data nobody has — FR-AAA-05 requires the distinction, and this is
        the assertion that makes the requirement true rather than intended.
        """
        report = await AaaCorrelationService(session).correlate()

        assert report.secrets_not_exposable == 6, "three clients each on ISE and FAC"
        assert any("does not expose" in note for note in report.limitations), (
            "the report must say so on its face, not only in the count"
        )

    async def test_the_protocol_panel_unions_the_servers_and_flags_the_weak(
        self, session: AsyncSession, lab: dict[str, Device]
    ) -> None:
        """What the estate will accept, with the weak ones first.

        MS-CHAPv2 is deliberately in the not-weak set. It is the one every estate still
        runs, and a check that swept it up with MS-CHAPv1 would produce a finding nobody
        can action and train its readers to ignore the panel.
        """
        posture = await AaaPostureService(session).build()
        protocols = {p.name: p for p in posture.accepted_protocols}

        assert set(protocols) == {
            "CHAP",
            "EAP-MD5",
            "EAP-TLS",
            "LEAP",
            "MAB",
            "MS-CHAPv1",
            "MS-CHAPv2",
            "PAP",
            "PEAP",
        }
        assert set(posture.weak_protocols_in_use) == {
            "CHAP",
            "EAP-MD5",
            "LEAP",
            "MS-CHAPv1",
            "PAP",
        }
        assert protocols["MS-CHAPv2"].weak is False
        assert protocols["EAP-TLS"].weak is False

        # Weak first: the reason to open this panel is the weak ones.
        assert [p.weak for p in posture.accepted_protocols][:5] == [True] * 5

        # PAP names every server that will accept it, so the panel is actionable.
        assert protocols["PAP"].servers == ["fac-campus-01", "ise-pan-01", "radius-01"]

    async def test_the_certificate_timeline_states_where_it_is_blind(
        self, session: AsyncSession, lab: dict[str, Device]
    ) -> None:
        """Five certificates, one undated, and two servers contributing none.

        A timeline is a promise that what is not on it is not coming. FreeRADIUS and
        tac_plus contribute no certificate to the NCM, so the timeline is blind to them,
        and saying so is the difference between a complete picture and one that looks
        complete. `pxgrid-node` carries an expiry nothing could interpret and is counted
        rather than dropped — an unreadable date is not a distant one.
        """
        posture = await AaaPostureService(session).build()
        timeline = posture.certificates

        assert timeline.total == 5, "three from ISE, two from FortiAuthenticator"
        assert timeline.undated == 1, "pxgrid-node has no readable expiry"
        assert timeline.servers_without_certificates == ["radius-01", "tacacs-01"]

        # The two 2025 certificates are permanently in the past, so this cannot rot.
        expired = {entry.name for entry in timeline.entries if (entry.days_remaining or 0) < 0}
        assert "legacy-portal" in expired
        assert timeline.expired >= 2

        # Undated entries sort last but stay present: they belong at the bottom of a list
        # read top-down, and absent from it they would read as "nothing to see".
        assert timeline.entries[-1].days_remaining is None

        assert any("blind" in note for note in posture.limitations)

    async def test_the_number_the_ui_receives_is_the_number_the_service_computed(
        self,
        session: AsyncSession,
        client: AsyncClient,
        lab: dict[str, Device],
        analyst_user: User,
        authenticate,
    ) -> None:
        """The last link: coverage survives the trip through the API unchanged.

        Asserted because this is where a percentage is most likely to acquire a
        well-meaning `or 0` on its way to a UI that would rather not render a null.
        """
        authenticate(analyst_user)

        posture = await AaaPostureService(session).build()
        body = (await client.get(POSTURE)).json()

        assert body["coverage_percentage"] == posture.coverage_percentage == 50
        assert body["devices_total"] == 9
        assert body["devices_not_evaluated"] == 1
        assert body["correlation"]["servers_examined"] == 4
        assert len(body["correlation"]["orphaned_clients"]) == 5
        assert body["certificates"]["servers_without_certificates"] == ["radius-01", "tacacs-01"]

        # Every shared secret in the lab, absent from the response that renders it. The
        # correlation is the one place a real key could plausibly leak, because reuse is
        # the only analysis that has to touch the key material to reach its answer.
        rendered = (await client.get(CORRELATION)).text
        for secret in LAB_SECRETS:
            assert secret not in rendered, f"{secret!r} reached the API response"


# ══════════════ the answer the report must refuse to give ════════════════════


class TestPhase5AcceptanceRefusals:
    """Coverage over an estate nobody collected from.

    The acceptance criterion is that the report is *correct*, and the most damaging way
    for it to be wrong is not an off-by-one — it is a confident zero. Both numbers below
    would be catastrophic as `0` and are correct as "unknown".
    """

    async def test_no_snapshots_means_unknown_coverage_not_zero_percent(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        await InventoryService(session).create_device(
            mgmt_ip="10.10.10.10",
            actor=actor,
            hostname="never-collected",
            vendor=Vendor.CISCO,
            platform="cisco_ios",
            device_class=DeviceClass.SWITCH,
        )

        report = await AaaCorrelationService(session).correlate()

        assert report.coverage.devices_total == 1
        assert report.coverage.percentage is None, "0% and 'we have not looked' are different"
        assert summarise(report)["coverage_percentage"] is None
        assert any("no honest denominator" in note for note in report.limitations)

    async def test_no_aaa_server_means_registration_is_not_analysed(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """Without a server, every device trivially appears on no client list.

        Reporting that as "every device is unregistered" would be a false positive across
        the entire estate — the single worst output this analysis could produce, and the
        one it is easiest to produce by accident.
        """
        device = await InventoryService(session).create_device(
            mgmt_ip="10.10.10.11",
            actor=actor,
            hostname="lonely-switch",
            vendor=Vendor.CISCO,
            platform="cisco_ios",
            device_class=DeviceClass.SWITCH,
        )
        text = (FIXTURES / "cisco/ios/17.9/hardened_switch.cfg").read_text(encoding="utf-8")
        ncm = get_parser("cisco_ios").parse(ParseContext(text=text))
        digest = sha256(f"{device.id}lonely".encode()).hexdigest()
        session.add(
            Snapshot(
                org_id=device.org_id,
                device_id=device.id,
                ncm=ncm.model_dump(mode="json"),
                config_redacted="",
                config_hash=digest,
                normalized_hash=digest,
            )
        )
        await session.flush()

        report = await AaaCorrelationService(session).correlate()

        assert report.servers_examined == 0
        assert report.registration_analysed is False
        assert report.unregistered_devices == [], "the absence of the question, not its answer"
        assert any("not a finding that every device" in note for note in report.limitations)

        # The device-side half still works: coverage is answerable from the device alone.
        assert report.coverage.percentage == 100
