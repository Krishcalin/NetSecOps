"""The demonstration estate (P5 — commercial posture).

This is the evaluation path: a prospective user runs one command and gets a console with
real findings in it, without a device, a credential or a change window. So the thing
these tests protect is not that the seeder runs — it is that what it produces is worth
looking at. A demo that seeds four devices and finds nothing is worse than no demo,
because it says the product finds nothing.

They also pin the safety guard. The seeder ships in the same binary as the product and
writes devices into a real inventory; the failure to prevent is demonstration devices
appearing in an estate somebody later reports compliance percentages on.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from netsecops.core.errors import ValidationProblem
from netsecops.db.models import Device, Finding, Snapshot
from netsecops.demo import DEMO_DEVICES, DEMO_TAG, purge_demo_estate, seed_demo_estate
from netsecops.topology.path import PolicyVerdict, RoutingConfidence, walk
from tests.conftest import make_user

pytestmark = pytest.mark.asyncio


async def _count(session, model) -> int:
    return int((await session.execute(select(func.count()).select_from(model))).scalar_one())


class TestWhatTheDemoProduces:
    async def test_it_seeds_every_device_with_a_snapshot(self, session, vault) -> None:
        report = await seed_demo_estate(session, vault=vault)

        assert report.devices == len(DEMO_DEVICES)
        assert report.snapshots == len(DEMO_DEVICES)
        assert await _count(session, Device) == len(DEMO_DEVICES)
        assert await _count(session, Snapshot) == len(DEMO_DEVICES)

    async def test_every_configuration_parses_into_something(self, session, vault) -> None:
        """A config that fails to parse stores a snapshot with an empty NCM, and the
        device then silently passes every check. That reads as a clean device."""
        await seed_demo_estate(session, vault=vault)

        snapshots = (await session.execute(select(Snapshot))).scalars().all()
        for snapshot in snapshots:
            assert snapshot.ncm, "a demo configuration parsed into an empty NCM"
            assert len(snapshot.ncm) > 1

    async def test_it_produces_findings_worth_looking_at(self, session, vault) -> None:
        """The whole point. An evaluator's first screen is the findings list."""
        report = await seed_demo_estate(session, vault=vault)

        assert report.checks_run > 0
        assert report.findings >= 10, (
            f"the demo estate produced only {report.findings} findings, which does not "
            "demonstrate anything"
        )
        assert await _count(session, Finding) == report.findings

    async def test_the_weak_switch_is_the_worst_device(self, session, vault) -> None:
        """It is in the estate to be bad. If something else out-scores it the estate has
        drifted from what the documentation says it shows."""
        await seed_demo_estate(session, vault=vault)

        rows = (await session.execute(select(Device))).scalars().all()
        by_id = {device.id: device.hostname for device in rows}
        findings = (await session.execute(select(Finding))).scalars().all()

        counts: dict[str, int] = {}
        for finding in findings:
            counts[by_id.get(finding.device_id, "?")] = (
                counts.get(by_id.get(finding.device_id, "?"), 0) + 1
            )

        assert counts, "no device carried a finding"
        worst = max(counts, key=lambda name: counts[name])
        assert worst == "demo-access-sw-01", f"expected the weak switch to be worst, got {counts}"


class TestThePathItDemonstrates:
    async def test_a_user_reaches_the_dmz_web_server_and_the_answer_is_honest(
        self, session, vault
    ) -> None:
        """The headline query, and the reason the estate is shaped this way.

        Every firewall on the path permits it and the trace reaches the destination —
        but it crossed a device carrying NAT rules on the way, so the firewalls after
        that device were asked about the addresses in the query rather than the ones the
        packet was carrying. `allowed` would be a claim the data does not support.
        """
        await seed_demo_estate(session, vault=vault)
        graph = await build_graph_from_estate(session)

        result = walk(graph, source="10.10.10.50", destination="10.20.0.10", port=443)

        assert result.routing is RoutingConfidence.ROUTED
        assert result.policy is PolicyVerdict.PARTIALLY_ALLOWED
        assert result.translated_at, "the NAT caveat did not fire on a path that crosses NAT"
        assert "demo-edge-fw-01" in result.translated_at[0]
        assert [hop.hostname for hop in result.hops][:2] == [
            "demo-access-sw-01",
            "demo-core-sw-01",
        ]

    async def test_the_core_switch_reports_no_decision(self, session, vault) -> None:
        """It carries no rulebase. A router that inspected nothing must not read as a
        control that allowed something."""
        await seed_demo_estate(session, vault=vault)
        graph = await build_graph_from_estate(session)

        result = walk(graph, source="10.10.10.50", destination="10.20.0.10", port=443)
        core = next(hop for hop in result.hops if hop.hostname == "demo-core-sw-01")

        assert core.action is None

    async def test_ssh_to_the_same_host_is_blocked_and_names_the_firewall(
        self, session, vault
    ) -> None:
        """The second demo query. A verdict nobody can act on is barely better than a
        wrong one, so the answer has to name the device that denied it."""
        await seed_demo_estate(session, vault=vault)
        graph = await build_graph_from_estate(session)

        result = walk(graph, source="10.10.10.50", destination="10.20.0.10", port=22)

        assert result.policy is PolicyVerdict.BLOCKED
        assert result.blocked_by is not None
        assert result.blocked_by.hostname == "demo-dmz-fw-01"


class TestTheVulnerabilityHalf:
    async def test_the_shipped_advisories_import(self, session, vault) -> None:
        report = await seed_demo_estate(session, vault=vault)

        assert not [note for note in report.notes if "could not be imported" in note], report.notes
        assert report.advisories > 0

    async def test_the_edge_firewall_matches_something(self, session, vault) -> None:
        """9.18(2) is chosen so the matcher has a real answer. If this stops matching,
        either the sample or the device version has drifted and the demo quietly stops
        demonstrating the one capability the competitors do not have at all."""
        report = await seed_demo_estate(session, vault=vault)

        assert report.vulnerability_matches > 0


class TestItRefusesToDamageARealInstallation:
    async def test_it_stops_when_a_device_it_did_not_create_exists(
        self, session, vault, user_factory
    ) -> None:
        from netsecops.core.rbac import Principal, Scope
        from netsecops.services.inventory import InventoryService

        operator = await make_user(session, username="demo_guard")
        await InventoryService(session).create_device(
            mgmt_ip="192.0.2.77",
            actor=Principal(
                id=operator.id, username=operator.username, roles=frozenset(), scope=Scope.all()
            ),
            hostname="a-real-device",
        )

        with pytest.raises(ValidationProblem, match="real inventory"):
            await seed_demo_estate(session, vault=vault)

        assert await _count(session, Device) == 1, "the refusal must write nothing"

    async def test_force_overrides_it(self, session, vault) -> None:
        from netsecops.core.rbac import Principal, Scope
        from netsecops.services.inventory import InventoryService

        operator = await make_user(session, username="demo_force")
        await InventoryService(session).create_device(
            mgmt_ip="192.0.2.78",
            actor=Principal(
                id=operator.id, username=operator.username, roles=frozenset(), scope=Scope.all()
            ),
            hostname="a-real-device",
        )

        report = await seed_demo_estate(session, vault=vault, force=True)

        assert report.devices == len(DEMO_DEVICES)

    async def test_seeding_twice_adds_nothing(self, session, vault) -> None:
        """An evaluator who runs it again should not get a duplicate estate, and the
        second run must not trip its own guard on the devices the first one made."""
        await seed_demo_estate(session, vault=vault)
        second = await seed_demo_estate(session, vault=vault)

        assert second.devices == 0
        assert len(second.notes) == len(DEMO_DEVICES)
        assert await _count(session, Device) == len(DEMO_DEVICES)


class TestThePurge:
    async def test_it_removes_exactly_what_was_seeded(self, session, vault) -> None:
        await seed_demo_estate(session, vault=vault)

        removed = await purge_demo_estate(session)

        assert removed == len(DEMO_DEVICES)
        assert await _count(session, Device) == 0

    async def test_it_leaves_a_real_device_alone(self, session, vault) -> None:
        """The purge runs at exactly the moment somebody is onboarding their first real
        device. Deleting it then would be the worst possible time."""
        from netsecops.core.rbac import Principal, Scope
        from netsecops.services.inventory import InventoryService

        await seed_demo_estate(session, vault=vault)
        operator = await make_user(session, username="demo_keeper")
        await InventoryService(session).create_device(
            mgmt_ip="192.0.2.79",
            actor=Principal(
                id=operator.id, username=operator.username, roles=frozenset(), scope=Scope.all()
            ),
            hostname="their-first-real-device",
        )

        removed = await purge_demo_estate(session)

        assert removed == len(DEMO_DEVICES)
        remaining = (await session.execute(select(Device))).scalars().all()
        assert [device.hostname for device in remaining] == ["their-first-real-device"]


class TestTheEstateIsIdentifiable:
    async def test_every_device_carries_the_demo_tag(self, session, vault) -> None:
        """Somebody who inherits this installation must be able to tell at a glance which
        devices are not real."""
        from netsecops.db.models import DeviceTag, Tag

        await seed_demo_estate(session, vault=vault)

        tagged = (
            await session.execute(
                select(func.count())
                .select_from(DeviceTag)
                .join(Tag, Tag.id == DeviceTag.tag_id)
                .where(Tag.name == DEMO_TAG)
            )
        ).scalar_one()
        assert int(tagged) == len(DEMO_DEVICES)

    async def test_the_notes_say_what_each_device_is_for(self, session, vault) -> None:
        await seed_demo_estate(session, vault=vault)

        devices = (await session.execute(select(Device))).scalars().all()
        for device in devices:
            assert device.notes and device.notes.startswith("Demonstration device.")


async def build_graph_from_estate(session):
    """Build the topology graph the same way the API does."""
    from netsecops.services.topology import TopologyService

    return await TopologyService(session).graph()
