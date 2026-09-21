"""A platform means three different things, and they are not interchangeable.

Found 2026-09-20 by sweeping every shipped fixture for silent emptiness. Three registries
key off a platform name and each answers a different question:

* `POLICIES` — what NetSecOps is permitted to *send* (SRS §8.2)
* `PROFILES` — what it actually sends during a collection
* `PARSERS`  — how it reads the answer

`Device.policy_platform` belongs to the first and was named `effective_platform` and used
as all three plus a fourth, the check-applicability platform. Enabling `allow_expert` on
a Check Point gateway — a documented, supported option — therefore broke it twice over:
no parser is registered for `checkpoint_gaia_expert`, so it could no longer store a
snapshot; and the shipped library writes `platforms: [checkpoint_gaia]` against an exact
set-membership test, so every Check Point check reported Not Applicable.

The second is the dangerous one. Existing findings stayed open — only a PASS resolves one
— but nothing new was ever evaluated, and a gateway that is not being assessed looks
exactly like a gateway with nothing wrong.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsecops.adapters.children import INTERPRETERS
from netsecops.adapters.policies import POLICIES
from netsecops.adapters.profiles import PROFILES
from netsecops.checks.engine import Outcome
from netsecops.core.errors import ValidationProblem
from netsecops.core.rbac import Principal, Scope
from netsecops.db.models.inventory import Device, Vendor
from netsecops.parsers.registry import PARSERS
from netsecops.services.assessment import AssessmentService, get_registry
from netsecops.services.inventory import InventoryService
from netsecops.services.snapshots import SnapshotService
from tests.conftest import make_user

FIXTURES = Path(__file__).parent / "fixtures"

# Applied per class rather than per module: most of what this file asserts is about the
# registries, which are plain dictionaries and need no event loop. A module-wide mark
# tags those synchronous tests too, and pytest-asyncio warns about every one.

#: Escapes, not platforms. Derived from a base platform plus a per-device flag, and
#: meaningful only to the read-only allow-list.
ESCAPES = {"checkpoint_gaia_expert", "linux_aaa_sudo"}


class TestThePolicyKeyIsOnlyAPolicyKey:
    def test_an_escape_resolves_for_policy(self) -> None:
        device = Device(mgmt_ip="192.0.2.1", platform="checkpoint_gaia", allow_expert=True)

        assert device.policy_platform == "checkpoint_gaia_expert"

    def test_but_the_device_still_parses_as_its_own_platform(self) -> None:
        """The regression. `get_parser("checkpoint_gaia_expert")` raises, so a device
        that had been collecting happily could no longer store a snapshot the moment
        somebody turned expert mode on."""
        device = Device(mgmt_ip="192.0.2.1", platform="checkpoint_gaia", allow_expert=True)

        assert device.platform in PARSERS
        assert device.policy_platform not in PARSERS

    def test_every_escape_is_a_policy_and_nothing_else(self) -> None:
        """Pins the asymmetry rather than the two names: an escape that acquired a
        profile or a parser would mean somebody had started treating it as a platform."""
        for escape in ESCAPES:
            assert escape in POLICIES
            assert escape not in PROFILES, f"{escape} should never be collected from directly"
            assert escape not in PARSERS, f"{escape} is not a configuration format"


class TestTheCheckLibraryTargetsBasePlatforms:
    def test_no_shipped_check_targets_an_escape(self) -> None:
        """Applicability is an exact set membership test, so a check naming an escape
        would apply to a device only while the flag was on — and every check naming the
        base platform would stop applying at the same moment."""
        for definition in get_registry().definitions():
            for platform in definition.applicability.platforms:
                assert platform not in ESCAPES, f"{definition.id} targets the escape {platform}"


@pytest.mark.asyncio
class TestExpertModeDoesNotBreakTheDevice:
    """The regression end to end, through the two call sites that misused the key.

    Enabling expert mode is a supported, documented act (ADR-002). Before this, doing it
    stopped the gateway storing snapshots at all, and any re-assessment of an existing
    one evaluated zero checks.
    """

    @pytest.fixture
    async def gateway(self, session):
        user = await make_user(session, username="expert_mode")
        actor = Principal(id=user.id, username=user.username, roles=frozenset(), scope=Scope.all())
        device = await InventoryService(session).create_device(
            mgmt_ip="192.0.2.90",
            actor=actor,
            hostname="cp-gw-expert",
            platform="checkpoint_gaia",
            vendor=Vendor.CHECKPOINT,
        )
        # The act under test: a per-device escape, turned on after onboarding.
        device.allow_expert = True
        await session.flush()
        return device, actor

    async def test_it_can_still_store_a_snapshot(self, session, vault, gateway) -> None:
        device, actor = gateway
        config = (FIXTURES / "checkpoint/gaia/R81.20/cp_gw_edge_01.txt").read_text(encoding="utf-8")

        result = await SnapshotService(session, vault=vault).ingest_config(
            device, config_text=config, filename="cp.txt", actor=actor
        )

        assert result is not None
        snapshot = await SnapshotService(session, vault=vault).latest(device)
        assert snapshot is not None and snapshot.ncm

    async def test_its_checks_are_still_evaluated(self, session, vault, gateway) -> None:
        """The silent half. Applicability is an exact match against
        `platforms: [checkpoint_gaia]`, so passing the escape made every Check Point
        check Not Applicable — a gateway assessed to nothing, which reads as a gateway
        with nothing wrong."""
        device, actor = gateway
        config = (FIXTURES / "checkpoint/gaia/R81.20/cp_gw_edge_01.txt").read_text(encoding="utf-8")
        snapshots = SnapshotService(session, vault=vault)
        await snapshots.ingest_config(device, config_text=config, filename="cp.txt", actor=actor)
        snapshot = await snapshots.latest(device)
        assert snapshot is not None

        outcome = await AssessmentService(session).assess(device, snapshot)

        # Specifically the platform-targeted ones. The `common` pack names no platform
        # and stays applicable whatever is passed, so asserting "something was
        # evaluated" passes with the defect fully restored — which is what a mutation
        # check of the first version of this test showed.
        registry = get_registry()
        targeted = {
            definition.id
            for definition in registry.definitions()
            if "checkpoint_gaia" in definition.applicability.platforms
        }
        assert targeted, "the library no longer has Check Point checks to assert about"

        evaluated = [
            result
            for result in outcome.results
            if result.check_id in targeted and result.outcome is not Outcome.NOT_APPLICABLE
        ]
        assert evaluated, (
            "every Check Point check reported Not Applicable, so expert mode silently "
            "stopped the gateway being assessed"
        )


@pytest.mark.asyncio
class TestOnboardingRejectsWhatItCannotCollect:
    """`_validate_platform` checked only that a policy existed, which is the narrowest of
    the three. Five platforms passed validation and failed at first collection."""

    @pytest.fixture
    async def service(self, session):
        return InventoryService(session)

    @pytest.fixture
    async def actor(self, session) -> Principal:
        user = await make_user(session, username="platform_keys")
        return Principal(id=user.id, username=user.username, roles=frozenset(), scope=Scope.all())

    @pytest.mark.parametrize(
        "platform", ["cisco_iosxr", "cisco_ftd_fmc", "linux_aaa", "checkpoint_gaia_expert"]
    )
    async def test_a_platform_with_no_way_to_collect_is_refused(
        self, service, actor, platform: str
    ) -> None:
        with pytest.raises(ValidationProblem, match="nothing that can collect"):
            await service.create_device(mgmt_ip="192.0.2.50", actor=actor, platform=platform)

    async def test_a_manager_is_still_accepted(self, service, actor) -> None:
        """A FortiManager is enumerated for the devices it manages rather than collected
        from, so having no collection profile is correct for it and must not be read as
        the same defect."""
        device = await service.create_device(
            mgmt_ip="192.0.2.51", actor=actor, platform="fortimanager"
        )

        assert device.platform == "fortimanager"

    @pytest.mark.parametrize("platform", ["cisco_ios", "panos", "fortios", "freeradius"])
    async def test_an_ordinary_platform_is_unaffected(self, service, actor, platform: str) -> None:
        device = await service.create_device(
            mgmt_ip=f"192.0.2.{60 + len(platform)}", actor=actor, platform=platform
        )

        assert device.platform == platform


class TestTheRegistriesAgreeWhereTheyMust:
    def test_anything_with_a_collection_profile_can_be_parsed(self) -> None:
        """Collecting from a platform nothing can read stores an artefact and produces
        no NCM — the device is then assessed against an empty configuration and passes
        everything, which is the failure this whole sweep was looking for."""
        unreadable = sorted(set(PROFILES) - set(PARSERS))

        assert unreadable == [], f"collected but unparseable: {unreadable}"

    def test_anything_with_a_parser_may_be_sent_something(self) -> None:
        """A parser with no read-only policy is one nothing can legally feed."""
        unreachable = sorted(set(PARSERS) - set(POLICIES))

        assert unreachable == [], f"parseable but not collectable: {unreachable}"

    def test_every_onboardable_platform_is_usable_end_to_end(self) -> None:
        """The property the sweep actually checks: anything a device can be set to can
        be collected from and read."""
        onboardable = (set(PROFILES) | set(INTERPRETERS)) & set(POLICIES)

        for platform in sorted(onboardable):
            collectable = platform in PROFILES or platform in INTERPRETERS
            readable = platform in PARSERS or platform in INTERPRETERS
            assert collectable and readable, f"{platform} cannot be used end to end"
