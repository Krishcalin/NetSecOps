"""Building and removing the demonstration estate.

See :mod:`netsecops.demo` for what the estate is and why it is shaped this way. This
module is the mechanics, and its one rule is that it takes no shortcuts: every device is
created through ``InventoryService``, every configuration through the same
``ingest_config`` path an operator's upload uses (FR-COL-11), and every finding through
``AssessmentService``. There is no demo-only write path, because a demo-only write path
is how a demonstration comes to show something the product does not do.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.crypto import SecretVault
from netsecops.core.errors import ValidationProblem
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, DeviceTag, Finding, Tag
from netsecops.db.models.inventory import Criticality, DeviceClass, Vendor
from netsecops.services.assessment import AssessmentService
from netsecops.services.feeds import FeedImportService
from netsecops.services.inventory import InventoryService
from netsecops.services.snapshots import SnapshotService
from netsecops.services.vuln_assessment import VulnAssessmentService

log = structlog.get_logger(__name__)

#: Every device the seeder creates carries this tag, and the purge removes exactly the
#: devices that carry it. Identification by tag rather than by hostname prefix because a
#: tag survives somebody renaming a device while evaluating.
DEMO_TAG = "netsecops-demo"


@dataclass(frozen=True, slots=True)
class DemoDevice:
    """One device in the demonstration estate."""

    hostname: str
    mgmt_ip: str
    platform: str
    vendor: Vendor
    device_class: DeviceClass
    config: str
    criticality: Criticality
    #: Why this device is in the estate. Written onto the device's notes, so somebody
    #: clicking through the inventory can see what each one is for without the docs.
    purpose: str


@dataclass(frozen=True, slots=True)
class DemoFeed:
    """One advisory bundle shipped with the demo."""

    bundle: str
    feed: str
    vendor: str | None = None
    product: str | None = None


DEMO_DEVICES: tuple[DemoDevice, ...] = (
    DemoDevice(
        hostname="demo-access-sw-01",
        mgmt_ip="10.10.10.5",
        platform="cisco_ios",
        vendor=Vendor.CISCO,
        device_class=DeviceClass.SWITCH,
        config="demo-access-sw-01.cfg",
        criticality=Criticality.MEDIUM,
        purpose=(
            "An ordinary access switch that was stood up quickly and never revisited. "
            "It is here for the findings: telnet, default SNMP communities, no AAA, "
            "no session timeout, passwords in the clear."
        ),
    ),
    DemoDevice(
        hostname="demo-core-sw-01",
        mgmt_ip="10.10.10.1",
        platform="cisco_nxos",
        vendor=Vendor.CISCO,
        device_class=DeviceClass.SWITCH,
        config="demo-core-sw-01.cfg",
        criticality=Criticality.HIGH,
        purpose=(
            "The middle of the path, and hardened. It carries no rulebase, so a path "
            "crossing it reports 'no decision' rather than 'allowed' — a device that "
            "inspected nothing is not a control that was checked."
        ),
    ),
    DemoDevice(
        hostname="demo-edge-fw-01",
        mgmt_ip="10.0.1.2",
        platform="cisco_asa",
        vendor=Vendor.CISCO,
        device_class=DeviceClass.FIREWALL,
        config="demo-edge-fw-01.cfg",
        criticality=Criticality.CRITICAL,
        purpose=(
            "Permits the traffic, and translates it. Because the path continues past "
            "this device, the firewalls after it were asked about the addresses in the "
            "query rather than the ones the packet carried — so the verdict is "
            "'partially allowed' with this device named. Its version is also old "
            "enough for the shipped advisories to match."
        ),
    ),
    DemoDevice(
        hostname="demo-dmz-fw-01",
        mgmt_ip="10.0.2.2",
        platform="panos",
        vendor=Vendor.PALOALTO,
        device_class=DeviceClass.FIREWALL,
        config="demo-dmz-fw-01.xml",
        criticality=Criticality.CRITICAL,
        purpose=(
            "The rulebase worth reading: a deny sitting above an allow that can never "
            "match, a disabled migration rule nobody removed, an any-any permit with "
            "logging off, and a duplicate address object. It translates too — and "
            "because the path ends here, that costs nothing."
        ),
    ),
)

DEMO_FEEDS: tuple[DemoFeed, ...] = (
    DemoFeed(bundle="cisco_asa_cves.json", feed="demo-nvd"),
    DemoFeed(bundle="pan_advisory.json", feed="demo-csaf"),
    DemoFeed(
        bundle="cisco_asa_eol.json",
        feed="demo-eol",
        # EoL bundles carry release cycles and nothing saying whose they are, so the
        # importer has to be told rather than allowed to guess.
        vendor="cisco",
        product="adaptive_security_appliance_software",
    ),
)


@dataclass
class SeedReport:
    """What the seed actually produced, so the CLI can report facts rather than a spinner."""

    devices: int = 0
    snapshots: int = 0
    checks_run: int = 0
    #: Every finding now open in the estate, counted from the table at the end rather
    #: than summed from each assessment's `findings_opened`. Those two differ — the
    #: vulnerability matcher and the rulebase analysis also open findings — and the
    #: number the CLI prints has to be the number the console will show, or the first
    #: thing the demo does is disagree with itself.
    findings: int = 0
    advisories: int = 0
    vulnerability_matches: int = 0
    notes: list[str] = field(default_factory=list)


def _read(name: str) -> str:
    """Read a shipped demo file out of the installed package.

    `importlib.resources` rather than a path relative to ``__file__`` because the
    configurations have to be readable from inside the container image, where the
    package may be installed anywhere and is not a source checkout.
    """
    return (resources.files("netsecops.demo") / "configs" / name).read_text(encoding="utf-8")


def _read_feed(name: str) -> bytes:
    return (resources.files("netsecops.demo") / "feeds" / name).read_bytes()


def demo_actor() -> Principal:
    """The principal the seeder acts as.

    A real id so audit rows reference something stable, and Super Admin because seeding
    creates devices, imports advisories and writes findings. Named `demo-seed` in the
    audit log rather than borrowing a human's account: everything this writes should be
    attributable to the seeder, not to whoever ran it.
    """
    return Principal(
        id=uuid.UUID("00000000-0000-0000-0000-0000000de110"),
        username="demo-seed",
        roles=frozenset({Role.SUPER_ADMIN}),
        scope=Scope.all(),
    )


async def _existing_devices(session: AsyncSession, org_id: int) -> list[Device]:
    return list(
        (await session.execute(select(Device).where(Device.org_id == org_id))).scalars().all()
    )


async def _demo_device_ids(session: AsyncSession, org_id: int) -> set[uuid.UUID]:
    """The devices carrying the demo tag.

    Resolved by joining through `device_tags`, because `Device.tags` holds association
    rows rather than the tags themselves — reading a name off one gets an attribute that
    is not there.
    """
    rows = await session.execute(
        select(DeviceTag.device_id)
        .join(Tag, Tag.id == DeviceTag.tag_id)
        .where(Tag.name == DEMO_TAG, Tag.org_id == org_id)
    )
    return set(rows.scalars().all())


async def seed_demo_estate(
    session: AsyncSession,
    *,
    org_id: int = 1,
    force: bool = False,
    vault: SecretVault | None = None,
) -> SeedReport:
    """Create the demonstration estate and assess it.

    Refuses if the inventory holds any device the seeder did not create, unless `force`
    is given. That guard is the whole reason this is safe to ship in the same binary as
    the product: the failure it prevents is demonstration devices appearing in a real
    estate's inventory, where they would be reported on, counted in compliance
    percentages, and eventually collected from.
    """
    actor = demo_actor()
    report = SeedReport()

    existing = await _existing_devices(session, org_id)
    demo_ids = await _demo_device_ids(session, org_id)
    foreign = [device for device in existing if device.id not in demo_ids]
    if foreign and not force:
        raise ValidationProblem(
            f"This installation already holds {len(foreign)} device(s) that the demo "
            "seeder did not create, so it looks like a real inventory rather than an "
            "empty one. Seeding would add demonstration devices alongside them. Re-run "
            "with --force if that is genuinely what you want."
        )

    inventory = InventoryService(session)
    # The vault is threaded through rather than built from global config, because the
    # configurations are stored as sealed artefacts exactly as a collection's output is.
    # A demo that skipped that would be storing evidence through a path the product does
    # not use.
    snapshots = SnapshotService(session, vault=vault)
    assessment = AssessmentService(session)

    already = {device.hostname for device in existing if device.id in demo_ids}

    for spec in DEMO_DEVICES:
        if spec.hostname in already:
            report.notes.append(f"{spec.hostname} already existed and was left alone.")
            continue

        device = await inventory.create_device(
            mgmt_ip=spec.mgmt_ip,
            actor=actor,
            hostname=spec.hostname,
            vendor=spec.vendor,
            platform=spec.platform,
            device_class=spec.device_class,
            criticality=spec.criticality,
            tags=[DEMO_TAG],
            notes=f"Demonstration device. {spec.purpose}",
            org_id=org_id,
        )
        report.devices += 1

        await snapshots.ingest_config(
            device,
            config_text=_read(spec.config),
            # The filename records provenance honestly: this configuration came from the
            # shipped demo, not from the device.
            filename=f"demo:{spec.config}",
            actor=actor,
        )
        report.snapshots += 1

        snapshot = await snapshots.latest(device)
        if snapshot is None:
            # Should not happen — it was just ingested — but reporting it beats a seed
            # that silently produces a device with no findings.
            report.notes.append(f"{spec.hostname} stored no snapshot, so it was not assessed.")
            continue

        outcome = await assessment.assess(device, snapshot)
        report.checks_run += len(outcome.results)

    await _seed_feeds(session, actor=actor, report=report, org_id=org_id)

    report.findings = int(
        (
            await session.execute(
                select(func.count()).select_from(Finding).where(Finding.org_id == org_id)
            )
        ).scalar_one()
    )

    return report


async def _seed_feeds(
    session: AsyncSession, *, actor: Principal, report: SeedReport, org_id: int
) -> None:
    """Import the shipped advisories and match them against the estate.

    Separate from the device loop because matching needs every device's snapshot in
    place first — an advisory imported halfway through would be weighed against half an
    estate, and the count in the report would be a number nobody could reproduce.
    """
    feeds = FeedImportService(session, org_id=org_id)

    for spec in DEMO_FEEDS:
        try:
            result = await feeds.import_bundle(
                _read_feed(spec.bundle),
                feed=spec.feed,
                actor=actor,
                vendor=spec.vendor,
                product=spec.product,
            )
        except Exception as exc:
            # The devices and findings above are the product; advisories are an
            # enrichment. A feed that fails to import is worth saying out loud and is
            # not worth discarding a working demonstration over.
            report.notes.append(f"The {spec.feed} bundle could not be imported: {exc}")
            continue
        report.advisories += result.advisories

    assessments = await VulnAssessmentService(session, org_id=org_id).assess_all()
    report.vulnerability_matches = sum(len(item.matches) for item in assessments)


async def purge_demo_estate(session: AsyncSession, *, org_id: int = 1) -> int:
    """Remove every device the seeder created, and nothing else.

    Identified by tag, so a device somebody added by hand during an evaluation survives
    — the purge is for clearing the demonstration before real onboarding, and deleting
    an operator's first real device at that moment would be the worst possible time.

    Advisories are left in place: they are public data about the world rather than
    anything about this estate, and an evaluator who imported real feeds alongside the
    demo would not thank us for removing them.
    """
    inventory = InventoryService(session)
    actor = demo_actor()
    demo_ids = await _demo_device_ids(session, org_id)

    removed = 0
    for device in await _existing_devices(session, org_id):
        if device.id not in demo_ids:
            continue
        await inventory.delete_device(device, actor=actor)
        removed += 1

    log.info("demo.purged", devices=removed)
    return removed


def config_path(name: str) -> Path:
    """Where a shipped demo configuration lives, for tooling that wants the file."""
    return Path(str(resources.files("netsecops.demo") / "configs" / name))
