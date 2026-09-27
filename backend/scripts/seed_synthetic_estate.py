#!/usr/bin/env python3
"""Seed a large synthetic estate into a development database.

    cd backend
    .venv/Scripts/python scripts/seed_synthetic_estate.py --help
    .venv/Scripts/python scripts/seed_synthetic_estate.py            # 650 devices
    .venv/Scripts/python scripts/seed_synthetic_estate.py --purge    # remove them

Development only. `netsecops.demo` is the shipped demonstration — four devices, each
chosen to show something — and this is the other thing entirely: volume, so that the
screens which only misbehave at scale get exercised before a customer finds them.

Every device is created through `InventoryService`, every configuration ingested
through `SnapshotService.ingest_config` exactly as an operator's upload is, and every
finding produced by `AssessmentService`. There is no seeder-only write path, because a
seeder-only write path fills a console with rows the product cannot actually produce.

Everything it creates carries one tag and `--purge` removes exactly that, so a
synthetic estate can be cleared without touching anything else in the database.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

# The synthetic package sits beside this file rather than inside `netsecops`, because
# it is not part of the product.
sys.path.insert(0, str(Path(__file__).parent))

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from synthetic.plan import build_plan, summarise
from synthetic.render import render

from netsecops.core.config import get_settings
from netsecops.core.crypto import SecretVault, build_vault
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, DeviceTag, Finding, Tag
from netsecops.db.models.collection import Snapshot
from netsecops.db.models.inventory import Criticality, DeviceClass, Vendor
from netsecops.services.assessment import AssessmentService
from netsecops.services.inventory import InventoryService
from netsecops.services.snapshots import SnapshotService

#: Every device this creates carries it, and `--purge` removes exactly these. By tag
#: rather than by hostname prefix, so a device somebody renames while testing is still
#: removed by the purge that created it.
SYNTHETIC_TAG = "synthetic-estate"

log = structlog.get_logger(__name__)


def actor() -> Principal:
    """Named `synthetic-seed` in the audit log rather than borrowing a real account.

    Everything this writes should be attributable to the seeder, so an audit trail
    full of synthetic devices is obviously that, and a `GET /audit` while testing does
    not look like a human did 650 things in four minutes.
    """
    return Principal(
        id=__import__("uuid").UUID("00000000-0000-0000-0000-00005eed0001"),
        username="synthetic-seed",
        roles=frozenset({Role.SUPER_ADMIN}),
        scope=Scope.all(),
    )


async def _tagged_ids(session: AsyncSession, org_id: int) -> set:
    rows = await session.execute(
        select(DeviceTag.device_id)
        .join(Tag, Tag.id == DeviceTag.tag_id)
        .where(Tag.name == SYNTHETIC_TAG, Tag.org_id == org_id)
    )
    return set(rows.scalars().all())


async def _count(session: AsyncSession, model, org_id: int) -> int:
    return int(
        (
            await session.execute(
                select(func.count()).select_from(model).where(model.org_id == org_id)
            )
        ).scalar_one()
    )


async def seed(session: AsyncSession, args: argparse.Namespace, vault: SecretVault) -> None:
    plan = build_plan(
        sites=args.sites,
        firewalls_per_site=args.firewalls // args.sites,
        routers_per_site=args.routers // args.sites,
        switches_per_site=args.switches // args.sites,
    )
    counts = summarise(plan)
    print(f"planned {counts['devices']} devices across {counts['sites']} sites:")
    for key in sorted(k for k in counts if k.startswith("platform:")):
        print(f"  {key[9:]:18} {counts[key]}")
    print()

    inventory = InventoryService(session)
    snapshots = SnapshotService(session, vault=vault)
    assessment = AssessmentService(session)
    principal = actor()

    existing = {
        row.hostname
        for row in (
            await session.execute(select(Device).where(Device.org_id == args.org))
        ).scalars()
    }

    created = ingested = assessed = skipped = 0
    empty_models: list[str] = []
    started = time.monotonic()
    total = counts["devices"]

    for site in plan:
        for node in site.nodes:
            if node.hostname in existing:
                skipped += 1
                continue

            device = await inventory.create_device(
                mgmt_ip=node.mgmt_ip,
                actor=principal,
                hostname=node.hostname,
                vendor=Vendor(node.vendor),
                platform=node.platform,
                device_class=DeviceClass(node.device_class),
                criticality=Criticality(node.criticality),
                tags=[SYNTHETIC_TAG, f"site:{site.name}", f"tier:{node.tier.value}"],
                notes=f"Synthetic device. {node.purpose}",
                org_id=args.org,
            )
            created += 1

            await snapshots.ingest_config(
                device,
                config_text=render(node),
                # Provenance stated honestly: this came from the generator, not a device.
                filename=f"synthetic:{node.platform}:{node.hostname}",
                actor=principal,
            )
            ingested += 1

            snapshot = await snapshots.latest(device)
            if snapshot is None:
                empty_models.append(node.hostname)
                continue

            # A snapshot whose model is empty is the failure worth catching here: the
            # device still appears in the inventory and contributes nothing to any
            # feature, which looks like data and is not.
            ncm = snapshot.ncm or {}
            if not ncm.get("interfaces") and node.interfaces:
                empty_models.append(node.hostname)

            if not args.no_assess:
                await assessment.assess(device, snapshot)
                assessed += 1

            done = created + skipped
            if done % 50 == 0:
                rate = done / max(time.monotonic() - started, 0.001)
                remaining = (total - done) / max(rate, 0.001)
                print(
                    f"  {done:>4}/{total}  {rate:5.1f} devices/s  "
                    f"~{remaining / 60:4.1f} min remaining"
                )
                await session.commit()

    await session.commit()
    elapsed = time.monotonic() - started

    print(f"\ncreated {created} devices, ingested {ingested} configs, assessed {assessed}")
    if skipped:
        print(f"  {skipped} already existed and were left alone")
    print(f"  in {elapsed / 60:.1f} minutes")

    if empty_models:
        print(
            f"\n{len(empty_models)} device(s) stored an empty model, which means the "
            "renderer and the parser disagree. They are in the inventory and will "
            "contribute nothing:"
        )
        for hostname in empty_models[:10]:
            print(f"  {hostname}")

    if not args.no_segmentation:
        await _seed_segmentation(session, plan, args)

    print("\nnow in the database:")
    for label, model in (("devices", Device), ("snapshots", Snapshot), ("findings", Finding)):
        print(f"  {label:12} {await _count(session, model, args.org)}")


async def _seed_segmentation(session: AsyncSession, plan, args: argparse.Namespace) -> None:
    """Declare zones and intent, so the matrix has something to evaluate.

    Deliberately a mix of outcomes rather than a policy the estate satisfies. A matrix
    of green proves nothing was checked as surely as a matrix of grey, and the three
    statuses render differently — so all three need to be on the page.

    * users → DMZ, denied. The segment firewall's implicit deny upholds it.
    * users → DMZ on 443, allowed. Nothing permits it, so it reads as violated.
    * users → management, denied. Nothing routes there, which upholds it *and* says
      so — separation by routing gap is not a control.
    """
    from netsecops.core.errors import ValidationProblem
    from netsecops.db.models.segmentation import SegmentationExpectation
    from netsecops.services.segmentation import SegmentationService

    service = SegmentationService(session, org_id=args.org)
    existing = {zone.name for zone in await service.zones()}

    management = None
    if "Management" not in existing:
        management = await service.create_zone(
            name="Management",
            prefixes=["10.100.0.0/16"],
            description="Out-of-band management. Nothing in a user VLAN should reach it.",
        )

    declared = 0
    for site in plan[: args.segmentation_sites]:
        base = 20 + site.index
        users_name, dmz_name = f"{site.name} Users", f"{site.name} DMZ"
        if users_name in existing:
            continue

        users = await service.create_zone(
            name=users_name,
            prefixes=[f"10.{base}.10.0/24", f"10.{base}.11.0/24"],
            description=f"Access VLANs at {site.name}.",
        )
        dmz = await service.create_zone(
            name=dmz_name,
            prefixes=[f"10.{base}.201.0/24"],
            description=f"The DMZ behind {site.name}'s segment firewall.",
        )

        intents = [
            (users, dmz, SegmentationExpectation.DENIED, 445, "SMB never crosses into the DMZ."),
            (
                users,
                dmz,
                SegmentationExpectation.ALLOWED,
                443,
                "Staff reach the DMZ web service over TLS.",
            ),
        ]
        if management is not None:
            intents.append(
                (
                    users,
                    management,
                    SegmentationExpectation.DENIED,
                    22,
                    "Management is out of band. No user VLAN reaches it.",
                )
            )

        for source, destination, expectation, port, why in intents:
            try:
                await service.create_rule(
                    source_zone_id=source.id,
                    destination_zone_id=destination.id,
                    expectation=expectation,
                    port=port,
                    justification=why,
                )
                declared += 1
            except ValidationProblem as exc:
                print(f"  segmentation rule refused: {exc}")

    await session.commit()
    print(f"\ndeclared {declared} segmentation rule(s) across {args.segmentation_sites} site(s)")


async def purge(session: AsyncSession, args: argparse.Namespace) -> None:
    inventory = InventoryService(session)
    principal = actor()
    ids = await _tagged_ids(session, args.org)

    removed = 0
    for device in (
        (await session.execute(select(Device).where(Device.org_id == args.org))).scalars().all()
    ):
        if device.id not in ids:
            continue
        await inventory.delete_device(device, actor=principal)
        removed += 1
        if removed % 100 == 0:
            await session.commit()
            print(f"  removed {removed}…")

    await session.commit()
    print(f"removed {removed} synthetic device(s)")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sites", type=int, default=10)
    parser.add_argument("--firewalls", type=int, default=50)
    parser.add_argument("--routers", type=int, default=100)
    parser.add_argument("--switches", type=int, default=500)
    parser.add_argument("--org", type=int, default=1)
    parser.add_argument(
        "--no-assess",
        action="store_true",
        help="Skip the check engine. Much faster, and leaves an estate with no findings.",
    )
    parser.add_argument(
        "--no-segmentation",
        action="store_true",
        help="Skip declaring segmentation zones and intent.",
    )
    parser.add_argument(
        "--segmentation-sites",
        type=int,
        default=4,
        help="How many sites get a declared policy. Not all of them, on purpose: the "
        "matrix should show what has been declared, not every pair that exists.",
    )
    parser.add_argument("--purge", action="store_true", help="Remove what this created.")
    return parser.parse_args(argv)


async def main(argv: list[str]) -> int:
    args = parse_args(argv)
    settings = get_settings()
    engine = create_async_engine(str(settings.database_url), pool_pre_ping=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    vault = build_vault()

    print(f"database: {str(settings.database_url).split('@')[-1]}\n")

    try:
        async with factory() as session:
            if args.purge:
                await purge(session, args)
            else:
                await seed(session, args, vault)
    finally:
        await engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(sys.argv[1:])))
