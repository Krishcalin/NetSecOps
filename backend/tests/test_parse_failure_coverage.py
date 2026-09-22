"""A parse that read nothing must not report high coverage (FR-PARSE-03, IF-UI-04).

Four parsers — PAN-OS, Cisco ISE, Check Point management, FortiAuthenticator — take an
artefact that is meant to be XML or JSON and can fail to read it wholesale. They handle
that deliberately and well: one explanatory line in `raw_unparsed`, an NCM carrying only
the vendor and platform, so every check downstream reports *Not evaluated* rather than
the device being reported clean.

The defect was one layer up. `parse_coverage` is computed as meaningful lines minus
unparsed lines, and a wholesale failure records *one* unparsed line however long the
input was. So a five-hundred-line PAN-OS configuration that parsed into nothing scored
99.8%, and the device page rendered a green "99% parsed" pill beside an empty NCM — the
most reassuring possible presentation of the least useful possible snapshot.

Found by pointing `scripts/parse_coverage.py` at 104 PAN-OS configurations from a corpus
we did not write: coverage said 93.8%, and all 22 of the NCM fields any check depends on
were populated in exactly none of them.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser
from netsecops.services.inventory import InventoryService
from netsecops.services.snapshots import SnapshotService
from tests.conftest import make_user

#: One per parser with a wholesale-failure path, with input of that shape it cannot read.
#: Each is long enough that the old arithmetic scored it in the nineties.
UNREADABLE: list[tuple[str, str]] = [
    ("panos", "\n".join(f"set deviceconfig system line-{n} value" for n in range(200))),
    ("cisco_ise", "\n".join(f"not json, line {n}" for n in range(200))),
    ("checkpoint_mgmt", "\n".join(f"not json, line {n}" for n in range(200))),
    ("fortiauthenticator", "\n".join(f"not json, line {n}" for n in range(200))),
]


def meaningful(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip() and not line.strip().startswith("!"))


@pytest.mark.parametrize(("platform", "text"), UNREADABLE, ids=[p for p, _ in UNREADABLE])
def test_a_wholesale_failure_is_flagged(platform: str, text: str) -> None:
    ncm = get_parser(platform).parse(ParseContext(text=text, command="show config"))

    assert ncm.parse_failed is True
    assert ncm.raw_unparsed, "the reason must still be readable in the evidence"


@pytest.mark.parametrize(("platform", "text"), UNREADABLE, ids=[p for p, _ in UNREADABLE])
def test_the_old_arithmetic_would_have_scored_it_in_the_nineties(platform: str, text: str) -> None:
    """The defect, pinned so the fix cannot be quietly reverted.

    This asserts the *shape of the bug*: one unparsed line against two hundred meaningful
    ones. If a future change made these parsers record every line instead, this test
    would fail and should simply be deleted — the flag would no longer be carrying the
    distinction, because the arithmetic would be right on its own.
    """
    ncm = get_parser(platform).parse(ParseContext(text=text, command="show config"))
    total = meaningful(text)
    naive = round(100 * (total - len(ncm.raw_unparsed)) / total)

    assert naive >= 90, f"expected the naive figure to be misleadingly high, got {naive}%"


@pytest.mark.parametrize(("platform", "text"), UNREADABLE, ids=[p for p, _ in UNREADABLE])
def test_a_readable_parse_is_not_flagged(platform: str, text: str) -> None:
    """The flag must mean "could not read this", not "this platform is JSON-ish"."""
    readable = {
        "panos": "<config><devices/></config>",
        "cisco_ise": '{"responses": {}}',
        "checkpoint_mgmt": '{"commands": {}}',
        "fortiauthenticator": '{"responses": {}}',
    }[platform]

    ncm = get_parser(platform).parse(ParseContext(text=readable, command="show config"))

    assert ncm.parse_failed is False


# ══════════════ the number a person actually sees ══════════════


@pytest.fixture
async def panos_device(session: AsyncSession) -> Device:
    user = await make_user(session, username="parse_cov", roles={Role.SECURITY_ANALYST})
    actor = Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())
    return await InventoryService(session).create_device(
        mgmt_ip="198.51.100.77",
        actor=actor,
        hostname="fw-parse-cov",
        vendor=Vendor.PALOALTO,
        platform="panos",
        device_class=DeviceClass.FIREWALL,
    )


class TestTheCoverageOnTheDevicePage:
    async def test_an_unreadable_configuration_reports_zero_not_ninety_nine(
        self, session: AsyncSession, panos_device: Device
    ) -> None:
        """The regression. `parse_coverage` drives a pill that is green at 90 and above."""
        unreadable = "\n".join(f"set deviceconfig system line-{n} value" for n in range(200))

        snapshot = await SnapshotService(session).create_snapshot(
            panos_device, config_text=unreadable, platform="panos"
        )

        assert snapshot.parse_coverage == 0

    async def test_a_readable_configuration_still_reports_its_real_coverage(
        self, session: AsyncSession, panos_device: Device
    ) -> None:
        """The flag must not become a blanket zero for a platform that parses fine."""
        snapshot = await SnapshotService(session).create_snapshot(
            panos_device,
            config_text="<config><devices><entry name='localhost.localdomain'/></devices></config>",
            platform="panos",
        )

        assert snapshot.parse_coverage is None or snapshot.parse_coverage > 0
