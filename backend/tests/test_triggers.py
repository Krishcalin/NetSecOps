"""Event derivation (integrations.triggers.scan), and the KEV promotion in particular.

The 2026-09-30 audit found scan() filtered findings by severity BEFORE promoting KEV
matches, so a medium/low finding for a CISA-KEV CVE — "being exploited right now", the
alert the whole KEV path exists to raise — was never emitted. scan() had no direct test,
which is how it shipped.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.collection import Finding, FindingKind, FindingStatus
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.db.models.vulnerability import VulnCve
from netsecops.integrations.events import EventKind, EventSeverity
from netsecops.integrations.triggers import scan
from netsecops.services.inventory import InventoryService
from tests.conftest import make_user


async def _device(session: AsyncSession, ip: str = "10.7.0.1"):
    user = await make_user(session, username=f"trig_{ip}", roles={Role.SECURITY_ANALYST})
    actor = Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())
    return await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=actor,
        hostname="trig-dev",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )


async def _vuln_finding(session: AsyncSession, device, *, cve_id: str, severity: str) -> None:
    now = datetime.now(UTC)
    session.add(
        Finding(
            org_id=1,
            device_id=device.id,
            kind=FindingKind.VULN.value,
            fingerprint=f"vuln:{cve_id}:{device.id}",
            title=f"{cve_id} affects this device",
            severity=severity,
            status=FindingStatus.OPEN.value,
            cve_id=cve_id,
            first_seen_at=now - timedelta(hours=1),
            last_seen_at=now,
        )
    )
    await session.flush()


# Findings are fetched with created_at <= moment - COMMIT_LAG (30s); created_at is set at
# insert, so the scan moment is pushed a minute ahead.
def _moment() -> datetime:
    return datetime.now(UTC) + timedelta(minutes=1)


class TestKevPromotionIgnoresSeverityFloor:
    async def test_a_medium_kev_finding_is_promoted_to_a_critical_kev_event(
        self, session: AsyncSession
    ) -> None:
        device = await _device(session, "10.7.0.1")
        session.add(VulnCve(org_id=1, cve_id="CVE-2026-0001", kev=True))
        await _vuln_finding(session, device, cve_id="CVE-2026-0001", severity="medium")
        await session.flush()

        events = await scan(session, org_id=1, now=_moment())

        kev = [e for e in events if e.kind == EventKind.KEV_MATCHED]
        assert len(kev) == 1
        assert kev[0].severity is EventSeverity.CRITICAL
        assert kev[0].attributes.get("cve") == "CVE-2026-0001"

    async def test_a_medium_non_kev_vuln_finding_is_not_notified(
        self, session: AsyncSession
    ) -> None:
        device = await _device(session, "10.7.0.2")
        await _vuln_finding(session, device, cve_id="CVE-2026-0002", severity="medium")
        await session.flush()

        events = await scan(session, org_id=1, now=_moment())

        assert not any(e.attributes.get("cve") == "CVE-2026-0002" for e in events)
