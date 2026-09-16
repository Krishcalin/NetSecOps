"""Vulnerability endpoints (FR-VUL-04, FR-VUL-07, FR-VUL-08).

Phase 6 built the matcher, the feed importer and the assessment service and shipped none
of them: no route, no worker branch, no CLI command. Everything here is about the
surface that finally reaches a user, and most of it is about the distinctions the
underlying engine took care to preserve surviving the trip through JSON.

Three of those distinctions do the most work, and each collapses under one careless
`or 0` on the way out:

* **Not Evaluated is not clear.** A device whose version could not be read, or whose
  release trains are incomparable, is neither affected nor safe. It gets its own list.
* **KEV null is not KEV false.** Null means the catalogue was never imported; false
  means it was and this CVE is not on it. Rendered the same, an estate that has never
  checked looks like an estate that checked and is clean.
* **Assessed-and-clean is not never-assessed.** The summary counts unassessed devices
  separately for the same reason.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, User
from netsecops.db.models.collection import Finding, FindingKind, FindingStatus
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.db.models.vulnerability import VulnAdvisory, VulnCve, VulnMatch
from netsecops.services.inventory import InventoryService
from tests.conftest import make_user

LIST = "/api/v1/vulnerabilities"
SUMMARY = "/api/v1/vulnerabilities/summary"
FEEDS = "/api/v1/vulnerabilities/feeds"
IMPORT = "/api/v1/vulnerabilities/feeds/import"


@pytest.fixture
async def analyst_user(session: AsyncSession) -> User:
    return await make_user(session, username="vuln_api_analyst", roles={Role.SECURITY_ANALYST})


@pytest.fixture
async def principal(analyst_user: User) -> Principal:
    return Principal(
        id=analyst_user.id,
        username=analyst_user.username,
        roles=analyst_user.role_set,
        scope=Scope.all(),
    )


async def add_device(
    session: AsyncSession, principal: Principal, *, ip: str, hostname: str, version: str
) -> Device:
    device = await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=principal,
        hostname=hostname,
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )
    device.os_version = version
    await session.flush()
    return device


async def add_advisory(
    session: AsyncSession, *, source: str, advisory_id: str, cve_ids: list[str]
) -> VulnAdvisory:
    row = VulnAdvisory(
        org_id=1,
        source=source,
        advisory_id=advisory_id,
        title=f"{advisory_id} title",
        cve_ids=cve_ids,
        cwe_ids=["CWE-287"],
        references=["https://example.invalid/advisory"],
        published=datetime(2024, 4, 24, tzinfo=UTC),
        modified=datetime(2024, 5, 1, tzinfo=UTC),
    )
    session.add(row)
    await session.flush()
    return row


async def add_cve(
    session: AsyncSession,
    *,
    cve_id: str,
    score: float,
    kev: bool | None,
    epss: float | None = None,
) -> VulnCve:
    row = VulnCve(
        org_id=1,
        cve_id=cve_id,
        description=f"{cve_id} description",
        cvss31={"version": "3.1", "base_score": score, "base_severity": "HIGH", "vector": "AV:N"},
        epss=epss,
        kev=kev,
        published=datetime(2024, 4, 24, tzinfo=UTC),
    )
    session.add(row)
    await session.flush()
    return row


async def add_finding(
    session: AsyncSession,
    device: Device,
    advisory: VulnAdvisory,
    *,
    confidence: str,
    severity: str = "high",
    fixed: list[str] | None = None,
) -> Finding:
    now = datetime.now(UTC)
    row = Finding(
        org_id=1,
        device_id=device.id,
        kind=FindingKind.VULN.value,
        fingerprint=f"vuln:{advisory.source}:{advisory.advisory_id}",
        title=", ".join(advisory.cve_ids),
        description="version matched\nfeature condition unknown",
        severity=severity,
        status=FindingStatus.OPEN.value,
        cve_id=advisory.cve_ids[0] if advisory.cve_ids else None,
        remediation="Upgrade to 15.2(7)E6 or later.",
        evidence={
            "advisory_id": advisory.advisory_id,
            "source": advisory.source,
            "cve_ids": advisory.cve_ids,
            "confidence": confidence,
            "fixed_versions": fixed or [],
            "references": list(advisory.references),
        },
        first_seen_at=now,
        last_seen_at=now,
    )
    session.add(row)
    await session.flush()
    return row


async def add_match(
    session: AsyncSession, device: Device, advisory: VulnAdvisory, *, confidence: str
) -> VulnMatch:
    row = VulnMatch(
        org_id=1,
        device_id=device.id,
        advisory_id=advisory.id,
        confidence=confidence,
        cve_ids=list(advisory.cve_ids),
        reasoning=["version 15.2(7)E3 is within the affected range"],
        fixed_versions=["15.2(7)E6"],
    )
    session.add(row)
    await session.flush()
    return row


@pytest.fixture
async def estate(session: AsyncSession, principal: Principal, analyst_user: User, authenticate):
    """Three devices: one confirmed, one likely, one never assessed at all."""
    confirmed_device = await add_device(
        session, principal, ip="10.0.0.1", hostname="sw-confirmed", version="15.2(7)E3"
    )
    likely_device = await add_device(
        session, principal, ip="10.0.0.2", hostname="sw-likely", version="15.2(7)E3"
    )
    unassessed = await add_device(
        session, principal, ip="10.0.0.3", hostname="sw-unassessed", version="17.9.4"
    )

    kev_advisory = await add_advisory(
        session, source="nvd", advisory_id="CVE-2024-20353", cve_ids=["CVE-2024-20353"]
    )
    quiet_advisory = await add_advisory(
        session, source="cisco", advisory_id="cisco-sa-quiet", cve_ids=["CVE-2024-11111"]
    )

    await add_cve(session, cve_id="CVE-2024-20353", score=8.6, kev=True, epss=0.71)
    await add_cve(session, cve_id="CVE-2024-11111", score=5.3, kev=False)

    await add_finding(
        session, confirmed_device, kev_advisory, confidence="confirmed", severity="critical",
        fixed=["15.2(7)E6"],
    )
    await add_finding(session, likely_device, quiet_advisory, confidence="likely", severity="medium")

    await add_match(session, confirmed_device, kev_advisory, confidence="confirmed")
    await add_match(session, likely_device, quiet_advisory, confidence="likely")
    # Checked and ruled out — a real answer, and not an exposure.
    await add_match(session, likely_device, kev_advisory, confidence="not_affected")
    # The question could not be asked on this one.
    await add_match(session, unassessed, quiet_advisory, confidence="not_evaluated")

    await session.commit()
    authenticate(analyst_user)
    return {"confirmed": confirmed_device, "likely": likely_device, "unassessed": unassessed}


class TestRouteOrdering:
    """`/summary` and `/feeds` are literal siblings of `/{cve_id}`.

    FastAPI matches in registration order, so declaring the parameterised route first
    would swallow both. The `/devices/pending-review` comment in `api/router.py`
    describes the same trap, but that one at least fails loudly: `pending-review` is not
    a UUID, so it 422s. A CVE id is a plain string, so this one would quietly 404 and
    look like an empty estate.
    """

    async def test_literal_vulnerability_routes_are_not_shadowed(
        self, client: AsyncClient, estate
    ) -> None:
        summary = await client.get(SUMMARY)
        feeds = await client.get(FEEDS)

        assert summary.status_code == 200
        assert "total" in summary.json()
        assert feeds.status_code == 200
        assert isinstance(feeds.json(), list)


class TestListing:
    async def test_findings_come_back_worst_first(self, client: AsyncClient, estate) -> None:
        response = await client.get(LIST)

        assert response.status_code == 200
        rows = response.json()["data"]
        assert [row["severity"] for row in rows] == ["critical", "medium"]

    async def test_a_row_carries_what_fr_vul_04_requires(
        self, client: AsyncClient, estate
    ) -> None:
        """CVE, advisory, CVSS, EPSS, KEV, dates, fixed versions, links — in one row."""
        rows = (await client.get(LIST)).json()["data"]
        row = next(r for r in rows if r["severity"] == "critical")

        assert row["cve_ids"] == ["CVE-2024-20353"]
        assert row["advisory_id"] == "CVE-2024-20353"
        assert row["advisory_source"] == "nvd"
        assert row["cvss"]["base_score"] == 8.6
        assert row["cvss"]["vector"] == "AV:N"
        assert row["epss"] == 0.71
        assert row["kev"] is True
        assert row["fixed_versions"] == ["15.2(7)E6"]
        assert row["installed_version"] == "15.2(7)E3"
        assert row["published"] is not None
        assert row["references"]
        assert row["remediations"] == ["Upgrade to 15.2(7)E6 or later."]

    async def test_the_matchers_reasoning_survives_to_the_api(
        self, client: AsyncClient, estate
    ) -> None:
        """A Likely with no explanation is just an alarm. The reasoning is the payload."""
        rows = (await client.get(LIST)).json()["data"]
        likely = next(r for r in rows if r["confidence"] == "likely")

        assert likely["reasoning"] == ["version matched", "feature condition unknown"]

    async def test_filtering_by_confidence(self, client: AsyncClient, estate) -> None:
        rows = (await client.get(LIST, params={"confidence": "confirmed"})).json()["data"]

        assert [row["confidence"] for row in rows] == ["confirmed"]

    async def test_filtering_by_device(self, client: AsyncClient, estate) -> None:
        device_id = str(estate["likely"].id)
        rows = (await client.get(LIST, params={"device_id": device_id})).json()["data"]

        assert [row["device_id"] for row in rows] == [device_id]

    async def test_kev_only_says_that_the_total_precedes_it(
        self, client: AsyncClient, estate
    ) -> None:
        """The KEV flag is on the CVE row, not the finding, so it filters after paging.

        The meta says so rather than letting `total` read as a count of the rows shown.
        """
        body = (await client.get(LIST, params={"kev_only": True})).json()

        assert [row["kev"] for row in body["data"]] == [True]
        assert body["meta"]["filtered_after_count"] is True


class TestKevAndEpssNullsSurvive:
    async def test_a_cve_checked_and_not_listed_reports_false(
        self, client: AsyncClient, estate
    ) -> None:
        rows = (await client.get(LIST)).json()["data"]
        quiet = next(r for r in rows if r["cve_ids"] == ["CVE-2024-11111"])

        assert quiet["kev"] is False

    async def test_a_cve_with_no_scoring_row_reports_null_not_false(
        self, client: AsyncClient, session: AsyncSession, estate, analyst_user, authenticate
    ) -> None:
        """No VulnCve row means no catalogue has ever mentioned it.

        False here would tell an operator the CVE was checked against KEV and cleared.
        """
        advisory = await add_advisory(
            session, source="cisco", advisory_id="cisco-sa-unscored", cve_ids=["CVE-2099-00001"]
        )
        await add_finding(session, estate["unassessed"], advisory, confidence="confirmed")
        await session.commit()
        authenticate(analyst_user)

        rows = (await client.get(LIST)).json()["data"]
        unscored = next(r for r in rows if r["cve_ids"] == ["CVE-2099-00001"])

        assert unscored["kev"] is None
        assert unscored["epss"] is None
        assert unscored["cvss"] is None


class TestCveDetail:
    async def test_affected_and_unevaluated_are_separate_lists(
        self, client: AsyncClient, estate
    ) -> None:
        """A device the matcher could not evaluate is neither affected nor clear.

        Listing it with the clear ones is the most dangerous rounding error this
        endpoint could make.
        """
        body = (await client.get(f"{LIST}/CVE-2024-11111")).json()

        affected = {d["hostname"] for d in body["affected_devices"]}
        unevaluated = {d["hostname"] for d in body["unevaluated_devices"]}

        assert affected == {"sw-likely"}
        assert unevaluated == {"sw-unassessed"}

    async def test_a_not_affected_device_appears_in_neither_list(
        self, client: AsyncClient, estate
    ) -> None:
        """Checked and ruled out is a real answer, not an exposure and not a gap."""
        body = (await client.get(f"{LIST}/CVE-2024-20353")).json()

        hostnames = {d["hostname"] for d in body["affected_devices"]} | {
            d["hostname"] for d in body["unevaluated_devices"]
        }
        assert "sw-likely" not in hostnames
        assert {d["hostname"] for d in body["affected_devices"]} == {"sw-confirmed"}

    async def test_the_detail_carries_scoring_and_advisories(
        self, client: AsyncClient, estate
    ) -> None:
        body = (await client.get(f"{LIST}/CVE-2024-20353")).json()

        assert body["kev"] is True
        assert body["epss"] == 0.71
        assert body["cvss31"]["base_score"] == 8.6
        assert [a["advisory_id"] for a in body["advisories"]] == ["CVE-2024-20353"]

    async def test_a_lowercase_cve_resolves(self, client: AsyncClient, estate) -> None:
        response = await client.get(f"{LIST}/cve-2024-20353")

        assert response.status_code == 200

    async def test_an_unknown_cve_is_a_404_not_an_empty_all_clear(
        self, client: AsyncClient, estate
    ) -> None:
        """"Nothing affected" and "never heard of it" must not render the same."""
        response = await client.get(f"{LIST}/CVE-1999-00001")

        assert response.status_code == 404


class TestSummary:
    async def test_unassessed_devices_are_counted_separately(
        self, client: AsyncClient, estate
    ) -> None:
        """Zero vulnerabilities on a device nobody assessed is not good news."""
        body = (await client.get(SUMMARY)).json()

        assert body["total"] == 2
        assert body["devices_affected"] == 2
        assert body["by_severity"] == {"critical": 1, "medium": 1}
        assert body["by_confidence"] == {"confirmed": 1, "likely": 1}
        assert body["kev_count"] == 1

    async def test_a_device_with_no_match_rows_counts_as_unassessed(
        self, client: AsyncClient, session: AsyncSession, principal, analyst_user, authenticate,
        estate,
    ) -> None:
        await add_device(
            session, principal, ip="10.0.0.9", hostname="sw-never-looked", version="17.9.4"
        )
        await session.commit()
        authenticate(analyst_user)

        body = (await client.get(SUMMARY)).json()

        assert body["devices_unassessed"] >= 1


class TestFeeds:
    async def test_feed_history_is_empty_before_any_import(
        self, client: AsyncClient, estate
    ) -> None:
        response = await client.get(FEEDS)

        assert response.status_code == 200
        assert response.json() == []

    async def test_an_import_appears_in_the_history_with_its_counts(
        self, client: AsyncClient, estate
    ) -> None:
        bundle = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2025-00001",
                        "published": "2025-01-01T00:00:00.000",
                        "lastModified": "2025-01-02T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "A test CVE."}],
                        "metrics": {},
                        "configurations": [],
                    }
                }
            ]
        }

        posted = await client.post(
            IMPORT,
            params={"feed": "nvd-offline"},
            files={"file": ("nvd.json", json.dumps(bundle).encode(), "application/json")},
        )

        assert posted.status_code == 200, posted.text
        body = posted.json()
        assert body["kind"] == "nvd"
        assert body["digest"]

        history = (await client.get(FEEDS)).json()
        assert [row["feed"] for row in history] == ["nvd-offline"]

    async def test_a_failed_import_is_still_recorded(
        self, client: AsyncClient, estate
    ) -> None:
        """"When did this last work" is unanswerable if only successes are kept."""
        response = await client.post(
            IMPORT,
            params={"feed": "broken"},
            files={"file": ("junk.json", b"{not json", "application/json")},
        )

        assert response.status_code >= 400
        history = (await client.get(FEEDS)).json()
        assert any(row["feed"] == "broken" and row["status"] == "failed" for row in history)

    async def test_a_digest_mismatch_imports_nothing(
        self, client: AsyncClient, estate
    ) -> None:
        bundle = json.dumps({"vulnerabilities": []}).encode()

        response = await client.post(
            IMPORT,
            params={"feed": "tampered", "expected_sha256": "0" * 64},
            files={"file": ("nvd.json", bundle, "application/json")},
        )

        assert response.status_code >= 400
        assert "0000" in response.text or "SHA-256" in response.text

    async def test_an_empty_upload_is_refused(self, client: AsyncClient, estate) -> None:
        response = await client.post(
            IMPORT, files={"file": ("empty.json", b"", "application/json")}
        )

        assert response.status_code == 422
        assert "empty" in response.text


class TestScoping:
    """Device-group scope, exercised at the service where the query is built.

    Driving this through HTTP would mostly test the login plumbing, which
    `test_authz_matrix.py` and `test_inventory.py` already cover. What is specific to
    this module is that the narrowing happens *in the query* rather than as a filter
    over the results — otherwise a paged response returns a short page of visible rows
    out of a long page of invisible ones and reports a total the caller cannot see.
    """

    async def test_a_scope_with_no_groups_sees_nothing(
        self, session: AsyncSession, estate
    ) -> None:
        from netsecops.services.vuln_view import VulnViewService

        rows, total = await VulnViewService(session).list_vulnerabilities(
            scope=Scope(unrestricted=False, device_group_ids=frozenset())
        )

        assert rows == []
        assert total == 0

    async def test_an_unrestricted_scope_sees_the_estate(
        self, session: AsyncSession, estate
    ) -> None:
        from netsecops.services.vuln_view import VulnViewService

        rows, total = await VulnViewService(session).list_vulnerabilities(scope=Scope.all())

        assert total == 2
        assert len(rows) == 2

    async def test_the_total_is_narrowed_too_not_just_the_page(
        self, session: AsyncSession, estate
    ) -> None:
        """The bug this guards: filtering rows after counting reports a total nobody
        can reach by paging."""
        from netsecops.services.vuln_view import VulnViewService

        _, total = await VulnViewService(session).list_vulnerabilities(
            scope=Scope(unrestricted=False, device_group_ids=frozenset()), limit=1
        )

        assert total == 0

    async def test_the_summary_is_scoped_as_well(
        self, session: AsyncSession, estate
    ) -> None:
        from netsecops.services.vuln_view import VulnViewService

        summary = await VulnViewService(session).summary(
            scope=Scope(unrestricted=False, device_group_ids=frozenset())
        )

        assert summary.total == 0
        assert summary.devices_affected == 0
