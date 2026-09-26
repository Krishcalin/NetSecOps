"""Rulebase viewer and rule query endpoints (FR-FW-06, FR-FW-07).

Two things here are worth more than the rest.

**Filters must not change the analysis.** A rule is shadowed by its *neighbours*, so a
rulebase filtered to one zone has none. If the filter were applied before the analysis
instead of after it, filtering would silently make problems disappear — and it would
look like the filter working, because the rule you were looking for would be gone
exactly as asked. `test_filtering_does_not_change_what_was_found` is that assertion.

**An empty rulebase must not read as a clean one.** A switch has no firewall policy and
a failed parse produces the same empty block. Both arrive at the viewer as zero rows in
a table, and only one of them is good news.
"""

from __future__ import annotations

import csv
import io
from hashlib import sha256
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, User
from netsecops.db.models.collection import Snapshot
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.services.inventory import InventoryService
from tests.conftest import make_group, make_user


@pytest.fixture
async def analyst_user(session: AsyncSession) -> User:
    return await make_user(session, username="fw_api_analyst", roles={Role.SECURITY_ANALYST})


@pytest.fixture
async def device(session: AsyncSession, analyst_user: User) -> Device:
    principal = Principal(
        id=analyst_user.id,
        username=analyst_user.username,
        roles=analyst_user.role_set,
        scope=Scope.all(),
    )
    return await InventoryService(session).create_device(
        mgmt_ip="198.51.100.88",
        actor=principal,
        hostname="viewer-fw-01",
        vendor=Vendor.PALOALTO,
        platform="panos",
        device_class=DeviceClass.FIREWALL,
    )


def rule(
    order: int,
    name: str,
    *,
    src: str = "any",
    dst: str = "any",
    service: str = "any",
    action: str = "allow",
    src_zone: str = "untrust",
    dst_zone: str = "dmz",
    enabled: bool = True,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "order": order,
        "name": name,
        "enabled": enabled,
        "src": [src],
        "dst": [dst],
        "services": [service],
        "action": action,
        "src_zones": [src_zone],
        "dst_zones": [dst_zone],
        **extra,
    }


#: A rulebase with one of each problem the viewer has to show.
RULES = [
    rule(1, "Block inbound RDP", service="tcp/3389", action="deny", log_end=True),
    rule(
        2,
        "Partner RDP to web",
        src="198.51.100.0/24",
        dst="10.20.0.10",
        service="tcp/3389",
        log_end=True,
    ),
    rule(
        3,
        "Inbound web",
        dst="10.20.0.10",
        service="tcp/443",
        log_end=True,
        profiles={"ips": "strict"},
    ),
    rule(4, "Internal admin", src_zone="trust", dst_zone="trust", service="tcp/22", log_end=False),
    rule(5, "Old migration rule", enabled=False, log_end=True),
]


def ncm(rules: list[dict[str, Any]] | None = None, **firewall: Any) -> dict[str, Any]:
    return {
        "device": {"hostname": "viewer-fw-01", "vendor": "paloalto", "platform": "panos"},
        "firewall": {
            "security_rules": RULES if rules is None else rules,
            "zones": ["untrust", "dmz", "trust"],
            **firewall,
        },
    }


async def snapshot_with(session: AsyncSession, device: Device, payload: dict[str, Any]) -> Snapshot:
    digest = sha256(repr(payload).encode()).hexdigest()
    row = Snapshot(
        org_id=device.org_id,
        device_id=device.id,
        ncm=payload,
        config_redacted="",
        config_hash=digest,
        normalized_hash=digest,
        parser_platform="panos",
    )
    session.add(row)
    await session.flush()
    return row


@pytest.fixture
async def seeded(session: AsyncSession, device: Device, analyst_user: User, authenticate) -> Device:
    await snapshot_with(session, device, ncm())
    authenticate(analyst_user)
    return device


# ───────────────────────────── the rulebase ─────────────────────────────


class TestReadingTheRulebase:
    async def test_every_rule_is_returned_in_evaluation_order(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        """Order is the whole subject. A viewer that sorted by name or severity would
        make shadowing impossible to see, because shadowing *is* a statement about
        position."""
        response = await client.get(f"/api/v1/devices/{seeded.id}/firewall/rulebase")

        assert response.status_code == 200
        body = response.json()
        assert [r["order"] for r in body["rules"]] == [1, 2, 3, 4, 5]
        assert body["total"] == 5

    async def test_a_shadowed_rule_carries_its_problem_and_names_the_cause(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        """Attached to the rule, not listed separately — and naming the other rule, so
        the viewer can scroll to it. A shadowing finding is unreadable without both."""
        body = (await client.get(f"/api/v1/devices/{seeded.id}/firewall/rulebase")).json()
        partner = next(r for r in body["rules"] if r["order"] == 2)

        shadowed = [i for i in partner["issues"] if i["issue"] == "shadowed"]
        assert len(shadowed) == 1
        assert shadowed[0]["related_rule_order"] == 1
        assert shadowed[0]["related_rule_name"] == "Block inbound RDP"
        assert shadowed[0]["severity"] == "high"

    async def test_the_causing_rule_is_annotated_too(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        """Scrolling to rule 1 should say why it was named, rather than leaving the
        operator to work it out from the order."""
        body = (await client.get(f"/api/v1/devices/{seeded.id}/firewall/rulebase")).json()
        blocker = next(r for r in body["rules"] if r["order"] == 1)

        mirrored = [i for i in blocker["issues"] if i["issue"] == "shadowed_cause"]
        assert len(mirrored) == 1
        assert mirrored[0]["related_rule_order"] == 2
        assert mirrored[0]["severity"] == "info"

    async def test_addresses_are_rendered_for_reading(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        """`10.20.0.10` is recognisable; `169083402` is the same thing and is not."""
        body = (await client.get(f"/api/v1/devices/{seeded.id}/firewall/rulebase")).json()
        partner = next(r for r in body["rules"] if r["order"] == 2)

        assert partner["source"] == "198.51.100.0/24"
        assert partner["destination"] == "10.20.0.10"
        assert "3389" in partner["services"]

    async def test_the_objects_a_rule_names_are_returned_alongside_what_they_resolve_to(
        self, client: AsyncClient, session: AsyncSession, device: Device, analyst_user, authenticate
    ) -> None:
        """The two differing — a group whose members are not what its name suggests — is
        often the entire problem, and a viewer showing only the resolved form hides it."""
        payload = ncm(
            [rule(1, "Web", dst="web-servers", service="tcp/443")],
            address_objects=[{"name": "web-01", "type": "host", "value": "10.20.0.10"}],
            address_groups=[{"name": "web-servers", "type": "group", "members": ["web-01"]}],
        )
        await snapshot_with(session, device, payload)
        authenticate(analyst_user)

        body = (await client.get(f"/api/v1/devices/{device.id}/firewall/rulebase")).json()
        web = body["rules"][0]

        assert web["destination_objects"] == ["web-servers"]
        assert web["destination"] == "10.20.0.10"

    async def test_unknown_logging_is_distinguishable_from_no_logging(
        self, client: AsyncClient, session: AsyncSession, device: Device, analyst_user, authenticate
    ) -> None:
        """Absent is not false. A UI that rendered None as "no" would send someone to
        enable logging on a rule that already has it."""
        await snapshot_with(session, device, ncm([rule(1, "No log field stated")]))
        authenticate(analyst_user)

        body = (await client.get(f"/api/v1/devices/{device.id}/firewall/rulebase")).json()
        assert body["rules"][0]["logs"] is None

    async def test_the_summary_counts_the_whole_rulebase(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        body = (await client.get(f"/api/v1/devices/{seeded.id}/firewall/rulebase")).json()
        summary = body["summary"]

        assert summary["rules_total"] == 5
        assert summary["rules_enabled"] == 4
        # The disabled rule is excluded from the analysis but not from the count.
        assert summary["rules_analysed"] == 4
        assert summary["relationships"]["shadowed"] == 1

    async def test_the_limitations_are_stated_on_every_response(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        """An unqualified "no shadowed rules" would be read as a guarantee. The pairwise
        analysis cannot see a rule shadowed by the union of several others, and the
        response says so rather than leaving it in the documentation."""
        body = (await client.get(f"/api/v1/devices/{seeded.id}/firewall/rulebase")).json()
        assert body["summary"]["limitations"]

    async def test_a_partially_retrieved_rulebase_says_so_before_any_count(
        self, client: AsyncClient, session: AsyncSession, device: Device, analyst_user, authenticate
    ) -> None:
        """The worst thing this service can do is analyse a fraction and sound certain.

        Check Point's `show-access-rulebase` paginates. A request that does not ask for a
        limit gets the server's default page, so a five-hundred-rule policy can arrive as
        fifty rules that shadow nothing, contain no any-any and end in a tidy cleanup
        rule — a clean report about a seventh of a firewall, with nothing in it wrong
        except the scope.

        Distinct from `summary.truncated`, which means every rule was read and not every
        pair compared. This means the rules are not here.
        """
        payload = ncm([rule(1, "Only the first page", dst="web-01", service="tcp/443")])
        payload["firewall"]["rules_not_retrieved"] = 498
        await snapshot_with(session, device, payload)
        authenticate(analyst_user)

        body = (await client.get(f"/api/v1/devices/{device.id}/firewall/rulebase")).json()
        summary = body["summary"]

        assert summary["rules_not_retrieved"] == 498
        assert any("not retrieved" in note for note in summary["limitations"]), summary[
            "limitations"
        ]

    async def test_hygiene_findings_are_returned_separately(
        self, client: AsyncClient, session: AsyncSession, device: Device, analyst_user, authenticate
    ) -> None:
        """They are about the object catalogue, not about any one rule, so attaching
        them to a rule would put them where nobody would look for them."""
        payload = ncm(
            [rule(1, "Web", dst="web-01", service="tcp/443")],
            address_objects=[
                {"name": "web-01", "type": "host", "value": "10.20.0.10"},
                {"name": "web-01-copy", "type": "host", "value": "10.20.0.10"},
            ],
        )
        await snapshot_with(session, device, payload)
        authenticate(analyst_user)

        body = (await client.get(f"/api/v1/devices/{device.id}/firewall/rulebase")).json()
        duplicates = [h for h in body["hygiene"] if h["issue"] == "duplicate_object"]
        assert len(duplicates) == 1


class TestFilters:
    async def test_filtering_does_not_change_what_was_found(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        """The assertion this design exists for.

        A rule is shadowed by its neighbours. If the filter were applied before the
        analysis, filtering to one zone would remove the neighbours and the shadowing
        would vanish — and it would look exactly like the filter working, because the
        rule you were looking for would be gone as asked.
        """
        base = f"/api/v1/devices/{seeded.id}/firewall/rulebase"
        everything = (await client.get(base)).json()
        filtered = (await client.get(base, params={"zone": "trust"})).json()

        assert len(filtered["rules"]) < len(everything["rules"])
        # The counts are over the whole rulebase either way.
        assert filtered["summary"] == everything["summary"]
        assert filtered["total"] == everything["total"]

    async def test_search_matches_names_and_objects(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        response = await client.get(
            f"/api/v1/devices/{seeded.id}/firewall/rulebase", params={"search": "rdp"}
        )
        names = [r["name"] for r in response.json()["rules"]]
        assert names == ["Block inbound RDP", "Partner RDP to web"]

    async def test_the_action_filter_uses_the_verdict_not_the_vendors_word(
        self, client: AsyncClient, session: AsyncSession, device: Device, analyst_user, authenticate
    ) -> None:
        """Check Point says Drop, PAN-OS says deny, FortiOS says deny, ASA says deny. A
        filter matching the literal string would work on three platforms and lie on the
        fourth."""
        await snapshot_with(
            session,
            device,
            ncm(
                [
                    rule(1, "Cleanup", action="Drop"),
                    rule(2, "Permit", action="Accept", service="tcp/443"),
                ]
            ),
        )
        authenticate(analyst_user)

        response = await client.get(
            f"/api/v1/devices/{device.id}/firewall/rulebase", params={"action": "deny"}
        )
        assert [r["name"] for r in response.json()["rules"]] == ["Cleanup"]

    async def test_filtering_by_issue(self, client: AsyncClient, seeded: Device) -> None:
        response = await client.get(
            f"/api/v1/devices/{seeded.id}/firewall/rulebase", params={"issue": "shadowed"}
        )
        assert [r["order"] for r in response.json()["rules"]] == [2]

    async def test_hiding_disabled_rules(self, client: AsyncClient, seeded: Device) -> None:
        response = await client.get(
            f"/api/v1/devices/{seeded.id}/firewall/rulebase",
            params={"include_disabled": "false"},
        )
        assert all(r["enabled"] for r in response.json()["rules"])

    async def test_showing_only_rules_with_problems(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        response = await client.get(
            f"/api/v1/devices/{seeded.id}/firewall/rulebase",
            params={"with_issues_only": "true"},
        )
        assert all(r["issues"] for r in response.json()["rules"])


class TestNoRulebase:
    async def test_an_empty_rulebase_says_so_rather_than_showing_nothing(
        self, client: AsyncClient, session: AsyncSession, device: Device, analyst_user, authenticate
    ) -> None:
        """A switch has no policy and a failed parse produces the same empty block. Both
        reach the viewer as zero rows in a table, and only one of them is good news."""
        await snapshot_with(session, device, {"device": {}, "firewall": {}})
        authenticate(analyst_user)

        body = (await client.get(f"/api/v1/devices/{device.id}/firewall/rulebase")).json()

        assert body["rules"] == []
        assert body["summary"]["limitations"]
        assert "no firewall rulebase" in body["summary"]["limitations"][0]

    async def test_a_device_with_no_snapshot_is_a_clear_404(
        self, client: AsyncClient, device: Device, analyst_user, authenticate
    ) -> None:
        authenticate(analyst_user)
        response = await client.get(f"/api/v1/devices/{device.id}/firewall/rulebase")

        assert response.status_code == 404
        assert "collection" in response.json()["detail"].lower()


class TestHistoricalSnapshots:
    """Naming a snapshot is what makes the viewer usable during an investigation: the
    rulebase that matters is the one that was live at the time, not the one live now."""

    async def test_an_older_snapshot_can_be_viewed(
        self, client: AsyncClient, session: AsyncSession, device: Device, analyst_user, authenticate
    ) -> None:
        old = await snapshot_with(session, device, ncm([rule(1, "The old rulebase")]))
        await snapshot_with(session, device, ncm([rule(1, "The current rulebase")]))
        authenticate(analyst_user)

        latest = (await client.get(f"/api/v1/devices/{device.id}/firewall/rulebase")).json()
        assert latest["rules"][0]["name"] == "The current rulebase"

        historical = (
            await client.get(
                f"/api/v1/devices/{device.id}/firewall/rulebase",
                params={"snapshot_id": str(old.id)},
            )
        ).json()
        assert historical["rules"][0]["name"] == "The old rulebase"

    async def test_a_snapshot_belonging_to_another_device_is_refused(
        self,
        client: AsyncClient,
        session: AsyncSession,
        device: Device,
        analyst_user,
        authenticate,
    ) -> None:
        """Refused as a 404 rather than a 403: the snapshot may be perfectly visible to
        this caller, it just belongs to a different device, and saying which is more
        useful than a blanket refusal."""
        principal = Principal(
            id=analyst_user.id,
            username=analyst_user.username,
            roles=analyst_user.role_set,
            scope=Scope.all(),
        )
        other = await InventoryService(session).create_device(
            mgmt_ip="198.51.100.89",
            actor=principal,
            hostname="other-fw",
            vendor=Vendor.PALOALTO,
            platform="panos",
            device_class=DeviceClass.FIREWALL,
        )
        foreign = await snapshot_with(session, other, ncm())
        await snapshot_with(session, device, ncm())
        authenticate(analyst_user)

        response = await client.get(
            f"/api/v1/devices/{device.id}/firewall/rulebase",
            params={"snapshot_id": str(foreign.id)},
        )

        assert response.status_code == 404
        assert "does not belong to this device" in response.json()["detail"]


# ─────────────────────────── the rule query (FR-FW-06) ──────────────────


class TestTheRuleQuery:
    async def test_it_reports_the_first_matching_rule(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        response = await client.post(
            f"/api/v1/devices/{seeded.id}/firewall/query",
            json={
                "source": "198.51.100.5",
                "destination": "10.20.0.10",
                "protocol": "tcp",
                "port": 3389,
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["matched"]["order"] == 1
        assert body["matched"]["name"] == "Block inbound RDP"

    async def test_it_names_the_rules_that_would_have_matched(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        """The answer to "why did my new rule not take effect", which is the question
        this endpoint exists for."""
        response = await client.post(
            f"/api/v1/devices/{seeded.id}/firewall/query",
            json={
                "source": "198.51.100.5",
                "destination": "10.20.0.10",
                "protocol": "tcp",
                "port": 3389,
            },
        )
        also = response.json()["also_matched"]
        assert [r["name"] for r in also] == ["Partner RDP to web"]

    async def test_the_limitations_come_back_with_the_answer(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        """A bare rule number would be read as a guarantee. App-ID and User-ID are not
        simulated, so a rule the device would narrow may be reported as matching."""
        response = await client.post(
            f"/api/v1/devices/{seeded.id}/firewall/query",
            json={"source": "10.0.0.1", "destination": "10.20.0.10", "port": 443},
        )
        assert response.json()["limitations"]

    async def test_no_match_is_an_answer_not_an_error(
        self, client: AsyncClient, session: AsyncSession, device: Device, analyst_user, authenticate
    ) -> None:
        """A packet no rule matches falls to the platform default, which differs by
        vendor. Reporting nothing matched is the honest answer."""
        await snapshot_with(
            session,
            device,
            ncm([rule(1, "Narrow", src="10.1.1.1", dst="10.2.2.2", service="tcp/1")]),
        )
        authenticate(analyst_user)

        response = await client.post(
            f"/api/v1/devices/{device.id}/firewall/query",
            json={"source": "192.0.2.1", "destination": "203.0.113.1", "port": 9999},
        )

        assert response.status_code == 200
        assert response.json()["matched"] is None

    async def test_a_bad_address_is_a_422_that_explains_itself(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        response = await client.post(
            f"/api/v1/devices/{seeded.id}/firewall/query",
            json={"source": "10.0.0.0/8", "destination": "10.20.0.10", "port": 443},
        )

        assert response.status_code == 422
        assert "single packet" in response.json()["detail"]

    async def test_an_unknown_protocol_lists_the_ones_that_work(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        response = await client.post(
            f"/api/v1/devices/{seeded.id}/firewall/query",
            json={
                "source": "10.0.0.1",
                "destination": "10.20.0.10",
                "protocol": "carrier-pigeon",
                "port": 443,
            },
        )

        assert response.status_code == 422
        assert "tcp" in response.json()["detail"]

    async def test_querying_a_device_with_no_rulebase_explains_why(
        self, client: AsyncClient, session: AsyncSession, device: Device, analyst_user, authenticate
    ) -> None:
        await snapshot_with(session, device, {"device": {}, "firewall": {}})
        authenticate(analyst_user)

        response = await client.post(
            f"/api/v1/devices/{device.id}/firewall/query",
            json={"source": "10.0.0.1", "destination": "10.20.0.10", "port": 443},
        )

        assert response.status_code == 422
        assert "no firewall rulebase" in response.json()["detail"]


# ───────────────────────────── export (FR-FW-07) ────────────────────────


class TestExport:
    async def test_it_returns_csv_with_a_filename(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        response = await client.get(f"/api/v1/devices/{seeded.id}/firewall/export")

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        assert "attachment" in response.headers["content-disposition"]

    async def test_every_rule_and_its_problems_are_in_the_rows(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        response = await client.get(f"/api/v1/devices/{seeded.id}/firewall/export")
        rows = list(csv.DictReader(io.StringIO(response.text)))

        assert len(rows) == 5
        partner = next(r for r in rows if r["name"] == "Partner RDP to web")
        assert "shadowed" in partner["issues"]
        assert partner["worst_severity"] == "high"

    async def test_unknown_logging_is_spelled_out_rather_than_left_blank(
        self, client: AsyncClient, session: AsyncSession, device: Device, analyst_user, authenticate
    ) -> None:
        """A blank cell in a spreadsheet reads as "no" to everyone who opens it, and
        "not determined" is a different fact with a different action attached."""
        await snapshot_with(session, device, ncm([rule(1, "No log field stated")]))
        authenticate(analyst_user)

        response = await client.get(f"/api/v1/devices/{device.id}/firewall/export")
        rows = list(csv.DictReader(io.StringIO(response.text)))
        assert rows[0]["logging"] == "unknown"

    async def test_the_export_honours_the_filters(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        """The reason to export is usually to send on what you are looking at. Exporting
        the whole rulebase regardless would be a different document from the one on
        screen."""
        response = await client.get(
            f"/api/v1/devices/{seeded.id}/firewall/export", params={"issue": "shadowed"}
        )
        rows = list(csv.DictReader(io.StringIO(response.text)))

        assert len(rows) == 1
        assert rows[0]["name"] == "Partner RDP to web"


# ─────────────────────── the estate-wide rule query ──────────────────────


class TestSearchingTheWholeEstate:
    """ "Every any-any-any rule in the estate" was previously unaskable.

    Every firewall route was per-device, so the question meant opening each firewall in
    turn and applying the same filter by hand — even though `any_any_any` was already an
    issue key the analysis produced.

    The two properties worth testing are the ones that make the answer trustworthy
    rather than merely present: rules stay grouped and ordered per device, and devices
    that could not be searched are named rather than dropped.
    """

    async def test_it_finds_the_rule_on_every_firewall_at_once(
        self, client: AsyncClient, session: AsyncSession, seeded: Device, analyst_user: User
    ) -> None:
        principal = Principal(
            id=analyst_user.id,
            username=analyst_user.username,
            roles=analyst_user.role_set,
            scope=Scope.all(),
        )
        second = await InventoryService(session).create_device(
            mgmt_ip="198.51.100.89",
            actor=principal,
            hostname="viewer-fw-02",
            vendor=Vendor.PALOALTO,
            platform="panos",
            device_class=DeviceClass.FIREWALL,
        )
        # The headline case: one firewall in the estate carries a live any-any-any
        # permit. The seeded firewall's only such rule is disabled, so exactly one
        # device should match — which also proves a searched device that matches
        # nothing is distinguishable from one that was never searched at all.
        await snapshot_with(
            session,
            second,
            ncm([rule(1, "Temporary full access", log_end=True)]),
        )

        body = (await client.get("/api/v1/firewall/rules?issue=any_any_any")).json()

        matched = {row["hostname"] for row in body["devices"] if row["matched"]}
        assert matched == {"viewer-fw-02"}
        assert body["matched_total"] == 1

        # The other firewall was read and simply has none, which is a different fact
        # from not having been read.
        other = next(r for r in body["devices"] if r["hostname"] == "viewer-fw-01")
        assert other["not_searched"] is None
        assert other["rules_total"] == len(RULES)
        assert body["devices_searched"] == 2

    async def test_rules_stay_in_evaluation_order_within_each_device(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        """Order is meaning. A rule is shadowed because of where it sits, so a merged,
        severity-sorted estate table would destroy the fact that makes the finding true."""
        body = (await client.get("/api/v1/firewall/rules")).json()

        row = next(r for r in body["devices"] if r["hostname"] == "viewer-fw-01")
        orders = [rule["order"] for rule in row["rules"]]
        assert orders == sorted(orders)

    async def test_a_device_with_no_snapshot_is_named_not_omitted(
        self, client: AsyncClient, session: AsyncSession, seeded: Device, analyst_user: User
    ) -> None:
        """Otherwise "nothing in the estate matches" becomes a claim about devices
        nobody read."""
        principal = Principal(
            id=analyst_user.id,
            username=analyst_user.username,
            roles=analyst_user.role_set,
            scope=Scope.all(),
        )
        await InventoryService(session).create_device(
            mgmt_ip="198.51.100.90",
            actor=principal,
            hostname="never-collected",
            vendor=Vendor.PALOALTO,
            platform="panos",
            device_class=DeviceClass.FIREWALL,
        )

        body = (await client.get("/api/v1/firewall/rules")).json()

        row = next(r for r in body["devices"] if r["hostname"] == "never-collected")
        assert row["not_searched"]
        assert "no configuration has been collected" in row["not_searched"].lower()
        assert body["devices_not_searched"] == 1
        assert any("could not be searched" in note for note in body["limitations"])

    async def test_a_snapshot_with_no_rulebase_does_not_claim_the_device_is_clean(
        self, client: AsyncClient, session: AsyncSession, seeded: Device, analyst_user: User
    ) -> None:
        """A switch and a firewall whose policy failed to parse produce an identical
        empty block. The response says that rather than reporting zero matches."""
        principal = Principal(
            id=analyst_user.id,
            username=analyst_user.username,
            roles=analyst_user.role_set,
            scope=Scope.all(),
        )
        switch = await InventoryService(session).create_device(
            mgmt_ip="198.51.100.91",
            actor=principal,
            hostname="core-switch",
            vendor=Vendor.CISCO,
            platform="cisco_ios",
            device_class=DeviceClass.SWITCH,
        )
        await snapshot_with(session, switch, {"device": {"hostname": "core-switch"}})

        body = (await client.get("/api/v1/firewall/rules")).json()

        row = next(r for r in body["devices"] if r["hostname"] == "core-switch")
        assert row["matched"] == 0
        assert row["not_searched"]
        assert "could not be parsed" in row["not_searched"]

    async def test_an_incomplete_rulebase_is_carried_up_as_a_limitation(
        self, client: AsyncClient, session: AsyncSession, device: Device, analyst_user, authenticate
    ) -> None:
        """A device whose rulebase arrived short cannot support "no match here"."""
        await snapshot_with(session, device, ncm(rules_not_retrieved=450))
        authenticate(analyst_user)

        body = (await client.get("/api/v1/firewall/rules")).json()

        row = next(r for r in body["devices"] if r["hostname"] == "viewer-fw-01")
        assert row["rules_not_retrieved"] == 450
        assert any("never retrieved" in note for note in body["limitations"])

    async def test_the_filter_narrows_the_estate_the_same_way_it_narrows_one_device(
        self, client: AsyncClient, seeded: Device
    ) -> None:
        wide = (await client.get("/api/v1/firewall/rules")).json()
        narrow = (await client.get("/api/v1/firewall/rules?action=deny")).json()

        assert narrow["matched_total"] < wide["matched_total"]
        for row in narrow["devices"]:
            for rule_row in row["rules"]:
                assert rule_row["action"].lower() in {"deny", "drop", "reject"}

    async def test_it_says_when_it_did_not_look_at_the_whole_estate(
        self, client: AsyncClient, session: AsyncSession, seeded: Device, analyst_user: User
    ) -> None:
        """The response must not present the first page as though it were the estate."""
        principal = Principal(
            id=analyst_user.id,
            username=analyst_user.username,
            roles=analyst_user.role_set,
            scope=Scope.all(),
        )
        for n in range(2):
            await InventoryService(session).create_device(
                mgmt_ip=f"198.51.100.{100 + n}",
                actor=principal,
                hostname=f"extra-{n}",
                vendor=Vendor.PALOALTO,
                platform="panos",
                device_class=DeviceClass.FIREWALL,
            )

        body = (await client.get("/api/v1/firewall/rules?limit=1")).json()

        assert len(body["devices"]) == 1
        assert any("not the whole estate" in note for note in body["limitations"])

    async def test_the_estate_is_limited_to_the_callers_scope(
        self,
        client: AsyncClient,
        session: AsyncSession,
        seeded: Device,
        analyst_user: User,
        authenticate,
    ) -> None:
        """Every other firewall route names a device in its path, so the scope check sits
        on that one device. This route names none: the caller asks about "the estate" and
        the handler decides which devices that means. Nothing in the authorization matrix
        can catch a regression here, because the permission is held either way — only the
        query's scope filter keeps one tenant's rules out of another's answer.
        """
        principal = Principal(
            id=analyst_user.id,
            username=analyst_user.username,
            roles=analyst_user.role_set,
            scope=Scope.all(),
        )
        inventory = InventoryService(session)
        mine = await make_group(session, name="estate-mine")
        theirs = await make_group(session, name="estate-theirs")

        for ip, hostname, group in (
            ("198.51.100.91", "in-my-scope", mine),
            ("198.51.100.92", "not-my-scope", theirs),
        ):
            device = await inventory.create_device(
                mgmt_ip=ip,
                actor=principal,
                hostname=hostname,
                vendor=Vendor.PALOALTO,
                platform="panos",
                device_class=DeviceClass.FIREWALL,
                group_ids=[group.id],
            )
            # Both carry a live any-any-any rule, so if the filter leaked the other
            # device it would arrive with a match rather than as an empty row.
            await snapshot_with(session, device, ncm([rule(1, "Full access", log_end=True)]))

        authenticate(
            analyst_user, scope=Scope(unrestricted=False, device_group_ids=frozenset({mine.id}))
        )
        body = (await client.get("/api/v1/firewall/rules?issue=any_any_any")).json()

        assert [row["hostname"] for row in body["devices"]] == ["in-my-scope"]
        assert body["matched_total"] == 1
        # And the count it reports against is the scoped one, so the response never
        # says "1 of 2" about an estate the caller cannot see.
        assert not any("not the whole estate" in note for note in body["limitations"])
