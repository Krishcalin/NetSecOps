"""Discovery endpoints (FR-DISC-01, FR-DISC-04).

The scope model, probe allow-list, fingerprinter and review queue were all built in
Phase 7 and reachable by nobody, because no router was registered. These tests cover
the surface that closes that — and, more importantly, that the narrowness the subsystem
was built with survives being exposed over HTTP.

SRS §1.2 rules out port sweeps. The scope endpoint is where that constraint either holds
or quietly erodes: one more port for a customer running SSH on 2222, a slightly wider
prefix than intended, each defensible alone and a scanner in sum. So the refusals are
tested as carefully as the successes.

There is now an endpoint that starts a run, where before there deliberately was not. What
made it writable is FR-DISC-05: the pacer, and the fact that the prober holds one, so
"go" cannot mean "as fast as the event loop allows". These tests cover what this layer is
responsible for — refusing a disabled or unresolvable scope *before* anything is queued,
and handing the work to the queue rather than doing it in the request. The pacing itself
is proved in ``test_discovery_pacing.py`` and the run in ``test_discovery_executor.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import User
from netsecops.db.models.discovery import DiscoveredHost, DiscoveredHostStatus
from tests.conftest import make_user

SCOPES = "/api/v1/discovery/scopes"
RUNS = "/api/v1/discovery/runs"
PENDING = "/api/v1/discovery/pending"


@pytest.fixture
async def analyst_user(session: AsyncSession) -> User:
    return await make_user(session, username="disc_api_analyst", roles={Role.SECURITY_ANALYST})


@pytest.fixture
async def principal(analyst_user: User) -> Principal:
    return Principal(
        id=analyst_user.id,
        username=analyst_user.username,
        roles=analyst_user.role_set,
        scope=Scope.all(),
    )


@pytest.fixture
async def signed_in(analyst_user: User, session: AsyncSession, authenticate):
    await session.commit()
    authenticate(analyst_user)
    return analyst_user


async def add_host(
    session: AsyncSession,
    *,
    address: str,
    confidence: int,
    vendor: str | None = None,
    platform: str | None = None,
    hostname: str | None = None,
) -> DiscoveredHost:
    now = datetime.now(UTC)
    row = DiscoveredHost(
        org_id=1,
        address=address,
        status=DiscoveredHostStatus.PENDING.value,
        vendor=vendor,
        platform=platform,
        hostname=hostname,
        confidence=confidence,
        fingerprint={"ssh_banner": "SSH-2.0-Cisco-1.25"} if vendor else {},
        first_seen_at=now,
        last_seen_at=now,
    )
    session.add(row)
    await session.flush()
    return row


class TestScopes:
    async def test_a_scope_reports_its_resolved_address_count(
        self, client: AsyncClient, signed_in
    ) -> None:
        """The number an operator sanity-checks before running anything."""
        response = await client.post(
            SCOPES, json={"name": "branch-edge", "targets": ["198.51.100.0/24"]}
        )

        assert response.status_code == 201, response.text
        assert response.json()["address_count"] == 254

    async def test_exclusions_are_subtracted_from_the_count(
        self, client: AsyncClient, signed_in
    ) -> None:
        """Excluded space is removed from the address space, not filtered at probe time.

        So an excluded host is never enumerated at all, and the count says so up front.

        126, not 128: what remains is the `198.51.100.128/25` network, and the count is
        of *usable* hosts, so its network and broadcast addresses are not probed. The
        /24 above gives 254 on the same rule.
        """
        response = await client.post(
            SCOPES,
            json={
                "name": "carved",
                "targets": ["198.51.100.0/24"],
                "exclusions": ["198.51.100.0/25"],
            },
        )

        assert response.status_code == 201
        assert response.json()["address_count"] == 126

    async def test_a_mistyped_prefix_is_refused_with_a_reason(
        self, client: AsyncClient, signed_in
    ) -> None:
        """`10.0.0.0/8` is one character from `10.0.0.0/18` and sixteen million probes
        from what the operator meant."""
        response = await client.post(SCOPES, json={"name": "oops", "targets": ["10.0.0.0/8"]})

        assert response.status_code >= 400
        assert "10.0.0.0" in response.text or "addresses" in response.text.lower()

    async def test_a_long_port_list_is_refused(self, client: AsyncClient, signed_in) -> None:
        """ "Configurable list" otherwise permits a sweep assembled entirely from
        individually permitted probes."""
        response = await client.post(
            SCOPES,
            json={
                "name": "sweepy",
                "targets": ["198.51.100.0/30"],
                "tcp_ports": [22, 23, 80, 443, 445, 3389, 8080, 8443, 9090],
            },
        )

        assert response.status_code == 422
        assert "port" in response.text.lower()

    async def test_an_eight_port_list_is_allowed(self, client: AsyncClient, signed_in) -> None:
        """The ceiling is eight, not "a few" — the boundary is the whole point."""
        response = await client.post(
            SCOPES,
            json={
                "name": "at-the-limit",
                "targets": ["198.51.100.0/30"],
                "tcp_ports": [22, 23, 80, 443, 445, 3389, 8080, 8443],
            },
        )

        assert response.status_code == 201

    async def test_auto_onboard_is_off_unless_asked_for(
        self, client: AsyncClient, signed_in
    ) -> None:
        """FR-DISC-04 makes review the norm and auto-onboarding the exception."""
        body = (
            await client.post(SCOPES, json={"name": "default", "targets": ["198.51.100.0/30"]})
        ).json()

        assert body["auto_onboard"] is False

    async def test_snmp_is_off_unless_a_credential_is_configured(
        self, client: AsyncClient, signed_in
    ) -> None:
        """Probing SNMP without a credential means trying `public`, which is a guess."""
        body = (
            await client.post(SCOPES, json={"name": "nosnmp", "targets": ["198.51.100.0/30"]})
        ).json()

        assert body["snmp_configured"] is False

    async def test_scopes_round_trip(self, client: AsyncClient, signed_in) -> None:
        await client.post(SCOPES, json={"name": "one", "targets": ["198.51.100.0/30"]})

        listed = (await client.get(SCOPES)).json()

        assert [row["name"] for row in listed] == ["one"]

    async def test_a_scope_can_be_deleted(self, client: AsyncClient, signed_in) -> None:
        created = (
            await client.post(SCOPES, json={"name": "temp", "targets": ["198.51.100.0/30"]})
        ).json()

        deleted = await client.delete(f"{SCOPES}/{created['id']}")

        assert deleted.status_code == 204
        assert (await client.get(SCOPES)).json() == []

    async def test_deleting_an_unknown_scope_is_a_404(self, client: AsyncClient, signed_in) -> None:
        response = await client.delete(f"{SCOPES}/00000000-0000-0000-0000-000000000000")

        assert response.status_code == 404


@pytest.fixture
def deferred_queue():
    """Record what the endpoint queues without executing it.

    The default queue runs jobs inline, which is right for development and wrong here:
    it would open its own database session and probe real addresses from inside an HTTP
    test. What this layer owes is "the right work was queued"; whether the work is
    correct is `test_discovery_executor.py`'s question.
    """
    from netsecops.workers.queue import DeferredQueue, set_queue

    queue = DeferredQueue()
    set_queue(queue)
    yield queue
    set_queue(None)


async def create_scope(client: AsyncClient, **overrides) -> dict:
    body = {"name": "lab", "targets": ["198.51.100.0/30"], **overrides}
    response = await client.post(SCOPES, json=body)
    assert response.status_code == 201, response.text
    return response.json()


class TestStartingARun:
    async def test_it_queues_the_work_rather_than_doing_it(
        self, client: AsyncClient, signed_in, deferred_queue
    ) -> None:
        """202, and a job to watch.

        Probing even a small scope outlives an HTTP request, so the run is handed to the
        queue. The ``discovery_runs`` row does not exist yet when this returns — the
        executor writes it as its first act — which is why a job id comes back.
        """
        scope = await create_scope(client)

        response = await client.post(f"{SCOPES}/{scope['id']}/runs", json={})

        assert response.status_code == 202
        body = response.json()
        assert body["scope_id"] == scope["id"]
        assert body["address_count"] == 2
        assert body["rate_limit_per_second"] == 50
        assert len(deferred_queue.enqueued) == 1
        assert str(deferred_queue.enqueued[0][0]) == body["job_id"]

    async def test_the_job_it_queues_targets_no_devices(
        self, client: AsyncClient, signed_in, session: AsyncSession, deferred_queue
    ) -> None:
        """The property that keeps discovery from authenticating to anything.

        A discovery job carries a scope id and no ``job_devices`` rows. If it carried
        devices, the runner's device loop would resolve credentials and open a session
        against a host nobody has approved — which is what FR-DISC-04 exists to prevent.
        """
        from sqlalchemy import select

        from netsecops.db.models.jobs import Job, JobDevice, JobType

        scope = await create_scope(client)
        await client.post(f"{SCOPES}/{scope['id']}/runs", json={})

        job = (await session.execute(select(Job))).scalars().one()
        assert job.job_type == JobType.DISCOVERY.value
        assert job.scope == {"discovery_scope_id": scope["id"]}
        assert (await session.execute(select(JobDevice))).scalars().all() == []

    async def test_a_disabled_scope_is_refused_and_nothing_is_queued(
        self, client: AsyncClient, signed_in, deferred_queue
    ) -> None:
        """Enabling is how the decision to send packets is made explicit."""
        scope = await create_scope(client, enabled=False)

        response = await client.post(f"{SCOPES}/{scope['id']}/runs", json={})

        assert response.status_code == 422
        assert deferred_queue.enqueued == []

    async def test_an_unknown_scope_is_a_404(
        self, client: AsyncClient, signed_in, deferred_queue
    ) -> None:
        response = await client.post(f"{SCOPES}/00000000-0000-0000-0000-000000000000/runs", json={})

        assert response.status_code == 404
        assert deferred_queue.enqueued == []

    async def test_a_retried_request_does_not_start_a_second_run(
        self, client: AsyncClient, signed_in, deferred_queue
    ) -> None:
        """An idempotency key means a retried POST re-probes nothing.

        Without it, a client that times out and retries sends every packet twice — and
        the operator has no way to tell that from a network that answered differently.
        """
        scope = await create_scope(client)
        payload = {"idempotency_key": "run-once-please"}

        first = await client.post(f"{SCOPES}/{scope['id']}/runs", json=payload)
        second = await client.post(f"{SCOPES}/{scope['id']}/runs", json=payload)

        assert first.json()["job_id"] == second.json()["job_id"]

    async def test_starting_a_run_needs_more_than_read_access(
        self, client: AsyncClient, session: AsyncSession, authenticate, deferred_queue
    ) -> None:
        """Sending packets to a customer's network is not a read.

        It sits with the roles that may create devices, not with everyone who may look
        at them — the same placement as defining the scope in the first place.
        """
        auditor = await make_user(session, username="disc_auditor", roles={Role.AUDITOR})
        analyst = await make_user(session, username="disc_starter", roles={Role.SECURITY_ANALYST})
        await session.commit()

        authenticate(analyst)
        scope = await create_scope(client)

        authenticate(auditor)
        response = await client.post(f"{SCOPES}/{scope['id']}/runs", json={})

        assert response.status_code == 403
        assert deferred_queue.enqueued == []


class TestRunHistory:
    async def test_the_run_history_reads_empty_rather_than_erroring(
        self, client: AsyncClient, signed_in
    ) -> None:
        response = await client.get(RUNS)

        assert response.status_code == 200
        assert response.json() == []

    async def test_a_run_carries_its_caveats_alongside_its_counters(
        self, client: AsyncClient, signed_in, session: AsyncSession
    ) -> None:
        """ "0 hosts found" beside "no echo request could be sent" is a different answer.

        The counters alone would make an estate nobody could have detected read exactly
        like a quiet one, which is the same misreport as an unevaluated check shown as a
        pass.
        """
        from netsecops.db.models.discovery import DiscoveryRun, DiscoveryRunStatus, DiscoveryScope

        scope_row = DiscoveryScope(
            org_id=1, name="noted", targets=["198.51.100.0/30"], tcp_ports=[22]
        )
        session.add(scope_row)
        await session.flush()
        session.add(
            DiscoveryRun(
                org_id=1,
                scope_id=scope_row.id,
                status=DiscoveryRunStatus.SUCCEEDED.value,
                notes=["ICMP was unavailable."],
            )
        )
        await session.flush()

        body = (await client.get(RUNS)).json()

        assert body[0]["notes"] == ["ICMP was unavailable."]


class TestTheReviewQueue:
    async def test_the_queue_opens_with_the_least_understood_host(
        self, client: AsyncClient, session: AsyncSession, signed_in
    ) -> None:
        """Ascending confidence, deliberately.

        The entries that most need a human are the ones the fingerprinter was least
        sure about; sorting the other way puts the easy ones on page one and the
        genuinely unknown devices where nobody looks.
        """
        await add_host(session, address="198.51.100.10", confidence=90, vendor="cisco")
        await add_host(session, address="198.51.100.11", confidence=20)
        await add_host(session, address="198.51.100.12", confidence=55, vendor="fortinet")
        await session.commit()

        rows = (await client.get(PENDING)).json()["data"]

        assert [row["confidence"] for row in rows] == [20, 55, 90]

    async def test_a_host_carries_the_evidence_behind_its_guess(
        self, client: AsyncClient, session: AsyncSession, signed_in
    ) -> None:
        """A fingerprint an operator cannot inspect is one they have to take on faith."""
        host = await add_host(
            session, address="198.51.100.20", confidence=70, vendor="cisco", platform="cisco_ios"
        )
        await session.commit()

        body = (await client.get(f"{PENDING}/{host.id}")).json()

        assert body["address"] == "198.51.100.20"
        assert body["vendor"] == "cisco"
        assert body["fingerprint"]["ssh_banner"] == "SSH-2.0-Cisco-1.25"

    async def test_approving_creates_the_device(
        self, client: AsyncClient, session: AsyncSession, signed_in
    ) -> None:
        host = await add_host(
            session, address="198.51.100.30", confidence=80, vendor="cisco", platform="cisco_ios"
        )
        await session.commit()

        response = await client.post(
            f"{PENDING}/{host.id}/approve",
            json={"platform": "cisco_ios", "device_class": "switch", "hostname": "sw-new"},
        )

        assert response.status_code == 200, response.text
        assert response.json()["hostname"] == "sw-new"

    async def test_an_operator_can_correct_the_fingerprinters_guess(
        self, client: AsyncClient, session: AsyncSession, signed_in
    ) -> None:
        """A wrong platform picks the wrong collection profile and with it the wrong
        command allow-list — the one mistake here with a blast radius past the
        inventory."""
        host = await add_host(
            session, address="198.51.100.31", confidence=40, vendor="cisco", platform="cisco_ios"
        )
        await session.commit()

        response = await client.post(
            f"{PENDING}/{host.id}/approve",
            json={"vendor": "fortinet", "platform": "fortios", "device_class": "firewall"},
        )

        assert response.status_code == 200
        assert response.json()["platform"] == "fortios"

    async def test_an_approved_host_leaves_the_queue(
        self, client: AsyncClient, session: AsyncSession, signed_in
    ) -> None:
        host = await add_host(session, address="198.51.100.32", confidence=80, vendor="cisco")
        await session.commit()

        await client.post(
            f"{PENDING}/{host.id}/approve", json={"platform": "cisco_ios", "device_class": "switch"}
        )

        assert (await client.get(PENDING)).json()["data"] == []

    async def test_rejecting_without_a_reason_is_refused(
        self, client: AsyncClient, session: AsyncSession, signed_in
    ) -> None:
        """ "Rejected" with no reason tells the next person nothing, and the question
        they will have — a printer, or a switch nobody got round to — decides whether
        they reopen it."""
        host = await add_host(session, address="198.51.100.40", confidence=15)
        await session.commit()

        response = await client.post(f"{PENDING}/{host.id}/reject", json={"note": ""})

        assert response.status_code == 422

    async def test_rejecting_with_a_reason_records_it(
        self, client: AsyncClient, session: AsyncSession, signed_in
    ) -> None:
        host = await add_host(session, address="198.51.100.41", confidence=15)
        await session.commit()

        response = await client.post(
            f"{PENDING}/{host.id}/reject",
            json={"note": "Site printer, confirmed with the facilities team."},
        )

        assert response.status_code == 200
        assert response.json()["review_note"].startswith("Site printer")
        assert (await client.get(PENDING)).json()["data"] == []

    async def test_an_unknown_host_is_a_404(self, client: AsyncClient, signed_in) -> None:
        response = await client.get(f"{PENDING}/00000000-0000-0000-0000-000000000000")

        assert response.status_code == 404
