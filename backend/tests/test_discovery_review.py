"""The discovery review queue (FR-DISC-04).

    Nothing is assessed automatically without approval unless a scope is flagged
    "auto-onboard".

That sentence is the whole safety boundary of the discovery feature. Everything before
it only reads — a probe opens a TCP connection and reads a banner. Approval is where
NetSecOps stops looking at a host and starts *authenticating* to it, on a customer's
production network, with credentials it may inherit from a group nobody thought about.

So most of what follows is about one property: an unapproved host has no device row, and
therefore cannot be reached by anything that enumerates the estate. Not because the
queries filter it out — because there is nothing to find.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ConflictError, ValidationProblem
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import AuditLog, Device
from netsecops.db.models.discovery import DiscoveredHost, DiscoveredHostStatus
from netsecops.db.models.inventory import DeviceClass, DeviceStatus
from netsecops.discovery.fingerprint import Evidence, Signal, fingerprint, read_sysobjectid
from netsecops.services.discovery_review import DiscoveryReviewService
from tests.conftest import make_user


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="discovery_reviewer", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
def review(session: AsyncSession) -> DiscoveryReviewService:
    return DiscoveryReviewService(session)


def cisco_asa():
    """A confidently-identified host: the authoritative signal, uncontested."""
    return fingerprint([read_sysobjectid("1.3.6.1.4.1.9.1.745")])


def unidentified():
    return fingerprint([Evidence(Signal.SSH_BANNER, "SSH-2.0-OpenSSH_8.2")])


def contested():
    return fingerprint(
        [
            Evidence(Signal.SSH_BANNER, "SSH-2.0-Cisco-1.25", vendor="cisco"),
            Evidence(Signal.TLS_SUBJECT, "O=Fortinet", vendor="fortinet"),
        ]
    )


# ════════════════════════ the boundary itself ════════════════════════════════


class TestAnUnapprovedHostIsNotADevice:
    async def test_recording_creates_no_device(self, review, session) -> None:
        """The property everything else rests on.

        A discovery run that created inventory would have NetSecOps authenticating to
        boxes nobody agreed it should touch.
        """
        await review.record("10.0.0.5", fingerprint=cisco_asa())

        assert (await session.execute(select(Device))).scalars().all() == []

    async def test_it_lands_pending(self, review, session) -> None:
        host = await review.record("10.0.0.5", fingerprint=cisco_asa())

        assert host.status == DiscoveredHostStatus.PENDING.value
        assert host.device_id is None

    async def test_the_fingerprint_is_kept_verbatim_for_the_reviewer(self, review) -> None:
        """ "Cisco, 90%" is not something anybody can check."""
        host = await review.record("10.0.0.5", fingerprint=cisco_asa())

        assert host.fingerprint["evidence"][0]["raw"] == "1.3.6.1.4.1.9.1.745"
        assert host.fingerprint["evidence"][0]["signal"] == "snmp_sysobjectid"
        assert host.confidence > 0


class TestApproval:
    async def test_approving_creates_the_device(self, review, actor, session) -> None:
        host = await review.record("10.0.0.5", fingerprint=cisco_asa())

        device = await review.approve(host, actor=actor, device_class=DeviceClass.FIREWALL)

        assert str(device.mgmt_ip) == "10.0.0.5"
        assert device.vendor == "cisco"
        assert device.platform == "cisco_asa"
        assert host.status == DiscoveredHostStatus.APPROVED.value
        assert host.device_id == device.id

    async def test_the_new_device_is_not_yet_assessable(self, review, actor) -> None:
        """Approved is not onboarded.

        Nothing has been collected and no credential is assigned, so reporting it as
        active would put a device into compliance figures that cannot be assessed.
        """
        host = await review.record("10.0.0.5", fingerprint=cisco_asa())

        device = await review.approve(host, actor=actor)

        assert device.status == DeviceStatus.PENDING_REVIEW.value

    async def test_the_reviewer_can_override_the_fingerprint(self, review, actor) -> None:
        """Confidence is capped below certainty precisely because nothing here is
        authenticated. What the human confirms is what gets stored."""
        host = await review.record("10.0.0.5", fingerprint=cisco_asa())

        device = await review.approve(host, actor=actor, vendor="fortinet", platform="fortios")

        assert device.vendor == "fortinet"
        assert device.platform == "fortios"

    async def test_an_unidentified_host_cannot_be_approved_blind(self, review, actor) -> None:
        """Without a vendor there is no parser and no collection profile.

        The device would be created and immediately unusable, so the reviewer is made to
        say what it is rather than shipping a broken inventory row.
        """
        host = await review.record("10.0.0.9", fingerprint=unidentified())

        with pytest.raises(ValidationProblem, match="could not be identified"):
            await review.approve(host, actor=actor)

    async def test_an_unidentified_host_can_be_approved_with_a_vendor(self, review, actor) -> None:
        host = await review.record("10.0.0.9", fingerprint=unidentified())

        device = await review.approve(host, actor=actor, vendor="cisco", platform="cisco_ios")

        assert device.vendor == "cisco"

    async def test_approving_twice_is_refused(self, review, actor) -> None:
        host = await review.record("10.0.0.5", fingerprint=cisco_asa())
        await review.approve(host, actor=actor)

        with pytest.raises(ConflictError, match="already been approved"):
            await review.approve(host, actor=actor)

    async def test_approval_is_attributable(self, review, actor, session) -> None:
        """Somebody agreed to this. The record says who."""
        host = await review.record("10.0.0.5", fingerprint=cisco_asa())
        await review.approve(host, actor=actor)

        assert host.reviewed_by_id == actor.id
        assert host.reviewed_at is not None

        entries = (
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.object_type == "discovered_host")
                )
            )
            .scalars()
            .all()
        )
        assert entries
        assert entries[0].details["origin"] == "discovery.approved"


class TestRejection:
    async def test_rejecting_needs_a_reason(self, review, actor) -> None:
        """ "Rejected" with no reason tells the next person nothing, and the question
        they will have — printer, or switch nobody got round to? — is what decides
        whether they re-open it."""
        host = await review.record("10.0.0.7", fingerprint=unidentified())

        with pytest.raises(ValidationProblem, match="needs a reason"):
            await review.reject(host, actor=actor, note="")

    async def test_a_rejected_host_creates_no_device(self, review, actor, session) -> None:
        host = await review.record("10.0.0.7", fingerprint=cisco_asa())

        await review.reject(host, actor=actor, note="Neighbouring tenant's switch.")

        assert host.status == DiscoveredHostStatus.REJECTED.value
        assert host.device_id is None
        assert (await session.execute(select(Device))).scalars().all() == []

    async def test_a_later_run_does_not_requeue_a_rejected_host(self, review, actor) -> None:
        """Re-queueing every night trains reviewers to clear the queue without reading
        it, which is how the one host that mattered gets waved through."""
        host = await review.record("10.0.0.7", fingerprint=cisco_asa())
        await review.reject(host, actor=actor, note="Not ours.")

        again = await review.record("10.0.0.7", fingerprint=cisco_asa())

        assert again.id == host.id
        assert again.status == DiscoveredHostStatus.REJECTED.value


class TestRepeatedDiscovery:
    async def test_a_host_seen_twice_is_one_queue_entry(self, review, session) -> None:
        await review.record("10.0.0.5", fingerprint=cisco_asa())
        await review.record("10.0.0.5", fingerprint=cisco_asa())

        hosts = (await session.execute(select(DiscoveredHost))).scalars().all()
        assert len(hosts) == 1
        assert hosts[0].last_seen_at is not None

    async def test_a_later_run_does_not_relabel_an_approved_host(self, review, actor) -> None:
        """Once a human has ruled on it, a run must not silently change what it is.

        Relabelling an approved entry would change the identity of something somebody
        already agreed to onboard.
        """
        host = await review.record("10.0.0.5", fingerprint=cisco_asa())
        await review.approve(host, actor=actor)

        await review.record(
            "10.0.0.5",
            fingerprint=fingerprint([Evidence(Signal.SSH_BANNER, "x", vendor="fortinet")]),
        )

        assert host.vendor == "cisco"


# ═══════════════════════ the escape hatch (FR-DISC-04) ═══════════════════════


class TestAutoOnboard:
    async def test_a_confident_uncontested_host_is_onboarded(self, review, actor) -> None:
        host = await review.record("10.0.0.5", fingerprint=cisco_asa())

        device = await review.auto_onboard(host, actor=actor)

        assert device is not None
        assert host.status == DiscoveredHostStatus.APPROVED.value

    async def test_an_unidentified_host_still_queues(self, review, actor, session) -> None:
        """The escape hatch must not become the thing the requirement prevents."""
        host = await review.record("10.0.0.9", fingerprint=unidentified())

        assert await review.auto_onboard(host, actor=actor) is None
        assert host.status == DiscoveredHostStatus.PENDING.value
        assert (await session.execute(select(Device))).scalars().all() == []

    async def test_a_contested_host_still_queues(self, review, actor, session) -> None:
        """Signals disagreeing means a proxy, a NAT, or a stale certificate.

        Auto-onboarding that is how NetSecOps ends up authenticating to whatever is
        actually behind the address.
        """
        host = await review.record("10.0.0.8", fingerprint=contested())

        assert await review.auto_onboard(host, actor=actor) is None
        assert host.status == DiscoveredHostStatus.PENDING.value

    async def test_auto_onboarding_is_distinguishable_in_the_audit_trail(
        self, review, actor, session
    ) -> None:
        """ "Did a human agree to this device?" must be answerable without inferring it
        from a timestamp."""
        host = await review.record("10.0.0.5", fingerprint=cisco_asa())
        await review.auto_onboard(host, actor=actor)

        origins = {
            entry.details.get("origin")
            for entry in (
                (
                    await session.execute(
                        select(AuditLog).where(AuditLog.object_type == "discovered_host")
                    )
                )
                .scalars()
                .all()
            )
        }
        assert "discovery.auto_onboarded" in origins


# ═══════════════════════════════ the queue ═══════════════════════════════════


class TestTheQueue:
    async def test_only_pending_hosts_appear(self, review, actor) -> None:
        pending = await review.record("10.0.0.5", fingerprint=cisco_asa())
        rejected = await review.record("10.0.0.6", fingerprint=cisco_asa())
        await review.reject(rejected, actor=actor, note="Not ours.")

        queue = await review.pending()

        assert [h.id for h in queue] == [pending.id]

    async def test_the_least_certain_are_first(self, review) -> None:
        """The entries that most need a human are the ones the fingerprinter was least
        sure about. Sorted the other way, page one is the easy ones."""
        await review.record("10.0.0.5", fingerprint=cisco_asa())
        await review.record(
            "10.0.0.6", fingerprint=fingerprint([Evidence(Signal.HTTP_HEADER, "x", vendor="cisco")])
        )

        queue = await review.pending()

        assert [h.confidence for h in queue] == sorted(h.confidence for h in queue)
        assert str(queue[0].address) == "10.0.0.6"
