"""Running a discovery scope (FR-DISC-05).

The four pieces built before this — the scope, the probe allow-list, the fingerprinter
and the review queue — had nothing driving them, so the review queue was empty in any
real deployment and that was the state of the subsystem rather than a fault. This is
what drives them.

**The run is paced, and the pacing is not optional.** Addresses are probed through a
:class:`~netsecops.discovery.transport.HostProber`, which holds the
:class:`~netsecops.discovery.pacing.HostPacer` and takes a slot before every host. There
is no path from here to a socket that skips it. That is the whole reason this executor
did not ship alongside the scope model: an unpaced run across a scope is the port sweep
SRS §1.2 forbids, whatever the allow-list says about the individual packets.

**Concurrency is bounded, and separate from the rate.** They answer different questions:
the rate says how often a host may be *started*, concurrency says how many may be in
flight while the slow ones time out. Without the second, a scope of mostly-dead
addresses runs at one host per timeout — a /24 of silence costs thirteen minutes at a
three-second timeout, and the rate limit never binds, so the operator's setting appears
to do nothing. Hosts are probed a batch at a time and the batch's results are written
together, which keeps every database write on the one session that owns it: an
``AsyncSession`` used from several tasks at once corrupts quietly rather than failing.

**A run reports what it could not do.** Two things can be unavailable and both would
otherwise look like an empty network. SNMP needs an SNMPv2c credential attached to the
scope; without one a flagged scope gets a caveat rather than a sysObjectID — the single
heaviest fingerprint signal, whose absence is why an entry sits low in the queue. ICMP
needs a capability containers withhold by default. Both land in
:attr:`DiscoveryRun.notes`, because "found 0 hosts" and "found 0 hosts and could not send
a single echo request" are different answers and must not print the same.
"""

from __future__ import annotations

import asyncio
import itertools
import uuid
from collections.abc import Awaitable, Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.crypto import SecretVault
from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Principal
from netsecops.db.models.discovery import DiscoveryRun, DiscoveryRunStatus, DiscoveryScope
from netsecops.discovery.fingerprint import Fingerprint, fingerprint
from netsecops.discovery.pacing import HostPacer
from netsecops.discovery.probes import ProbeViolationError
from netsecops.discovery.scopes import build_scope
from netsecops.discovery.transport import (
    DEFAULT_PROBE_TIMEOUT,
    HostProber,
    HostResult,
    icmp_capability,
)
from netsecops.services.discovery_review import DiscoveryReviewService

log = get_logger(__name__)

#: How many hosts may be in flight at once.
#:
#: Chosen against the timeout rather than the rate: at a three-second probe timeout, 32
#: concurrent hosts clear roughly ten addresses a second through dead space, which keeps
#: a /24 sweep inside half a minute without ever approaching the default 50/s ceiling.
#: Raising it does not make discovery faster than its rate limit — the pacer still gates
#: every host — it only stops slow addresses from being the constraint.
DEFAULT_CONCURRENCY: Final[int] = 32

#: Caveat recorded when a scope asks for SNMP and no usable credential is available.
#:
#: Recorded rather than fatal: SNMP is optional (FR-DISC-02), so the run still sends the
#: other four probes. But the operator has to be told, because the difference this makes
#: is every host's fingerprint confidence — and a queue full of low-confidence entries
#: looks like a hard-to-identify estate rather than a missing credential.
SNMP_UNAVAILABLE_NOTE: Final[str] = (
    "This scope is flagged for SNMP, but no usable SNMPv2c credential is attached to it, "
    "so sysDescr and sysObjectID were not read. That is the heaviest fingerprint signal "
    "there is, so hosts here score lower and sit further up the review queue than they "
    "would with SNMP available (FR-DISC-02). Attach an SNMPv2c credential to the scope."
)

#: Called between batches; returning True stops the run and marks it partial.
StopCheck = Callable[[], Awaitable[bool]]

#: Probes one address. Injected so a test can drive a whole run without a socket.
ProbeHost = Callable[[str], Awaitable[HostResult]]


@dataclass(slots=True)
class RunSummary:
    """The counters a job's stats and the run row both want."""

    run_id: uuid.UUID
    status: str
    addresses_probed: int = 0
    hosts_found: int = 0
    hosts_unidentified: int = 0
    hosts_onboarded: int = 0
    probes_sent: int = 0
    #: Seconds spent waiting on the limiter. Zero means the rate was never the binding
    #: constraint, which is the normal case for a sparse scope and worth being able to
    #: tell apart from a limiter that is not working.
    paced_seconds: float = 0.0
    notes: list[str] = field(default_factory=list)

    def as_stats(self) -> dict[str, Any]:
        return {
            "discovery_run_id": str(self.run_id),
            "addresses_probed": self.addresses_probed,
            "hosts_found": self.hosts_found,
            "hosts_unidentified": self.hosts_unidentified,
            "hosts_onboarded": self.hosts_onboarded,
            "probes_sent": self.probes_sent,
            "paced_seconds": round(self.paced_seconds, 3),
        }


class DiscoveryExecutor:
    """Turns a stored scope into probes, findings and queue entries."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        org_id: int = 1,
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: float = DEFAULT_PROBE_TIMEOUT,
        probe_host: ProbeHost | None = None,
        vault: SecretVault | None = None,
    ) -> None:
        self.session = session
        self.vault = vault
        self.org_id = org_id
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        #: When supplied, replaces the real prober entirely. Tests use it to run the
        #: executor end to end — batching, counters, cancellation, auto-onboard — with no
        #: socket, which is the only way those paths get covered in CI.
        self._probe_host = probe_host
        self.reviews = DiscoveryReviewService(session, org_id=org_id)

    async def run(
        self,
        scope_row: DiscoveryScope,
        *,
        actor: Principal,
        should_stop: StopCheck | None = None,
        job_id: uuid.UUID | None = None,
    ) -> RunSummary:
        """Probe every address in the scope, then close the run.

        The ``DiscoveryRun`` row is created before the first probe and updated after
        every batch, so an operator watching a long run sees it move. A run that dies
        mid-way therefore leaves a row saying how far it got, rather than nothing.
        """
        if not scope_row.enabled:
            raise ValidationProblem(
                f"Discovery scope '{scope_row.name}' is disabled. Enable it before "
                "running it, so that the decision to probe these addresses is explicit."
            )

        resolved = build_scope(
            scope_row.name,
            scope_row.targets,
            exclusions=scope_row.exclusions,
            tcp_ports=scope_row.tcp_ports or None,
            snmp_configured=scope_row.snmp_configured,
            auto_onboard=scope_row.auto_onboard,
        )

        notes: list[str] = []
        icmp_note = icmp_capability()
        if icmp_note:
            notes.append(icmp_note)

        # Resolved *before* the run row is written, because the row takes a copy of
        # `notes` and anything appended afterwards is never persisted. A caveat that does
        # not reach the run is the same as no caveat at all.
        community = await self._snmp_community(scope_row)
        if scope_row.snmp_configured and community is None:
            notes.append(SNMP_UNAVAILABLE_NOTE)

        run = DiscoveryRun(
            org_id=self.org_id,
            scope_id=scope_row.id,
            job_id=job_id,
            status=DiscoveryRunStatus.RUNNING.value,
            started_at=datetime.now(UTC),
            notes=list(notes),
        )
        self.session.add(run)
        await self.session.flush()

        summary = RunSummary(run_id=run.id, status=DiscoveryRunStatus.RUNNING.value, notes=notes)

        pacer = HostPacer(scope_row.rate_limit_per_second)

        prober = HostProber(
            pacer,
            tcp_ports=resolved.tcp_ports,
            snmp_configured=scope_row.snmp_configured and community is not None,
            snmp_community=community,
            timeout=self.timeout,
            icmp_available=icmp_note is None,
        )
        probe_host = self._probe_host or prober.probe

        log.info(
            "discovery.run_started",
            run_id=str(run.id),
            scope=scope_row.name,
            addresses=resolved.size,
            rate_per_second=scope_row.rate_limit_per_second,
            concurrency=self.concurrency,
            icmp=icmp_note is None,
        )

        stopped = False
        try:
            for batch in _batched(resolved.hosts(), self.concurrency):
                if should_stop is not None and await should_stop():
                    stopped = True
                    log.info("discovery.run_cancelled", run_id=str(run.id))
                    break

                results = await self._probe_batch(probe_host, batch)
                await self._record_batch(
                    results, run=run, scope_row=scope_row, actor=actor, summary=summary
                )

                run.addresses_probed = summary.addresses_probed
                run.hosts_found = summary.hosts_found
                run.hosts_unidentified = summary.hosts_unidentified
                await self.session.flush()

        except ProbeViolationError as exc:
            # The platform tried to send something it guarantees it does not send. That
            # is not a host that failed to answer, and it must not be counted as one:
            # the run stops and says so.
            summary.status = DiscoveryRunStatus.FAILED.value
            run.status = summary.status
            run.finished_at = datetime.now(UTC)
            run.error_message = str(exc)
            await self.session.flush()
            log.error("discovery.run_aborted", run_id=str(run.id), error=str(exc))
            raise

        if self._probe_host is None:
            summary.paced_seconds = prober.paced_seconds

        summary.status = (
            DiscoveryRunStatus.PARTIAL.value if stopped else DiscoveryRunStatus.SUCCEEDED.value
        )
        run.status = summary.status
        run.finished_at = datetime.now(UTC)
        run.addresses_probed = summary.addresses_probed
        run.hosts_found = summary.hosts_found
        run.hosts_unidentified = summary.hosts_unidentified
        run.notes = list(summary.notes)
        await self.session.flush()

        log.info(
            "discovery.run_finished",
            run_id=str(run.id),
            status=run.status,
            addresses_probed=summary.addresses_probed,
            hosts_found=summary.hosts_found,
            hosts_unidentified=summary.hosts_unidentified,
        )
        return summary

    async def _snmp_community(self, scope_row: DiscoveryScope) -> str | None:
        """Open the scope's SNMP credential, or None if it cannot be used.

        Returns None rather than raising for every ordinary reason — no credential set,
        the credential deleted, the wrong type, an unreadable blob — because SNMP is
        optional (FR-DISC-02) and the scope should still send the other four probes. The
        caller records a note, so the gap is visible rather than silent: the difference it
        makes is every host's fingerprint confidence.

        SNMPv3 is refused here rather than attempted. Its User Security Model needs a
        username and two keys *per device*, which nobody has for a host they have not yet
        identified, so a v3 attempt against an unknown host is a guess — exactly what
        FR-DISC-02 rules out.
        """
        import json

        from sqlalchemy import select

        from netsecops.db.models.inventory import Credential, CredentialType

        if scope_row.snmp_credential_id is None or self.vault is None:
            return None

        credential = (
            await self.session.execute(
                select(Credential).where(Credential.id == scope_row.snmp_credential_id)
            )
        ).scalar_one_or_none()
        if credential is None:
            return None

        if credential.credential_type != CredentialType.SNMP_V2C.value:
            log.info(
                "discovery.snmp_credential_unusable",
                scope=str(scope_row.id),
                credential_type=credential.credential_type,
            )
            return None

        try:
            opened = self.vault.open(credential.encrypted_blob, aad=str(credential.id))
            secret = json.loads(opened)
        except Exception:
            log.warning("discovery.snmp_credential_unreadable", scope=str(scope_row.id))
            return None

        community = secret.get("community") or secret.get("password")
        return str(community) if community else None

    async def _probe_batch(self, probe_host: ProbeHost, batch: list[str]) -> list[HostResult]:
        """Probe a batch concurrently, and let a violation through.

        ``return_exceptions`` keeps one unreachable address from abandoning the other
        thirty-one — the same reasoning as a device failure not failing a collection job.
        A :class:`ProbeViolationError` is the exception to that, and is re-raised: it
        means the allow-list was breached, which is a fault in the platform rather than
        in the network.
        """
        outcomes = await asyncio.gather(
            *(probe_host(address) for address in batch), return_exceptions=True
        )

        results: list[HostResult] = []
        for address, outcome in zip(batch, outcomes, strict=True):
            if isinstance(outcome, ProbeViolationError):
                raise outcome
            if isinstance(outcome, BaseException):
                log.warning("discovery.probe_failed", address=address, error=str(outcome))
                results.append(HostResult(address=address, responded=False))
                continue
            results.append(outcome)
        return results

    async def _record_batch(
        self,
        results: list[HostResult],
        *,
        run: DiscoveryRun,
        scope_row: DiscoveryScope,
        actor: Principal,
        summary: RunSummary,
    ) -> None:
        """Write one batch's results. Serial, on the session that owns them."""
        for result in results:
            summary.addresses_probed += 1
            summary.probes_sent += result.probes_sent

            if not result.responded:
                # Silence is the normal answer and is not recorded. A row per dead
                # address would bury the queue under the network's empty space.
                continue

            summary.hosts_found += 1
            identity: Fingerprint = fingerprint(result.evidence)
            if not identity.identified:
                summary.hosts_unidentified += 1

            host = await self.reviews.record(
                result.address,
                fingerprint=identity,
                run_id=run.id,
                hostname=result.hostname,
            )

            for note in result.notes:
                if note not in summary.notes:
                    summary.notes.append(note)

            if scope_row.auto_onboard:
                device = await self.reviews.auto_onboard(host, actor=actor)
                if device is not None:
                    summary.hosts_onboarded += 1


def _batched(addresses: Iterable[object], size: int) -> Iterator[list[str]]:
    """Yield lists of at most ``size`` addresses, as text.

    ``Scope.hosts()`` yields ``ip_address`` objects lazily, and lazily is the point: a
    /16 inside the ceiling is 65,534 addresses and materialising them before the first
    probe delays the run and buys nothing. This keeps that laziness while giving the
    gather a concrete list to zip against.
    """
    iterator = iter(addresses)
    while chunk := list(itertools.islice(iterator, size)):
        yield [str(address) for address in chunk]


__all__ = [
    "DEFAULT_CONCURRENCY",
    "SNMP_UNAVAILABLE_NOTE",
    "DiscoveryExecutor",
    "RunSummary",
]
