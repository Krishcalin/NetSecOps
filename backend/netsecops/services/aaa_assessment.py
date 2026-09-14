"""Turning AAA correlation into per-device findings (FR-AAA-05, FR-AAA-06, FR-FIND-01).

FR-AAA-06 says AAA findings appear *both* per device and on the posture dashboard. The
dashboard is a live read of the correlation; this module is the other half — the rows
that make a correlation result show up on a device's own page, survive until they are
fixed, and carry a first-seen date.

**Every finding here was found by looking somewhere else.** That is what separates this
from every other assessment in the system, and it decides where each row lands:

* An *orphaned client* is a device the server knows and inventory does not. The device
  itself has no row to attach to — that is the finding — so it attaches to the **server**
  that named it. The server's owner is also the person who can confirm whether the entry
  is stale or the device is real.
* An *unregistered device* attaches to that device.
* An *unknown AAA server* attaches to **each device that points at it**. Not to one
  representative device: if four switches authenticate against a server nobody assesses,
  all four carry that risk, and closing it on one must not close it on the others.
* A *reused shared secret* attaches to the **AAA servers** whose configuration exposed
  it. The clients sharing the key are frequently not in inventory at all.

**Nothing is resolved unless the analysis could actually run.** Closure by absence is
safe for rulebase analysis because every relationship is re-derived from the whole
rulebase each time. Here it is safe only when at least one AAA server contributed a
client list: with no server data every device trivially appears on no client list, and a
run in that state must not silently close last week's real findings. That is the same
``registration_analysed`` gate the correlation uses to refuse the conclusion in the first
place, applied to the writing side.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.logging import get_logger
from netsecops.db.models.collection import Finding, FindingKind, FindingStatus
from netsecops.db.models.inventory import Device
from netsecops.services.aaa_correlation import AaaCorrelationReport, AaaCorrelationService

log = get_logger(__name__)

#: How old an AAA server snapshot may be before an orphan derived from it is reported as
#: informational rather than actionable. A device added to inventory after the server was
#: last collected looks exactly like a device nobody ever added.
STALE_SNAPSHOT_DAYS = 30


@dataclass(slots=True)
class AaaAssessment:
    """What one correlation run wrote."""

    findings_opened: int = 0
    findings_resolved: int = 0
    devices_touched: int = 0
    #: False when no AAA server contributed a client list, which stops any resolution.
    registration_analysed: bool = False
    counts: dict[str, int] = field(default_factory=dict)


def _fingerprint(issue: str, *parts: str) -> str:
    tail = ":".join(part.strip().lower() for part in parts if part)
    return f"aaa:{issue}:{tail}" if tail else f"aaa:{issue}"


class AaaAssessmentService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def assess(self, *, org_id: int = 1) -> AaaAssessment:
        """Correlate the estate and store the result as findings."""
        report = await AaaCorrelationService(self.session).correlate(org_id=org_id)
        return await self.store(report, org_id=org_id)

    async def store(self, report: AaaCorrelationReport, *, org_id: int = 1) -> AaaAssessment:
        """Persist an already-computed correlation, so the dashboard and the findings
        table are written from one analysis rather than two that may disagree."""
        outcome = AaaAssessment(registration_analysed=report.registration_analysed)
        outcome.counts = dict(report.counts)

        devices = await self._devices(org_id)
        payloads = list(self._collect(report, devices))

        seen: dict[uuid.UUID, set[str]] = {}
        for device_id, fingerprint, payload in payloads:
            if device_id not in devices:
                # The correlation named a device that has since been archived or
                # deleted. Skipped rather than written against a dangling id.
                continue
            seen.setdefault(device_id, set()).add(fingerprint)
            if await self._open(devices[device_id], fingerprint, payload):
                outcome.findings_opened += 1

        outcome.devices_touched = len(seen)

        if report.registration_analysed:
            outcome.findings_resolved = await self._resolve_absent(org_id, seen)
        else:
            log.info("aaa_assessment.resolution_skipped", org_id=org_id, reason="no_server_data")

        await self.session.flush()
        log.info(
            "aaa_assessment.completed",
            org_id=org_id,
            opened=outcome.findings_opened,
            resolved=outcome.findings_resolved,
            devices=outcome.devices_touched,
        )
        return outcome

    # ── turning the report into payloads ────────────────────────────────

    def _collect(
        self, report: AaaCorrelationReport, devices: dict[uuid.UUID, Device]
    ) -> list[tuple[uuid.UUID, str, dict[str, Any]]]:
        collected: list[tuple[uuid.UUID, str, dict[str, Any]]] = []

        for client in report.orphaned_clients:
            stale = (
                client.server_snapshot_age_days is not None
                and client.server_snapshot_age_days > STALE_SNAPSHOT_DAYS
            )
            age = (
                "The server's snapshot is "
                f"{client.server_snapshot_age_days} days old, so a device added to "
                "inventory since then would still appear here — re-collect the server "
                "before acting on this."
                if stale
                else "The server's snapshot is recent, so this gap is unlikely to be an "
                "artefact of stale data."
            )
            collected.append(
                (
                    client.server_device_id,
                    _fingerprint("orphaned_client", client.server, client.name),
                    {
                        "title": f"'{client.name}' authenticates here but is not in inventory",
                        "description": (
                            f"{client.server} is configured to authenticate a device it calls "
                            f"'{client.name}'"
                            + (f" at {client.address}" if client.address else "")
                            + ". NetSecOps has no such device, so whatever it is, nothing is "
                            "assessing its configuration and it is not counted in any "
                            f"compliance figure. {age}"
                        ),
                        # Informational when it may be an artefact of a stale snapshot:
                        # a medium finding that turns out to be a collection gap trains
                        # people to ignore the next one.
                        "severity": "low" if stale else "medium",
                        "evidence": {
                            "client_name": client.name,
                            "client_address": client.address,
                            "server": client.server,
                            "server_snapshot_age_days": client.server_snapshot_age_days,
                        },
                        "remediation": (
                            "Confirm what the device is. If it is live, add it to inventory so "
                            "it is assessed; if it has been decommissioned, remove it from the "
                            "AAA server — a stale client entry with a working shared secret is "
                            "a credential nobody is watching."
                        ),
                    },
                )
            )

        for device in report.unregistered_devices:
            collected.append(
                (
                    device.device_id,
                    _fingerprint("unregistered_device"),
                    {
                        "title": "This device is on no AAA server's client list",
                        "description": (
                            "No collected AAA server lists this device as a client."
                            + (
                                " Its own configuration names an AAA server, so either it "
                                "authenticates against a server NetSecOps has not collected "
                                "from, or its authentication is failing and falling back to "
                                "local accounts."
                                if device.configured_for_aaa
                                else " Its configuration names no AAA server either, so "
                                "administrative access here is local-only: the credentials "
                                "are not centrally revocable and the logins are not centrally "
                                "logged."
                            )
                        ),
                        "severity": "medium" if device.configured_for_aaa else "high",
                        "evidence": {
                            "mgmt_ip": device.mgmt_ip,
                            "hostname": device.hostname,
                            "configured_for_aaa": device.configured_for_aaa,
                        },
                        "remediation": (
                            "Register the device on the AAA server and point it at that "
                            "server, keeping one local break-glass account. If it is already "
                            "registered on a server NetSecOps does not collect from, add that "
                            "server to inventory so the picture is complete."
                        ),
                    },
                )
            )

        for server in report.unknown_servers:
            for device_id in server.used_by_ids:
                name = devices[device_id].hostname if device_id in devices else None
                collected.append(
                    (
                        device_id,
                        _fingerprint("unknown_server", server.address),
                        {
                            "title": (
                                f"Authenticates against {server.address}, which is not in inventory"
                            ),
                            "description": (
                                f"This device sends {server.kind.upper()} authentication to "
                                f"{server.address}. NetSecOps has no device at that address, so "
                                "that server's own configuration — its protocol set, its "
                                "identity sources, who administers it — is assessed by nothing. "
                                "A server holding the credentials for this device is a single "
                                "point of compromise for it."
                            ),
                            "severity": "medium",
                            "evidence": {
                                "server_address": server.address,
                                "kind": server.kind,
                                "also_used_by": [
                                    label for label in server.used_by if label != name
                                ],
                            },
                            "remediation": (
                                "Add the server to inventory and collect from it, or confirm it "
                                "is decommissioned and remove it from this device's "
                                "configuration."
                            ),
                        },
                    )
                )

        for secret in report.reused_secrets:
            for device_id in secret.server_ids:
                collected.append(
                    (
                        device_id,
                        _fingerprint("reused_secret", secret.fingerprint),
                        {
                            "title": (
                                f"One shared secret is configured for {secret.count} clients"
                            ),
                            "description": (
                                f"{secret.count} client entries are configured with the same "
                                "shared secret: "
                                + ", ".join(secret.used_by[:8])
                                + (f" and {secret.count - 8} more." if secret.count > 8 else ".")
                                + " Recovering the key from any one of those devices — from a "
                                "configuration backup, a TFTP transfer, or the device itself — "
                                "yields the key for all of them. RADIUS uses the shared secret "
                                "to protect the User-Password attribute, so this is the "
                                "difference between one compromised switch and every "
                                "credential that crosses the network."
                            ),
                            "severity": "high",
                            "evidence": {
                                # The fingerprint, never the secret. It is the same
                                # function the redaction module uses, which is what makes
                                # reuse detectable without the key ever being stored.
                                "secret_fingerprint": secret.fingerprint,
                                "used_by": secret.used_by,
                                "clients": secret.count,
                            },
                            "remediation": (
                                "Give each client its own shared secret, generated randomly and "
                                "at least 22 characters. Rotate rather than re-deriving from a "
                                "pattern: a per-device key built from the hostname is one "
                                "disclosure away from being a shared key again."
                            ),
                        },
                    )
                )

        return collected

    # ── persistence ─────────────────────────────────────────────────────

    async def _open(self, device: Device, fingerprint: str, payload: dict[str, Any]) -> bool:
        now = datetime.now(UTC)
        existing = (
            await self.session.execute(
                select(Finding).where(
                    Finding.device_id == device.id, Finding.fingerprint == fingerprint
                )
            )
        ).scalar_one_or_none()

        if existing is not None:
            was_closed = not FindingStatus(existing.status).is_active
            existing.title = payload["title"]
            existing.description = payload["description"]
            existing.severity = payload["severity"]
            existing.evidence = payload["evidence"]
            existing.remediation = payload["remediation"]
            existing.last_seen_at = now
            existing.occurrences += 1
            if was_closed:
                existing.status = FindingStatus.REOPENED.value
                existing.resolved_at = None
            await self.session.flush()
            return was_closed

        self.session.add(
            Finding(
                org_id=device.org_id,
                device_id=device.id,
                kind=FindingKind.AAA.value,
                fingerprint=fingerprint,
                title=payload["title"],
                description=payload["description"],
                severity=payload["severity"],
                status=FindingStatus.NEW.value,
                evidence=payload["evidence"],
                remediation=payload["remediation"],
                # Deliberately no snapshot_id: this conclusion does not come from one
                # snapshot. Pointing at the device's own snapshot would invite a reader
                # to go looking for the evidence in a file that does not contain it.
                snapshot_id=None,
                first_seen_at=now,
                last_seen_at=now,
            )
        )
        await self.session.flush()
        return True

    async def _resolve_absent(self, org_id: int, seen: dict[uuid.UUID, set[str]]) -> int:
        """Close AAA findings this correlation did not reproduce.

        Only called when at least one AAA server contributed a client list. Every device
        is considered, not only the ones with findings this time — a device that is now
        correctly registered produces no payload at all, and that silence is exactly what
        should close its finding.
        """
        rows = (
            (
                await self.session.execute(
                    select(Finding).where(
                        Finding.org_id == org_id,
                        Finding.kind == FindingKind.AAA.value,
                    )
                )
            )
            .scalars()
            .all()
        )

        now = datetime.now(UTC)
        resolved = 0
        for row in rows:
            if not FindingStatus(row.status).is_active:
                continue
            if row.fingerprint in seen.get(row.device_id, set()):
                continue
            row.status = FindingStatus.RESOLVED.value
            row.resolved_at = now
            resolved += 1

        if resolved:
            await self.session.flush()
        return resolved

    async def _devices(self, org_id: int) -> dict[uuid.UUID, Device]:
        rows = (
            (await self.session.execute(select(Device).where(Device.org_id == org_id)))
            .scalars()
            .all()
        )
        return {row.id: row for row in rows}


__all__ = ["STALE_SNAPSHOT_DAYS", "AaaAssessment", "AaaAssessmentService"]
