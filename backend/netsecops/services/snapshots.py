"""Snapshots, diff and drift (FR-DRIFT-01 … FR-DRIFT-04, FR-COL-03, FR-COL-13).

The interesting problem here is deciding what counts as a change.

A running configuration contains lines that differ on every poll without anything
having been configured: NVRAM checksums, uptime counters, `ntp clock-period`, the
"Last configuration change" timestamp. Treating those as drift would produce a finding
per device per day and train operators to ignore drift entirely — which is worse than
having no drift detection at all. So a *volatile* set is normalised away before
hashing, and the list of what was ignored is written down rather than buried.

Two hashes are kept per snapshot. ``config_hash`` is over the normalised text and
answers "did the configuration change". ``normalized_hash`` is over the NCM and answers
"did anything we understand change" — a stricter question, useful when a cosmetic
reordering moves lines without altering meaning.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.crypto import SecretVault, build_vault
from netsecops.core.errors import ConflictError, NotFoundError, ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Principal
from netsecops.core.redaction import redact_config
from netsecops.db.models.audit import AuditAction
from netsecops.db.models.collection import (
    Artifact,
    ArtifactKind,
    Collection,
    Finding,
    FindingKind,
    FindingSeverity,
    FindingStatus,
    Snapshot,
)
from netsecops.db.models.inventory import Device
from netsecops.ncm.models import NCM_VERSION, NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import NoParserError, get_parser
from netsecops.services.audit import AuditService

log = get_logger(__name__)


#: Lines that change without the configuration changing (FR-DRIFT-01).
#:
#: Being too aggressive here hides real drift; being too timid buries it in noise. Each
#: entry is a line whose *value* is derived from device state rather than configured by
#: an operator, so removing it cannot conceal an intentional change.
VOLATILE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*!\s*Last configuration change", re.IGNORECASE),
    re.compile(r"^\s*!\s*NVRAM config last updated", re.IGNORECASE),
    re.compile(r"^\s*ntp clock-period\s", re.IGNORECASE),
    re.compile(r"^\s*!\s*Time:", re.IGNORECASE),
    re.compile(r"^\s*Current configuration\s*:", re.IGNORECASE),
    re.compile(r"^\s*Building configuration", re.IGNORECASE),
    re.compile(r"^\s*Cryptochecksum\s*:", re.IGNORECASE),
    re.compile(r"^\s*:\s*Written by \S+ at ", re.IGNORECASE),
    re.compile(r"^\s*!Running configuration last done at", re.IGNORECASE),
    re.compile(r"^\s*!Time:", re.IGNORECASE),
)


@dataclass(frozen=True, slots=True)
class ConfigDiff:
    """A textual diff between two snapshots (FR-DRIFT-02)."""

    added: tuple[str, ...]
    removed: tuple[str, ...]
    unified: str

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)

    @property
    def summary(self) -> str:
        return f"{len(self.added)} added, {len(self.removed)} removed"


@dataclass(frozen=True, slots=True)
class SemanticChange:
    """One meaningful change, expressed in NCM terms rather than as text."""

    path: str
    before: Any
    after: Any

    def describe(self) -> str:
        """Human wording. This is what appears in a drift finding."""
        if self.before is None:
            return f"{self.path} set to {_render(self.after)}"
        if self.after is None:
            return f"{self.path} removed (was {_render(self.before)})"
        return f"{self.path} changed {_render(self.before)} → {_render(self.after)}"


def _render(value: Any) -> str:
    if isinstance(value, bool):
        return "enabled" if value else "disabled"
    if isinstance(value, list | dict):
        return f"{len(value)} item(s)"
    return repr(value)


@dataclass(slots=True)
class DriftResult:
    """What changed relative to a baseline, and how much it matters."""

    changed: bool
    diff: ConfigDiff | None = None
    semantic: list[SemanticChange] = field(default_factory=list)
    severity: FindingSeverity = FindingSeverity.LOW

    @property
    def headline(self) -> str:
        if not self.changed:
            return "No drift from baseline."
        if self.semantic:
            return self.semantic[0].describe()
        return self.diff.summary if self.diff else "Configuration changed."


#: NCM paths whose change is more than cosmetic. Drift severity is raised when one of
#: these moves, because "somebody turned Telnet on" and "somebody edited a description"
#: should not arrive looking the same.
SECURITY_RELEVANT_PREFIXES: tuple[str, ...] = (
    "management.services",
    "management.password_policy",
    "management.session",
    "aaa",
    "snmp",
    "users",
    "features",
    "logging.syslog_servers",
    "ntp",
    "firewall.security_rules",
    "acls",
)


def normalise_config(text: str) -> str:
    """Strip volatile lines and trailing whitespace, for stable hashing."""
    kept: list[str] = []
    for line in text.splitlines():
        if any(pattern.match(line) for pattern in VOLATILE_PATTERNS):
            continue
        kept.append(line.rstrip())
    return "\n".join(kept).strip() + "\n"


def config_hash(text: str) -> str:
    return hashlib.sha256(normalise_config(text).encode("utf-8")).hexdigest()


def ncm_hash(ncm: NormalisedConfig) -> str:
    """Hash the NCM excluding provenance.

    Provenance carries line numbers, which shift whenever anything above them changes.
    Including it would make every snapshot look semantically different from the last
    and defeat the purpose of the second hash.
    """
    payload = ncm.model_dump(mode="json", exclude={"provenance", "raw_unparsed"})
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def diff_configs(before: str, after: str, *, context: int = 3) -> ConfigDiff:
    before_lines = normalise_config(before).splitlines()
    after_lines = normalise_config(after).splitlines()

    unified = "\n".join(
        difflib.unified_diff(
            before_lines, after_lines, fromfile="baseline", tofile="current", lineterm="", n=context
        )
    )

    added = tuple(
        line[1:].strip()
        for line in unified.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    removed = tuple(
        line[1:].strip()
        for line in unified.splitlines()
        if line.startswith("-") and not line.startswith("---")
    )
    return ConfigDiff(added=added, removed=removed, unified=unified)


def diff_ncm(before: dict[str, Any], after: dict[str, Any]) -> list[SemanticChange]:
    """Semantic diff over the NCM (FR-DRIFT-02).

    Reports "rule 42 action changed allow→deny" rather than a block of +/- lines. The
    walk skips provenance and raw_unparsed, which change for reasons unrelated to
    configuration.
    """
    changes: list[SemanticChange] = []
    _walk(before, after, "", changes)
    return changes


_SKIP_KEYS = {"provenance", "raw_unparsed"}


def _walk(before: Any, after: Any, path: str, out: list[SemanticChange]) -> None:
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(set(before) | set(after)):
            if key in _SKIP_KEYS:
                continue
            _walk(before.get(key), after.get(key), f"{path}.{key}" if path else key, out)
        return

    if isinstance(before, list) and isinstance(after, list):
        if before == after:
            return
        # Lists are compared as sets of rendered members rather than by index: an
        # interface inserted at position 2 would otherwise report every later
        # interface as changed, which is noise rather than information.
        before_set = {json.dumps(item, sort_keys=True) for item in before}
        after_set = {json.dumps(item, sort_keys=True) for item in after}
        if before_set != after_set:
            out.append(SemanticChange(path=path, before=before, after=after))
        return

    if before != after:
        out.append(SemanticChange(path=path, before=before, after=after))


def _drift_fingerprint(device: Device) -> str:
    """One drift finding per device.

    Successive drift updates that one finding rather than adding a row per scan, which
    would bury the device's current state under a history nobody reads.
    """
    return f"drift:{device.id}"


@dataclass(slots=True)
class IngestResult:
    """What an offline configuration upload produced (FR-COL-11)."""

    collection: Collection
    artifact: Artifact
    snapshot: Snapshot
    drift: DriftResult
    finding: Finding | None
    deduplicated: bool


class SnapshotService:
    def __init__(self, session: AsyncSession, *, vault: SecretVault | None = None) -> None:
        self.session = session
        self._vault = vault
        self.audit = AuditService(session)

    @property
    def vault(self) -> SecretVault:
        if self._vault is None:
            self._vault = build_vault()
        return self._vault

    # ──────────────────────────── artefacts ─────────────────────────────

    async def store_artifact(
        self,
        collection: Collection,
        *,
        command: str,
        response: str,
        ordinal: int = 0,
        duration_ms: int | None = None,
        succeeded: bool = True,
        kind: ArtifactKind = ArtifactKind.COMMAND,
    ) -> Artifact:
        """Store one command's output, encrypted, with a redacted copy (FR-COL-03/13)."""
        artifact = Artifact(
            org_id=collection.org_id,
            collection_id=collection.id,
            kind=kind.value,
            request_text=command,
            # Placeholders: sealing needs the row id as AAD (DATA-01).
            response_encrypted=b"",
            response_redacted=redact_config(response),
            # Hash the *original*: this is evidentiary, and hashing the redacted copy
            # would prove only that the redaction was reproducible.
            sha256=hashlib.sha256(response.encode("utf-8")).hexdigest(),
            size_bytes=len(response.encode("utf-8")),
            duration_ms=duration_ms,
            ordinal=ordinal,
            succeeded=succeeded,
        )
        self.session.add(artifact)
        await self.session.flush()

        artifact.response_encrypted = self.vault.seal(response, aad=str(artifact.id))
        await self.session.flush()
        return artifact

    def open_artifact(self, artifact: Artifact) -> str:
        """Decrypt an artefact's original response.

        Gated at the API layer by ``config:view_unredacted`` and audited (SEC-09).
        """
        return self.vault.open(artifact.response_encrypted, aad=str(artifact.id)).decode("utf-8")

    async def get_artifact(self, artifact_id: uuid.UUID) -> Artifact:
        artifact = (
            await self.session.execute(select(Artifact).where(Artifact.id == artifact_id))
        ).scalar_one_or_none()
        if artifact is None:
            raise NotFoundError("Artifact not found.")
        return artifact

    async def get_collection(self, collection_id: uuid.UUID) -> Collection:
        collection = (
            await self.session.execute(select(Collection).where(Collection.id == collection_id))
        ).scalar_one_or_none()
        if collection is None:
            raise NotFoundError("Collection not found.")
        return collection

    async def artifacts_for(self, collection: Collection) -> Sequence[Artifact]:
        return (
            (
                await self.session.execute(
                    select(Artifact)
                    .where(Artifact.collection_id == collection.id)
                    .order_by(Artifact.ordinal)
                )
            )
            .scalars()
            .all()
        )

    # ───────────────────────── offline ingestion ────────────────────────

    async def ingest_config(
        self,
        device: Device,
        *,
        config_text: str,
        filename: str,
        actor: Principal,
        platform: str | None = None,
    ) -> IngestResult:
        """Assess a configuration supplied by an operator rather than collected.

        FR-COL-11: air-gapped sites and pre-onboarding devices need assessment without
        NetSecOps ever reaching the device. The result is stored through exactly the
        same path as a live collection — same artefact encryption, same snapshot, same
        drift detection — so an uploaded configuration is not a second-class citizen
        with its own quietly different behaviour.
        """
        # The device's own platform, never its policy key: expert mode and sudo reads
        # widen the command allow-list and do not change the configuration format, so
        # `checkpoint_gaia_expert` has no parser and never will.
        platform = platform or device.platform
        if not platform:
            raise ValidationProblem(
                "This device has no platform set, so the file cannot be parsed. "
                "Set the device's platform first."
            )

        collection = Collection(
            org_id=device.org_id,
            device_id=device.id,
            adapter=platform,
            adapter_version=NCM_VERSION,
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )
        self.session.add(collection)
        await self.session.flush()

        artifact = await self.store_artifact(
            collection,
            # The request text records provenance honestly: nothing was asked of a
            # device, and the audit trail should not imply that it was.
            command=f"upload:{filename}",
            response=config_text,
            kind=ArtifactKind.UPLOAD,
        )

        digest = config_hash(config_text)
        already = (
            await self.session.execute(
                select(Snapshot.id).where(
                    Snapshot.device_id == device.id, Snapshot.config_hash == digest
                )
            )
        ).first() is not None

        snapshot = await self.create_snapshot(
            device,
            config_text=config_text,
            collection=collection,
            platform=platform,
            artifact_id=artifact.id,
            command=f"upload:{filename}",
        )

        drift = await self.detect_drift(device, snapshot)
        finding = (
            await self.record_drift_finding(device, snapshot, drift)
            if drift.changed
            else await self.resolve_drift_finding(device)
        )

        await self.audit.record(
            AuditAction.DEVICE_COMMAND,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="collection",
            object_id=collection.id,
            device_id=device.id,
            command_text=f"upload:{filename}",
            details={"source": "offline_upload", "bytes": len(config_text.encode("utf-8"))},
            org_id=device.org_id,
        )

        return IngestResult(
            collection=collection,
            artifact=artifact,
            snapshot=snapshot,
            drift=drift,
            finding=finding if drift.changed else None,
            deduplicated=already,
        )

    # ──────────────────────────── snapshots ─────────────────────────────

    async def create_snapshot(
        self,
        device: Device,
        *,
        config_text: str,
        collection: Collection | None = None,
        platform: str | None = None,
        artifact_id: uuid.UUID | None = None,
        command: str | None = None,
        supporting: Mapping[str, str] | None = None,
    ) -> Snapshot:
        """Parse a configuration and store it, de-duplicating identical ones.

        ``supporting`` carries the collection's non-configuration artefacts, keyed by
        command. Only ``config_text`` is hashed and diffed; the supporting output feeds
        the NCM fields that do not appear in a running configuration — version, model,
        serial — without which no CVE can be matched (FR-VUL-01).
        """
        platform = platform or device.platform
        if not platform:
            raise ValidationProblem(
                f"Device {device.mgmt_ip} has no platform set, so its configuration "
                "cannot be parsed."
            )

        try:
            parser = get_parser(platform)
        except NoParserError as exc:
            raise ValidationProblem(str(exc)) from exc

        ncm = parser.parse(
            ParseContext(
                text=config_text,
                artifact_id=str(artifact_id) if artifact_id else None,
                command=command,
                supporting=dict(supporting or {}),
            )
        )

        digest = config_hash(config_text)
        meaningful = [
            line
            for line in normalise_config(config_text).splitlines()
            if line.strip() and not line.strip().startswith("!")
        ]
        coverage = (
            round(100 * (len(meaningful) - len(ncm.raw_unparsed)) / len(meaningful))
            if meaningful
            else None
        )

        existing = (
            await self.session.execute(
                select(Snapshot).where(
                    Snapshot.device_id == device.id,
                    Snapshot.config_hash == digest,
                    Snapshot.duplicate_of_id.is_(None),
                )
            )
        ).scalar_one_or_none()

        if existing is not None:
            # FR-DRIFT-01: an unchanged configuration updates the existing row rather
            # than storing the same text again.
            existing.seen_count += 1
            existing.last_seen_at = datetime.now(UTC)
            await self.session.flush()
            log.info(
                "snapshot.deduplicated",
                device_id=str(device.id),
                snapshot_id=str(existing.id),
                seen_count=existing.seen_count,
            )
            return existing

        snapshot = Snapshot(
            org_id=device.org_id,
            device_id=device.id,
            collection_id=collection.id if collection else None,
            config_hash=digest,
            normalized_hash=ncm_hash(ncm),
            config_redacted=redact_config(config_text),
            ncm=ncm.to_storage(),
            ncm_version=ncm.ncm_version,
            parser_platform=platform,
            parse_coverage=coverage,
            unparsed_count=len(ncm.raw_unparsed),
            last_seen_at=datetime.now(UTC),
        )
        self.session.add(snapshot)
        await self.session.flush()

        log.info(
            "snapshot.created",
            device_id=str(device.id),
            snapshot_id=str(snapshot.id),
            coverage=coverage,
            unparsed=len(ncm.raw_unparsed),
        )
        return snapshot

    async def get(self, snapshot_id: uuid.UUID) -> Snapshot:
        snapshot = (
            await self.session.execute(select(Snapshot).where(Snapshot.id == snapshot_id))
        ).scalar_one_or_none()
        if snapshot is None:
            raise NotFoundError("Snapshot not found.")
        return snapshot

    async def list_for_device(
        self, device: Device, *, limit: int = 50, offset: int = 0
    ) -> tuple[Sequence[Snapshot], int]:
        stmt = select(Snapshot).where(Snapshot.device_id == device.id)
        total = int(
            (
                await self.session.execute(select(func.count()).select_from(stmt.subquery()))
            ).scalar_one()
        )
        rows = (
            (
                await self.session.execute(
                    stmt.order_by(Snapshot.created_at.desc()).limit(limit).offset(offset)
                )
            )
            .scalars()
            .all()
        )
        return rows, total

    async def latest(self, device: Device) -> Snapshot | None:
        return (
            await self.session.execute(
                select(Snapshot)
                .where(Snapshot.device_id == device.id)
                .order_by(Snapshot.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

    async def baseline(self, device: Device) -> Snapshot | None:
        return (
            await self.session.execute(
                select(Snapshot).where(
                    Snapshot.device_id == device.id, Snapshot.is_baseline.is_(True)
                )
            )
        ).scalar_one_or_none()

    # ──────────────────────────── baselines ─────────────────────────────

    async def pin_baseline(self, snapshot: Snapshot, *, actor: Principal) -> Snapshot:
        """Pin a snapshot as the device's baseline (FR-DRIFT-03).

        Unpinning the previous one first is required, not merely tidy: the database
        enforces at most one baseline per device.
        """
        current = (
            await self.session.execute(
                select(Snapshot).where(
                    Snapshot.device_id == snapshot.device_id,
                    Snapshot.is_baseline.is_(True),
                )
            )
        ).scalar_one_or_none()

        if current is not None:
            if current.id == snapshot.id:
                return current
            current.is_baseline = False
            current.baseline_pinned_at = None
            await self.session.flush()

        snapshot.is_baseline = True
        snapshot.baseline_pinned_at = datetime.now(UTC)
        snapshot.baseline_pinned_by_id = actor.id
        await self.session.flush()

        await self.audit.record(
            AuditAction.BASELINE_PINNED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="snapshot",
            object_id=snapshot.id,
            device_id=snapshot.device_id,
            details={"replaced": str(current.id) if current else None},
            org_id=snapshot.org_id,
        )
        return snapshot

    async def clear_baseline(self, device: Device, *, actor: Principal) -> None:
        current = await self.baseline(device)
        if current is None:
            raise ConflictError("This device has no baseline pinned.")

        current.is_baseline = False
        current.baseline_pinned_at = None
        await self.session.flush()

        await self.audit.record(
            AuditAction.BASELINE_CLEARED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="snapshot",
            object_id=current.id,
            device_id=device.id,
            org_id=device.org_id,
        )

    # ─────────────────────────────── diff ───────────────────────────────

    async def diff(
        self, before: Snapshot, after: Snapshot
    ) -> tuple[ConfigDiff, list[SemanticChange]]:
        """Textual and semantic diff between two snapshots (FR-DRIFT-02)."""
        if before.device_id != after.device_id:
            raise ValidationProblem("Snapshots from different devices cannot be compared.")

        text_diff = diff_configs(before.config_redacted, after.config_redacted)
        semantic = diff_ncm(before.ncm, after.ncm)
        return text_diff, semantic

    # ─────────────────────────────── drift ──────────────────────────────

    async def detect_drift(self, device: Device, snapshot: Snapshot) -> DriftResult:
        """Compare a snapshot against the device's baseline (FR-DRIFT-03).

        No baseline means no drift — not "everything is drift". A device whose baseline
        has never been pinned should produce silence, not a finding on its first scan.
        """
        baseline = await self.baseline(device)
        if baseline is None or baseline.id == snapshot.id:
            return DriftResult(changed=False)

        if baseline.config_hash == snapshot.config_hash:
            return DriftResult(changed=False)

        text_diff, semantic = await self.diff(baseline, snapshot)

        significant: list[SemanticChange] = []
        incidental: list[SemanticChange] = []
        for change in semantic:
            target = (
                significant if change.path.startswith(SECURITY_RELEVANT_PREFIXES) else incidental
            )
            target.append(change)

        return DriftResult(
            changed=True,
            diff=text_diff,
            # Security-relevant changes lead, so the finding's headline is the thing
            # that matters rather than whichever NCM path happened to sort first.
            semantic=significant + incidental,
            severity=FindingSeverity.HIGH if significant else FindingSeverity.LOW,
        )

    async def record_drift_finding(
        self,
        device: Device,
        snapshot: Snapshot,
        drift: DriftResult,
    ) -> Finding | None:
        """Create or update the device's drift finding (FR-DRIFT-03)."""
        if not drift.changed:
            return None

        fingerprint = _drift_fingerprint(device)
        now = datetime.now(UTC)
        existing = await self.find_drift_finding(device)

        evidence: dict[str, Any] = {
            "added": list(drift.diff.added[:50]) if drift.diff else [],
            "removed": list(drift.diff.removed[:50]) if drift.diff else [],
            "unified_diff": (drift.diff.unified[:20_000] if drift.diff else ""),
            "semantic_changes": [c.describe() for c in drift.semantic[:50]],
            "snapshot_id": str(snapshot.id),
        }
        description = (
            f"The running configuration differs from the pinned baseline: "
            f"{drift.diff.summary if drift.diff else 'changed'}."
        )

        if existing is not None:
            existing.severity = drift.severity.value
            existing.evidence = evidence
            existing.description = description
            existing.snapshot_id = snapshot.id
            existing.last_seen_at = now
            existing.occurrences += 1
            if not FindingStatus(existing.status).is_active:
                existing.status = FindingStatus.REOPENED.value
                existing.resolved_at = None
            await self.session.flush()
            finding = existing
        else:
            finding = Finding(
                org_id=device.org_id,
                device_id=device.id,
                kind=FindingKind.DRIFT.value,
                fingerprint=fingerprint,
                title=f"Configuration drift from baseline on {device.hostname or device.mgmt_ip}",
                description=description,
                severity=drift.severity.value,
                status=FindingStatus.NEW.value,
                evidence=evidence,
                snapshot_id=snapshot.id,
                first_seen_at=now,
                last_seen_at=now,
                remediation=(
                    "Review the diff. If the change was intended, pin the current "
                    "snapshot as the new baseline; if not, restore the baseline "
                    "configuration through your change process."
                ),
            )
            self.session.add(finding)
            await self.session.flush()

        log.info(
            "drift.detected",
            device_id=str(device.id),
            severity=drift.severity.value,
            changes=len(drift.semantic),
        )
        return finding

    async def find_drift_finding(self, device: Device) -> Finding | None:
        """This device's drift finding, whatever its status."""
        return (
            await self.session.execute(
                select(Finding).where(
                    Finding.device_id == device.id,
                    Finding.fingerprint == _drift_fingerprint(device),
                )
            )
        ).scalar_one_or_none()

    async def resolve_drift_finding(self, device: Device) -> Finding | None:
        """Close a drift finding once the configuration matches the baseline again."""
        finding = await self.find_drift_finding(device)

        if finding is None or not FindingStatus(finding.status).is_active:
            return finding

        finding.status = FindingStatus.RESOLVED.value
        finding.resolved_at = datetime.now(UTC)
        await self.session.flush()
        return finding


__all__ = [
    "VOLATILE_PATTERNS",
    "ConfigDiff",
    "DriftResult",
    "IngestResult",
    "SemanticChange",
    "SnapshotService",
    "config_hash",
    "diff_configs",
    "diff_ncm",
    "ncm_hash",
    "normalise_config",
]
