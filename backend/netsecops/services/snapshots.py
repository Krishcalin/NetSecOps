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
from pathlib import PurePosixPath
from typing import Any, Final

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.adapters.policies import get_policy
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
from netsecops.services.inventory import InventoryService

log = get_logger(__name__)


# ────────────────────── supporting captures (FR-COL-11) ─────────────────────


@dataclass(frozen=True, slots=True)
class SupportingCapture:
    """One file of operational command output, uploaded rather than collected.

    **Why this exists.** Twelve places across six parsers read `ParseContext.artifact`
    — the device version, model and serial that every CVE match depends on, the
    protocol-learned routes the topology graph is built from, ACL hit counts, a
    controller's access points, CDP and LLDP neighbours. None of it appears in a running
    configuration, and until now the only way to supply it was a live collection.

    That left an estate onboarded by upload with every one of those capabilities dead
    and nothing saying so — an empty neighbour list on an uploaded switch reads exactly
    like a switch with CDP disabled. Air-gapped sites are precisely the ones FR-COL-11
    exists for, so the gap was widest where the feature was most needed.
    """

    #: What the operator called the file. The command is read from it — see
    #: `command_from_filename`.
    filename: str
    text: str


#: Extensions a captured-output file is likely to carry. Stripped before the rest of the
#: name is read as a command, and deliberately a closed set: a device genuinely named
#: `show flash` must not lose its tail to a suffix nobody meant as one.
_CAPTURE_SUFFIXES: Final = (".txt", ".log", ".out", ".json", ".xml", ".cfg", ".conf")


def command_from_filename(filename: str) -> list[str]:
    """The commands a capture's filename might name, best first.

    Two spellings are accepted because both are what people actually type:
    `show version.txt` and `show_version.txt`. Underscores become spaces; **hyphens do
    not**, and that is the whole subtlety here — `show radius-server`,
    `show run-config commands` and `get router info routing-table all` are real
    allow-list entries whose hyphens are part of the command.
    """
    stem = PurePosixPath(filename.replace("\\", "/")).name
    for suffix in _CAPTURE_SUFFIXES:
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break

    literal = " ".join(stem.split())
    underscored = " ".join(stem.replace("_", " ").split())

    candidates = [literal]
    if underscored != literal:
        candidates.append(underscored)
    return [candidate for candidate in candidates if candidate]


def resolve_supporting_command(filename: str, platform: str) -> str:
    """Which approved command a capture is the output of.

    **Resolved against the platform's own allow-list, never trusted from the filename.**
    SRS §8.2 is the list of what this product may read from a device, and an upload is
    still this product reading a device's output — accepting `cat /etc/shadow.txt`
    because somebody named a file that way would put data in the NCM that §8.1 promises
    is never gathered. The allow-list is already the answer to "may we hold this", so it
    is the gate here too, and it costs nothing to reuse.

    `session_only` entries are refused as well. `terminal length 0` sets paging and
    produces no output; a file claiming to be its result is a mistake, not a capture.
    """
    try:
        policy = get_policy(platform)
    except KeyError as exc:
        raise ValidationProblem(str(exc)) from None

    candidates = command_from_filename(filename)
    for candidate in candidates:
        rule = policy.match(candidate)
        if rule is not None and not rule.session_only:
            return candidate

    raise ValidationProblem(
        f"'{filename}' does not name a command {platform} is permitted to be read with. "
        "Name each supporting file after the command that produced it — "
        "'show cdp neighbors detail.txt' or 'show_cdp_neighbors_detail.txt' — and see "
        "`netsecops-cli audit-commands` for the full list.",
        filename=filename,
        platform=platform,
        read_as=candidates,
    )


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
    #: The commands the supporting captures were read as. Returned rather than counted
    #: so the caller can see that `show_verison.txt` was not silently accepted.
    supporting_commands: tuple[str, ...] = ()


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
        supporting: Sequence[SupportingCapture] | None = None,
    ) -> IngestResult:
        """Assess a configuration supplied by an operator rather than collected.

        FR-COL-11: air-gapped sites and pre-onboarding devices need assessment without
        NetSecOps ever reaching the device. The result is stored through exactly the
        same path as a live collection — same artefact encryption, same snapshot, same
        drift detection — so an uploaded configuration is not a second-class citizen
        with its own quietly different behaviour.

        ``supporting`` closes the one place it *was* second-class. A live collection
        gathers command output beside the configuration and the parsers read it; an
        upload could not, so version, model and serial (and therefore every CVE match),
        protocol-learned routes, ACL hit counts and CDP/LLDP neighbours were all
        unavailable to exactly the estates this endpoint exists for. Each capture is
        named after the command that produced it, checked against the platform's
        allow-list, and stored as its own artefact so the evidence trail says where
        every NCM field came from.
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

        # Resolved first, before a Collection or an artefact exists. The transaction
        # would roll a later refusal back anyway, but ordering the check ahead of the
        # writes is what makes "a bad filename costs you nothing" true of the code
        # rather than true of the enclosing transaction.
        captures: dict[str, str] = {}
        for capture in supporting or ():
            command = resolve_supporting_command(capture.filename, platform)
            if command in captures:
                raise ValidationProblem(
                    f"Two files both name '{command}'. Each command may be supplied once, "
                    "because the parser reads one output per command and silently taking "
                    "whichever arrived last would make the result depend on upload order.",
                    command=command,
                )
            captures[command] = capture.text

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

        for ordinal, (command, text) in enumerate(captures.items(), start=1):
            await self.store_artifact(
                collection,
                command=command,
                response=text,
                ordinal=ordinal,
                # UPLOAD, not COMMAND: this output is real, and nothing was sent to a
                # device to obtain it. An evidence trail that cannot tell those apart
                # is one that would let an offline assessment be read as a live one.
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
            supporting=captures,
            # Nothing was contacted. The facts are still real — they came from the
            # device's own configuration — but `last_collected_at` would claim a
            # conversation that never happened.
            contacted=False,
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
            details={
                "source": "offline_upload",
                "bytes": len(config_text.encode("utf-8")),
                # Named in the audit record, not just counted: this is the list of
                # device output the product took in, and SRS §8.1 item 8 is a promise
                # that the log says exactly what was read.
                "supporting_commands": list(captures),
            },
            org_id=device.org_id,
        )

        return IngestResult(
            collection=collection,
            artifact=artifact,
            snapshot=snapshot,
            drift=drift,
            finding=finding if drift.changed else None,
            deduplicated=already,
            supporting_commands=tuple(captures),
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
        contacted: bool = True,
    ) -> Snapshot:
        """Parse a configuration and store it, de-duplicating identical ones.

        ``supporting`` carries the collection's non-configuration artefacts, keyed by
        command. Only ``config_text`` is hashed and diffed; the supporting output feeds
        the NCM fields that do not appear in a running configuration — version, model,
        serial — without which no CVE can be matched (FR-VUL-01).

        A forwarding table arrives the same way, as the output of the platform's own
        route command, and :func:`netsecops.parsers.route_tables.store_routes` decides
        how it combines with the routes the configuration declares. It is deliberately
        not hashed: a routing table reconverges on its own, so folding one into the
        digest would make every collection of an unchanged device look like drift.
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

        # **FR-INV-05, which was written and never called.** Both routes into this
        # method — the collection runner and the offline upload — build an NCM carrying
        # the device's hostname, version, model and serial, and neither copied any of it
        # onto the device. The consequence was total rather than partial: `software_cpe`
        # returns None without a version, so no CPE was ever built, nothing matched a
        # feed, and every device read as having no advisories instead of as one nothing
        # could assess.
        #
        # Recorded here rather than in the two callers because putting it in the callers
        # is what produced the gap: one of them would always forget, and this is the one
        # place that holds both the device and the freshly parsed facts.
        #
        # Before the dedup branch below, so a re-upload that finally carries
        # `show version` updates the device even though the configuration is unchanged.
        await InventoryService(self.session).record_facts(
            device,
            {
                key: value
                for key, value in (
                    ("hostname", ncm.device.hostname),
                    ("version", ncm.device.version),
                    ("model", ncm.device.model),
                    ("serial", ncm.device.serials[0] if ncm.device.serials else None),
                )
                if value
            },
            contacted=contacted,
        )

        digest = config_hash(config_text)
        meaningful = [
            line
            for line in normalise_config(config_text).splitlines()
            if line.strip() and not line.strip().startswith("!")
        ]
        if ncm.parse_failed:
            # The parser read none of it. The arithmetic below would score this in the
            # high nineties, because a wholesale failure records one explanatory line in
            # `raw_unparsed` rather than one line per line of input — so a configuration
            # that yielded an empty NCM rendered as a green "99% parsed" pill. Zero is
            # the honest figure and the only one that cannot be misread.
            coverage = 0
        elif meaningful:
            coverage = round(100 * (len(meaningful) - len(ncm.raw_unparsed)) / len(meaningful))
        else:
            coverage = None

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

            # **The configuration being identical does not make what we know identical.**
            # `config_hash` is over the text; supporting command output is not in it, by
            # design — a routing table reconverges on its own and folding it into the
            # digest would make every collection of an unchanged device look like drift.
            #
            # The consequence was that this branch parsed the NCM and threw it away. Add
            # `show cdp neighbors detail` to a configuration already stored and the
            # neighbours were read, discarded, and the panel stayed empty with nothing
            # saying why — which is the failure mode this codebase is named for, sitting
            # in the one path an air-gapped estate has.
            #
            # Refreshed only when it actually differs, so an unchanged re-upload still
            # writes nothing but the counter.
            refreshed = ncm_hash(ncm)
            # Captured before the assignment below, which would otherwise make this
            # comparison false every time and the log say nothing ever changed.
            changed = refreshed != existing.normalized_hash
            if changed:
                existing.ncm = ncm.to_storage()
                existing.normalized_hash = refreshed
                existing.ncm_version = ncm.ncm_version
                existing.parser_platform = platform
                existing.parse_coverage = coverage
                existing.unparsed_count = len(ncm.raw_unparsed)

            await self.session.flush()
            log.info(
                "snapshot.deduplicated",
                device_id=str(device.id),
                snapshot_id=str(existing.id),
                seen_count=existing.seen_count,
                ncm_refreshed=changed,
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
