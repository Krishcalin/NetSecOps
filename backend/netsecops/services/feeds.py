"""Vulnerability feed ingestion (FR-VUL-07, FR-VUL-08).

Built offline-first, and the ordering is the design rather than an accident of what got
written when. C-7 requires the whole application to run air-gapped with feeds imported
by hand, so the bundle path is the primary one and a network fetch is a later
convenience that produces the same bytes. Building the network path first and retrofitting
offline import is how air-gapped support ends up as a second-class mode that nobody
tests — and air-gapped is the deployment this product is most often bought for.

**The integrity check is not decoration.** An air-gapped operator carries these files in
on removable media, through a process that involves at least one machine outside the
security boundary. A bundle is a list of statements about which of your devices are
exploitable; one that has been altered can hide a CVE affecting the whole estate, and
nothing downstream would look wrong. So a digest, when supplied, is checked *before*
anything is written, and a mismatch imports nothing at all rather than partially.

**A failed sync is still a sync.** Every run is recorded, successful or not. "When did
this last work?" is the question asked the morning somebody notices the vulnerability
page looks thin, and a table holding only successes cannot answer it (FR-VUL-07).

**Partial is not success.** A bundle of ten thousand records where four hundred could not
be parsed has left four hundred blind spots, and reporting "imported 9,600" as a clean
result hides them. ``records_rejected`` is carried on the sync row and the status says
``partial``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Principal
from netsecops.db.models.audit import AuditAction, AuditOutcome
from netsecops.db.models.vulnerability import EolRecordRow, FeedSync, VulnAdvisory, VulnCve
from netsecops.services.audit import AuditService
from netsecops.vuln.advisory import Advisory
from netsecops.vuln.csaf import parse_csaf
from netsecops.vuln.eol import parse_endoflife_date
from netsecops.vuln.nvd import parse_nvd_feed

log = get_logger(__name__)


class SyncStatus(StrEnum):
    SUCCEEDED = "succeeded"
    #: Some records could not be read. Distinct from success on purpose.
    PARTIAL = "partial"
    FAILED = "failed"


class BundleKind(StrEnum):
    CSAF = "csaf"
    NVD = "nvd"
    EOL = "eol"


@dataclass(slots=True)
class ImportResult:
    """What one import did."""

    sync: FeedSync
    advisories: int = 0
    cves: int = 0
    eol_records: int = 0
    rejected: int = 0
    #: Which format the bundle was read as. Reported because `detect_kind` orders its
    #: tests deliberately — a CSAF document also carries a `vulnerabilities` key — and
    #: the failure mode of getting it wrong is a clean, empty import that looks fine.
    #: An operator who uploaded a Cisco advisory wants to see "csaf" come back.
    kind: BundleKind | None = None

    @property
    def status(self) -> SyncStatus:
        return SyncStatus(self.sync.status)


def detect_kind(payload: Any) -> BundleKind:
    """Work out which feed format a bundle is.

    Order matters. A CSAF document also has a top-level ``vulnerabilities`` key, so
    checking for ``document`` first is what stops a vendor advisory being read as an NVD
    feed — which would silently find no records in it and report a clean, empty import.
    """
    if isinstance(payload, list):
        return BundleKind.EOL
    if isinstance(payload, dict):
        if "document" in payload:
            return BundleKind.CSAF
        if "vulnerabilities" in payload:
            return BundleKind.NVD
    raise ValidationProblem(
        "This file is not a bundle NetSecOps recognises. Expected a CSAF advisory "
        "(with a `document` key), an NVD 2.0 response (with `vulnerabilities`), or an "
        "endoflife.date list of release cycles."
    )


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class FeedImportService:
    """Import a feed bundle and record what happened."""

    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id
        self.audit = AuditService(session)

    async def import_bundle(
        self,
        raw: bytes,
        *,
        feed: str,
        actor: Principal,
        expected_sha256: str | None = None,
        # EoL bundles carry release cycles and nothing that says whose they are, so the
        # importer must be told. Required rather than guessed: filing Cisco's lifecycle
        # dates under Fortinet would mark a supported estate as dead.
        vendor: str | None = None,
        product: str | None = None,
        mode: str = "offline",
    ) -> ImportResult:
        """Import one bundle, atomically with respect to its integrity check."""
        sync = FeedSync(
            org_id=self.org_id,
            feed=feed,
            mode=mode,
            status=SyncStatus.FAILED.value,
            bundle_sha256=digest(raw),
            advisories_ingested=0,
            cves_ingested=0,
            eol_records_ingested=0,
            records_rejected=0,
        )
        self.session.add(sync)
        await self.session.flush()

        try:
            result = await self._ingest(
                raw, sync=sync, vendor=vendor, product=product, expected_sha256=expected_sha256
            )
        except ValidationProblem as exc:
            # Recorded, then re-raised. The caller needs to know it failed; the operator
            # looking at the feed page next week needs to know it was tried.
            sync.status = SyncStatus.FAILED.value
            sync.error_message = str(exc)
            sync.finished_at = datetime.now(UTC)
            await self.session.flush()
            await self._audit(sync, actor, outcome=AuditOutcome.FAILURE)
            log.warning("vuln.feed_import_failed", feed=feed, error=str(exc))
            raise

        await self._audit(sync, actor)
        return result

    async def _ingest(
        self,
        raw: bytes,
        *,
        sync: FeedSync,
        vendor: str | None,
        product: str | None,
        expected_sha256: str | None,
    ) -> ImportResult:
        if expected_sha256:
            actual = sync.bundle_sha256
            if actual != expected_sha256.strip().lower():
                # Refused before anything is written. A bundle that does not match its
                # digest is not a bundle to import most of.
                raise ValidationProblem(
                    f"This bundle's SHA-256 is {actual}, not the {expected_sha256} that "
                    "was expected. Nothing has been imported. A feed bundle states which "
                    "of your devices are exploitable — one that changed in transit could "
                    "hide a vulnerability affecting the whole estate."
                )

        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValidationProblem(f"This bundle is not readable JSON: {exc}") from exc

        kind = detect_kind(payload)
        result = ImportResult(sync=sync, kind=kind)

        match kind:
            case BundleKind.CSAF:
                await self._ingest_csaf(payload, sync.feed, result)
            case BundleKind.NVD:
                await self._ingest_nvd(payload, sync.feed, result)
            case BundleKind.EOL:
                await self._ingest_eol(payload, vendor, product, result)

        sync.advisories_ingested = result.advisories
        sync.cves_ingested = result.cves
        sync.eol_records_ingested = result.eol_records
        sync.records_rejected = result.rejected
        sync.status = (
            SyncStatus.PARTIAL.value if result.rejected else SyncStatus.SUCCEEDED.value
        ).strip()
        sync.finished_at = datetime.now(UTC)
        await self.session.flush()

        log.info(
            "vuln.feed_imported",
            feed=sync.feed,
            kind=kind.value,
            advisories=result.advisories,
            cves=result.cves,
            eol=result.eol_records,
            rejected=result.rejected,
            status=sync.status,
        )
        return result

    # ── per-format ingestion ────────────────────────────────────────────

    async def _ingest_csaf(self, payload: Any, feed: str, result: ImportResult) -> None:
        documents = payload if isinstance(payload, list) else [payload]
        for document in documents:
            advisory = parse_csaf(document, source=feed)
            if advisory is None:
                result.rejected += 1
                continue
            await self._store_advisory(advisory, result)

    async def _ingest_nvd(self, payload: Any, feed: str, result: ImportResult) -> None:
        advisories = parse_nvd_feed(payload, source=feed)
        # Every record NVD sent that did not become an advisory is a blind spot, so the
        # count comes from the input rather than from what survived.
        offered = len(payload.get("vulnerabilities") or []) if isinstance(payload, dict) else 0
        result.rejected += max(0, offered - len(advisories))

        for advisory in advisories:
            await self._store_advisory(advisory, result)
            await self._store_cve(advisory, result)

    async def _ingest_eol(
        self, payload: Any, vendor: str | None, product: str | None, result: ImportResult
    ) -> None:
        if not vendor or not product:
            raise ValidationProblem(
                "An end-of-life bundle lists release cycles but does not say whose, so "
                "the vendor and product must be given with the import. Filing one "
                "vendor's lifecycle dates under another would report a supported estate "
                "as dead."
            )

        records = parse_endoflife_date(payload, vendor=vendor, product=product)
        result.rejected += max(0, len(payload) - len(records)) if isinstance(payload, list) else 0

        for record in records:
            existing = (
                await self.session.execute(
                    select(EolRecordRow).where(
                        EolRecordRow.org_id == self.org_id,
                        EolRecordRow.vendor == record.vendor,
                        EolRecordRow.product == record.product,
                        EolRecordRow.cycle == record.cycle,
                    )
                )
            ).scalar_one_or_none()

            row = existing or EolRecordRow(
                org_id=self.org_id,
                vendor=record.vendor,
                product=record.product,
                cycle=record.cycle,
                source=record.source,
            )
            row.support_ends = record.support_ends
            row.life_ends = record.life_ends
            row.support_ended_undated = record.support_ended_undated
            row.life_ended_undated = record.life_ended_undated
            row.latest = record.latest
            row.source = record.source

            if existing is None:
                self.session.add(row)
            result.eol_records += 1

        await self.session.flush()

    # ── storage ─────────────────────────────────────────────────────────

    async def _store_advisory(self, advisory: Advisory, result: ImportResult) -> None:
        """Upsert on (source, advisory_id).

        Replaced wholesale rather than merged. A vendor revising an advisory has
        restated it, and reconstructing the new version by patching the old one is how a
        withdrawn affected-version range survives a re-sync.
        """
        existing = (
            await self.session.execute(
                select(VulnAdvisory).where(
                    VulnAdvisory.org_id == self.org_id,
                    VulnAdvisory.source == advisory.source,
                    VulnAdvisory.advisory_id == advisory.advisory_id,
                )
            )
        ).scalar_one_or_none()

        row = existing or VulnAdvisory(
            org_id=self.org_id, source=advisory.source, advisory_id=advisory.advisory_id
        )
        row.title = advisory.title
        row.description = advisory.description
        row.cve_ids = list(advisory.cve_ids)
        row.cwe_ids = list(advisory.cwe_ids)
        row.affected = [_affected_json(entry) for entry in advisory.affected]
        row.fixed = [_affected_json(entry) for entry in advisory.fixed]
        row.conditions = [
            {
                "path": condition.path,
                "expected": condition.expected,
                "description": condition.description,
            }
            for condition in advisory.conditions
        ]
        row.scores = [
            {
                "version": score.version,
                "base_score": score.base_score,
                "vector": score.vector,
                "severity": score.severity,
            }
            for score in advisory.scores
        ]
        row.remediations = list(advisory.remediations)
        row.references = list(advisory.references)
        # The reason an advisory can raise a finding but never clear a device. Dropping
        # it here would make every re-imported advisory look fully understood.
        row.notes_unparsed = list(advisory.notes_unparsed)
        row.published = advisory.published
        row.modified = advisory.modified

        if existing is None:
            self.session.add(row)
        result.advisories += 1
        await self.session.flush()

    async def _store_cve(self, advisory: Advisory, result: ImportResult) -> None:
        """Record per-CVE scoring for an NVD advisory."""
        for cve_id in advisory.cve_ids:
            existing = (
                await self.session.execute(
                    select(VulnCve).where(VulnCve.org_id == self.org_id, VulnCve.cve_id == cve_id)
                )
            ).scalar_one_or_none()

            row = existing or VulnCve(org_id=self.org_id, cve_id=cve_id)
            row.description = advisory.description
            row.cwe_ids = list(advisory.cwe_ids)
            row.published = advisory.published
            row.modified = advisory.modified

            for score in advisory.scores:
                payload = {
                    "base_score": score.base_score,
                    "vector": score.vector,
                    "severity": score.severity,
                }
                if score.version.startswith("3."):
                    row.cvss31 = payload
                elif score.version.startswith("4."):
                    row.cvss40 = payload

            # epss and kev are deliberately untouched. They come from other feeds, and
            # writing a default here would turn "never imported" into "checked, zero".
            if existing is None:
                self.session.add(row)
            result.cves += 1

        await self.session.flush()

    async def _audit(
        self, sync: FeedSync, actor: Principal, *, outcome: AuditOutcome = AuditOutcome.SUCCESS
    ) -> None:
        await self.audit.record(
            AuditAction.FEED_SYNCED,
            outcome=outcome,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="feed_sync",
            object_id=sync.id,
            details={
                "feed": sync.feed,
                "mode": sync.mode,
                "status": sync.status,
                "advisories": sync.advisories_ingested,
                "cves": sync.cves_ingested,
                "eol_records": sync.eol_records_ingested,
                "rejected": sync.records_rejected,
                "sha256": sync.bundle_sha256,
            },
            org_id=self.org_id,
        )

    # ── status (FR-VUL-07) ──────────────────────────────────────────────

    async def last_sync(self, feed: str) -> FeedSync | None:
        """The most recent run of a feed, successful or not."""
        return (
            await self.session.execute(
                select(FeedSync)
                .where(FeedSync.org_id == self.org_id, FeedSync.feed == feed)
                .order_by(FeedSync.started_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

    async def history(self, *, limit: int = 50) -> list[FeedSync]:
        return list(
            (
                await self.session.execute(
                    select(FeedSync)
                    .where(FeedSync.org_id == self.org_id)
                    .order_by(FeedSync.started_at.desc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )


def _affected_json(entry: Any) -> dict[str, Any]:
    """Serialise an AffectedProduct, constraint and all.

    The constraint's ``kind`` and ``raw`` both survive: ``kind`` is how the matcher knows
    a range was never interpreted, and ``raw`` is what an operator reads when it asks
    them to check the advisory themselves.
    """
    return {
        "vendor": entry.vendor,
        "product": entry.product,
        "cpe": entry.cpe,
        "product_id": entry.product_id,
        "constraint": {
            "kind": entry.constraint.kind.value,
            "raw": entry.constraint.raw,
            "introduced": entry.constraint.introduced,
            "fixed": entry.constraint.fixed,
            "version": entry.constraint.version,
        },
    }


__all__ = [
    "BundleKind",
    "FeedImportService",
    "ImportResult",
    "SyncStatus",
    "detect_kind",
    "digest",
]
