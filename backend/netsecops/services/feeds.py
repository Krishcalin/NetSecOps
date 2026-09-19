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
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.config import Settings
from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Principal
from netsecops.db.models.audit import AuditAction, AuditOutcome
from netsecops.db.models.vulnerability import (
    EolRecordRow,
    FeedSync,
    KevEntry,
    VulnAdvisory,
    VulnCve,
)
from netsecops.services.audit import AuditService
from netsecops.vuln.advisory import Advisory
from netsecops.vuln.csaf import parse_csaf
from netsecops.vuln.eol import parse_endoflife_date
from netsecops.vuln.epss import decompress, looks_like_epss_csv, looks_like_epss_json, read_epss
from netsecops.vuln.fetch import DEFAULT_SOURCES, MAX_NVD_WINDOW, fetch_nvd, fetch_simple
from netsecops.vuln.kev import looks_like_kev, parse_kev_catalogue
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
    #: CISA Known Exploited Vulnerabilities (FR-VUL-06).
    KEV = "kev"
    #: FIRST Exploit Prediction Scoring System (FR-VUL-06).
    EPSS = "epss"


@dataclass(slots=True)
class ImportResult:
    """What one import did."""

    sync: FeedSync
    advisories: int = 0
    cves: int = 0
    eol_records: int = 0
    #: Catalogue entries stored, and CVE rows an EPSS bundle scored. Separate from
    #: `cves`, which counts rows an advisory feed created.
    kev_entries: int = 0
    epss_scores: int = 0
    #: How many CVEs the KEV import set to `False` — "checked, not listed". Worth
    #: reporting on its own: it is the number that turns the flag from unusable into a
    #: filter, and it should be roughly the size of the CVE table.
    kev_cleared: int = 0
    #: The feed's own stamp, as opposed to when the import ran.
    source_version: str | None = None
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

    **Order matters, and the cost of getting it wrong is silence.** Three of the five
    formats carry a top-level ``vulnerabilities`` key — a CSAF advisory, an NVD 2.0
    response and a CISA KEV catalogue — so each is distinguished by something only it
    has, tested before the generic key is reached. Read as the wrong format, a bundle
    does not raise: the parser finds nothing it recognises and reports a clean, empty
    import.

    For KEV that failure is worse than empty. A catalogue read as an NVD feed imports
    nothing, so `kev` stays NULL everywhere and the operator believes the catalogue is
    loaded — which is the state this whole feed exists to end.
    """
    if isinstance(payload, list):
        return BundleKind.EOL
    if isinstance(payload, dict):
        if "document" in payload:
            return BundleKind.CSAF
        if looks_like_kev(payload):
            return BundleKind.KEV
        if looks_like_epss_json(payload):
            return BundleKind.EPSS
        if "vulnerabilities" in payload:
            return BundleKind.NVD
    raise ValidationProblem(
        "This file is not a bundle NetSecOps recognises. Expected a CSAF advisory "
        "(with a `document` key), an NVD 2.0 response (with `vulnerabilities`), a CISA "
        "KEV catalogue (with `catalogVersion`), a FIRST EPSS export (CSV or JSON), or "
        "an endoflife.date list of release cycles."
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

    async def sync_online(
        self,
        source_name: str,
        *,
        actor: Principal,
        settings: Settings,
        client: httpx.AsyncClient | None = None,
    ) -> ImportResult:
        """Fetch one feed and import it (FR-VUL-07).

        Thin on purpose. Everything after the bytes arrive is `import_bundle`, unchanged
        and unbranched, so an online sync and a hand-uploaded bundle are ingested by the
        same code and differ only in the `mode` recorded against the run. The alternative
        — an online path with its own ingest — means the code air-gapped customers depend
        on is not the code anyone exercises day to day.
        """
        source = DEFAULT_SOURCES.get(source_name)
        if source is None:
            raise ValidationProblem(
                f"There is no feed source called {source_name!r}. "
                f"Known sources: {', '.join(sorted(DEFAULT_SOURCES))}."
            )

        gap_note: str | None = None
        if source_name == "nvd":
            since = await self._last_success_at("nvd")
            now = datetime.now(UTC)
            if since is not None and now - since > MAX_NVD_WINDOW:
                # NVD will not answer a window wider than 120 days, so the fetch clamps
                # it — which means CVEs changed in the uncovered stretch are not in this
                # import. Recorded on the run, because a sync that reports success while
                # having skipped three months of revisions is the exact
                # confident-but-wrong answer the feed subsystem exists to prevent.
                gap_note = (
                    f"NVD only answers a 120-day window. The last successful sync was "
                    f"{(now - since).days} days ago, so changes before "
                    f"{(now - MAX_NVD_WINDOW).date()} were not fetched — import an NVD "
                    f"bundle to close the gap, or run this sync again to walk forward."
                )
            raw = await fetch_nvd(settings, since=since, now=now, client=client)
        else:
            raw = await fetch_simple(source, settings, client=client)

        result = await self.import_bundle(raw, feed=source_name, actor=actor, mode="online")

        if gap_note:
            result.sync.error_message = gap_note
            if result.sync.status == SyncStatus.SUCCEEDED.value:
                result.sync.status = SyncStatus.PARTIAL.value
            await self.session.flush()

        return result

    async def _last_success_at(self, feed: str) -> datetime | None:
        """When this feed last brought data in.

        Partial counts. A run that imported 9,000 of 10,000 records still advanced the
        watermark for the 9,000, and treating it as no progress would re-fetch the same
        window every night for as long as one record stayed unreadable.
        """
        row = (
            await self.session.execute(
                select(FeedSync.started_at)
                .where(
                    FeedSync.org_id == self.org_id,
                    FeedSync.feed == feed,
                    FeedSync.status.in_([SyncStatus.SUCCEEDED.value, SyncStatus.PARTIAL.value]),
                )
                .order_by(FeedSync.started_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        return row

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

        # Four of the five formats are JSON; FIRST publishes EPSS as gzipped CSV, which
        # is what an operator actually downloads. So a bundle that is not JSON is offered
        # to the CSV reader before being refused, rather than the whole importer assuming
        # its input parses.
        payload: Any = None
        try:
            payload = json.loads(decompress(raw).decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            if not looks_like_epss_csv(raw):
                raise ValidationProblem(
                    f"This bundle is neither readable JSON nor a FIRST EPSS CSV: {exc}"
                ) from exc

        kind = detect_kind(payload) if payload is not None else BundleKind.EPSS
        result = ImportResult(sync=sync, kind=kind)

        match kind:
            case BundleKind.CSAF:
                await self._ingest_csaf(payload, sync.feed, result)
            case BundleKind.NVD:
                await self._ingest_nvd(payload, sync.feed, result)
            case BundleKind.EOL:
                await self._ingest_eol(payload, vendor, product, result)
            case BundleKind.KEV:
                await self._ingest_kev(payload, sync, result)
            case BundleKind.EPSS:
                await self._ingest_epss(raw, payload, sync, result)

        sync.advisories_ingested = result.advisories
        sync.cves_ingested = result.cves
        sync.eol_records_ingested = result.eol_records
        sync.kev_entries_ingested = result.kev_entries
        sync.epss_scores_ingested = result.epss_scores
        sync.source_version = result.source_version
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

    async def _ingest_kev(self, payload: Any, sync: FeedSync, result: ImportResult) -> None:
        """Store the catalogue, then apply it to every CVE on record (FR-VUL-06).

        **The second half is what makes the flag mean anything.** Setting `kev = True` on
        the listed CVEs and stopping would leave every other CVE at NULL, which reads as
        "the catalogue was never imported" — so the filter would still match nothing and
        the estate would still look unchecked. Applying the catalogue means writing
        `False` onto everything it does *not* list. That is the whole difference between
        three states and two.

        Done as two bulk statements rather than per row: the CVE table runs to hundreds
        of thousands of rows on a real estate, and a per-row update would make importing
        the catalogue the slowest thing the product does.
        """
        catalogue = parse_kev_catalogue(payload)
        result.rejected += catalogue.rejected
        result.source_version = catalogue.catalog_version or catalogue.released

        listed = {record.cve_id for record in catalogue.records}

        for record in catalogue.records:
            existing = (
                await self.session.execute(
                    select(KevEntry).where(
                        KevEntry.org_id == self.org_id, KevEntry.cve_id == record.cve_id
                    )
                )
            ).scalar_one_or_none()

            row = existing or KevEntry(org_id=self.org_id, cve_id=record.cve_id)
            row.date_added = record.date_added
            row.due_date = record.due_date
            row.known_ransomware = record.known_ransomware
            row.vendor_project = record.vendor_project
            row.product = record.product
            row.vulnerability_name = record.vulnerability_name
            row.required_action = record.required_action
            row.catalog_version = catalogue.catalog_version

            if existing is None:
                self.session.add(row)
            result.kev_entries += 1

        await self.session.flush()

        # Everything we hold that the catalogue does not list: checked, not listed.
        cleared = await self.session.execute(
            update(VulnCve)
            .where(VulnCve.org_id == self.org_id, VulnCve.cve_id.notin_(listed))
            .values(kev=False, kev_due_date=None)
        )
        # `rowcount` is on CursorResult, which is what an UPDATE returns at runtime; the
        # declared return type is the wider Result, which does not carry it.
        result.kev_cleared = getattr(cleared, "rowcount", 0) or 0

        # Everything it does list, with CISA's deadline attached.
        for record in catalogue.records:
            await self.session.execute(
                update(VulnCve)
                .where(VulnCve.org_id == self.org_id, VulnCve.cve_id == record.cve_id)
                .values(kev=True, kev_due_date=record.due_date)
            )

        await self.session.flush()

        log.info(
            "vuln.kev_applied",
            entries=result.kev_entries,
            cleared=result.kev_cleared,
            catalog_version=catalogue.catalog_version,
        )

    async def _ingest_epss(
        self, raw: bytes, payload: Any, sync: FeedSync, result: ImportResult
    ) -> None:
        """Score the CVEs we hold (FR-VUL-06).

        Only the CVEs already on record are scored. The bulk feed covers every published
        CVE — a quarter of a million of them — and storing scores for advisories that
        reach no device in the estate would be a large table answering a question nobody
        asks.

        A CVE the feed does not mention keeps a NULL score. It is *unscored*, which is
        not the same as scored zero: zero says "almost certainly not exploited", and for
        a CVE too new to have been modelled that is precisely backwards.
        """
        scores = read_epss(raw, payload)
        result.rejected += scores.rejected
        result.source_version = scores.score_date or scores.model_version

        rows = (
            (await self.session.execute(select(VulnCve).where(VulnCve.org_id == self.org_id)))
            .scalars()
            .all()
        )

        for row in rows:
            score = scores.scores.get(row.cve_id.upper())
            if score is None:
                continue
            row.epss = score
            result.epss_scores += 1

        await self.session.flush()

        log.info(
            "vuln.epss_applied",
            offered=len(scores),
            scored=result.epss_scores,
            known_cves=len(rows),
            score_date=scores.score_date,
        )

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

    async def _kev_state(self, cve_id: str) -> tuple[bool, date | None] | None:
        """This CVE's KEV standing, or None if no catalogue has ever been imported.

        Consulted when a CVE row is created or refreshed, which is what makes the flag
        independent of import order. Without it, importing the catalogue and *then* an
        NVD bundle leaves the newly-created CVEs at NULL — reading as "never checked"
        while an entry for them sits in `vuln_kev_entries`, and quietly re-opening the
        hole this feed was built to close.
        """
        imported = (
            await self.session.execute(
                select(KevEntry.id).where(KevEntry.org_id == self.org_id).limit(1)
            )
        ).scalar_one_or_none()
        if imported is None:
            return None

        entry = (
            await self.session.execute(
                select(KevEntry).where(
                    KevEntry.org_id == self.org_id, KevEntry.cve_id == cve_id.upper()
                )
            )
        ).scalar_one_or_none()

        return (True, entry.due_date) if entry else (False, None)

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

            # `epss` is deliberately untouched: it comes from another feed entirely, and
            # writing a default here would turn "unscored" into "scored zero".
            #
            # `kev` *is* set, from the stored catalogue rather than from a default. The
            # distinction matters: this is not inventing a value, it is answering a
            # question the database can already answer. Leaving it NULL would make a
            # CVE's flag depend on whether its advisory happened to arrive before or
            # after the catalogue, which no operator could be expected to reason about.
            if (kev_state := await self._kev_state(cve_id)) is not None:
                row.kev, row.kev_due_date = kev_state

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
            # Dropping this on the way to storage would turn an inclusive upper bound
            # into an unbounded range on the way back, so every later release would read
            # as affected.
            "last_affected": entry.constraint.last_affected,
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
