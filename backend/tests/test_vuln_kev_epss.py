"""CISA KEV and FIRST EPSS ingestion (FR-VUL-06).

Both columns have existed since Phase 6 with no feed behind them. `kev` was NULL on every
row, so the `kev_only` filter in the API and the console could only ever return an empty
list — a control that always answers "none", which reads as "your estate is clean".

The assertions that matter are not "the file parsed". They are:

- **A catalogue import writes `False`, not just `True`.** Setting the flag only on listed
  CVEs leaves every other one NULL, which still means "never checked" — so the filter
  still matches nothing and nothing has actually been fixed. This is the single
  difference between two states and three.
- **The flag survives import order.** Catalogue first then advisories, or the reverse,
  must give the same answer. Storing only the flag cannot do this, which is why the
  catalogue is a table.
- **A file that cannot be read imports nothing.** An empty catalogue applied to the
  estate would mark every CVE as not-exploited on the strength of a parse failure.

Mutations worth trying: delete the `notin_` update in `_ingest_kev`, and make
`_store_cve` skip `_kev_state`. Both leave a feature that looks like it works.
"""

from __future__ import annotations

import gzip
import json

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ValidationProblem
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.vulnerability import KevEntry, VulnCve
from netsecops.services.feeds import BundleKind, FeedImportService, detect_kind
from netsecops.vuln.epss import parse_epss_csv, parse_epss_json
from netsecops.vuln.kev import looks_like_kev, parse_kev_catalogue
from tests.conftest import make_user

EXPLOITED = "CVE-2024-20353"
QUIET = "CVE-2024-99999"


def kev_catalogue(*cve_ids: str, version: str = "2024.05.01") -> bytes:
    return json.dumps(
        {
            "title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": version,
            "dateReleased": "2024-05-01T13:00:00.0000Z",
            "count": len(cve_ids),
            "vulnerabilities": [
                {
                    "cveID": cve_id,
                    "vendorProject": "Cisco",
                    "product": "Adaptive Security Appliance",
                    "vulnerabilityName": "Cisco ASA Persistent Execution",
                    "dateAdded": "2024-04-24",
                    "shortDescription": "…",
                    "requiredAction": "Apply mitigations per vendor instructions.",
                    "dueDate": "2024-05-01",
                    "knownRansomwareCampaignUse": "Unknown",
                    "notes": "",
                }
                for cve_id in cve_ids
            ],
        }
    ).encode("utf-8")


def epss_csv(scores: dict[str, float], *, score_date: str = "2024-05-01T00:00:00+0000") -> bytes:
    lines = [f"#model_version:v2023.03.01,score_date:{score_date}", "cve,epss,percentile"]
    lines += [f"{cve},{score},0.5" for cve, score in scores.items()]
    return "\n".join(lines).encode("utf-8")


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="kev_analyst", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
def feeds(session: AsyncSession) -> FeedImportService:
    return FeedImportService(session)


async def add_cve(session: AsyncSession, cve_id: str) -> VulnCve:
    row = VulnCve(org_id=1, cve_id=cve_id)
    session.add(row)
    await session.flush()
    return row


async def cve(session: AsyncSession, cve_id: str) -> VulnCve:
    return (await session.execute(select(VulnCve).where(VulnCve.cve_id == cve_id))).scalar_one()


# ═══════════════════════ telling the formats apart ═══════════════════════════


class TestDetection:
    def test_a_kev_catalogue_is_not_read_as_an_nvd_feed(self) -> None:
        """All three of CSAF, NVD and KEV carry a top-level `vulnerabilities` key.

        Read as NVD, a catalogue imports nothing and raises nothing: `kev` stays NULL
        everywhere while the operator believes the catalogue is loaded. That is the exact
        state this feed exists to end, so the misdetection is worse than a crash.
        """
        assert detect_kind(json.loads(kev_catalogue(EXPLOITED))) is BundleKind.KEV

    def test_an_nvd_feed_is_still_read_as_nvd(self) -> None:
        payload = {"vulnerabilities": [{"cve": {"id": EXPLOITED}}], "totalResults": 1}

        assert detect_kind(payload) is BundleKind.NVD

    def test_a_csaf_advisory_still_wins_on_its_document_key(self) -> None:
        payload = {"document": {"title": "x"}, "vulnerabilities": [{"cve": EXPLOITED}]}

        assert detect_kind(payload) is BundleKind.CSAF

    def test_a_catalogue_slice_without_its_header_is_still_recognised(self) -> None:
        """NVD nests the id as `{"cve": {"id": ...}}`; KEV puts `cveID` on the entry."""
        assert looks_like_kev({"vulnerabilities": [{"cveID": EXPLOITED}]}) is True
        assert looks_like_kev({"vulnerabilities": [{"cve": {"id": EXPLOITED}}]}) is False

    def test_an_epss_json_export_is_recognised(self) -> None:
        payload = {"status": "OK", "data": [{"cve": EXPLOITED, "epss": "0.5", "percentile": "0.9"}]}

        assert detect_kind(payload) is BundleKind.EPSS


# ════════════════════════ reading the catalogue ══════════════════════════════


class TestParsingTheCatalogue:
    def test_it_carries_the_dates_and_the_version(self) -> None:
        catalogue = parse_kev_catalogue(json.loads(kev_catalogue(EXPLOITED)))

        assert catalogue.catalog_version == "2024.05.01"
        record = catalogue.records[0]
        assert record.cve_id == EXPLOITED
        assert record.due_date is not None and record.due_date.isoformat() == "2024-05-01"
        assert record.date_added is not None

    def test_cisas_unknown_ransomware_is_not_a_no(self) -> None:
        """CISA's "Unknown" means not established. Mapping it to False would assert
        something the catalogue does not say."""
        catalogue = parse_kev_catalogue(json.loads(kev_catalogue(EXPLOITED)))

        assert catalogue.records[0].known_ransomware is None

    def test_a_known_ransomware_entry_is_true(self) -> None:
        payload = json.loads(kev_catalogue(EXPLOITED))
        payload["vulnerabilities"][0]["knownRansomwareCampaignUse"] = "Known"

        assert parse_kev_catalogue(payload).records[0].known_ransomware is True

    def test_unreadable_entries_are_counted_not_dropped_silently(self) -> None:
        payload = json.loads(kev_catalogue(EXPLOITED))
        payload["vulnerabilities"].append({"cveID": "not-a-cve"})

        catalogue = parse_kev_catalogue(payload)

        assert len(catalogue.records) == 1
        assert catalogue.rejected == 1

    def test_a_catalogue_that_parses_to_nothing_is_refused(self) -> None:
        """Applying it would flip every CVE in the estate from unknown to not-exploited
        on the strength of a file this could not read."""
        with pytest.raises(ValidationProblem) as raised:
            parse_kev_catalogue({"catalogVersion": "x", "vulnerabilities": [{"bad": 1}]})

        assert "not known-exploited" in str(raised.value)


# ══════════════════ the three states, which is the point ═════════════════════


class TestImportingTheCatalogue:
    async def test_before_any_import_every_cve_is_unknown(
        self, session: AsyncSession, actor
    ) -> None:
        await add_cve(session, EXPLOITED)

        assert (await cve(session, EXPLOITED)).kev is None

    async def test_a_listed_cve_becomes_true_with_its_due_date(
        self, session: AsyncSession, actor, feeds
    ) -> None:
        await add_cve(session, EXPLOITED)

        await feeds.import_bundle(kev_catalogue(EXPLOITED), feed="kev", actor=actor)

        row = await cve(session, EXPLOITED)
        assert row.kev is True
        assert row.kev_due_date is not None and row.kev_due_date.isoformat() == "2024-05-01"

    async def test_an_unlisted_cve_becomes_false_not_null(
        self, session: AsyncSession, actor, feeds
    ) -> None:
        """**The assertion this whole feature turns on.**

        Setting only the listed CVEs to True leaves every other one NULL, which still
        means "the catalogue was never imported" — so `kev_only` still matches nothing
        and the estate still reads as unchecked. Writing False is the entire difference
        between two states and three.
        """
        await add_cve(session, EXPLOITED)
        await add_cve(session, QUIET)

        result = await feeds.import_bundle(kev_catalogue(EXPLOITED), feed="kev", actor=actor)

        assert (await cve(session, QUIET)).kev is False
        assert result.kev_cleared >= 1

    async def test_the_catalogue_itself_is_stored(
        self, session: AsyncSession, actor, feeds
    ) -> None:
        result = await feeds.import_bundle(kev_catalogue(EXPLOITED), feed="kev", actor=actor)

        entries = (await session.execute(select(KevEntry))).scalars().all()
        assert [entry.cve_id for entry in entries] == [EXPLOITED]
        assert result.kev_entries == 1
        assert entries[0].required_action is not None

    async def test_the_source_version_is_recorded_separately_from_the_import_time(
        self, session: AsyncSession, actor, feeds
    ) -> None:
        """A sync that ran a minute ago against a year-old catalogue is fresh and stale
        at once, and `started_at` reports only the reassuring half."""
        result = await feeds.import_bundle(
            kev_catalogue(EXPLOITED, version="2023.01.01"), feed="kev", actor=actor
        )

        assert result.source_version == "2023.01.01"
        assert result.sync.source_version == "2023.01.01"

    async def test_reimporting_a_shrunken_catalogue_clears_what_left_it(
        self, session: AsyncSession, actor, feeds
    ) -> None:
        """CISA does remove entries. A CVE that drops out must stop reading as exploited
        rather than keeping a stale True forever."""
        await add_cve(session, EXPLOITED)
        await feeds.import_bundle(kev_catalogue(EXPLOITED), feed="kev", actor=actor)
        assert (await cve(session, EXPLOITED)).kev is True

        await feeds.import_bundle(kev_catalogue(QUIET), feed="kev", actor=actor)

        assert (await cve(session, EXPLOITED)).kev is False


class TestImportOrderDoesNotChangeTheAnswer:
    """The reason the catalogue is a table rather than just a flag."""

    NVD = json.dumps(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": EXPLOITED,
                        "descriptions": [{"lang": "en", "value": "ASA flaw"}],
                        "metrics": {},
                        "configurations": [],
                        "published": "2024-04-24T00:00:00.000",
                        "lastModified": "2024-04-25T00:00:00.000",
                    }
                }
            ],
            "totalResults": 1,
        }
    ).encode("utf-8")

    async def test_catalogue_then_advisories(self, session: AsyncSession, actor, feeds) -> None:
        """The order that breaks a flag-only design.

        The CVE row does not exist when the catalogue lands, so nothing can be flagged
        then; it is created by the NVD import afterwards. Without the stored catalogue to
        consult, it would be created reading "never checked" while an entry for it sat in
        the same database.
        """
        await feeds.import_bundle(kev_catalogue(EXPLOITED), feed="kev", actor=actor)
        await feeds.import_bundle(self.NVD, feed="nvd", actor=actor)

        assert (await cve(session, EXPLOITED)).kev is True

    async def test_advisories_then_catalogue(self, session: AsyncSession, actor, feeds) -> None:
        await feeds.import_bundle(self.NVD, feed="nvd", actor=actor)
        await feeds.import_bundle(kev_catalogue(EXPLOITED), feed="kev", actor=actor)

        assert (await cve(session, EXPLOITED)).kev is True

    async def test_an_advisory_arriving_before_any_catalogue_stays_unknown(
        self, session: AsyncSession, actor, feeds
    ) -> None:
        """No catalogue has been imported, so the honest answer is still "unknown" —
        not False. `_kev_state` returns None and the column is left alone."""
        await feeds.import_bundle(self.NVD, feed="nvd", actor=actor)

        assert (await cve(session, EXPLOITED)).kev is None


# ════════════════════════════════ EPSS ═══════════════════════════════════════


class TestParsingEpss:
    def test_the_csv_header_carries_the_score_date(self) -> None:
        scores = parse_epss_csv(epss_csv({EXPLOITED: 0.97}))

        assert scores.scores[EXPLOITED] == pytest.approx(0.97)
        assert scores.model_version == "v2023.03.01"
        # The full ISO timestamp, not truncated at its first colon.
        assert scores.score_date == "2024-05-01T00:00:00+0000"

    def test_a_gzipped_bundle_is_read(self) -> None:
        """FIRST publishes `.csv.gz`; an operator should not have to unpack it first."""
        scores = parse_epss_csv(gzip.compress(epss_csv({EXPLOITED: 0.5})))

        assert scores.scores[EXPLOITED] == pytest.approx(0.5)

    @pytest.mark.parametrize("bad", ["1.5", "-0.2", "banana", ""])
    def test_a_score_outside_zero_to_one_is_rejected_not_clamped(self, bad: str) -> None:
        """Clamping a corrupt 5.0 to 1.0 would make it the most urgent finding in the
        estate. The bad row is counted as rejected and the good one still lands."""
        raw = f"cve,epss,percentile\n{EXPLOITED},{bad},0.5\n{QUIET},0.25,0.5".encode()

        scores = parse_epss_csv(raw)

        assert EXPLOITED not in scores.scores
        assert scores.scores[QUIET] == pytest.approx(0.25)
        assert scores.rejected == 1

    def test_a_bundle_of_only_bad_rows_is_refused(self) -> None:
        with pytest.raises(ValidationProblem):
            parse_epss_csv(f"cve,epss,percentile\n{EXPLOITED},banana,0.5".encode())

    def test_the_json_form_reads_the_same_fields(self) -> None:
        scores = parse_epss_json(
            {"status": "OK", "data": [{"cve": EXPLOITED, "epss": "0.42", "percentile": "0.9"}]}
        )

        assert scores.scores[EXPLOITED] == pytest.approx(0.42)


class TestImportingEpss:
    async def test_a_known_cve_is_scored(self, session: AsyncSession, actor, feeds) -> None:
        await add_cve(session, EXPLOITED)

        result = await feeds.import_bundle(epss_csv({EXPLOITED: 0.97}), feed="epss", actor=actor)

        assert (await cve(session, EXPLOITED)).epss == pytest.approx(0.97)
        assert result.epss_scores == 1

    async def test_a_cve_the_feed_omits_stays_unscored(
        self, session: AsyncSession, actor, feeds
    ) -> None:
        """Unscored is not zero. Zero says "almost certainly not exploited", which for a
        CVE too new to have been modelled is precisely backwards."""
        await add_cve(session, EXPLOITED)
        await add_cve(session, QUIET)

        await feeds.import_bundle(epss_csv({EXPLOITED: 0.97}), feed="epss", actor=actor)

        assert (await cve(session, QUIET)).epss is None

    async def test_scores_for_cves_we_do_not_hold_are_not_stored(
        self, session: AsyncSession, actor, feeds
    ) -> None:
        """The bulk feed covers a quarter of a million CVEs; storing scores for
        advisories that reach no device would be a large table nobody queries."""
        await add_cve(session, EXPLOITED)

        result = await feeds.import_bundle(
            epss_csv({EXPLOITED: 0.97, QUIET: 0.01}), feed="epss", actor=actor
        )

        assert result.epss_scores == 1
        assert (await session.execute(select(VulnCve))).scalars().all().__len__() == 1

    async def test_the_score_date_is_recorded(self, session: AsyncSession, actor, feeds) -> None:
        result = await feeds.import_bundle(
            epss_csv({EXPLOITED: 0.5}, score_date="2023-01-01T00:00:00+0000"),
            feed="epss",
            actor=actor,
        )

        assert result.source_version == "2023-01-01T00:00:00+0000"

    async def test_importing_epss_does_not_touch_the_kev_flag(
        self, session: AsyncSession, actor, feeds
    ) -> None:
        """Two independent feeds. A scoring run must not answer a question about
        exploitation that it has no data for."""
        await add_cve(session, EXPLOITED)

        await feeds.import_bundle(epss_csv({EXPLOITED: 0.5}), feed="epss", actor=actor)

        assert (await cve(session, EXPLOITED)).kev is None


class TestBadBundles:
    async def test_a_file_that_is_neither_json_nor_csv_is_refused(
        self, session: AsyncSession, actor, feeds
    ) -> None:
        with pytest.raises(ValidationProblem) as raised:
            await feeds.import_bundle(b"\x00\x01\x02 not a feed", feed="kev", actor=actor)

        assert "neither readable JSON nor" in str(raised.value)

    async def test_a_failed_import_leaves_the_flags_alone(
        self, session: AsyncSession, actor, feeds
    ) -> None:
        """Nothing half-applied: a catalogue that could not be read must not clear the
        estate's flags on the way to failing."""
        await add_cve(session, EXPLOITED)

        with pytest.raises(ValidationProblem):
            await feeds.import_bundle(
                json.dumps({"catalogVersion": "x", "vulnerabilities": [{"bad": 1}]}).encode(),
                feed="kev",
                actor=actor,
            )

        assert (await cve(session, EXPLOITED)).kev is None
