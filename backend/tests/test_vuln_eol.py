"""End-of-life and end-of-support detection (FR-VUL-05).

An unsupported release is a permanent, unfixable vulnerability — no advisory will name
it because the vendor stopped looking, and no patch exists. It is frequently the most
actionable line on a device's page, because the remedy is a project rather than a
maintenance window.

The fixture is shaped like a real `endoflife.date` response, including the quirk that
breaks naive readers: the `eol` and `support` fields are *either* an ISO date *or* a
boolean. `"eol": true` is the dataset's strongest possible statement — this release is
dead — and code expecting a string drops exactly that record.

Dates are pinned with an explicit `today` throughout. A lifecycle test that depends on
the wall clock passes until the day it silently starts asserting something else.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from netsecops.vuln.eol import (
    EolRecord,
    LifecycleStatus,
    assess,
    parse_endoflife_date,
)

FIXTURES = Path(__file__).parent / "fixtures" / "feeds" / "eol"

#: Every test reasons from this date rather than today's.
NOW = date(2026, 1, 15)


@pytest.fixture
def asa_records() -> list[EolRecord]:
    payload = json.loads((FIXTURES / "cisco_asa.json").read_text(encoding="utf-8"))
    return parse_endoflife_date(payload, vendor="cisco", product="asa")


# ═════════════════════════════ parsing the feed ══════════════════════════════


class TestParsing:
    def test_every_cycle_is_read(self, asa_records) -> None:
        assert {record.cycle for record in asa_records} == {"9.20", "9.18", "9.16", "9.12", "9.8"}

    def test_iso_dates_are_parsed(self, asa_records) -> None:
        record = next(r for r in asa_records if r.cycle == "9.18")

        assert record.support_ends == date(2025, 11, 30)
        assert record.life_ends == date(2027, 5, 31)
        assert record.latest == "9.18.4"

    def test_a_boolean_true_is_kept_as_an_undated_ending(self, asa_records) -> None:
        """`"eol": true` is the strongest statement the dataset makes.

        A reader expecting a string drops it, and dropping it turns a dead release into
        one with no opinion attached.
        """
        record = next(r for r in asa_records if r.cycle == "9.12")

        assert record.life_ends is None
        assert record.life_ended_undated is True

    def test_a_boolean_false_means_not_ended(self, asa_records) -> None:
        """`false` is "not yet", which is the opposite of `true` and must not collapse
        into the same undated flag."""
        record = next(r for r in asa_records if r.cycle == "9.16")

        assert record.support_ended_undated is False
        assert record.support_ends is None

    def test_a_cycle_with_no_lifecycle_fields_at_all(self, asa_records) -> None:
        record = next(r for r in asa_records if r.cycle == "9.8")

        assert record.support_ends is None and record.life_ends is None
        assert record.support_ended_undated is False and record.life_ended_undated is False

    @pytest.mark.parametrize("payload", [None, {}, "", 42, [1, 2, 3], [{"no": "cycle"}]])
    def test_a_malformed_payload_yields_nothing_rather_than_raising(self, payload) -> None:
        assert parse_endoflife_date(payload, vendor="cisco", product="asa") == []

    def test_an_unreadable_date_does_not_become_an_ending(self) -> None:
        """A date nobody can parse is not evidence the release ended."""
        records = parse_endoflife_date(
            [{"cycle": "9.18", "eol": "sometime in 2027"}], vendor="cisco", product="asa"
        )

        assert records[0].life_ends is None
        assert records[0].life_ended_undated is False


# ═══════════════════════════ placing a device ════════════════════════════════


class TestAssessment:
    def test_a_supported_release(self, asa_records) -> None:
        result = assess("9.20(3)", asa_records, platform="cisco_asa", today=NOW)

        assert result.status is LifecycleStatus.SUPPORTED

    def test_a_release_past_security_maintenance(self, asa_records) -> None:
        """The state operators most often do not know they are in.

        9.18 support ended 2025-11-30; EOL is 2027-05-31. The device runs, boots, has a
        contract, and receives no security fixes.
        """
        result = assess("9.18(4)", asa_records, platform="cisco_asa", today=NOW)

        assert result.status is LifecycleStatus.END_OF_SUPPORT
        assert "still runs and still boots" in result.reasoning
        assert "9.18.4" in result.reasoning, "the upgrade target must be named"

    def test_an_undated_end_of_life_still_reports_end_of_life(self, asa_records) -> None:
        result = assess("9.12(4)", asa_records, platform="cisco_asa", today=NOW)

        assert result.status is LifecycleStatus.END_OF_LIFE
        assert "no future advisory will name it" in result.reasoning

    def test_end_of_life_outranks_end_of_support(self, asa_records) -> None:
        """9.12 is past both. The more serious statement is the one reported."""
        result = assess("9.12(4)", asa_records, platform="cisco_asa", today=NOW)

        assert result.status is not LifecycleStatus.END_OF_SUPPORT

    def test_a_cycle_approaching_end_of_support_warns_early(self) -> None:
        """A quarter's notice, because the remedy is a funded project.

        Warning on the day support ends is warning too late to do anything about it.
        """
        records = parse_endoflife_date(
            [{"cycle": "9.20", "support": "2026-03-01", "eol": "2029-03-31"}],
            vendor="cisco",
            product="asa",
        )
        result = assess("9.20(1)", records, platform="cisco_asa", today=NOW)

        assert result.status is LifecycleStatus.APPROACHING_END_OF_SUPPORT
        assert "planning now" in result.reasoning

    def test_a_cycle_with_no_dates_is_unknown_not_supported(self, asa_records) -> None:
        """An entry exists; its lifecycle does not. Saying "supported" invents it."""
        result = assess("9.8(4)", asa_records, platform="cisco_asa", today=NOW)

        assert result.status is LifecycleStatus.UNKNOWN


class TestWhatItRefusesToCallSupported:
    """Every path to UNKNOWN. Each would be a device quietly filed as fine."""

    def test_no_version(self, asa_records) -> None:
        result = assess(None, asa_records, platform="cisco_asa", today=NOW)

        assert result.status is LifecycleStatus.UNKNOWN
        assert "reports no software version" in result.reasoning

    def test_no_imported_data(self) -> None:
        result = assess("9.18(4)", [], platform="cisco_asa", today=NOW)

        assert result.status is LifecycleStatus.UNKNOWN
        assert "Import an EoL bundle" in result.reasoning, "say how to fix it"

    def test_a_version_outside_every_known_cycle(self, asa_records) -> None:
        """Newer than the dataset, or a dataset with holes. Either way, not supported."""
        result = assess("9.22(1)", asa_records, platform="cisco_asa", today=NOW)

        assert result.status is LifecycleStatus.UNKNOWN
        assert "does not fall in any release cycle" in result.reasoning

    def test_unknown_is_surfaced_rather_than_filed_with_the_supported(self, asa_records) -> None:
        assert assess("9.22(1)", asa_records, platform="cisco_asa", today=NOW).actionable
        assert not assess("9.20(3)", asa_records, platform="cisco_asa", today=NOW).actionable


class TestCycleMatching:
    def test_the_bracketed_device_spelling_matches_a_dotted_cycle(self, asa_records) -> None:
        """A device says `9.18(4)`; the dataset tracks `9.18`.

        Matched through the version model rather than by string prefix, which is what
        makes these the same train rather than two unrelated strings.
        """
        result = assess("9.18(4)", asa_records, platform="cisco_asa", today=NOW)

        assert result.record is not None
        assert result.record.cycle == "9.18"

    def test_the_longest_matching_cycle_wins(self) -> None:
        """`9.18.4` belongs to the `9.18` cycle, not a broader `9` one."""
        records = parse_endoflife_date(
            [
                {"cycle": "9", "eol": "2030-01-01"},
                {"cycle": "9.18", "eol": "2027-05-31", "support": "2025-11-30"},
            ],
            vendor="cisco",
            product="asa",
        )
        result = assess("9.18(4)", records, platform="cisco_asa", today=NOW)

        assert result.record is not None
        assert result.record.cycle == "9.18"
        assert result.status is LifecycleStatus.END_OF_SUPPORT

    def test_a_shorter_version_does_not_match_a_longer_cycle(self) -> None:
        """`9.1` must not be swallowed by the `9.18` cycle.

        A string prefix match would do exactly that, and would place a device three
        trains older into a cycle that is still supported.
        """
        records = parse_endoflife_date(
            [{"cycle": "9.18", "eol": "2027-05-31"}], vendor="cisco", product="asa"
        )
        result = assess("9.1(7)", records, platform="cisco_asa", today=NOW)

        assert result.status is LifecycleStatus.UNKNOWN
