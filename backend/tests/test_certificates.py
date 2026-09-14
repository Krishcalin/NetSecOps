"""Reading certificate expiry dates out of the NCM (FR-AAA-06).

The failure this file exists to prevent is a quiet one. Every vendor prints dates
differently; a parser that shrugs at an unfamiliar format and moves on produces an
expiry timeline that is *shorter* than reality, and a short timeline looks exactly like
good news. So the contract tested here is: read every format our parsers emit, and when
a date cannot be read, say so rather than dropping the certificate that carried it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from netsecops.ncm.certificates import describe, parse_expiry
from netsecops.ncm.models import Certificate


class TestVendorDateFormats:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            # ISO-8601, with and without a zone — the shape a sane API returns.
            ("2027-05-31T23:59:59Z", datetime(2027, 5, 31, 23, 59, 59, tzinfo=UTC)),
            ("2027-05-31T23:59:59", datetime(2027, 5, 31, 23, 59, 59, tzinfo=UTC)),
            ("2027-05-31T23:59:59+00:00", datetime(2027, 5, 31, 23, 59, 59, tzinfo=UTC)),
            ("2027-05-31 23:59:59", datetime(2027, 5, 31, 23, 59, 59, tzinfo=UTC)),
            ("2027-05-31", datetime(2027, 5, 31, tzinfo=UTC)),
            # Fractional seconds. This one was a real defect: a format-string list that
            # did not include it reported every certificate from an API that emits
            # microseconds as undated, which is the exact failure the module exists to
            # prevent — and it was invisible, because undated still renders.
            (
                "2027-05-31T23:59:59.123456+00:00",
                datetime(2027, 5, 31, 23, 59, 59, 123456, tzinfo=UTC),
            ),
            # PAN-OS prints OpenSSL's ASN1_TIME.
            ("Mar 12 09:14:22 2027 GMT", datetime(2027, 3, 12, 9, 14, 22, tzinfo=UTC)),
            # Cisco ISE prints Java's Date.toString.
            ("Fri Mar 12 09:14:22 UTC 2027", datetime(2027, 3, 12, 9, 14, 22, tzinfo=UTC)),
        ],
    )
    def test_every_format_our_parsers_emit_is_read(self, value: str, expected: datetime) -> None:
        assert parse_expiry(value) == expected

    def test_an_epoch_in_seconds_or_milliseconds_is_read(self) -> None:
        """FortiAuthenticator returns these on some firmware. Milliseconds and seconds
        differ by a factor of a thousand, which is the difference between 2027 and the
        year 57,000 — a timeline sorted on that would put a live certificate last."""
        seconds = parse_expiry("1811808000")
        millis = parse_expiry("1811808000000")
        assert seconds is not None and millis is not None
        assert seconds == millis

    @pytest.mark.parametrize("value", [None, "", "   ", "unknown", "n/a", "never", "31/05/2027"])
    def test_anything_unrecognised_is_none_rather_than_guessed(self, value: str | None) -> None:
        """`31/05/2027` is the important one in this list. A lenient date parser reads it
        as the 5th of a month that does not exist, or silently as 5 March — either way it
        invents a date, and an invented expiry is worse than an admitted gap."""
        assert parse_expiry(value) is None


class TestTimelinePlacement:
    def test_a_certificate_with_an_unreadable_date_stays_on_the_timeline(self) -> None:
        """The whole reason this module exists. Dropping it would shorten the timeline,
        and a shorter timeline reads as better news."""
        entry = describe(
            Certificate(name="pxgrid", not_after="unknown"),
            device_id="d1",
            device="ise-01",
        )
        assert entry.name == "pxgrid"
        assert entry.expires_at is None
        assert entry.days_remaining is None
        assert entry.dated is False
        # And it must not be mistaken for an expired one, which would page someone.
        assert entry.expired is False

    def test_days_remaining_is_negative_for_an_expired_certificate(self) -> None:
        now = datetime(2026, 9, 14, tzinfo=UTC)
        entry = describe(
            Certificate(name="old", not_after="2026-01-01T00:00:00Z"),
            device_id="d1",
            device="fac-01",
            now=now,
        )
        assert entry.days_remaining is not None
        assert entry.days_remaining < 0
        assert entry.expired is True

    def test_days_remaining_is_measured_from_the_moment_supplied(self) -> None:
        """Passing `now` in rather than reading the clock is what lets one posture build
        place every certificate against a single instant. Two certificates compared
        against two different 'now's can order wrongly at a day boundary."""
        now = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)
        expiry = (now + timedelta(days=45)).isoformat()
        entry = describe(
            Certificate(name="eap", not_after=expiry), device_id="d1", device="ise-01", now=now
        )
        assert entry.days_remaining == 45

    def test_the_fields_that_make_a_certificate_identifiable_are_carried(self) -> None:
        entry = describe(
            Certificate(
                name="campus-eap",
                subject="ise-psn-01.campus.example.com",
                issuer="Campus Issuing CA G2",
                self_signed=False,
                usage=["EAP Authentication"],
                not_after="2031-03-13T09:14:22Z",
            ),
            device_id="d1",
            device="ise-01",
        )
        assert entry.subject == "ise-psn-01.campus.example.com"
        assert entry.issuer == "Campus Issuing CA G2"
        assert entry.self_signed is False
        # The usage is what tells an operator this is the one every supplicant sees.
        assert entry.usage == ["EAP Authentication"]
