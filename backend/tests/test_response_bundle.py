"""The endpoint-keyed collection artefact reader (FR-COL-08).

This class exists because both API parsers answered "which responses did nothing read"
from a hand-maintained set of endpoints they believed they read — and both sets had
drifted, naming endpoints no rule touched. The claim was worse than no claim: it
silenced the one mechanism that would have reported the gap.

So the property under test is not really "get returns objects". It is that ``unread()``
is a fact derived from what the code did, with no second place to say it, which is what
makes the drift impossible rather than merely fixed.
"""

from __future__ import annotations

from typing import Any

import pytest

from netsecops.parsers.bundle import ResponseBundle, last_path_segment, whole_key


def objects(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        inner = payload.get("objects")
        if isinstance(inner, list):
            return [item for item in inner if isinstance(item, dict)]
        return [payload]
    return []


def bundle(payload: dict[str, Any], *, normalise=whole_key) -> ResponseBundle:
    return ResponseBundle(payload, normalise=normalise, extract=objects)


class TestReading:
    def test_a_response_is_found_by_its_normalised_key(self) -> None:
        reader = bundle({"NetworkDevice": [{"name": "sw-1"}]})

        assert reader.get("networkdevice") == [{"name": "sw-1"}]

    def test_a_path_keyed_bundle_matches_on_its_last_segment(self) -> None:
        reader = bundle(
            {"/api/v1/radiusclients/": {"objects": [{"name": "sw-1"}]}},
            normalise=last_path_segment,
        )

        assert reader.get("radiusclients") == [{"name": "sw-1"}]

    def test_an_absent_endpoint_yields_an_empty_list(self) -> None:
        """FR-COL-08. The policy endpoint returning 403 must not stop the network
        devices being read; the parser sees an empty list and the dependent checks
        report Not Evaluated."""
        assert bundle({"networkdevice": []}).get("allowedprotocols") == []

    def test_first_returns_the_single_settings_object(self) -> None:
        reader = bundle({"admin/settings": {"sessionTimeout": 30}})

        assert reader.first("admin/settings") == {"sessionTimeout": 30}

    def test_first_is_none_when_the_endpoint_is_absent(self) -> None:
        assert bundle({}).first("admin/settings") is None


class TestUnreadTracking:
    def test_an_endpoint_nothing_read_is_reported(self) -> None:
        reader = bundle({"networkdevice": [], "show-unicorns": []})
        reader.get("networkdevice")

        assert reader.unread() == ["show-unicorns"]

    def test_reading_an_endpoint_that_returned_nothing_still_counts_as_read(self) -> None:
        """The distinction the whole class turns on. A rule looked at the response and
        found it empty; that is an outcome. Nothing having looked is a gap. Conflating
        them would make every 403 look like a parser that forgot an endpoint."""
        reader = bundle({"networkdevice": []})
        assert reader.get("networkdevice") == []

        assert reader.unread() == []

    def test_asking_for_an_endpoint_that_is_not_present_marks_nothing(self) -> None:
        reader = bundle({"networkdevice": []})
        reader.get("allowedprotocols")

        assert reader.unread() == ["networkdevice"]

    def test_unread_is_stable_in_order(self) -> None:
        """The list reaches `raw_unparsed`, which is compared in tests and shown to
        users. An order that varies by dict insertion would make both flaky."""
        reader = bundle({"zebra": [], "alpha": [], "mike": []})

        assert reader.unread() == ["alpha", "mike", "zebra"]

    def test_the_original_key_is_reported_not_the_normalised_one(self) -> None:
        """`/api/v1/guestportals/` is what someone has to go and look at. Reporting
        `guestportals` would send them looking for an endpoint spelled that way."""
        reader = bundle({"/api/v1/guestportals/": {"objects": []}}, normalise=last_path_segment)

        assert reader.unread() == ["/api/v1/guestportals/"]


class TestContainerProtocol:
    def test_membership_uses_the_normalised_form(self) -> None:
        reader = bundle({"NetworkDevice": []})

        assert "networkdevice" in reader
        assert "allowedprotocols" not in reader

    def test_membership_does_not_count_as_reading(self) -> None:
        """Otherwise a parser could silence the gap report by merely asking whether an
        endpoint exists, which is the drift arriving through a different door."""
        reader = bundle({"networkdevice": []})
        assert "networkdevice" in reader

        assert reader.unread() == ["networkdevice"]

    @pytest.mark.parametrize("payload", [{}, {"a": []}, {"a": [], "b": []}])
    def test_length_is_the_number_of_responses(self, payload: dict[str, Any]) -> None:
        assert len(bundle(payload)) == len(payload)
