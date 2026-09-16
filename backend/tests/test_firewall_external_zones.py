"""Whether the external zones were confirmed or guessed (FR-FW-04).

`examine_nat` takes no default for `external_zones`, and that is right: guessing either
invents exposure findings for an internal NAT or hides a real one. But both callers fall
back to `external_zones_from`, a substring match on zone names — untrust, outside,
internet, wan, external, public — and no caller anywhere passes an explicit list, so in
practice the heuristic always decides.

That leaves two states indistinguishable in the output: exposure analysed against zones
an operator confirmed, and exposure analysed against zones a substring match picked. The
findings are identical; their trustworthiness is not. These tests pin that the
difference is now reported.
"""

from __future__ import annotations

from typing import Any

from netsecops.firewall.nat import external_zones_from
from netsecops.services.firewall_view import FirewallViewService


class FakeSnapshot:
    """Enough of a Snapshot for the view service; it only reads three attributes."""

    def __init__(self, firewall: dict[str, Any]) -> None:
        self.id = "00000000-0000-0000-0000-000000000001"
        self.device_id = "00000000-0000-0000-0000-000000000002"
        self.parser_platform = "panos"
        self.ncm = {"firewall": firewall}


def firewall_with(zones: list[str]) -> dict[str, Any]:
    return {
        "zones": zones,
        "address_objects": [{"name": "web", "type": "ip-netmask", "value": "10.20.0.10/32"}],
        "security_rules": [
            {
                "order": 1,
                "name": "inbound-web",
                "enabled": True,
                "src_zones": [zones[0]],
                "src": ["any"],
                "dst_zones": [zones[-1]],
                "dst": ["web"],
                "services": ["tcp/443"],
                "action": "allow",
                "log_end": True,
            }
        ],
        "nat_rules": [
            {
                "order": 1,
                "name": "publish-web",
                "direction": "destination",
                "original": "203.0.113.10",
                "translated": "10.20.0.10",
                "service": "tcp/443",
            }
        ],
    }


def build(firewall: dict[str, Any], external_zones: list[str] | None = None):
    service = FirewallViewService(FakeSnapshot(firewall), external_zones=external_zones)
    return service.build().summary


class TestTheHeuristicIsDeclared:
    def test_inferred_zones_are_flagged_as_inferred(self) -> None:
        summary = build(firewall_with(["untrust", "dmz"]))

        assert summary.exposure_analysed is True
        assert summary.external_zones_inferred is True
        assert summary.external_zones == ["untrust"]

    def test_the_limitation_names_the_zones_and_the_risk_of_the_guess(self) -> None:
        summary = build(firewall_with(["untrust", "dmz"]))

        text = " ".join(summary.limitations)
        assert "untrust" in text
        assert "rather than confirmed" in text

    def test_supplied_zones_are_not_flagged(self) -> None:
        summary = build(firewall_with(["untrust", "dmz"]), external_zones=["untrust"])

        assert summary.exposure_analysed is True
        assert summary.external_zones_inferred is False
        assert not any("rather than confirmed" in line for line in summary.limitations)


class TestSiteNamedZonesGetNoExposureAnalysis:
    def test_zones_named_after_sites_match_nothing(self) -> None:
        """The case the naming heuristic cannot serve, and the reason it must say so."""
        assert external_zones_from({"zones": ["mumbai-edge", "pune-core"]}) == []

    def test_exposure_is_reported_as_not_analysed_rather_than_as_none_found(self) -> None:
        summary = build(firewall_with(["mumbai-edge", "pune-core"]))

        assert summary.exposure_analysed is False
        assert summary.external_zones == []
        assert summary.external_zones_inferred is False

    def test_the_limitation_explains_why_no_zone_matched(self) -> None:
        """An operator who reads only "not analysed" will not know what to do about it."""
        summary = build(firewall_with(["mumbai-edge", "pune-core"]))

        text = " ".join(summary.limitations)
        assert "not a finding of 'no exposure'" in text
        assert "names its zones after sites" in text


class TestAssessmentRecordsTheSameBasis:
    def test_the_outcome_carries_the_zones_it_used(self) -> None:
        """An exposure finding written months ago should not need the heuristic
        re-run to work out what it rested on."""
        from netsecops.services.firewall_assessment import FirewallAssessment

        outcome = FirewallAssessment()
        assert outcome.external_zones == []
        assert outcome.external_zones_inferred is False
