"""NAT analysis (FR-FW-04).

The point of this module is that exposure is invisible in either rulebase alone. A
security rule permitting `any → 10.20.0.10:443` reads as internal; it is internet-facing
only because a NAT rule publishes that host behind a public address, and that rule lives
in a different rulebase often maintained by different people.

So the tests that matter most are the ones about the *join*: that a NAT rule with no
matching permit is reported as such rather than as an exposure, that a permit to an
un-published host is not reported as exposure, and that neither is claimed at all when
the caller has not said which zones face the internet.

That last one is the easiest to get quietly wrong. If `examine` guessed at external
zones and guessed wrong, it would either invent exposure findings for an internal NAT or
report a genuinely published database as safe. Reporting zero findings and reporting
"not analysed" look identical in a count, and only one of them is honest.
"""

from __future__ import annotations

from typing import Any

import pytest

from netsecops.firewall import resolve_rulebase
from netsecops.firewall.nat import NatIssue, examine, external_zones_from


def rule(
    order: int,
    *,
    name: str | None = None,
    src: str = "any",
    dst: str = "any",
    service: str = "any",
    action: str = "allow",
    src_zone: str = "untrust",
    dst_zone: str = "dmz",
    enabled: bool = True,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "order": order,
        "name": name or f"rule-{order}",
        "enabled": enabled,
        "src": [src],
        "dst": [dst],
        "services": [service],
        "action": action,
        "src_zones": [src_zone],
        "dst_zones": [dst_zone],
        **extra,
    }


def nat(
    order: int,
    *,
    name: str | None = None,
    translated: str = "",
    direction: str = "destination",
    service: str = "any",
    original: str = "any",
) -> dict[str, Any]:
    return {
        "order": order,
        "name": name or f"nat-{order}",
        "original": original,
        "translated": translated,
        "service": service,
        "direction": direction,
    }


def examine_both(
    nat_rules: list[dict[str, Any]],
    security_rules: list[dict[str, Any]],
    *,
    external: list[str] | None = ("untrust",),  # type: ignore[assignment]
    objects: list[dict[str, Any]] | None = None,
):
    firewall: dict[str, Any] = {
        "security_rules": security_rules,
        "nat_rules": nat_rules,
        "address_objects": objects or [],
    }
    rules, resolver = resolve_rulebase(firewall)
    return examine(firewall, rules, resolver, external_zones=external)


# ───────────────────────── the join, which is the point ─────────────────────


class TestExposure:
    def test_a_published_host_with_a_matching_permit_is_exposed(self) -> None:
        report = examine_both(
            [nat(1, name="Publish web", translated="10.20.0.10:443")],
            [rule(1, dst="10.20.0.10", service="tcp/443")],
        )

        exposed = report.by_issue(NatIssue.EXPOSED_SERVICE)
        assert len(exposed) == 1
        assert exposed[0].nat_name == "Publish web"
        # Both halves are named: changing either one closes the exposure, and which to
        # change is the operator's call, not this module's.
        assert exposed[0].rule_order == 1

    def test_a_published_rdp_port_is_critical(self) -> None:
        """Publishing a service is what a perimeter firewall is for, so exposure on its
        own is Info. Publishing RDP to the internet is a different conversation."""
        report = examine_both(
            [nat(1, name="Publish RDP", translated="10.20.0.11:3389")],
            [rule(1, dst="10.20.0.11", service="tcp/3389")],
        )

        insecure = report.by_issue(NatIssue.EXPOSED_INSECURE_SERVICE)
        assert len(insecure) == 1
        assert "RDP" in insecure[0].message
        assert insecure[0].severity == "critical"
        # Not double-reported as a plain exposure as well.
        assert not report.by_issue(NatIssue.EXPOSED_SERVICE)

    def test_a_permit_from_an_internal_zone_is_not_exposure(self) -> None:
        """The NAT publishes the host, but the rule that permits it is reachable only
        from inside. Reporting this as internet exposure would be a false positive on a
        perfectly ordinary internal NAT."""
        report = examine_both(
            [nat(1, translated="10.20.0.10:443")],
            [rule(1, dst="10.20.0.10", service="tcp/443", src_zone="trust")],
        )

        assert not report.by_issue(NatIssue.EXPOSED_SERVICE)
        assert not report.by_issue(NatIssue.EXPOSED_INSECURE_SERVICE)

    def test_a_nat_matched_only_from_inside_is_still_reported(self) -> None:
        """The gap that made a published RDP host invisible.

        The NAT publishes 10.20.0.11:3389 and an internal any/any rule reaches it, so it
        is not "unmatched". But nothing external permits it, so it is not exposure
        either — and it fell through both branches, producing no finding at all. The
        translation is already in place; a single permit would expose RDP.
        """
        report = examine_both(
            [nat(1, name="Inbound RDP NAT", translated="10.20.0.11:3389")],
            [rule(1, src_zone="trust", dst="any", service="any")],
        )

        unmatched = report.by_issue(NatIssue.UNMATCHED_NAT)
        assert len(unmatched) == 1
        assert "not reachable from outside today" in unmatched[0].message
        assert "a single permit would expose it" in unmatched[0].message
        # Not claimed as exposure — nothing outside reaches it.
        assert not report.by_issue(NatIssue.EXPOSED_INSECURE_SERVICE)

    def test_a_permit_to_a_different_host_does_not_count(self) -> None:
        report = examine_both(
            [nat(1, translated="10.20.0.10:443")],
            [rule(1, dst="10.20.0.99", service="tcp/443")],
        )
        assert report.by_issue(NatIssue.UNMATCHED_NAT)
        assert not report.by_issue(NatIssue.EXPOSED_SERVICE)

    def test_a_permit_on_a_different_port_does_not_count(self) -> None:
        """The NAT lands traffic on 443. A rule permitting 22 to the same host does not
        complete this exposure."""
        report = examine_both(
            [nat(1, translated="10.20.0.10:443")],
            [rule(1, dst="10.20.0.10", service="tcp/22")],
        )
        assert not report.by_issue(NatIssue.EXPOSED_SERVICE)

    def test_a_nat_without_a_port_matches_any_permit_to_the_host(self) -> None:
        """Most NAT rules translate the address and leave the port alone. Requiring a
        port match would then find no exposure anywhere — the common case."""
        report = examine_both(
            [nat(1, translated="10.20.0.10")],
            [rule(1, dst="10.20.0.10", service="tcp/443")],
        )
        assert report.by_issue(NatIssue.EXPOSED_SERVICE)

    def test_a_deny_rule_does_not_expose_anything(self) -> None:
        report = examine_both(
            [nat(1, translated="10.20.0.10:443")],
            [rule(1, dst="10.20.0.10", service="tcp/443", action="deny")],
        )
        assert report.by_issue(NatIssue.UNMATCHED_NAT)

    def test_a_disabled_rule_does_not_expose_anything(self) -> None:
        report = examine_both(
            [nat(1, translated="10.20.0.10:443")],
            [rule(1, dst="10.20.0.10", service="tcp/443", enabled=False)],
        )
        assert report.by_issue(NatIssue.UNMATCHED_NAT)

    def test_source_nat_is_never_an_exposure(self) -> None:
        """Source NAT hides internal addresses on the way out. It publishes nothing, so
        it cannot create inbound exposure however broad the rules around it are."""
        report = examine_both(
            [nat(1, translated="203.0.113.2", direction="source")],
            [rule(1)],
        )
        assert report.findings == []

    def test_a_named_object_resolves(self) -> None:
        """PAN-OS and Check Point translate to an object name, not a literal."""
        report = examine_both(
            [nat(1, translated="web-01")],
            [rule(1, dst="10.20.0.10", service="tcp/443")],
            objects=[{"name": "web-01", "type": "host", "value": "10.20.0.10"}],
        )
        assert report.by_issue(NatIssue.EXPOSED_SERVICE)


class TestUnprotectedExposure:
    def test_a_published_service_without_logging_is_reported(self) -> None:
        report = examine_both(
            [nat(1, translated="10.20.0.10:443")],
            [rule(1, dst="10.20.0.10", service="tcp/443", log_end=False)],
        )

        unlogged = report.by_issue(NatIssue.EXPOSED_WITHOUT_LOGGING)
        assert len(unlogged) == 1
        assert unlogged[0].severity == "high"

    def test_unknown_logging_is_not_reported_as_absent(self) -> None:
        """Absent is not False. A parser that could not determine logging has not shown
        the rule to be unlogged, and reporting it sends someone to change a firewall for
        no reason."""
        report = examine_both(
            [nat(1, translated="10.20.0.10:443")],
            [rule(1, dst="10.20.0.10", service="tcp/443")],
        )
        assert not report.by_issue(NatIssue.EXPOSED_WITHOUT_LOGGING)

    def test_a_published_service_without_inspection_is_reported(self) -> None:
        report = examine_both(
            [nat(1, translated="10.20.0.10:443")],
            [rule(1, dst="10.20.0.10", service="tcp/443")],
        )
        assert report.by_issue(NatIssue.EXPOSED_WITHOUT_INSPECTION)

    def test_an_inspected_rule_is_not_reported(self) -> None:
        report = examine_both(
            [nat(1, translated="10.20.0.10:443")],
            [
                rule(
                    1,
                    dst="10.20.0.10",
                    service="tcp/443",
                    profiles={"ips": "strict"},
                    log_end=True,
                )
            ],
        )
        assert not report.by_issue(NatIssue.EXPOSED_WITHOUT_INSPECTION)
        assert not report.by_issue(NatIssue.EXPOSED_WITHOUT_LOGGING)


class TestInternalConsistency:
    def test_a_nat_with_no_matching_permit_is_reported(self) -> None:
        """Usually a leftover — and a leftover NAT rule is what remains when half a
        decommissioning is completed. It is the easy half to undo by accident."""
        report = examine_both([nat(1, name="Old service", translated="10.20.0.50:8080")], [])

        unmatched = report.by_issue(NatIssue.UNMATCHED_NAT)
        assert len(unmatched) == 1
        assert unmatched[0].nat_name == "Old service"
        assert unmatched[0].severity == "low"

    def test_an_unresolvable_translation_is_reported_not_assumed_harmless(self) -> None:
        """A dynamic pool or an object the collection missed. "Could not determine" and
        "publishes nothing" are very different claims, and only one of them is true."""
        report = examine_both([nat(1, translated="dynamic-pool-A")], [rule(1)])

        unresolved = report.by_issue(NatIssue.NAT_WITHOUT_TRANSLATION)
        assert len(unresolved) == 1
        assert "could not be resolved" in unresolved[0].message

    def test_an_empty_translation_is_reported(self) -> None:
        report = examine_both([nat(1, translated="")], [rule(1)])
        assert report.by_issue(NatIssue.NAT_WITHOUT_TRANSLATION)

    def test_an_unresolvable_rule_is_not_also_reported_as_unmatched(self) -> None:
        """One finding per problem. A rule whose target could not be resolved has not
        been shown to be unmatched — that would be two conclusions from one gap."""
        report = examine_both([nat(1, translated="dynamic-pool-A")], [])
        assert not report.by_issue(NatIssue.UNMATCHED_NAT)


class TestExposureIsNotGuessed:
    """The honesty requirement, and the easiest thing here to get quietly wrong."""

    def test_without_external_zones_no_exposure_is_claimed(self) -> None:
        report = examine_both(
            [nat(1, translated="10.20.0.11:3389")],
            [rule(1, dst="10.20.0.11", service="tcp/3389")],
            external=None,
        )

        assert report.exposure_analysed is False
        assert not report.by_issue(NatIssue.EXPOSED_INSECURE_SERVICE)
        assert not report.by_issue(NatIssue.EXPOSED_SERVICE)

    def test_the_report_says_so_rather_than_reporting_zero(self) -> None:
        """Zero findings and "not analysed" look identical in a count. Only one of them
        is honest, and a report that could not do the analysis has to say which."""
        report = examine_both([], [], external=None)
        assert report.exposure_analysed is False

        analysed = examine_both([], [], external=["untrust"])
        assert analysed.exposure_analysed is True

    def test_internal_consistency_is_still_checked_without_zones(self) -> None:
        """The unmatched-NAT finding does not depend on knowing which zones face the
        internet, so it must not be lost along with the exposure analysis."""
        report = examine_both([nat(1, translated="10.20.0.50")], [], external=None)
        assert report.by_issue(NatIssue.UNMATCHED_NAT)

    def test_an_empty_zone_list_counts_as_unset(self) -> None:
        report = examine_both([], [], external=[])
        assert report.exposure_analysed is False

    def test_whitespace_only_zone_names_count_as_unset(self) -> None:
        report = examine_both([], [], external=["  "])
        assert report.exposure_analysed is False


class TestExternalZoneHeuristic:
    @pytest.mark.parametrize(
        "zone", ["untrust", "outside", "internet", "wan1", "external-dmz", "PUBLIC"]
    )
    def test_recognised_names(self, zone: str) -> None:
        assert external_zones_from({"zones": [zone]}) == [zone]

    @pytest.mark.parametrize("zone", ["trust", "dmz", "london-office", "vlan20"])
    def test_unrecognised_names(self, zone: str) -> None:
        assert external_zones_from({"zones": [zone]}) == []

    def test_an_estate_that_names_zones_after_sites_gets_nothing(self) -> None:
        """Which is exactly why this is a caller's convenience and not the default
        inside `examine`: it silently returns nothing, and a default that silently
        skipped the analysis would report every such firewall as having no exposure."""
        assert external_zones_from({"zones": ["london", "frankfurt", "singapore"]}) == []


class TestDegenerateInput:
    def test_no_nat_rules_at_all(self) -> None:
        report = examine_both([], [rule(1)])
        assert report.findings == []
        assert report.nat_rules_examined == 0

    def test_a_nat_block_the_parser_never_filled(self) -> None:
        rules, resolver = resolve_rulebase({"security_rules": []})
        report = examine({}, rules, resolver, external_zones=["untrust"])
        assert report.findings == []

    def test_counts_are_reported_by_issue(self) -> None:
        report = examine_both(
            [
                nat(1, translated="10.20.0.10:443"),
                nat(2, translated="10.20.0.50:8080"),
            ],
            [rule(1, dst="10.20.0.10", service="tcp/443")],
        )
        counts = report.counts

        assert counts[NatIssue.UNMATCHED_NAT.value] == 1
        assert counts[NatIssue.EXPOSED_SERVICE.value] == 1
