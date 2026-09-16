"""Risk scoring across every finding source (FR-CHK-09).

`score_device` read check results and nothing else, which meant the number answered
"how is this device configured" while the API called it a risk score. A firewall whose
rulebase analysis had produced a Critical any/any/any finding, or whose software carried
a KEV-listed CVE, scored **zero** as long as its configuration checks passed — both
subsystems write `Finding` rows, and neither was ever read back.

The tests here pin three things: that those findings now move the score, that they do
not contaminate the compliance and coverage figures (which answer a different question
and must stay check-only), and that config findings are kept out so a failed check is
not counted twice.
"""

from __future__ import annotations

from dataclasses import dataclass

from netsecops.checks.schema import Outcome, Severity
from netsecops.db.models.collection import FindingKind, FindingStatus
from netsecops.db.models.inventory import Criticality
from netsecops.services.risk import score_device


@dataclass
class Result:
    """Stands in for an engine CheckResult or a stored check_results row."""

    outcome: Outcome
    severity: Severity = Severity.MEDIUM


@dataclass
class Row:
    """Stands in for a stored Finding row."""

    severity: str
    kind: str


def passing(n: int) -> list[Result]:
    return [Result(Outcome.PASS) for _ in range(n)]


class TestFindingsReachTheScore:
    def test_a_clean_config_with_a_critical_firewall_finding_is_not_zero_risk(self) -> None:
        """The defect, stated as a test.

        Ten passing checks and one Critical rulebase finding is not a clean device.
        """
        before = score_device(passing(10), criticality=Criticality.MEDIUM)
        after = score_device(
            passing(10),
            criticality=Criticality.MEDIUM,
            findings=[Row(Severity.CRITICAL.value, FindingKind.FIREWALL.value)],
        )

        assert before.score == 0
        assert after.score > 0

    def test_a_vulnerability_finding_counts_too(self) -> None:
        scored = score_device(
            passing(5),
            findings=[Row(Severity.HIGH.value, FindingKind.VULN.value)],
        )

        assert scored.score > 0
        assert scored.findings_by_kind == {FindingKind.VULN.value: 1}

    def test_findings_count_at_full_weight_not_the_warning_discount(self) -> None:
        """A shadowed rule is a conclusion, not a hint that something may be wrong."""
        as_finding = score_device(
            [], findings=[Row(Severity.HIGH.value, FindingKind.FIREWALL.value)]
        )
        as_warning = score_device([Result(Outcome.WARNING, Severity.HIGH)])

        assert as_finding.weighted_total > as_warning.weighted_total

    def test_severity_spacing_holds_across_sources(self) -> None:
        """One Critical finding must still outrank a pile of Lows, as it does for checks."""
        one_critical = score_device(
            [], findings=[Row(Severity.CRITICAL.value, FindingKind.FIREWALL.value)]
        )
        many_low = score_device(
            [], findings=[Row(Severity.LOW.value, FindingKind.FIREWALL.value)] * 10
        )

        assert one_critical.weighted_total > many_low.weighted_total

    def test_criticality_still_multiplies_the_whole_total(self) -> None:
        findings = [Row(Severity.HIGH.value, FindingKind.VULN.value)]
        medium = score_device([], criticality=Criticality.MEDIUM, findings=findings)
        critical = score_device([], criticality=Criticality.CRITICAL, findings=findings)

        assert critical.weighted_total == medium.weighted_total * 1.5

    def test_an_unrecognised_severity_does_not_score_zero(self) -> None:
        scored = score_device([], findings=[Row("catastrophic", FindingKind.VULN.value)])

        assert scored.weighted_total == float(Severity.MEDIUM.weight)
        assert scored.by_severity == {"catastrophic": 1}


class TestComplianceFiguresStayAboutChecks:
    def test_findings_do_not_change_compliance_percent(self) -> None:
        """A CVE is not a failed control, and must not move a compliance figure."""
        checks = passing(8) + [Result(Outcome.FAIL, Severity.MEDIUM)] * 2

        without = score_device(checks)
        with_findings = score_device(
            checks, findings=[Row(Severity.CRITICAL.value, FindingKind.VULN.value)] * 3
        )

        assert without.compliance_percent == 80
        assert with_findings.compliance_percent == 80

    def test_findings_do_not_change_coverage_percent(self) -> None:
        checks = passing(5) + [Result(Outcome.NOT_EVALUATED)] * 5

        with_findings = score_device(
            checks, findings=[Row(Severity.HIGH.value, FindingKind.FIREWALL.value)]
        )

        assert with_findings.coverage_percent == 50

    def test_findings_do_not_change_the_evaluated_count(self) -> None:
        scored = score_device(
            passing(3), findings=[Row(Severity.HIGH.value, FindingKind.FIREWALL.value)] * 4
        )

        assert scored.evaluated == 3

    def test_the_breakdown_names_the_kinds_it_folded_in(self) -> None:
        """The score has to be explainable, not asserted — FR-CHK-09's actual demand."""
        scored = score_device(
            passing(1),
            findings=[
                Row(Severity.HIGH.value, FindingKind.FIREWALL.value),
                Row(Severity.HIGH.value, FindingKind.FIREWALL.value),
                Row(Severity.CRITICAL.value, FindingKind.VULN.value),
            ],
        )

        assert scored.findings_by_kind == {
            FindingKind.FIREWALL.value: 2,
            FindingKind.VULN.value: 1,
        }
        assert scored.to_components()["findings_by_kind"] == scored.findings_by_kind


class TestDoubleCountingIsPrevented:
    def test_config_findings_are_not_among_the_kinds_the_service_folds_in(self) -> None:
        """Config findings mirror the check results already being scored in the same call.

        This is a property of the caller, not of `score_device`, so it is pinned where
        the decision lives.
        """
        from netsecops.services.assessment import AssessmentService

        assert FindingKind.CONFIG.value not in AssessmentService.RISK_FINDING_KINDS
        assert FindingKind.FIREWALL.value in AssessmentService.RISK_FINDING_KINDS
        assert FindingKind.VULN.value in AssessmentService.RISK_FINDING_KINDS

    def test_transient_kinds_are_left_out(self) -> None:
        """Drift and host-key changes describe an event, not a standing weakness.

        Folding them in would make the score move every time anything is edited, which
        is a change log rather than a risk position.
        """
        from netsecops.services.assessment import AssessmentService

        assert FindingKind.DRIFT.value not in AssessmentService.RISK_FINDING_KINDS
        assert FindingKind.HOSTKEY.value not in AssessmentService.RISK_FINDING_KINDS


class TestActiveStatusHelper:
    def test_resolved_and_accepted_findings_are_not_active(self) -> None:
        active = FindingStatus.active_values()

        assert set(active) == {
            FindingStatus.NEW.value,
            FindingStatus.OPEN.value,
            FindingStatus.REOPENED.value,
        }
        assert FindingStatus.RISK_ACCEPTED.value not in active
        assert FindingStatus.FALSE_POSITIVE.value not in active
        assert FindingStatus.RESOLVED.value not in active

    def test_the_helper_agrees_with_the_property(self) -> None:
        """One definition of active, so a new status cannot leave a query stale."""
        assert FindingStatus.active_values() == [s.value for s in FindingStatus if s.is_active]
