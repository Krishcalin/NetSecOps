"""Check engine unit tests (FR-CHK-01 … FR-CHK-03, FR-COL-08).

The assertions here are mostly about *what the engine refuses to conclude*. A check
engine that produces verdicts is easy; one that reliably declines to produce a verdict
when it has no business having an opinion is the hard part, and it is the part that
decides whether anyone can trust the report.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from netsecops.checks.engine import (
    CheckResult,
    DeviceContext,
    EvaluationContext,
    applies_to,
    evaluate,
    evaluate_all,
    evaluate_assertion,
    python_check,
    registered_python_checks,
)
from netsecops.checks.loader import (
    LIBRARY_ROOT,
    CheckLoadError,
    CheckRegistry,
    load_file,
    load_library,
)
from netsecops.checks.policy_packs import load_packs
from netsecops.checks.schema import (
    Assertion,
    CheckDefinition,
    MissingPolicy,
    Outcome,
    Severity,
)
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURES = Path(__file__).parent / "fixtures"


def ncm_for(relative: str, platform: str) -> dict[str, Any]:
    text = (FIXTURES / relative).read_text(encoding="utf-8")
    return get_parser(platform).parse(ParseContext(text=text)).to_storage()


@pytest.fixture(scope="module")
def hardened() -> dict[str, Any]:
    return ncm_for("cisco/ios/17.9/hardened_switch.cfg", "cisco_ios")


@pytest.fixture(scope="module")
def weak() -> dict[str, Any]:
    return ncm_for("cisco/ios/15.2/weak_switch.cfg", "cisco_ios")


@pytest.fixture(scope="module")
def registry() -> CheckRegistry:
    return CheckRegistry(load_library())


def make_check(**overrides: Any) -> CheckDefinition:
    base: dict[str, Any] = {
        "id": "test-check",
        "title": "Test check",
        "description": "A check used by the engine tests.",
        "rationale": "Exists so the engine has something to evaluate.",
        "severity": "medium",
        "remediation": "Nothing to do; this check is a test fixture.",
        "logic": {"type": "ncm", "expression": "device.hostname", "assert": {"not_equals": None}},
    }
    base.update(overrides)
    return CheckDefinition.model_validate(base)


# ─────────────────────────────── assertions ─────────────────────────────────


class TestAssertions:
    @pytest.mark.parametrize(
        ("operator", "expected", "value", "passes"),
        [
            ("equals", False, False, True),
            ("equals", False, True, False),
            ("equals", 2, 2, True),
            ("not_equals", None, "x", True),
            ("not_equals", None, None, False),
            ("gt", 0, 5, True),
            ("gt", 0, 0, False),
            ("gte", 12, 12, True),
            ("lt", 600, 300, True),
            ("lte", 600, 900, False),
            ("empty", True, [], True),
            ("empty", True, ["a"], False),
            ("empty", False, ["a"], True),
            ("contains", "ssh", ["ssh", "telnet"], True),
            ("not_contains", "telnet", ["ssh"], True),
            ("matches", "^Loop", "Loopback0", True),
            ("not_matches", "^Loop", "Vlan10", True),
            ("all_equal", False, [False, False], True),
            ("all_equal", False, [False, True], False),
            ("count_gte", 1, ["a"], True),
            ("count_gte", 2, ["a"], False),
            ("count_lte", 2, ["a", "b", "c"], False),
        ],
    )
    def test_operator(self, operator: str, expected: Any, value: Any, passes: bool) -> None:
        assertion = Assertion.model_validate({operator: expected})
        assert evaluate_assertion(assertion, value)[0] is passes

    def test_in_uses_its_yaml_spelling(self) -> None:
        """`in` is a Python keyword, so the field is `in_` with an alias. A check author
        writes `in:` and must never see the underscore."""
        assertion = Assertion.model_validate({"in": ["rapid-pvst", "mst"]})
        assert evaluate_assertion(assertion, "mst")[0] is True
        assert evaluate_assertion(assertion, "pvst")[0] is False

    def test_exactly_one_operator_is_required(self) -> None:
        """Two operators in one assertion would make the failure message ambiguous,
        and the failure message is what an operator reads."""
        with pytest.raises(ValueError, match="exactly one operator"):
            Assertion.model_validate({"equals": 1, "gt": 0})
        with pytest.raises(ValueError, match="exactly one operator"):
            Assertion.model_validate({})

    def test_false_and_zero_count_as_supplied(self) -> None:
        """`equals: false` is the single most common assertion in the library. If
        "was it supplied" were asked by truthiness, none of those checks would load."""
        assert Assertion.model_validate({"equals": False}).operator == "equals"
        assert Assertion.model_validate({"equals": 0}).operator == "equals"

    def test_booleans_are_not_numbers(self) -> None:
        """`True > 0` is true in Python and meaningless in a check."""
        assertion = Assertion.model_validate({"gt": 0})
        assert evaluate_assertion(assertion, True)[0] is False

    def test_invalid_regex_is_rejected_at_load(self) -> None:
        with pytest.raises(ValueError, match="Invalid regular expression"):
            Assertion.model_validate({"matches": "([unclosed"})

    def test_describe_reads_as_a_sentence(self) -> None:
        """This text goes straight into the failure message."""
        assert "be False" in Assertion.model_validate({"equals": False}).describe()
        assert "be empty" in Assertion.model_validate({"empty": True}).describe()
        assert "not be empty" in Assertion.model_validate({"empty": False}).describe()


# ───────────────────── absent is not false (the whole point) ────────────────


class TestMissingData:
    def test_missing_field_is_not_evaluated_not_failed(self, weak: dict[str, Any]) -> None:
        """FR-COL-08. The weak fixture never states an SSH version. Reporting "SSH v2
        is not configured — FAIL" would be defensible; reporting "SSH v2 is configured
        — PASS" would be a catastrophe. Reporting neither is correct."""
        check = make_check(
            logic={
                "type": "ncm",
                "expression": "management.services.ssh.version",
                "assert": {"equals": 2},
            }
        )
        result = evaluate(check, weak)

        assert result.outcome is Outcome.NOT_EVALUATED
        assert result.reason == "missing:management.services.ssh.version"
        assert "not the same as it being off" in result.message

    def test_an_empty_list_is_an_answer_not_a_gap(self) -> None:
        """`users[?weak_hash]` returning [] means "none", and must pass."""
        check = make_check(
            logic={
                "type": "ncm",
                "expression": "users[?weak_hash]",
                "assert": {"empty": True},
            }
        )
        assert evaluate(check, {"users": []}).outcome is Outcome.PASS

    def test_missing_policy_fail_reports_absence_as_the_finding(self) -> None:
        """Some checks want absence to fail — "is a syslog server configured" is
        exactly the case where nothing configured *is* the finding."""
        check = make_check(
            logic={
                "type": "ncm",
                "expression": "logging.source_interface",
                "assert": {"not_equals": None},
                "missing": "fail",
            }
        )
        assert evaluate(check, {}).outcome is Outcome.FAIL

    def test_requires_reports_which_input_was_missing(self) -> None:
        check = make_check(
            logic={
                "type": "ncm",
                "expression": "device.hostname",
                "assert": {"not_equals": None},
                "requires": ["management.services.ssh.enabled"],
            }
        )
        result = evaluate(check, {"device": {"hostname": "sw1"}})

        assert result.outcome is Outcome.NOT_EVALUATED
        assert "management.services.ssh.enabled" in result.message

    def test_missing_policy_values_are_all_reachable(self) -> None:
        for policy, expected in [
            (MissingPolicy.NOT_EVALUATED, Outcome.NOT_EVALUATED),
            (MissingPolicy.FAIL, Outcome.FAIL),
            (MissingPolicy.PASS, Outcome.PASS),
        ]:
            check = make_check(
                logic={
                    "type": "ncm",
                    "expression": "nothing.here",
                    "assert": {"equals": True},
                    "missing": policy.value,
                }
            )
            assert evaluate(check, {}).outcome is expected


# ────────────────────────────── applicability ───────────────────────────────


class TestApplicability:
    def test_wrong_vendor_is_not_applicable_with_a_reason(self, hardened: dict[str, Any]) -> None:
        check = make_check(applicability={"vendors": ["fortinet"]})
        result = evaluate(check, hardened)

        assert result.outcome is Outcome.NOT_APPLICABLE
        # The reason is what stops the report showing a blank an auditor has to chase.
        assert "fortinet" in result.message

    def test_device_class_narrows(self, hardened: dict[str, Any]) -> None:
        check = make_check(applicability={"device_classes": ["firewall"]})
        result = evaluate(
            check, hardened, device=DeviceContext.from_ncm(hardened, device_class="switch")
        )
        assert result.outcome is Outcome.NOT_APPLICABLE

    def test_matching_device_class_applies(self, hardened: dict[str, Any]) -> None:
        check = make_check(applicability={"device_classes": ["switch"]})
        result = evaluate(
            check, hardened, device=DeviceContext.from_ncm(hardened, device_class="switch")
        )
        assert result.outcome is Outcome.PASS

    @pytest.mark.parametrize(
        ("version", "min_version", "applies"),
        [
            ("17.9", "15.0", True),
            ("15.2(7)E3", "15.0", True),
            ("12.4", "15.0", False),
            ("10.3(4a)", "10.0", True),
        ],
    )
    def test_version_ranges_handle_vendor_spellings(
        self, version: str, min_version: str, applies: bool
    ) -> None:
        """Network versions are not PEP 440: 17.9(4a), 15.2(7)E3, 9.18(2)."""
        check = make_check(applicability={"min_version": min_version})
        device = DeviceContext(vendor="cisco", version=version)
        assert (applies_to(check, device, {}) is None) is applies

    def test_unknown_version_does_not_exclude(self) -> None:
        """An unparseable version means the check runs and reports honestly. Skipping
        it would read as a pass in every summary."""
        check = make_check(applicability={"min_version": "15.0"})
        assert applies_to(check, DeviceContext(version=None), {}) is None

    def test_required_feature_absent_is_not_applicable(self) -> None:
        check = make_check(applicability={"requires_features": ["wireless.wlans"]})
        result = evaluate(check, {"wireless": {"wlans": []}})
        assert result.outcome is Outcome.NOT_APPLICABLE


# ────────────────────────────── error handling ──────────────────────────────


class TestBrokenChecks:
    def test_a_bad_expression_is_an_error_not_a_fail(self) -> None:
        """A broken check must be distinguishable from a device that is misconfigured.
        Reporting Fail would send someone to change a device over a typo in YAML."""
        check = make_check(
            logic={"type": "ncm", "expression": "users[?", "assert": {"empty": True}}
        )
        result = evaluate(check, {"users": []})

        assert result.outcome is Outcome.ERROR
        assert result.reason in {"bad-expression", "error"}

    def test_an_exploding_python_check_is_contained(self) -> None:
        @python_check("engine_test_explode")
        def explode(context: EvaluationContext) -> CheckResult:
            raise RuntimeError("simulated failure")

        check = make_check(logic={"type": "python", "function": "engine_test_explode"})
        result = evaluate(check, {})

        assert result.outcome is Outcome.ERROR
        assert "simulated failure" in result.message

    def test_an_unregistered_python_check_is_an_error(self) -> None:
        check = make_check(logic={"type": "python", "function": "no_such_function"})
        result = evaluate(check, {})

        assert result.outcome is Outcome.ERROR
        assert "no_such_function" in result.message

    def test_one_broken_check_does_not_stop_the_others(self, hardened: dict[str, Any]) -> None:
        checks = [
            make_check(
                id="broken", logic={"type": "ncm", "expression": "[[", "assert": {"empty": True}}
            ),
            make_check(id="fine"),
        ]
        results = evaluate_all(checks, hardened)

        assert [r.outcome for r in results] == [Outcome.ERROR, Outcome.PASS]

    def test_registering_the_same_name_twice_is_refused(self) -> None:
        """Two checks silently sharing a name would make which logic ran unpredictable."""
        with pytest.raises(ValueError, match="already registered"):
            python_check("ssh_weak_kex")(lambda ctx: Outcome.PASS)  # type: ignore[arg-type,return-value]


# ──────────────────────────────── evidence ──────────────────────────────────


class TestEvidence:
    def test_a_failure_cites_the_configuration_line(self, weak: dict[str, Any]) -> None:
        """The acceptance criterion asks for evidence *and line provenance*. A finding
        that asserts a conclusion without showing the line is one an operator cannot
        verify, and will not act on."""
        check = make_check(
            logic={
                "type": "ncm",
                "expression": "management.services.telnet.enabled",
                "assert": {"equals": False},
            }
        )
        result = evaluate(check, weak)

        assert result.outcome is Outcome.FAIL
        assert result.evidence, "a failing check produced no evidence"
        assert result.evidence[0].line_start is not None
        assert result.evidence[0].excerpt

    def test_evidence_is_capped(self) -> None:
        """Fifty excerpts is a haystack, not evidence."""
        provenance = {
            "entries": {
                f"interfaces.{n}": {"line_start": n, "line_end": n, "excerpt": f"interface {n}"}
                for n in range(40)
            }
        }
        context = EvaluationContext(
            check=make_check(), ncm={}, device=DeviceContext(), provenance=provenance
        )
        assert len(context.evidence_for("interfaces")) <= 10

    def test_evidence_falls_back_to_the_nearest_ancestor(self) -> None:
        """A leaf often has no provenance of its own; the stanza it sits in does.
        Evidence at the wrong granularity still shows the right part of the config."""
        provenance = {
            "entries": {
                "management.services.ssh": {
                    "line_start": 12,
                    "line_end": 12,
                    "excerpt": "ip ssh version 2",
                }
            }
        }
        context = EvaluationContext(
            check=make_check(), ncm={}, device=DeviceContext(), provenance=provenance
        )
        found = context.evidence_for("management.services.ssh.version")

        assert len(found) == 1
        assert found[0].line_start == 12

    def test_regex_evidence_comes_from_the_redacted_text(self) -> None:
        check = make_check(
            logic={"type": "regex", "pattern": r"^enable password ", "expect": "absent"}
        )
        result = evaluate(check, {}, config_text="hostname sw1\nenable password [REDACTED:x]\n")

        assert result.outcome is Outcome.FAIL
        assert result.evidence[0].line_start == 2
        assert "REDACTED" in (result.evidence[0].excerpt or "")


# ──────────────────────────────── the library ───────────────────────────────


class TestShippedLibrary:
    def test_every_check_loads(self, registry: CheckRegistry) -> None:
        assert len(registry) >= 60

    def test_at_least_sixty_checks_apply_to_cisco_ios(self, registry: CheckRegistry) -> None:
        """Phase 3's stated scope: ">=60 Cisco checks + common checks"."""
        applicable = registry.for_platform("cisco_ios", vendor="cisco")
        assert len(applicable) >= 60, f"only {len(applicable)} checks apply to Cisco IOS"

    def test_ids_match_their_filenames(self) -> None:
        """A check must be findable by its id, and the id is what every finding it
        produces is keyed on."""
        for path in sorted(LIBRARY_ROOT.rglob("*.yaml")):
            assert load_file(path).id == path.stem

    def test_every_check_explains_why_it_matters(self, registry: CheckRegistry) -> None:
        """The first question anyone asks of a failed check is "so what?". A rationale
        of two sentences is not an answer."""
        for definition in registry.definitions():
            assert len(definition.rationale) > 80, f"{definition.id}: rationale is too thin"
            assert len(definition.remediation) > 40, f"{definition.id}: remediation is too thin"

    def test_no_check_offers_to_change_a_device(self, registry: CheckRegistry) -> None:
        """SRS §8. Remediation is guidance an operator applies, never an action this
        system takes — so no check may carry anything that looks like a command to run."""
        for definition in registry.definitions():
            assert not hasattr(definition, "fix")
            assert not hasattr(definition, "command")

    def test_every_python_check_is_registered(self, registry: CheckRegistry) -> None:
        """A YAML file naming a function that does not exist produces Error on every
        run — a check that is permanently broken and silently so."""
        registered = set(registered_python_checks())
        for definition in registry.definitions():
            if definition.logic.function:
                assert definition.logic.function in registered, (
                    f"{definition.id} names an unregistered function"
                )

    def test_every_check_carries_a_framework_mapping(self, registry: CheckRegistry) -> None:
        """FR-CHK-05 pivots compliance views by framework. A check mapped to nothing
        can never appear in one."""
        unmapped = [d.id for d in registry.definitions() if not d.references.frameworks()]
        assert not unmapped, f"checks with no framework mapping: {unmapped}"

    def test_severities_are_not_all_the_same(self, registry: CheckRegistry) -> None:
        """A library where everything is High is a library where nothing is."""
        severities = {d.severity for d in registry.definitions()}
        assert len(severities) >= 4

    def test_duplicate_ids_are_refused(self, tmp_path: Path) -> None:
        body = (LIBRARY_ROOT / "common" / "telnet-disabled.yaml").read_text(encoding="utf-8")
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        (tmp_path / "a" / "telnet-disabled.yaml").write_text(body, encoding="utf-8")
        (tmp_path / "b" / "telnet-disabled.yaml").write_text(body, encoding="utf-8")

        with pytest.raises(CheckLoadError, match="duplicate check id"):
            load_library(tmp_path)

    def test_a_malformed_file_names_itself(self, tmp_path: Path) -> None:
        """A load failure must say which file, because that is what gets fixed."""
        bad = tmp_path / "broken-check.yaml"
        bad.write_text("id: broken-check\ntitle: Missing everything else\n", encoding="utf-8")

        with pytest.raises(CheckLoadError, match=r"broken-check\.yaml"):
            load_library(tmp_path)


class TestPolicyPacks:
    def test_the_cis_pack_loads_and_names_real_checks(self, registry: CheckRegistry) -> None:
        packs = load_packs(known_check_ids=set(registry.ids))
        assert packs, "no policy packs shipped"

        cis = next(p for p in packs if p.pack.source == "cis-cisco-ios-l1")
        assert not cis.unknown_checks, f"pack names checks that do not exist: {cis.unknown_checks}"
        assert len(cis.pack.checks) >= 40
        assert cis.pack.frameworks == ["cis"]

    def test_the_pack_contains_no_duplicates(self, registry: CheckRegistry) -> None:
        cis = next(
            p
            for p in load_packs(known_check_ids=set(registry.ids))
            if p.pack.source == "cis-cisco-ios-l1"
        )
        ids = cis.pack.check_ids
        assert len(ids) == len(set(ids))


# ─────────────────────── the library against real configs ───────────────────


class TestLibraryAgainstFixtures:
    def test_it_separates_a_hardened_device_from_a_weak_one(
        self, registry: CheckRegistry, hardened: dict[str, Any], weak: dict[str, Any]
    ) -> None:
        """The real test of a check library. One that reports the same thing about both
        configurations is not measuring anything."""
        device = DeviceContext(vendor="cisco", platform="cisco_ios", device_class="switch")

        good = evaluate_all(registry.definitions(), hardened, device=device)
        bad = evaluate_all(registry.definitions(), weak, device=device)

        good_fails = sum(1 for r in good if r.outcome is Outcome.FAIL)
        bad_fails = sum(1 for r in bad if r.outcome is Outcome.FAIL)

        assert bad_fails > good_fails * 3, (
            f"the weak fixture produced {bad_fails} failures and the hardened one "
            f"{good_fails} — the library is not discriminating"
        )

    def test_no_check_errors_against_any_fixture(self, registry: CheckRegistry) -> None:
        """An Error means the check itself is broken, which no real configuration
        should be able to cause."""
        for relative, platform in [
            ("cisco/ios/17.9/hardened_switch.cfg", "cisco_ios"),
            ("cisco/ios/15.2/weak_switch.cfg", "cisco_ios"),
            ("cisco/nxos/10.3/dc_switch.cfg", "cisco_nxos"),
            ("cisco/nxos/9.3/edge_n3k.cfg", "cisco_nxos"),
            ("cisco/asa/9.18/edge_firewall.cfg", "cisco_asa"),
        ]:
            ncm = ncm_for(relative, platform)
            results = evaluate_all(registry.definitions(), ncm)
            errors = [(r.check_id, r.message) for r in results if r.outcome is Outcome.ERROR]
            assert not errors, f"{relative}: {errors}"

    def test_no_finding_message_leaks_a_secret(self, registry: CheckRegistry) -> None:
        """Findings travel into exports, emails and tickets — further than the
        configuration ever did."""
        from netsecops.core.redaction import redact_config
        from tests.test_parsers import PLANTED_SECRETS

        for relative, platform in [
            ("cisco/ios/17.9/hardened_switch.cfg", "cisco_ios"),
            ("cisco/ios/15.2/weak_switch.cfg", "cisco_ios"),
            ("cisco/asa/9.18/edge_firewall.cfg", "cisco_asa"),
        ]:
            ncm = ncm_for(relative, platform)
            # The redacted copy is the only text the engine is ever given: a regex
            # check's matched line becomes evidence on a finding, and an earlier
            # version of the job runner passed the raw collected output here.
            text = redact_config((FIXTURES / relative).read_text(encoding="utf-8"))
            for result in evaluate_all(registry.definitions(), ncm, config_text=text):
                blob = f"{result.message} {result.observed} {[e.excerpt for e in result.evidence]}"
                leaked = [s for s in PLANTED_SECRETS if s in blob]
                assert not leaked, f"{result.check_id} leaked {leaked}"

    def test_the_engine_is_never_handed_raw_configuration(self) -> None:
        """Guards the fix rather than the symptom.

        ``assess`` takes no configuration-text argument, so there is no parameter
        through which unredacted output could reach a regex check's evidence. If one
        is reintroduced, this fails.
        """
        import inspect

        from netsecops.services.assessment import AssessmentService

        parameters = inspect.signature(AssessmentService.assess).parameters
        assert "config_text" not in parameters, (
            "assess() accepts configuration text again. Regex checks must read only "
            "snapshot.config_redacted — their matched lines become finding evidence."
        )

    def test_severity_overrides_are_applied(
        self, registry: CheckRegistry, weak: dict[str, Any]
    ) -> None:
        results = evaluate_all(
            [registry.require("telnet-disabled")],
            weak,
            severity_overrides={"telnet-disabled": Severity.LOW},
        )
        assert results[0].severity is Severity.LOW
