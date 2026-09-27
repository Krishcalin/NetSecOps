"""Golden-config templates as a check type (FR-DRIFT-04).

A template says what a device of this kind is supposed to look like: blocks of lines
that must be present and blocks that must not. The requirement is short; the way it
goes wrong is not.

**A template that passes everything is the failure mode.** An empty block list, a
pattern that matches any line, a comparison defeated by indentation — each produces a
confident *Pass* on a device that does not match the build at all, and nobody
investigates a pass. Most of what is below is aimed at that.

**"Does not match golden" is not a finding anybody can act on.** The result has to
name the blocks that differ and the lines that are missing, which is why blocks are
named and why every one of them is evaluated rather than stopping at the first.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from netsecops.checks.engine import DeviceContext, evaluate
from netsecops.checks.schema import CheckDefinition, Outcome

#: A small IOS-ish configuration with deliberate indentation and comment noise, since
#: both are what a real `show running-config` carries and what a naive comparison
#: trips over.
CONFIG = """\
!
version 17.9
hostname edge-sw-01
!
aaa new-model
aaa authentication login default group TACACS-GRP local
!
interface Vlan10
 description USERS
 ip address 10.10.0.2 255.255.255.0
!
line vty 0 4
 exec-timeout 5 0
 transport input ssh
 transport output none
!
banner motd ^C
Authorised access only.
^C
!
end
"""


def check(blocks: list[dict], **overrides) -> CheckDefinition:
    body = {
        "id": "cisco-ios-standard-build",
        "title": "Standard access-switch build",
        "severity": "medium",
        "description": "The agreed build for an access switch.",
        "rationale": "A device that drifts from the standard build is one nobody owns.",
        "remediation": "Bring the configuration back in line with the template.",
        "logic": {"type": "golden", "blocks": blocks},
        **overrides,
    }
    return CheckDefinition.model_validate(body)


def run(definition: CheckDefinition, config: str = CONFIG):
    return evaluate(
        definition,
        {"ncm_version": "1.1"},
        device=DeviceContext(vendor="cisco", platform="cisco_ios", device_class="switch"),
        config_text=config,
    )


class TestItRefusesATemplateThatCannotFail:
    def test_a_template_with_no_blocks_is_rejected(self) -> None:
        """It would pass every device it was ever applied to."""
        with pytest.raises(ValidationError, match="at least one block"):
            check([])

    def test_a_block_with_no_lines_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            check([{"name": "Empty", "lines": []}])

    def test_an_invalid_pattern_is_rejected_at_authoring_time(self) -> None:
        """Not at evaluation time, which is after somebody has saved it and gone
        away, and where it would surface as Error on every device at once."""
        with pytest.raises(ValidationError, match="invalid regular expression"):
            check([{"name": "Bad", "lines": ["ip address ("], "match": "regex"}])


class TestRequiredLines:
    def test_a_satisfied_template_passes(self) -> None:
        result = run(
            check(
                [
                    {"name": "AAA", "lines": ["aaa new-model"]},
                    {"name": "SSH only", "lines": ["transport input ssh"]},
                ]
            )
        )

        assert result.outcome is Outcome.PASS
        assert result.observed == {"blocks": 2, "satisfied": 2}

    def test_indentation_does_not_defeat_the_comparison(self) -> None:
        """`transport input ssh` is indented under `line vty` in every real config.

        A literal comparison against the raw line would miss it and report the block
        missing on a device that has it — the false failure that makes people stop
        trusting the feature and switch it off.
        """
        result = run(check([{"name": "SSH only", "lines": ["transport input ssh"]}]))

        assert result.outcome is Outcome.PASS

    def test_a_missing_line_fails_and_is_named(self) -> None:
        result = run(check([{"name": "NTP", "lines": ["ntp server 10.0.0.1"]}]))

        assert result.outcome is Outcome.FAIL
        assert "NTP" in result.message
        assert "ntp server 10.0.0.1" in result.message

    def test_every_block_is_evaluated_not_just_the_first_failure(self) -> None:
        """A template exists to say how far a device is from the build. Stopping at
        the first miss turns that into "at least one thing is wrong", and sends
        somebody back for another pass after each fix."""
        result = run(
            check(
                [
                    {"name": "NTP", "lines": ["ntp server 10.0.0.1"]},
                    {"name": "Syslog", "lines": ["logging host 10.0.0.2"]},
                    {"name": "AAA", "lines": ["aaa new-model"]},
                ]
            )
        )

        assert result.outcome is Outcome.FAIL
        assert result.observed["failed"] == ["NTP", "Syslog"]
        assert result.observed["satisfied"] == 1
        assert "3 block(s)" in result.message


class TestForbiddenLines:
    def test_a_forbidden_line_that_is_absent_passes(self) -> None:
        result = run(
            check([{"name": "No telnet", "expect": "absent", "lines": ["transport input telnet"]}])
        )

        assert result.outcome is Outcome.PASS

    def test_a_forbidden_line_that_is_present_fails_with_its_location(self) -> None:
        result = run(
            check(
                [
                    {
                        "name": "No plaintext passwords",
                        "expect": "absent",
                        "lines": ["hostname edge-sw-01"],
                    }
                ]
            ),
        )

        assert result.outcome is Outcome.FAIL
        assert "No plaintext passwords" in result.message
        # The line number, so somebody can go and look at it.
        assert [line.line_start for line in result.evidence] == [3]


class TestRegexBlocks:
    def test_a_pattern_matches_a_line_carrying_an_address(self) -> None:
        """Literal matching cannot express "an address, any address", which is most
        of what a real template needs to say."""
        result = run(
            check(
                [
                    {
                        "name": "A management address",
                        "lines": [r"ip address 10\.\d+\.\d+\.\d+ 255\."],
                        "match": "regex",
                    }
                ]
            )
        )

        assert result.outcome is Outcome.PASS

    def test_a_pattern_that_matches_nothing_fails(self) -> None:
        result = run(
            check([{"name": "IPv6", "lines": [r"ipv6 address \S+"], "match": "regex"}]),
        )

        assert result.outcome is Outcome.FAIL


class TestContiguousBlocks:
    """Adjacency is the requirement for a banner or an ordered access list, and
    checking those lines individually would pass a device whose order means something
    entirely different."""

    def test_lines_in_order_satisfy_a_contiguous_block(self) -> None:
        result = run(
            check(
                [
                    {
                        "name": "VTY hardening",
                        "lines": [
                            "exec-timeout 5 0",
                            "transport input ssh",
                            "transport output none",
                        ],
                        "contiguous": True,
                    }
                ]
            )
        )

        assert result.outcome is Outcome.PASS

    def test_the_same_lines_out_of_order_do_not(self) -> None:
        result = run(
            check(
                [
                    {
                        "name": "VTY hardening",
                        "lines": [
                            "transport output none",
                            "transport input ssh",
                            "exec-timeout 5 0",
                        ],
                        "contiguous": True,
                    }
                ]
            )
        )

        assert result.outcome is Outcome.FAIL
        assert "consecutively" in result.message

    def test_lines_present_but_far_apart_do_not_satisfy_it(self) -> None:
        result = run(
            check(
                [
                    {
                        "name": "Two unrelated lines",
                        "lines": ["hostname edge-sw-01", "transport input ssh"],
                        "contiguous": True,
                    }
                ]
            )
        )

        assert result.outcome is Outcome.FAIL

    def test_a_comment_between_them_does_not_break_the_run(self) -> None:
        """`!` separators are formatting. Treating one as a gap would fail every
        device whose configuration has been through a tidy-up."""
        result = run(
            check(
                [
                    {
                        "name": "Across a separator",
                        "lines": ["hostname edge-sw-01", "aaa new-model"],
                        "contiguous": True,
                    }
                ]
            )
        )

        assert result.outcome is Outcome.PASS


class TestItNeverGuesses:
    def test_no_configuration_is_not_evaluated_rather_than_failed(self) -> None:
        """The rule this whole engine is built on. A device whose collection failed
        has not drifted from the build — nobody looked."""
        result = run(check([{"name": "AAA", "lines": ["aaa new-model"]}]), config="")

        assert result.outcome is Outcome.NOT_EVALUATED
        assert "no configuration text" in result.message

    def test_a_template_for_another_platform_is_not_applicable(self) -> None:
        """Per-platform templates use the same `applicability` every other check does,
        so a PAN-OS template evaluated against IOS says so rather than failing it."""
        result = run(
            check(
                [{"name": "AAA", "lines": ["aaa new-model"]}],
                applicability={"platforms": ["panos"]},
            )
        )

        assert result.outcome is Outcome.NOT_APPLICABLE


class TestItSurvivesRedaction:
    """The pipeline evaluates `snapshot.config_redacted`, never the raw text.

    A template is therefore always compared against configuration whose secrets have
    been replaced, and a template author writing from what the UI shows them is
    copying redacted lines.
    """

    #: What `redact_config` leaves behind: the keyword stays, the value goes.
    REDACTED_CONFIG = (
        "hostname edge-sw-01\n"
        " snmp-server community «redacted:snmp_community:efa1f375» RO\n"
        " username admin password 7 «redacted:username_secret:da44e247»\n"
    )

    def test_a_block_matching_on_the_keyword_still_works(self) -> None:
        """Which is what makes the feature usable at all: redaction keeps the
        structure, so a template can require or forbid a setting without ever naming
        the secret."""
        result = run(
            check(
                [
                    {
                        "name": "No type-7 passwords",
                        "expect": "absent",
                        "lines": [r"password 7 "],
                        "match": "regex",
                    }
                ]
            ),
            config=self.REDACTED_CONFIG,
        )

        assert result.outcome is Outcome.FAIL

    def test_a_line_pasted_from_a_redacted_config_is_refused(self) -> None:
        """It would match nothing on any device, for ever, without saying so — a
        `present` block failing devices that comply and an `absent` block passing
        devices that do not."""
        with pytest.raises(ValidationError, match="copied from a redacted configuration"):
            check(
                [
                    {
                        "name": "SNMP",
                        "lines": ["snmp-server community «redacted:snmp_community:efa1f375» RO"],
                    }
                ]
            )


class TestAnOperatorCanActuallyAuthorOne:
    """A golden template is by definition an organisation's own build standard, so
    the shipped library cannot contain it — the only way anybody gets one is the
    custom-check path. If that path rejects the type, the whole feature is
    unreachable and every test above it passes anyway.
    """

    @pytest.mark.anyio
    async def test_a_golden_template_is_accepted_as_a_custom_check(
        self, session, super_admin
    ) -> None:
        from netsecops.services.policies import PolicyService
        from tests.conftest import principal_for

        service = PolicyService(session)
        definition = check([{"name": "AAA", "lines": ["aaa new-model"]}]).model_dump(
            mode="json", by_alias=True
        )

        row = await service.create_custom_check(
            definition, actor=principal_for(super_admin), org_id=1
        )

        assert row.check_id == "cisco-ios-standard-build"
        assert row.definition["logic"]["type"] == "golden"

    @pytest.mark.anyio
    async def test_the_stored_definition_round_trips_back_into_an_evaluable_check(
        self, session, super_admin
    ) -> None:
        """The assessment reads it back out of JSON, and a block list that did not
        survive the round trip would evaluate as a template with nothing in it."""
        from netsecops.services.policies import PolicyService
        from tests.conftest import principal_for

        service = PolicyService(session)
        row = await service.create_custom_check(
            check([{"name": "AAA", "lines": ["aaa new-model"]}]).model_dump(
                mode="json", by_alias=True
            ),
            actor=principal_for(super_admin),
            org_id=1,
        )

        restored = CheckDefinition.model_validate(row.definition)
        result = run(restored)

        assert result.outcome is Outcome.PASS
        assert result.observed == {"blocks": 1, "satisfied": 1}


class TestTheSeededExampleIsReal:
    """The console's draft editor seeds a golden template, and that example is the
    only documentation most authors will read. An example the server rejects teaches
    the wrong shape to everybody who starts from it, and the frontend's own test can
    only prove it was *sent*."""

    def _template(self) -> dict:
        import json
        import re as _re
        from pathlib import Path

        source = Path(__file__).resolve().parents[2] / "frontend" / "src" / "app" / "ChecksPage.tsx"
        if not source.exists():  # a backend-only checkout
            pytest.skip("the frontend source is not present")

        match = _re.search(
            r"const GOLDEN_TEMPLATE = `(.*?)`;", source.read_text(encoding="utf-8"), _re.S
        )
        assert match, "GOLDEN_TEMPLATE has been renamed or removed from ChecksPage.tsx"
        return json.loads(match.group(1))

    def test_it_validates_against_the_same_schema_the_api_uses(self) -> None:
        definition = CheckDefinition.model_validate(self._template())

        assert definition.logic.type.value == "golden"

    def test_it_demonstrates_both_directions(self) -> None:
        """A template that only ever requires lines teaches half the feature, and
        `absent` is the half that catches telnet still being enabled."""
        definition = CheckDefinition.model_validate(self._template())

        assert {block.expect for block in definition.logic.blocks} == {"present", "absent"}

    def test_it_produces_a_verdict_rather_than_a_shrug(self) -> None:
        """Seeded examples drift into referring to things no parser populates. This
        one is compared against configuration text, so the guard is that it actually
        decides something on a plausible config."""
        definition = CheckDefinition.model_validate(self._template())

        assert run(definition).outcome in {Outcome.PASS, Outcome.FAIL}


class TestTheLibrarySurface:
    def test_a_golden_check_shows_its_blocks_rather_than_a_blank_expression(self) -> None:
        """The library renders `expression`, which a template does not have. Left
        None it reads as a check with no logic at all."""
        from netsecops.api.v1.checks import _detail

        detail = _detail(
            check(
                [
                    {"name": "AAA", "lines": ["aaa new-model"]},
                    {"name": "No telnet", "expect": "absent", "lines": ["transport input telnet"]},
                ]
            )
        )

        assert detail.expression is not None
        assert "AAA (present)" in detail.expression
        assert "No telnet (absent)" in detail.expression
