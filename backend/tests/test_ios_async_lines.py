"""AUX and numbered TTY lines on IOS (FR-PARSE-01, FR-CHK-01).

The IOS parser read `line vty` and `line con` and nothing else. `line aux` appeared
nowhere in it, and neither did numbered TTY lines — so a bare AUX port, which is a login
prompt on the management plane that nobody is watching, reached no field in the NCM and
no check could be written against it. An unsecured AUX port is a CIS Cisco IOS benchmark
item.

Found by pointing `scripts/parse_coverage.py` at a corpus we did not write: `line aux 0`
and `line 0/0/0 0/0/12` carrying `exec-timeout 0 0` were among the most common
unrecognised constructs, and the file carrying them was the worst-covered in the corpus
at 0%.

The distinctions these pin are the ones that decide whether the check tells the truth:
`no exec` versus an `exec-timeout`, `transport input none` versus a silent line, and a
device with no AUX port versus one whose configuration did not mention it.
"""

from __future__ import annotations

from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

BARE_AUX = """\
hostname rtr-01
!
line con 0
 exec-timeout 5 0
line aux 0
line vty 0 4
 transport input ssh
!
end
"""

HARDENED_AUX = """\
hostname rtr-01
!
line aux 0
 no exec
 transport input none
 transport output none
line vty 0 4
 transport input ssh
!
end
"""

TTY_LINES = """\
hostname as-01
!
line 2
 no exec
 exec-timeout 0 0
 transport output all
line 0/0/0 0/0/12
 exec-timeout 0 0
 transport input all
 transport output all
!
end
"""

NO_AUX = """\
hostname sw-01
!
line con 0
 exec-timeout 5 0
line vty 0 4
 transport input ssh
!
end
"""


def parse(text: str):
    return get_parser("cisco_ios").parse(ParseContext(text=text, command="show running-config"))


class TestParsingAuxAndTtyLines:
    def test_a_bare_aux_line_is_recorded_with_nothing_set(self) -> None:
        """The dangerous case: the port exists and nothing closes it."""
        lines = parse(BARE_AUX).management.session.async_lines

        assert [line.name for line in lines] == ["aux 0"]
        assert lines[0].exec_disabled is None
        assert lines[0].transport_input is None

    def test_no_exec_is_distinguished_from_an_exec_timeout(self) -> None:
        """`no exec` closes the line; a timeout only bounds a session already allowed."""
        lines = parse(HARDENED_AUX).management.session.async_lines

        assert lines[0].exec_disabled is True

    def test_transport_input_none_is_an_empty_list_not_a_missing_value(self) -> None:
        """Hardened and unstated are opposite facts: IOS defaults a silent line open."""
        hardened = parse(HARDENED_AUX).management.session.async_lines[0]
        bare = parse(BARE_AUX).management.session.async_lines[0]

        assert hardened.transport_input == []
        assert bare.transport_input is None

    def test_numbered_tty_lines_and_ranges_are_read(self) -> None:
        lines = parse(TTY_LINES).management.session.async_lines

        assert [line.name for line in lines] == ["2", "0/0/0 0/0/12"]
        # Both say "never time out"; only the first also says `no exec`, which is what
        # actually closes a line — the distinction the check turns on.
        assert [line.exec_timeout_s for line in lines] == [0, 0]
        assert [line.exec_disabled for line in lines] == [True, None]

    def test_a_device_with_no_aux_line_records_none(self) -> None:
        assert parse(NO_AUX).management.session.async_lines == []

    def test_vty_and_console_parsing_is_unaffected(self) -> None:
        """The new stanza matcher must not swallow the lines the old one reads."""
        ncm = parse(BARE_AUX)

        assert ncm.management.session.console_timeout_s == 300
        assert ncm.management.services.ssh.enabled is True
        assert "aux" not in {line.name for line in ncm.management.session.async_lines} - {"aux 0"}

    def test_the_stanzas_are_consumed_not_left_unparsed(self) -> None:
        """Otherwise coverage reports a gap that has just been closed."""
        unparsed = " ".join(parse(TTY_LINES).raw_unparsed)

        assert "exec-timeout" not in unparsed
        assert "transport" not in unparsed


def outcome_for(text: str) -> str:
    """Run `cisco-aux-port-disabled` against a configuration, through the real engine."""
    from netsecops.checks.engine import DeviceContext, evaluate
    from netsecops.checks.loader import load_library

    loaded = next(c for c in load_library() if c.id == "cisco-aux-port-disabled")
    check = loaded.definition
    device = DeviceContext(vendor="cisco", platform="cisco_ios")
    result = evaluate(check, parse(text).model_dump(mode="json"), device=device)
    return result.outcome.value


class TestTheCheck:
    def test_a_bare_aux_port_fails(self) -> None:
        assert outcome_for(BARE_AUX) == "fail"

    def test_no_exec_passes(self) -> None:
        assert outcome_for(HARDENED_AUX) == "pass"

    def test_a_device_with_no_aux_line_is_not_applicable_rather_than_a_pass(self) -> None:
        """The distinction the check exists or fails on.

        `requires` would not do this: it tests for null, an empty list satisfies it, and
        the expression would then assert clean — reporting "the auxiliary port has EXEC
        disabled" about a device that never mentioned one.
        """
        assert outcome_for(NO_AUX) == "not_applicable"
