"""Command authorization and accounting on Cisco (FR-CHK-01).

NetSecOps checked that AAA servers were configured and that `aaa new-model` was on. It
did not check that privileged commands are *authorised* against those servers, or that
they are *recorded*. Those are the controls that make central AAA mean something: without
authorization, anyone reaching privilege 15 can run anything and the TACACS+ server that
was supposed to constrain them constrains only the login; without accounting, an
investigation can establish that somebody logged in and not what they typed.

Named in Cisco's own "Guide to Harden Cisco IOS Devices" and in the NX-OS equivalent.

The fixtures make a natural pair — the hardened switch configures both, the weak one
configures neither — so pass and fail are exercised against real configuration rather
than against a string assembled to suit the check.

That pair is not sufficient on its own, though, and the third case is the important
one. Because neither fixture has an exec list *without* a command list, both checks
would go on passing and failing exactly as expected with the `purpose == 'commands'`
filter deleted. Exec-only is tested explicitly for that reason.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsecops.checks.engine import DeviceContext, evaluate
from netsecops.checks.loader import load_library
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURES = Path(__file__).parent / "fixtures/cisco/ios"
HARDENED = FIXTURES / "17.9/hardened_switch.cfg"
WEAK = FIXTURES / "15.2/weak_switch.cfg"

CHECKS = ("cisco-aaa-command-authorization", "cisco-aaa-command-accounting")


def outcome(check_id: str, config: str) -> str:
    loaded = next(c for c in load_library() if c.id == check_id)
    ncm = get_parser("cisco_ios").parse(ParseContext(text=config, command="show running-config"))
    device = DeviceContext(vendor="cisco", platform="cisco_ios")
    return evaluate(loaded.definition, ncm.model_dump(mode="json"), device=device).outcome.value


@pytest.mark.parametrize("check_id", CHECKS)
def test_the_hardened_switch_passes(check_id: str) -> None:
    """It configures `aaa authorization commands 15` and `aaa accounting commands 15`."""
    assert outcome(check_id, HARDENED.read_text(encoding="utf-8")) == "pass"


@pytest.mark.parametrize("check_id", CHECKS)
def test_the_weak_switch_fails(check_id: str) -> None:
    """It has AAA servers and neither command list — the gap these checks exist for.

    This is the case that looked clean before: `cisco-aaa-new-model` passes, the AAA
    server checks pass, and nothing said that the servers have no say over what an
    administrator may actually do.
    """
    assert outcome(check_id, WEAK.read_text(encoding="utf-8")) == "fail"


@pytest.mark.parametrize("check_id", CHECKS)
def test_exec_lists_alone_do_not_satisfy_the_check(check_id: str) -> None:
    """The case the two fixtures do not cover, and the one these checks exist for.

    Neither fixture distinguishes the checks from "is there any `aaa authorization`
    line at all": the hardened switch has both an exec list and a command list, the
    weak one has neither. Deleting `[?purpose == 'commands']` from either expression
    would leave both of those tests green while the check stopped meaning anything.

    Exec-only is also the common real-world shape rather than a contrived one. TACACS+
    decides who may log in and reach enable, and then has no say over a single thing
    they type — which reads as "we use TACACS+" in an audit and constrains nobody.
    """
    exec_only = (
        "hostname execonly\n"
        "!\n"
        "aaa new-model\n"
        "tacacs server T1\n"
        " address ipv4 10.0.0.1\n"
        "!\n"
        "aaa authentication login default group tacacs+ local\n"
        "aaa authorization exec default group tacacs+ local\n"
        "aaa accounting exec default start-stop group tacacs+\n"
        "!\n"
        "end\n"
    )

    assert outcome(check_id, exec_only) == "fail"


@pytest.mark.parametrize("check_id", CHECKS)
def test_a_device_with_no_aaa_servers_is_not_applicable(check_id: str) -> None:
    """One finding per fact.

    A device doing no central AAA at all has a larger problem, and `cisco-aaa-new-model`
    reports it. Failing these as well would be three findings about one omission, and
    the two extra are the less useful ones — they would also imply the fix is a command
    list when the fix is an AAA server.
    """
    bare = "hostname lonely\n!\nline vty 0 4\n transport input ssh\n!\nend\n"

    assert outcome(check_id, bare) == "not_applicable"
