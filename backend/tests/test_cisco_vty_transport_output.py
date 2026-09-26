"""Outbound transports on vty lines (FR-CHK-01, FR-PARSE-01).

`transport input` governs how administrators reach a device, and NetSecOps already read
it. `transport output` governs where the device can reach *from* a vty session, and
nothing read it at all — the parser collapsed vty lines into `telnet.enabled` and
`ssh.enabled` and discarded the rest.

It is the pivot path. An unrestricted line turns an authenticated session into a hop to
the next device, from a management address that access lists trust far more than the
attacker's own.

**Two fields, because the two facts fail independently.** An empty
`vty_transport_output` means every line explicitly says `none`; None means at least one
line does not state it at all. Those are opposite postures and a single list cannot hold
both — the trap `_parse_async_lines` already documents for `transport input`. `vty_lines`
separates the third case, a configuration with no vty block at all, which is a partial
capture rather than a device without remote access.
"""

from __future__ import annotations

from pathlib import Path

from netsecops.checks.engine import DeviceContext, evaluate
from netsecops.checks.loader import load_library
from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

CHECK = "cisco-vty-transport-output"
FIXTURES = Path(__file__).parent / "fixtures/cisco/ios"


def parse(config: str) -> NormalisedConfig:
    return get_parser("cisco_ios").parse(ParseContext(text=config, command="show running-config"))


def outcome(config: str) -> str:
    loaded = next(c for c in load_library() if c.id == CHECK)
    device = DeviceContext(vendor="cisco", platform="cisco_ios")
    return evaluate(
        loaded.definition, parse(config).model_dump(mode="json"), device=device
    ).outcome.value


def config(*vty_blocks: str) -> str:
    return "hostname sw\n!\n" + "!\n".join(vty_blocks) + "!\nend\n"


BOTH_NONE = config(
    "line vty 0 4\n transport input ssh\n transport output none\n",
    "line vty 5 15\n transport input ssh\n transport output none\n",
)
SECOND_SILENT = config(
    "line vty 0 4\n transport input ssh\n transport output none\n",
    "line vty 5 15\n transport input ssh\n",
)
SECOND_PERMISSIVE = config(
    "line vty 0 4\n transport input ssh\n transport output none\n",
    "line vty 5 15\n transport input ssh\n transport output telnet\n",
)


def test_none_on_every_line_is_an_empty_list_not_null() -> None:
    """The distinction the whole two-field split exists for."""
    session = parse(BOTH_NONE).management.session

    assert session.vty_transport_output == []
    assert session.vty_lines == 2


def test_one_silent_line_leaves_the_posture_unknown() -> None:
    """Not an empty list.

    A device where one block says `none` and another says nothing is not a device that
    permits nothing. IOS's default for `transport output` is version-dependent and
    Cisco documents no value for it, so an unstated line cannot be resolved.
    """
    session = parse(SECOND_SILENT).management.session

    assert session.vty_transport_output is None
    assert session.vty_lines == 2


def test_the_union_is_taken_not_the_first_block() -> None:
    """A device is only as restricted as its most permissive line.

    Reading the first block alone would report this switch as fully restricted, which
    is the flattering answer rather than the true one — the same reasoning the vty
    exec-timeout already uses when it takes the weakest.
    """
    session = parse(SECOND_PERMISSIVE).management.session

    assert session.vty_transport_output == ["telnet"]


def test_ssh_only_is_permitted() -> None:
    session = parse(
        config("line vty 0 4\n transport input ssh\n transport output ssh\n")
    ).management.session

    assert session.vty_transport_output == ["ssh"]


def test_every_line_restricted_passes() -> None:
    assert outcome(BOTH_NONE) == "pass"


def test_ssh_outbound_passes() -> None:
    """Restricted, not absent — the guide permits it where the device needs it."""
    assert outcome(config("line vty 0 4\n transport output ssh\n")) == "pass"


def test_telnet_outbound_fails() -> None:
    assert outcome(SECOND_PERMISSIVE) == "fail"


def test_transport_output_all_fails() -> None:
    """`all` is not a protocol this passes by not recognising it."""
    assert outcome(config("line vty 0 4\n transport output all\n")) == "fail"


def test_a_silent_line_fails_rather_than_reporting_not_evaluated() -> None:
    """The common real-world state, and the one the check exists for.

    Almost no configuration states `transport output`. If that came back Not Evaluated
    the check would be silent on exactly the estate it describes — and the control here
    genuinely is the explicit configuration, because there is no documented default to
    fall back on.
    """
    assert outcome(SECOND_SILENT) == "fail"


def test_a_config_with_no_vty_block_raises_nothing() -> None:
    """The one absence that is a gap in what we read rather than a finding.

    Every real IOS device shows `line vty 0 4` even at defaults, so a configuration
    without one is a truncated capture. Failing it would be a confident finding about
    lines nobody saw, and it would fire on every offline fragment somebody uploads.

    Reported Not Applicable rather than Not Evaluated, which is the closer label but
    not one the engine can give here: `logic.requires` shares the `missing` policy, and
    this check needs `missing: fail` for the silent-line case above. What matters is
    that no finding is raised, and the guard sits in `applicability` where the reason
    is recorded.
    """
    assert outcome("hostname sw\n!\nend\n") == "not_applicable"


def test_the_hardened_fixture_passes() -> None:
    """Against real configuration, not only assembled strings."""
    assert outcome((FIXTURES / "17.9/hardened_switch.cfg").read_text(encoding="utf-8")) == "pass"


def test_the_weak_fixture_fails_with_telnet_outbound() -> None:
    """The pivot path, in a fixture rather than a string.

    It also keeps the field non-empty somewhere in the corpus. The hardened switch
    restricts every line, so its value is `[]` — which the parser field baseline does
    not record, leaving nothing there to protect the field if the parsing were deleted.
    """
    config_text = (FIXTURES / "15.2/weak_switch.cfg").read_text(encoding="utf-8")

    assert parse(config_text).management.session.vty_transport_output == ["telnet"]
    assert outcome(config_text) == "fail"
