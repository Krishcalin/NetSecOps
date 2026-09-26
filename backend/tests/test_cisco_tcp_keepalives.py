"""TCP keepalives on Cisco management sessions (FR-CHK-01, FR-PARSE-01).

An orphaned vty holds a line and stays authenticated, and `exec-timeout` does not
reliably clear it because the session is idle rather than dead. Cisco's hardening guide
asks for both directions; NetSecOps read neither.

The interesting case here is absence. Every other flag on `Features` is a service that
should be *off*, where a config that never mentions it is genuinely ambiguous. These two
are the opposite: IOS writes `service tcp-keepalives-in` into the running-config when it
is enabled, so silence means disabled, and the check is built to say so rather than to
report Not Evaluated on the majority of real devices.
"""

from __future__ import annotations

from pathlib import Path

from netsecops.checks.engine import DeviceContext, evaluate
from netsecops.checks.loader import load_library
from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURES = Path(__file__).parent / "fixtures/cisco/ios"
HARDENED = FIXTURES / "17.9/hardened_switch.cfg"
CHECK = "cisco-tcp-keepalives"


def parse(config: str) -> NormalisedConfig:
    return get_parser("cisco_ios").parse(ParseContext(text=config, command="show running-config"))


def outcome(config: str) -> str:
    loaded = next(c for c in load_library() if c.id == CHECK)
    device = DeviceContext(vendor="cisco", platform="cisco_ios")
    ncm = parse(config).model_dump(mode="json")
    return evaluate(loaded.definition, ncm, device=device).outcome.value


BOTH = "hostname keep\n!\nservice tcp-keepalives-in\nservice tcp-keepalives-out\n!\nend\n"
INBOUND_ONLY = "hostname keep\n!\nservice tcp-keepalives-in\n!\nend\n"
NEITHER = "hostname keep\n!\nend\n"


def test_the_parser_reads_both_directions() -> None:
    ncm = parse(BOTH)

    assert ncm.features.tcp_keepalives_in is True
    assert ncm.features.tcp_keepalives_out is True


def test_the_parser_reads_the_negated_form() -> None:
    """`no service tcp-keepalives-in` is False, not None.

    The distinction matters for the same reason it does on `smart_install`: the explicit
    negation is a fact the device stated, and flattening it into "unset" would lose it.
    """
    ncm = parse("hostname keep\n!\nno service tcp-keepalives-in\n!\nend\n")

    assert ncm.features.tcp_keepalives_in is False


def test_both_directions_configured_passes() -> None:
    assert outcome(BOTH) == "pass"


def test_one_direction_is_not_enough() -> None:
    """The check is a pair, and half of it is a finding.

    Without this case the expression could select on either flag alone and stay green.
    """
    assert outcome(INBOUND_ONLY) == "fail"


def test_silence_fails_rather_than_reporting_not_evaluated() -> None:
    """The case that decides whether this check is worth having.

    Almost no real device configures keepalives, so if an unmentioned service came back
    Not Evaluated the check would be silent on exactly the estate it exists to describe.
    IOS emits these lines when they are on, so their absence is evidence rather than a
    gap in what we read.
    """
    assert outcome(NEITHER) == "fail"


def test_the_hardened_fixture_passes() -> None:
    """Against real configuration, not only assembled strings.

    This also keeps the field in `parser_field_baseline.json`: a field no fixture
    populates is one the baseline gate cannot protect, which is how the AUX-line
    parsing was deletable without turning anything red.
    """
    assert outcome(HARDENED.read_text(encoding="utf-8")) == "pass"
