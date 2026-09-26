"""Unicast RPF is read, and deliberately not asserted on (FR-PARSE-01).

`ip verify unicast source reachable-via {rx|any}` was consumed with the rest of the
interface body and extracted into nothing. A router with strict uRPF on its WAN
interface and one that had never heard of the feature produced identical NCMs, and
neither appeared in `raw_unparsed` — so parse coverage scored full for both. That is
exactly the blind spot `test_parser_field_baseline` documents: a parser that consumes a
line and extracts nothing from it looks perfect.

**No check reads this, on purpose, and that is different from the source-guard case.**
Strict uRPF drops legitimate traffic on any interface carrying an asymmetric path, so
"every routed interface should have it" is wrong advice in most real topologies —
multihomed edges and anything with a return path through a different device. Cisco
recommends it *at the edge facing single-homed customers*, and NetSecOps cannot yet
tell an edge interface from a core one: `Interface.zone` exists but nothing populates it
for IOS.

Shipping the blanket check would produce a finding on every core link in every estate,
which is not a finding, and advice that breaks routing if followed. The fact is
recorded so evidence and reports can show it, and so the check becomes possible the day
interfaces carry a reliable edge classification.
"""

from __future__ import annotations

import pytest

from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser


def parse(body: str) -> NormalisedConfig:
    return get_parser("cisco_ios").parse(
        ParseContext(text=f"hostname edge\n!\ninterface GigabitEthernet0/0\n{body}!\nend\n")
    )


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (" ip verify unicast source reachable-via rx\n", "rx"),
        (" ip verify unicast source reachable-via rx allow-default\n", "rx"),
        (" ip verify unicast source reachable-via any\n", "any"),
        (" ip verify unicast source reachable-via any allow-default 101\n", "any"),
    ],
)
def test_the_mode_is_read(line: str, expected: str) -> None:
    """Strict and loose are different postures and both are recorded as stated."""
    assert (
        parse(" ip address 10.0.0.1 255.255.255.0\n" + line).interfaces[0].security.urpf_mode
        == expected
    )


def test_an_interface_without_urpf_records_none() -> None:
    """None, not a default. Absence here means the interface does not configure it."""
    ncm = parse(" ip address 10.0.0.1 255.255.255.0\n")

    assert ncm.interfaces[0].security.urpf_mode is None


def test_the_trailing_options_are_not_mistaken_for_the_mode() -> None:
    """`allow-default` follows the mode and is not one."""
    ncm = parse(
        " ip address 10.0.0.1 255.255.255.0\n"
        " ip verify unicast source reachable-via rx allow-default allow-self-ping\n"
    )

    assert ncm.interfaces[0].security.urpf_mode == "rx"


def test_ip_verify_source_is_not_read_as_urpf() -> None:
    """Two different features whose commands share a prefix.

    `ip verify source` is IP source guard, a layer-2 control with its own field and
    its own check. Matching it here would report uRPF on every access port that has
    source guard, which is a confident statement about a feature the device is not
    running.
    """
    ncm = parse(" switchport\n switchport mode access\n ip verify source\n")

    assert ncm.interfaces[0].security.urpf_mode is None
    assert ncm.interfaces[0].security.ip_source_guard is True
