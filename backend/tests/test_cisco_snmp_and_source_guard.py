"""SNMP views and IP source guard (FR-CHK-01, FR-PARSE-01).

Both came out of Cisco's hardening guide, and both turned out to be about data that was
already nearly there.

**SNMP.** `SnmpCommunity.view` existed in the NCM and nothing ever set it, because the
community line was read by a positional regex that assumed `RO`/`RW` came straight after
the string. IOS spells it `community <string> [view <name>] [RO|RW] [<acl>]`, so on any
device that configured a view the parser read the literal word `view` as the access-list
name and missed the access mode entirely.

Both consequences pointed the safe way, which is why nothing noticed:

* a **read-write** community parsed as read-only, so `snmp-no-write-community` passed on
  it — the highest-severity SNMP finding there is, silently absent;
* a community with a view and **no** access list recorded `acl='view'`, so
  `cisco-snmp-community-acl` passed on an unrestricted community.

Both only on devices that had configured a view — that is, on the devices that had done
some of the hardening already.

**IP source guard.** `interfaces.security.ip_source_guard` was parsed, recorded in the
parser field baseline, and read by no check. It was also only ever `True` or `None`,
never `False`, so no check could have been written against it: absence on an access port
was indistinguishable from a field nobody filled in.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsecops.checks.engine import DeviceContext, evaluate
from netsecops.checks.loader import load_library
from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser


def parse(config: str) -> NormalisedConfig:
    return get_parser("cisco_ios").parse(
        ParseContext(text="hostname sw\n!\n" + config + "!\nend\n")
    )


def outcome(check_id: str, config: str) -> str:
    """Evaluate as a switch, because the layer-2 checks are scoped to one.

    `device_class` comes from the device's inventory classification rather than from
    anything in a configuration, so a context built from parsed text alone is
    unclassified and every `device_classes: [switch]` check reports Not Applicable —
    which would make the source-guard assertions below pass while testing nothing.
    """
    loaded = next(c for c in load_library() if c.id == check_id)
    ncm = parse(config).model_dump(mode="json")
    device = DeviceContext.from_ncm(ncm, device_class="switch")
    return evaluate(loaded.definition, ncm, device=device).outcome.value


# ── the community line, clause by clause ────────────────────────────────────


@pytest.mark.parametrize(
    ("line", "view", "access_is_rw", "acl"),
    [
        ("snmp-server community S RO 99", None, False, "99"),
        ("snmp-server community S RW", None, True, None),
        ("snmp-server community S view V RO", "V", False, None),
        ("snmp-server community S view V RW", "V", True, None),
        ("snmp-server community S view V RO 99", "V", False, "99"),
        ("snmp-server community S view V rw 99", "V", True, "99"),
        ("snmp-server community S", None, False, None),
        ("snmp-server community S view V RO ipv6 V6ACL", "V", False, "V6ACL"),
    ],
)
def test_the_community_clauses_are_read_in_any_order(
    line: str, view: str | None, access_is_rw: bool, acl: str | None
) -> None:
    """The clauses are optional and ordered, which a positional regex cannot read."""
    community = parse(line + "\n").snmp.v1v2c_communities[0]

    assert community.view == view
    assert community.rw is access_is_rw
    assert community.acl == acl


def test_a_write_community_with_a_view_is_not_read_as_read_only() -> None:
    """The defect that mattered most, asserted on its own.

    `snmp-no-write-community` reads `rw`. While a view made this False, the check
    passed on a community that could rewrite the device's configuration.
    """
    assert parse("snmp-server community WRITEME view V RW\n").snmp.v1v2c_communities[0].rw is True


def test_the_word_view_is_not_an_access_list() -> None:
    """`cisco-snmp-community-acl` reads `acl`, and `acl='view'` satisfied it."""
    community = parse("snmp-server community S view V RO\n").snmp.v1v2c_communities[0]

    assert community.acl is None
    assert outcome("cisco-snmp-community-acl", "snmp-server community S view V RO\n") == "fail"


# ── the view check ──────────────────────────────────────────────────────────


def test_a_community_without_a_view_fails() -> None:
    assert outcome("cisco-snmp-community-view", "snmp-server community S RO 99\n") == "fail"


def test_a_community_with_a_view_passes() -> None:
    config = "snmp-server view VIEW-SYSTEM-ONLY system included\nsnmp-server community S view VIEW-SYSTEM-ONLY RO 99\n"

    assert outcome("cisco-snmp-community-view", config) == "pass"


def test_one_unviewed_community_among_several_fails() -> None:
    """The weakest community is the device's exposure, not the average of them."""
    config = "snmp-server community GOOD view V RO 99\nsnmp-server community LEGACY RO\n"

    assert outcome("cisco-snmp-community-view", config) == "fail"


def test_a_device_with_no_communities_is_not_applicable() -> None:
    """A v3-only device has nothing here to restrict.

    `snmp-v1v2c-disabled` is the check with an opinion about communities existing.
    """
    assert (
        outcome("cisco-snmp-community-view", "snmp-server user u g v3 auth sha X priv aes 128 Y\n")
        == "not_applicable"
    )


# ── IP source guard ─────────────────────────────────────────────────────────

SNOOPING = "ip dhcp snooping\nip dhcp snooping vlan 10\n"


def access_port(name: str, *, guarded: bool) -> str:
    guard = " ip verify source\n" if guarded else ""
    return f"interface {name}\n switchport\n switchport mode access\n{guard}"


def test_source_guard_is_false_on_an_access_port_that_lacks_it() -> None:
    """Not None. While it was None, no check could tell absence from unparsed."""
    ncm = parse(SNOOPING + access_port("Gi1/0/1", guarded=False))

    assert ncm.interfaces[0].security.ip_source_guard is False


def test_source_guard_is_true_where_configured() -> None:
    ncm = parse(SNOOPING + access_port("Gi1/0/1", guarded=True))

    assert ncm.interfaces[0].security.ip_source_guard is True


def test_an_unguarded_access_port_fails() -> None:
    assert (
        outcome("cisco-ip-source-guard", SNOOPING + access_port("Gi1/0/1", guarded=False)) == "fail"
    )


def test_guarded_access_ports_pass() -> None:
    config = SNOOPING + access_port("Gi1/0/1", guarded=True) + access_port("Gi1/0/2", guarded=True)

    assert outcome("cisco-ip-source-guard", config) == "pass"


def test_a_trunk_is_not_expected_to_verify_source() -> None:
    """A trunk carries traffic for hosts attached elsewhere.

    There is no binding for the switch to check it against, and requiring it there
    would raise a finding on every uplink in the estate.
    """
    config = SNOOPING + "interface Gi1/0/48\n switchport\n switchport mode trunk\n"

    assert outcome("cisco-ip-source-guard", config) == "pass"


def test_a_shut_access_port_is_not_a_finding() -> None:
    """A port that forwards nothing cannot spoof anything.

    The same reasoning by which `connected_routes` declines to derive a route from an
    admin-down interface. Including them would put a finding on every unused port in
    an estate, which is how a check comes to be ignored.
    """
    config = SNOOPING + "interface Gi1/0/48\n switchport\n switchport mode access\n shutdown\n"

    assert outcome("cisco-ip-source-guard", config) == "pass"


def test_the_hardened_fixture_passes_both_checks() -> None:
    """Against real configuration, and it puts both fields in the parser baseline."""
    config = (Path(__file__).parent / "fixtures/cisco/ios/17.9/hardened_switch.cfg").read_text(
        encoding="utf-8"
    )
    loaded = {c.id: c for c in load_library()}
    ncm = get_parser("cisco_ios").parse(ParseContext(text=config)).model_dump(mode="json")
    device = DeviceContext.from_ncm(ncm, device_class="switch")

    for check_id in ("cisco-ip-source-guard", "cisco-snmp-community-view"):
        result = evaluate(loaded[check_id].definition, ncm, device=device)
        assert result.outcome.value == "pass", f"{check_id}: {result.message}"


def test_without_dhcp_snooping_it_is_not_applicable() -> None:
    """One finding per fact.

    Source guard reads the snooping binding table, so without snooping there is
    nothing to enforce against. `cisco-dhcp-snooping-enabled` reports that at high
    severity, and a finding per access port would bury it under its own consequence.
    """
    assert (
        outcome("cisco-ip-source-guard", access_port("Gi1/0/1", guarded=False)) == "not_applicable"
    )
