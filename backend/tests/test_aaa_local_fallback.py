"""A device nobody can log into when TACACS+ is unreachable (FR-CHK-01, FR-PARSE-01).

`aaa-local-fallback` has existed for a long time and could not report the case it was
written for. The parser set `aaa.local_fallback = any(...) or None`, so a device whose
method lists all point at a server and none of which falls back to local came out as
None — not False — and the check reported *Not Evaluated* rather than failing.

That is the device at risk: a switch with a TACACS+ server, no local fallback, and no
way in when the server is unreachable. The ones that *do* fall back reported pass
correctly, so the check looked like it worked.

Found by `scripts/seam_audit.py`, which looks for exactly this shape — a boolean no
parser can ever set False — after the same defect turned up by accident in
`interfaces.security.ip_source_guard`.
"""

from __future__ import annotations

import pytest

from netsecops.checks.engine import DeviceContext, evaluate
from netsecops.checks.loader import load_library
from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

CHECK = "aaa-local-fallback"

SERVERS = "tacacs server T1\n address ipv4 10.0.0.1\n"
WITH_FALLBACK = "aaa authentication login default group tacacs+ local\n"
WITHOUT_FALLBACK = "aaa authentication login default group tacacs+\n"


def parse(platform: str, body: str) -> NormalisedConfig:
    return get_parser(platform).parse(ParseContext(text=f"hostname d\n!\n{body}!\nend\n"))


def outcome(platform: str, body: str) -> str:
    loaded = next(c for c in load_library() if c.id == CHECK)
    ncm = parse(platform, body).model_dump(mode="json")
    return evaluate(loaded.definition, ncm, device=DeviceContext.from_ncm(ncm)).outcome.value


@pytest.mark.parametrize("platform", ["cisco_ios", "cisco_nxos"])
def test_no_fallback_is_false_not_unknown(platform: str) -> None:
    """The distinction the check depends on.

    Method lists were parsed and none falls back — that is a fact about the device, not
    an absence of information.
    """
    ncm = parse(platform, "aaa new-model\n" + SERVERS + WITHOUT_FALLBACK)

    assert ncm.aaa.authentication, "no method lists parsed; this asserts nothing"
    assert ncm.aaa.local_fallback is False


@pytest.mark.parametrize("platform", ["cisco_ios", "cisco_nxos"])
def test_a_fallback_is_true(platform: str) -> None:
    ncm = parse(platform, "aaa new-model\n" + SERVERS + WITH_FALLBACK)

    assert ncm.aaa.local_fallback is True


@pytest.mark.parametrize("platform", ["cisco_ios", "cisco_nxos"])
def test_no_method_lists_leaves_it_unknown(platform: str) -> None:
    """None, because there was nothing to read — not because the answer is no."""
    ncm = parse(platform, SERVERS)

    assert ncm.aaa.local_fallback is None


def test_the_locked_out_device_now_fails() -> None:
    """The finding the check could never raise.

    A switch with a TACACS+ server and no local fallback is one server outage away from
    being unmanageable, and this reported Not Evaluated.
    """
    assert outcome("cisco_ios", "aaa new-model\n" + SERVERS + WITHOUT_FALLBACK) == "fail"


def test_a_device_with_fallback_still_passes() -> None:
    assert outcome("cisco_ios", "aaa new-model\n" + SERVERS + WITH_FALLBACK) == "pass"


def test_without_aaa_servers_it_does_not_apply() -> None:
    """A device authenticating locally cannot be locked out by a server it does not use.

    This guard had never worked. It was written as `logic.requires: [aaa.servers]`,
    which tests for null — and a device with no AAA servers has an empty list, which is
    not null. Nobody noticed because the parser could not produce False either, so the
    check reported Not Evaluated for both reasons at once and looked correct.

    Fixing only the parser turned this case into a spurious *fail*, which is how the
    second half of the defect surfaced.
    """
    assert outcome("cisco_ios", "aaa new-model\n" + WITHOUT_FALLBACK) == "not_applicable"
