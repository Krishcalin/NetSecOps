"""SSL-VPN posture, and what it is for (FR-VUL-03, FR-PARSE-01).

Every mass-exploited FortiGate CVE is conditional on SSL-VPN being enabled —
CVE-2018-13379, CVE-2022-42475, CVE-2023-27997 and CVE-2024-21762 — and Fortinet's own
advisories say so, giving `config vpn ssl settings / set status disable` as the
workaround for two of them. NetSecOps matched those on version alone, so every
FortiGate of the right version was reported against all four, most of which do not run
SSL-VPN at all.

`features.ssl_vpn` is not a check and should not become one: running SSL-VPN is a
legitimate thing to do. It exists so the vulnerability matcher can tell a confirmed
exposure from a version coincidence, and the second half of this file proves it does —
otherwise this would be another field that is parsed and read by nothing.

**Only `status` is parsed.** The port, the source interfaces and the minimum TLS
version would all be useful, and the exact spelling of each could not be confirmed:
docs.fortinet.com renders its CLI reference in JavaScript and serves a table of contents
to anything that fetches it. Guessing is what produced four non-existent FortiOS setting
names in an earlier research pass, and a misspelled key does not fail here — it reads as
"not configured" for ever.
"""

from __future__ import annotations

from pathlib import Path

from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser
from netsecops.vuln.advisory import (
    Advisory,
    AffectedProduct,
    ConstraintKind,
    FeatureCondition,
    VersionConstraint,
)
from netsecops.vuln.matcher import Confidence, match

FIXTURE = Path(__file__).parent / "fixtures/fortinet/fortios/7.2/edge_fortigate.cfg"


def parse(text: str) -> NormalisedConfig:
    return get_parser("fortios").parse(ParseContext(text=text))


# ── the parser ──────────────────────────────────────────────────────────────


def test_enabled_is_read_from_the_settings_block() -> None:
    assert parse("config vpn ssl settings\n    set status enable\nend\n").features.ssl_vpn is True


def test_disabled_is_read_as_false_not_as_absent() -> None:
    """A device that turned it off has said something, and it rules four CVEs out."""
    assert parse("config vpn ssl settings\n    set status disable\nend\n").features.ssl_vpn is False


def test_no_settings_block_leaves_it_unknown() -> None:
    """Absent is not disabled.

    SSL-VPN not appearing in the configuration we were given is not the same as the
    device having it off, and the difference decides whether four advisories are ruled
    out or merely left unconfirmed. Ruling them out on silence is the dangerous
    direction.
    """
    assert parse("config system global\n    set hostname fg\nend\n").features.ssl_vpn is None


def test_a_block_with_no_status_line_leaves_it_unknown() -> None:
    """The section exists and says nothing about `status`."""
    config = 'config vpn ssl settings\n    set servercert "Fortinet_Factory"\nend\n'

    assert parse(config).features.ssl_vpn is None


def test_the_fixture_carries_it() -> None:
    assert parse(FIXTURE.read_text(encoding="utf-8")).features.ssl_vpn is True


# ── what it is for ──────────────────────────────────────────────────────────


SSL_VPN_ONLY = FeatureCondition(
    path="features.ssl_vpn",
    expected=True,
    description="Fortinet states this affects only devices with SSL-VPN enabled.",
)


def fortigate(version: str, **features: object) -> NormalisedConfig:
    ncm = NormalisedConfig()
    ncm.device.vendor = "fortinet"
    ncm.device.platform = "fortios"
    ncm.device.version = version
    for name, value in features.items():
        setattr(ncm.features, name, value)
    return ncm


def ssl_vpn_advisory() -> Advisory:
    return Advisory(
        source="Fortinet",
        advisory_id="FG-IR-24-015",
        cve_ids=["CVE-2024-21762"],
        affected=[
            AffectedProduct(
                vendor="Fortinet",
                product="FortiOS",
                cpe=None,
                product_id="CSAFPID-0001",
                constraint=VersionConstraint(
                    kind=ConstraintKind.RANGE,
                    raw="7.2.0 - 7.2.6",
                    introduced="7.2.0",
                    last_affected="7.2.6",
                ),
            )
        ],
        conditions=[SSL_VPN_ONLY],
    )


def test_ssl_vpn_enabled_confirms_the_advisory() -> None:
    result = match(fortigate("7.2.4", ssl_vpn=True), ssl_vpn_advisory())

    assert result.confidence is Confidence.CONFIRMED


def test_ssl_vpn_disabled_rules_it_out() -> None:
    """The false positive this removes.

    A FortiGate on an affected version with SSL-VPN switched off is not exposed to any
    of the four, and reporting it is what teaches an operator to stop reading the
    vulnerability view.
    """
    result = match(fortigate("7.2.4", ssl_vpn=False), ssl_vpn_advisory())

    assert result.confidence is Confidence.NOT_AFFECTED


def test_unknown_ssl_vpn_stays_likely_rather_than_either_extreme() -> None:
    """The three-valued discipline, on the field that motivated parsing it.

    Before the parser read `status` this was the answer for every FortiGate, which is
    why the matcher has a LIKELY at all. Rounding it down to Not Affected would hide a
    real exposure; rounding it up to Confirmed is what we were doing.
    """
    result = match(fortigate("7.2.4"), ssl_vpn_advisory())

    assert result.confidence is Confidence.LIKELY


def test_an_unaffected_version_is_not_rescued_by_the_condition() -> None:
    """The condition narrows a version match; it cannot create one."""
    result = match(fortigate("7.4.1", ssl_vpn=True), ssl_vpn_advisory())

    assert result.confidence is not Confidence.CONFIRMED
