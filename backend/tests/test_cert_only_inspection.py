"""Content profiles that cannot see the content (FR-FW-03).

Certificate inspection reads the TLS handshake and stops. A FortiOS policy carrying an
anti-virus profile, an IPS sensor *and* `ssl-ssh-profile certificate-inspection`
inspects nothing inside HTTPS — which on a modern gateway is nearly all of the traffic
it permits.

The rule looks fully protected while that happens, and that is the whole point of
reporting it separately from `NO_PROFILES`. A rule with no profiles is visibly
unprotected and somebody notices; this one lists two profiles and passes every
shadowing, redundancy and any-any test we have.

Our own FortiOS fixture has carried exactly this shape since it was written, and scored
clean.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsecops.firewall.model import resolve_rulebase
from netsecops.firewall.policy import (
    CERT_ONLY_SSL_PROFILES,
    CONTENT_PROFILE_KINDS,
    RuleIssue,
    examine,
)
from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURE = Path(__file__).parent / "fixtures/fortinet/fortios/7.2/edge_fortigate.cfg"


@pytest.fixture(scope="module")
def fortigate() -> NormalisedConfig:
    return get_parser("fortios").parse(
        ParseContext(text=FIXTURE.read_text(encoding="utf-8"), command="show full-configuration")
    )


def issues_by_rule(ncm: NormalisedConfig) -> dict[str, set[str]]:
    rules, _resolver = resolve_rulebase(ncm.firewall.model_dump())
    report = examine(rules)
    found: dict[str, set[str]] = {}
    for finding in report.findings:
        found.setdefault(str(finding.rule_name or finding.rule_order), set()).add(
            str(finding.issue)
        )
    return found


def test_the_fixture_still_contains_the_shape(fortigate: NormalisedConfig) -> None:
    """Guard the premise, so this file cannot quietly stop testing anything.

    If the fixture is ever edited to use deep inspection, every assertion below would
    pass by vacuity — green, and about nothing.
    """
    blinded = [
        rule
        for rule in fortigate.firewall.security_rules
        if (rule.profiles or {}).get("decryption") == "certificate-inspection"
        and set(rule.profiles or {}) & CONTENT_PROFILE_KINDS
    ]

    assert blinded, "no fixture rule pairs content profiles with certificate-inspection"


def test_a_rule_inspecting_nothing_inside_tls_is_reported(fortigate: NormalisedConfig) -> None:
    found = issues_by_rule(fortigate)
    reported = {name for name, issues in found.items() if "inspection_not_decrypted" in issues}

    assert reported, f"nothing reported; issues seen were {found}"


def rule_with(profiles: dict[str, str], name: str = "r1") -> set[str]:
    """Issues raised against a single permit rule carrying exactly these profiles.

    Built rather than taken from the fixture. The first version of the negative test
    below filtered the fixture for a cert-only rule with no content profiles, and the
    fixture has none — so it iterated an empty list and asserted nothing. Dropping the
    content-profile requirement from the check left it green, which is how the gap was
    found.
    """
    rules, _resolver = resolve_rulebase(
        {
            "security_rules": [
                {
                    "sequence": 1,
                    "name": name,
                    "action": "allow",
                    "src": ["any"],
                    "dst": ["any"],
                    "services": ["HTTPS"],
                    "profiles": profiles,
                    "log_end": True,
                }
            ]
        }
    )
    report = examine(rules)
    return {str(f.issue) for f in report.findings}


def test_certificate_inspection_alone_is_not_a_finding() -> None:
    """It is a policy choice, not a defect.

    The finding is the *combination* — paying for inspection that cannot run. A rule
    asking for no content inspection is not inconsistent with certificate inspection,
    and `NO_PROFILES` already has an opinion about rules that inspect nothing.
    """
    alone = rule_with({"decryption": "certificate-inspection"})
    with_content = rule_with({"decryption": "certificate-inspection", "ips": "default"})

    assert "inspection_not_decrypted" not in alone
    # Asserted against the positive case rather than on its own, so that a rule which
    # was never examined at all cannot satisfy this by producing nothing.
    assert "inspection_not_decrypted" in with_content


def test_content_profiles_behind_certificate_inspection_are_a_finding() -> None:
    """The positive half of the same pair, on a rule built for it."""
    issues = rule_with({"decryption": "certificate-inspection", "antivirus": "default"})

    assert "inspection_not_decrypted" in issues


def test_content_profiles_behind_deep_inspection_are_not() -> None:
    issues = rule_with({"decryption": "deep-inspection", "antivirus": "default"})

    assert "inspection_not_decrypted" not in issues


def test_deep_inspection_is_not_reported() -> None:
    """Only profiles known by name not to decrypt.

    `deep-inspection` does decrypt, and a custom profile could do either — its body is
    not parsed, so judging one by its name would be a guess, and a wrong guess tells
    somebody their inspection is broken when it works.
    """
    assert "deep-inspection" not in CERT_ONLY_SSL_PROFILES
    assert "custom-deep-inspection" not in CERT_ONLY_SSL_PROFILES
    assert CERT_ONLY_SSL_PROFILES == {"certificate-inspection"}


def test_the_ssl_profile_itself_is_not_counted_as_content() -> None:
    """`decryption` is the SSL profile, not something it blinds.

    Counting it would make every certificate-inspection rule self-report, including
    the ones asking for no content inspection at all.
    """
    assert "decryption" not in CONTENT_PROFILE_KINDS
    # A profile group's members are not resolved here, so whether it holds a content
    # profile is unknown rather than false.
    assert "group" not in CONTENT_PROFILE_KINDS


def test_the_issue_carries_the_same_severity_as_no_profiles() -> None:
    """Same exposure, so the same severity.

    Traffic passes uninspected either way. What differs is only whether a human
    reading the rule can tell, and that is not a reason to rank the exposure higher.
    """
    from netsecops.firewall.policy import ISSUE_SEVERITY

    assert (
        ISSUE_SEVERITY[RuleIssue.INSPECTION_NOT_DECRYPTED] == ISSUE_SEVERITY[RuleIssue.NO_PROFILES]
    )
