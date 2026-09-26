"""What the collector produces must be what the parser reads (FR-COL-08, FR-PARSE-01).

Three platforms have no configuration file. A Check Point management server, an ISE
deployment and a FortiAuthenticator are *APIs*, and their "configuration" is every
response together. Their parsers are built that way — each looks a response up by
endpoint through `ResponseBundle` — and every fixture is a bundle keyed by endpoint.

The collector was not built that way. `_collect_profile` assigned the body of the one
command marked `yields_config` to `config_text`, so the parser received the rulebase
response *alone* and looked inside it for a key named `show-access-rulebase`. There is
none, so every lookup returned empty.

The result was the worst available: a Check Point management server parsed to zero
security rules and zero NAT rules, with `parse_failed` False and `rules_not_retrieved`
None. Not an error, not a partial collection — a firewall with no policy, reported
confidently. `rules_not_retrieved` had just been added to catch a rulebase that arrived
short, and it could not fire, because `total` is on the response the parser never found.

Nothing caught it because the two sides were never tested together: every parser test
feeds a bundle, and the only test of `_collect_profile` uses `cisco_ios` over SSH.

So these tests assert the *seam*. They build what the collector builds, from the
profile itself, and parse it with the real parser.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from netsecops.adapters.profiles import PROFILES, get_profile
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURES = Path(__file__).parent / "fixtures"

#: A bundled platform, its fixture, and something that must survive the round trip.
CASES = {
    "checkpoint_mgmt": FIXTURES / "checkpoint/mgmt/R81.20/corporate_policy.json",
    "cisco_ise": FIXTURES / "cisco/ise/3.2/ise_deployment.json",
    "fortiauthenticator": FIXTURES / "fortinet/fortiauthenticator/6.5/campus_fac.json",
}


def same_endpoint(fixture_key: str, collector_key: str) -> bool:
    """Whether a fixture response and a profile command name the same endpoint.

    Compared through the two normalisations the parsers themselves use, because the
    fixtures do not agree on a spelling: FortiAuthenticator's are full paths
    (`/api/v1/radiusclients/`), ISE's are path tails (`policy/network-access/…`) and
    Check Point's are bare operation names. `ResponseBundle` is configured per parser
    to reconcile exactly that, so a collector key that differs in spelling is not a
    defect — one that differs in *identity* is.
    """
    trimmed = fixture_key.strip("/").lower()
    return collector_key in {trimmed, trimmed.split("/")[-1]}


def collected_bundle(platform: str, fixture: Path) -> str:
    """Rebuild the artefact the collector would write, keyed as the runner keys it.

    The fixture supplies the response bodies; the *keys* come from the profile, which
    is the half that was wrong. Taking them from the profile is the point: a command
    filed under a name its parser cannot resolve contributes nothing here, and the
    assertions below fail rather than quietly thinning the policy.
    """
    raw = json.loads(fixture.read_text(encoding="utf-8"))
    profile = get_profile(platform)

    bundle: dict[str, Any] = {}
    for entry in profile.commands:
        key = entry.key_in_bundle()
        for fixture_key, payload in raw.items():
            if same_endpoint(fixture_key, key):
                bundle[key] = payload
                break

    return json.dumps(bundle, sort_keys=True)


@pytest.mark.parametrize("platform", sorted(CASES))
def test_every_bundled_profile_is_marked_bundled(platform: str) -> None:
    """The flag is what makes the runner build a bundle at all."""
    assert get_profile(platform).bundled is True


def test_only_the_api_platforms_are_bundled() -> None:
    """PAN-OS must not be: its configuration really is a single XML document.

    Bundling it would wrap that document in a JSON object and the XML parser would
    receive something it cannot read at all.
    """
    bundled = {name for name, profile in PROFILES.items() if profile.bundled}

    assert bundled == set(CASES)


@pytest.mark.parametrize("platform", sorted(CASES))
def test_the_collectors_keys_are_the_ones_the_parser_reads(platform: str) -> None:
    """Every command's bundle key must name something the parser looks up.

    This is the assertion that fails if somebody adds an endpoint to a profile and
    keys it by a name nothing reads — the same shape of mistake, one command at a time
    rather than all of them at once.
    """
    raw = json.loads(CASES[platform].read_text(encoding="utf-8"))
    profile = get_profile(platform)

    unreadable = [
        entry.command
        for entry in profile.commands
        if entry.required and not any(same_endpoint(key, entry.key_in_bundle()) for key in raw)
    ]

    assert unreadable == [], (
        f"{platform}: these required commands are filed under a key the parser's own "
        f"fixture does not contain, so their response would be discarded: {unreadable}"
    )


def parsed(platform: str, bundle: dict[str, Any]) -> dict[str, Any]:
    """The NCM a bundle produces, without the parts that change for other reasons.

    Provenance holds positions and `raw_unparsed` holds the unread-endpoint accounting,
    which by definition changes whenever an endpoint is removed — comparing them would
    make the test below pass for the wrong reason.
    """
    ncm = get_parser(platform).parse(ParseContext(text=json.dumps(bundle, sort_keys=True)))
    return ncm.model_dump(mode="json", exclude={"provenance", "raw_unparsed"})


@pytest.mark.parametrize("platform", sorted(CASES))
def test_every_collected_endpoint_changes_the_result(platform: str) -> None:
    """Each endpoint the profile asks for must reach the NCM.

    The key-spelling test above is weaker than it looks: it only covers commands marked
    `required`, and on ISE that is one of eleven. Deleting the bundle key from
    `policy/network-access/authorization` left the whole suite green — the authorisation
    rules were being collected, filed under a name nothing reads, and discarded, which
    is the original defect at the scale of a single endpoint.

    So this drops each endpoint in turn and requires the parsed result to change. An
    endpoint that can be removed without effect is one of two things, and both need
    somebody to look: a response nothing reads, or a request nobody needed to send.
    """
    raw = json.loads(CASES[platform].read_text(encoding="utf-8"))
    profile = get_profile(platform)
    bundle = json.loads(collected_bundle(platform, CASES[platform]))

    baseline = parsed(platform, bundle)
    inert: list[str] = []

    for entry in profile.commands:
        key = entry.key_in_bundle()
        if key not in bundle:
            # The fixture does not cover this endpoint; nothing to conclude.
            continue
        without = {k: v for k, v in bundle.items() if k != key}
        if parsed(platform, without) == baseline:
            inert.append(f"{entry.command} (filed as {key!r})")

    assert inert == [], (
        f"{platform}: removing these endpoints changed nothing in the NCM, so their "
        f"responses are collected and then discarded:\n  " + "\n  ".join(inert)
    )
    assert raw, "fixture is empty"


def test_check_point_policy_survives_the_collector() -> None:
    """The defect, stated as the fact it cost.

    Before this, a real Check Point collection produced zero rules here.
    """
    ncm = get_parser("checkpoint_mgmt").parse(
        ParseContext(text=collected_bundle("checkpoint_mgmt", CASES["checkpoint_mgmt"]))
    )

    assert len(ncm.firewall.security_rules) == 8
    assert len(ncm.firewall.nat_rules) == 2
    # And the truncation guard can see `total`, which lives on the response the parser
    # previously never reached.
    assert ncm.firewall.rules_not_retrieved == 0


def test_ise_deployment_survives_the_collector() -> None:
    ncm = get_parser("cisco_ise").parse(
        ParseContext(text=collected_bundle("cisco_ise", CASES["cisco_ise"]))
    )

    assert ncm.users, "no administrators parsed from the collected bundle"
    assert ncm.certificates, "no certificates parsed from the collected bundle"


def test_fortiauthenticator_survives_the_collector() -> None:
    ncm = get_parser("fortiauthenticator").parse(
        ParseContext(text=collected_bundle("fortiauthenticator", CASES["fortiauthenticator"]))
    )

    assert ncm.users, "no local users parsed from the collected bundle"
