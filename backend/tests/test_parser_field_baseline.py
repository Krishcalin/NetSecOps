"""No parser may quietly stop populating a field (FR-PARSE-01, FR-COL-08).

`test_parsers.py` already asserts a coverage floor and that no parser raises. Neither
catches the failure this exists for, and the difference is not academic: a parser that
consumes a line and extracts nothing from it scores full coverage. Pointing
`scripts/parse_coverage.py` at a corpus we did not write turned that up as a fact rather
than a worry — 104 PAN-OS files reported 93.8% coverage with every NCM field a check
depends on populated in none of them.

When a field stops being populated, every check reading it reports *Not evaluated*. That
is the honest answer and an invisible one: an estate where `management.services.ssh.ciphers`
no longer parses produces no findings about SSH ciphers and looks exactly like an estate
with good ciphers. Nothing goes red. Nobody gets paged. The number on the dashboard
improves.

So the set of fields each parser populates across the fixtures is recorded in
`fixtures/parser_field_baseline.json`, and this fails when one disappears.

    # after a deliberate change to what a parser extracts
    NETSECOPS_UPDATE_BASELINE=1 pytest tests/test_parser_field_baseline.py

Regenerating is one command and the diff is reviewable, which is the point: losing a
field should be a line in a pull request somebody reads, not a silence.

**What this does not guard, stated plainly because the gate looks stronger than it is.**
It can only protect a field some fixture exercises. The first version of this file passed
cleanly with the AUX-line parsing deleted, because no fixture contained a `line aux`
stanza — the field had never been in the baseline, so losing it changed nothing. A
capability with no fixture is invisible here exactly as it is everywhere else, and adding
one is part of adding the capability. `scripts/parse_coverage.py` against an outside
corpus is what finds the fields we never thought to write a fixture for.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURES = Path(__file__).parent / "fixtures"
BASELINE = FIXTURES / "parser_field_baseline.json"


@dataclass(frozen=True)
class Sample:
    platform: str
    path: Path


#: Every configuration fixture, with the parser that owns it. Broader than
#: `test_parsers.py`'s CORPUS, which covers the three Cisco platforms whose per-fixture
#: expectations live there — this needs all thirteen, because the platforms nobody looks
#: at are exactly where a field can go missing unnoticed.
SAMPLES: list[Sample] = [
    Sample("cisco_ios", FIXTURES / "cisco/ios/17.9/hardened_switch.cfg"),
    Sample("cisco_ios", FIXTURES / "cisco/ios/15.2/weak_switch.cfg"),
    Sample("cisco_ios", FIXTURES / "cisco/ios/17.9/wlc_9800.cfg"),
    Sample("cisco_nxos", FIXTURES / "cisco/nxos/10.3/dc_switch.cfg"),
    Sample("cisco_nxos", FIXTURES / "cisco/nxos/9.3/edge_n3k.cfg"),
    Sample("cisco_asa", FIXTURES / "cisco/asa/9.18/edge_firewall.cfg"),
    Sample("cisco_wlc_aireos", FIXTURES / "cisco/wlc/8.10/campus_wlc.txt"),
    Sample("cisco_ise", FIXTURES / "cisco/ise/3.2/ise_deployment.json"),
    Sample("checkpoint_gaia", FIXTURES / "checkpoint/gaia/R81.20/cp_gw_edge_01.txt"),
    Sample("checkpoint_mgmt", FIXTURES / "checkpoint/mgmt/R81.20/corporate_policy.json"),
    Sample("panos", FIXTURES / "paloalto/panos/11.0/perimeter_fw.xml"),
    Sample("fortios", FIXTURES / "fortinet/fortios/7.2/edge_fortigate.cfg"),
    Sample("fortiauthenticator", FIXTURES / "fortinet/fortiauthenticator/6.5/campus_fac.json"),
    Sample("freeradius", FIXTURES / "linux/freeradius/3.0/campus_radius.json"),
    Sample("tac_plus", FIXTURES / "linux/tacplus/campus_tacplus.conf"),
]

#: Not recorded. `provenance` is line numbers, `raw_unparsed` is the leftovers, and
#: `ncm_version` is a constant — none of them says anything about what a parser extracts,
#: and all three churn whenever a fixture is edited.
IGNORED = {"provenance", "raw_unparsed", "ncm_version"}


def populated(value: Any, prefix: str, into: set[str]) -> None:
    """Every NCM leaf that came out with something in it.

    None, empty string, empty list and empty dict all count as absent: they are what a
    parser leaves behind when it did not find something, and this whole file is about
    telling "parsed and false" from "never parsed".
    """
    if isinstance(value, dict):
        for key, child in value.items():
            if key in IGNORED:
                continue
            populated(child, f"{prefix}.{key}" if prefix else key, into)
        return

    if isinstance(value, list):
        if value:
            into.add(prefix)
            # One representative element, so a list of interfaces records which interface
            # *fields* parse rather than only that interfaces exist at all.
            populated(value[0], prefix, into)
        return

    if value not in (None, "", {}, []):
        into.add(prefix)


def measure() -> dict[str, list[str]]:
    """Fields populated per platform, unioned across that platform's fixtures."""
    found: dict[str, set[str]] = {}

    for sample in SAMPLES:
        text = sample.path.read_text(encoding="utf-8")
        ncm = get_parser(sample.platform).parse(
            ParseContext(text=text, command="show running-config")
        )
        fields: set[str] = set()
        populated(ncm.model_dump(mode="json"), "", fields)
        found.setdefault(sample.platform, set()).update(fields)

    return {platform: sorted(fields) for platform, fields in sorted(found.items())}


def test_every_fixture_exists() -> None:
    """A path typo would silently shrink the corpus this guards."""
    missing = [str(s.path) for s in SAMPLES if not s.path.is_file()]
    assert not missing, f"fixture paths do not exist: {missing}"


def test_no_field_stops_being_populated() -> None:
    """The regression guard.

    Failing here means a parser that used to extract something no longer does. The
    checks reading it are now reporting Not Evaluated on every device of that platform,
    and nothing else in the suite will tell you.
    """
    current = measure()

    if os.environ.get("NETSECOPS_UPDATE_BASELINE"):
        BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        pytest.skip("baseline rewritten")

    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))

    lost: dict[str, list[str]] = {}
    for platform, expected in baseline.items():
        gone = sorted(set(expected) - set(current.get(platform, [])))
        if gone:
            lost[platform] = gone

    assert not lost, (
        "These NCM fields are no longer populated by their parser:\n"
        + "\n".join(f"  {platform}: {', '.join(fields)}" for platform, fields in lost.items())
        + "\n\nEvery check reading one of them now reports Not Evaluated on every device "
        "of that platform, which looks identical to a clean estate. If the loss is "
        "deliberate, rerun with NETSECOPS_UPDATE_BASELINE=1 so the change is visible in "
        "the diff."
    )


def test_new_fields_are_recorded() -> None:
    """Keeps the baseline honest, so the guard above keeps meaning something.

    A baseline that drifts out of date stops being a description of what the parsers do,
    and then nobody trusts it enough to act when it fails.
    """
    if os.environ.get("NETSECOPS_UPDATE_BASELINE"):
        pytest.skip("baseline rewritten")

    current = measure()
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))

    added: dict[str, list[str]] = {}
    for platform, fields in current.items():
        new = sorted(set(fields) - set(baseline.get(platform, [])))
        if new:
            added[platform] = new

    assert not added, (
        "These parsers now populate fields the baseline does not record:\n"
        + "\n".join(f"  {platform}: {', '.join(fields)}" for platform, fields in added.items())
        + "\n\nThat is usually good news. Rerun with NETSECOPS_UPDATE_BASELINE=1 to record it."
    )


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: f"{s.platform}:{s.path.name}")
def test_no_fixture_fails_to_parse(sample: Sample) -> None:
    """`parse_failed` means the parser read none of it.

    Separate from the coverage floor in `test_parsers.py`, and not redundant with it: a
    wholesale failure records one explanatory line in `raw_unparsed`, so the lines-minus-
    unparsed arithmetic scores it in the high nineties. That is the defect this baseline
    work started from.
    """
    text = sample.path.read_text(encoding="utf-8")
    ncm = get_parser(sample.platform).parse(ParseContext(text=text, command="show running-config"))

    assert ncm.parse_failed is False, f"{sample.path.name} could not be read at all"
