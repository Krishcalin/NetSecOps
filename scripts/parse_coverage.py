#!/usr/bin/env python3
"""Measure the parsers against configurations we did not write.

Every parser, check and allow-list in this product is validated against fixtures in
`backend/tests/fixtures` — which we authored. They are 1.5 to 14 KB; a real core switch
or perimeter firewall runs from 100 KB to a couple of megabytes. So the fixtures prove
the parsers handle the syntax we thought of, and say nothing about the syntax we did
not. This closes that loop as far as it can be closed without hardware.

Point it at a directory of real configurations:

    python scripts/parse_coverage.py ~/corpus
    python scripts/parse_coverage.py ~/corpus --platform cisco_ios --verbose
    python scripts/parse_coverage.py ~/corpus --json report.json

It reports three things, in increasing order of usefulness:

**Coverage** — the share of meaningful lines the parser consumed, the same number the
snapshot service records. Useful as a tripwire, weak as a goal: a parser can consume a
line and extract nothing from it.

**Unparsed shapes** — every unrecognised line reduced to its grammar by replacing
identifiers, addresses and numbers with placeholders, then counted. One line of output
per missing construct instead of ten thousand lines of noise, ranked by how often real
configurations contain it. This is the work queue.

**Field fill rates** — for each NCM field, the share of configurations in which it came
out populated. This is the one that matters. A check whose input is absent reports *Not
evaluated*, which is the honest answer and also an invisible one: an estate where
`crypto.ssh_ciphers` never parses produces no findings about SSH ciphers and looks
exactly like an estate with good ciphers. Coverage cannot see that. This can.

Nothing here touches a database or a device; it is a pure parse.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BACKEND = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import PARSERS, get_parser

#: Extensions worth attempting. Anything else in a corpus directory is ignored rather
#: than parsed as text, because a README counted as a 0%-coverage configuration would
#: drag every average down for no reason.
CONFIG_SUFFIXES = {".cfg", ".conf", ".txt", ".xml", ".json", ".config", ""}

#: Content sniffing, in priority order. Each pattern is something only that platform
#: prints, so the first match wins and ambiguity is reported rather than guessed.
SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("cisco_asa", re.compile(r"^ASA Version |^: Saved|^nameif ", re.MULTILINE)),
    ("cisco_nxos", re.compile(r"^feature \w+|^switchname |nxos\.\d", re.MULTILINE)),
    ("fortios", re.compile(r"^config system global|^#config-version=", re.MULTILINE)),
    ("panos", re.compile(r"<config[ >]|<devices>|<vsys>")),
    (
        "checkpoint_gaia",
        re.compile(r"^set (?:hostname|interface) |^add user ", re.MULTILINE),
    ),
    ("cisco_wlc_aireos", re.compile(r"^config wlan |^config sysname ", re.MULTILINE)),
    # Last, because IOS is the least distinctive: NX-OS and ASA also print `interface`
    # and `hostname`, so anything reaching here has already failed their signatures.
    (
        "cisco_ios",
        re.compile(r"^version \d+\.\d+|^interface (?:Gigabit|Fast|Te)", re.MULTILINE),
    ),
]

#: Token classes replaced when reducing an unparsed line to its shape.
_SHAPE_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b"), "<ip>"),
    (re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b"), "<mac>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<hash>"),
    (re.compile(r"\b\d+\b"), "<n>"),
    (re.compile(r'"[^"]*"'), "<str>"),
]


@dataclass
class PlatformReport:
    platform: str
    files: int = 0
    failures: list[tuple[str, str]] = field(default_factory=list)
    coverages: list[float] = field(default_factory=list)
    worst: list[tuple[float, str]] = field(default_factory=list)
    shapes: Counter[str] = field(default_factory=Counter)
    #: How many parsed files had each NCM leaf populated.
    filled: Counter[str] = field(default_factory=Counter)
    total_lines: int = 0
    #: Files the parser could not read at all — not a low score, no score.
    unreadable: int = 0

    @property
    def parsed(self) -> int:
        return len(self.coverages)

    @property
    def median_coverage(self) -> float:
        if not self.coverages:
            return 0.0
        ordered = sorted(self.coverages)
        return ordered[len(ordered) // 2]


def shape_of(line: str) -> str:
    """Reduce a line to its grammar, so ten thousand unique lines become ten shapes."""
    text = line.strip()
    for pattern, placeholder in _SHAPE_RULES:
        text = pattern.sub(placeholder, text)
    return " ".join(text.split())[:120]


def meaningful_lines(text: str) -> int:
    """Lines a coverage figure should be measured against.

    Mirrors the snapshot service: blank lines and comment-only lines are not something a
    parser fails to understand, and counting them would make a well-parsed configuration
    with a long banner look poorly parsed.
    """
    return sum(1 for line in text.splitlines() if line.strip() and not line.strip().startswith("!"))


#: Command output that is not a configuration. Feeding `show ip route` to a config
#: parser produces a file of unrecognised lines and a coverage figure near zero, which
#: looks exactly like a parser that cannot read that platform. Found by running this
#: against our own fixtures, where `operational/` is stored beside the configurations.
OPERATIONAL_MARKERS: re.Pattern[str] = re.compile(
    r"^(?:Codes:|Gateway of last resort|IP Route Table|Routing Table)"
    r"|ubest/mbest"
    r"|^\s*[A-Z*]{1,3}[ *]+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2} \[\d+/\d+\]",
    re.MULTILINE,
)


def detect_platform(path: Path, text: str) -> str | None:
    """Directory name first, then content. Never a guess dressed as a fact."""
    if OPERATIONAL_MARKERS.search(text):
        return None

    for parent in path.parents:
        if parent.name in PARSERS:
            return parent.name

    for platform, pattern in SIGNATURES:
        if pattern.search(text):
            return platform
    return None


def walk_filled(value: Any, prefix: str, into: set[str]) -> None:
    """Record every NCM leaf that came out populated.

    Empty string, empty list, empty dict and None all count as absent — they are what a
    parser leaves behind when it did not find something, and the point of this pass is to
    separate "parsed and false" from "never parsed".
    """
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"provenance", "raw_unparsed", "ncm_version"}:
                continue
            walk_filled(child, f"{prefix}.{key}" if prefix else key, into)
        return

    if isinstance(value, list):
        if value:
            into.add(prefix)
            # One representative element, so a list of interfaces reports which interface
            # fields parse rather than only that interfaces exist.
            walk_filled(value[0], prefix, into)
        return

    if value not in (None, "", {}, []):
        into.add(prefix)


def analyse(path: Path, platform: str, report: PlatformReport, *, keep_worst: int) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    report.files += 1

    try:
        ncm = get_parser(platform).parse(ParseContext(text=text, command="show running-config"))
    except Exception as exc:
        report.failures.append((str(path), f"{type(exc).__name__}: {exc}"))
        return

    total = meaningful_lines(text)
    report.total_lines += total

    if ncm.parse_failed:
        # Read none of it. Scoring this by lines-minus-unparsed gives 100%, because a
        # wholesale failure records one explanatory line however long the input was —
        # which is how 104 PAN-OS files that produced nothing averaged 93.8% here on the
        # first run, and how the product itself rendered a green "100% parsed" pill.
        report.unreadable += 1
        report.coverages.append(0.0)
        report.worst.append((0.0, str(path)))
        report.worst.sort()
        del report.worst[keep_worst:]
        return

    coverage = 100.0 * (total - len(ncm.raw_unparsed)) / total if total else 0.0
    report.coverages.append(coverage)

    report.worst.append((coverage, str(path)))
    report.worst.sort()
    del report.worst[keep_worst:]

    for entry in ncm.raw_unparsed:
        # `raw_unparsed` entries are "<line number>: <text>".
        _, _, line = entry.partition(": ")
        report.shapes[shape_of(line)] += 1

    filled: set[str] = set()
    walk_filled(ncm.model_dump(mode="json"), "", filled)
    report.filled.update(filled)


def render(reports: dict[str, PlatformReport], *, verbose: bool, top: int) -> None:
    print(f"\n{'platform':<22}{'files':>7}{'unread':>8}{'median':>9}{'lines':>10}")
    print("─" * 56)
    for platform, report in sorted(reports.items()):
        print(
            f"{platform:<22}{report.files:>7}{report.unreadable:>8}"
            f"{report.median_coverage:>8.1f}%{report.total_lines:>10,}"
        )
    print("\n  unread = the parser could not read the file at all. Those score 0, not 100:")
    print("  a wholesale failure records one unparsed line however long the input was.")

    for platform, report in sorted(reports.items()):
        if not report.parsed and not report.failures:
            continue

        print(f"\n\n══ {platform} ══")

        if report.failures:
            print(f"\n  RAISED ({len(report.failures)}) — a parser must never raise (FR-PARSE-03):")
            for name, error in report.failures[:top]:
                print(f"    {Path(name).name:<44} {error}")

        if report.shapes:
            print(f"\n  Unrecognised constructs, most common first (top {top}):")
            for construct, count in report.shapes.most_common(top):
                print(f"    {count:>6} x  {construct}")

        if report.worst:
            print("\n  Lowest coverage:")
            for coverage, name in report.worst:
                print(f"    {coverage:>6.1f}%  {Path(name).name}")

        if report.parsed:
            print("\n  NCM fields never populated in any file — checks reading these")
            print("  report Not Evaluated on every device in this corpus:")
            never = sorted(EXPECTED_FIELDS - set(report.filled))
            for name in never[:top] if not verbose else never:
                print(f"    {name}")
            if not never:
                print("    (none — every expected field parsed at least once)")

            print("\n  Populated in under a quarter of files:")
            rare = sorted(
                (count / report.parsed, name)
                for name, count in report.filled.items()
                if count / report.parsed < 0.25
            )
            for share, name in rare[:top]:
                print(f"    {share:>6.0%}  {name}")
            if not rare:
                print("    (none)")


#: Fields a check somewhere depends on. Listed explicitly rather than derived from the
#: model, because "this field is never populated" is only interesting for fields
#: something actually reads — the NCM carries plenty that no check consults yet.
#:
#: Every name here is checked against the live model at startup by
#: :func:`verify_expected_fields`. The first draft of this list was written from memory
#: and five of nineteen entries named fields that do not exist (`system.hostname` for
#: `device.hostname`, `crypto.ssh_ciphers` for `management.services.ssh.ciphers`, and so
#: on) — each of which would have been reported as a parser that never populates it.
#: A tool that manufactures defects is worse than no tool, so the check is not optional.
EXPECTED_FIELDS: set[str] = {
    "device.hostname",
    "device.version",
    "device.model",
    "device.serials",
    "management.services.telnet.enabled",
    "management.services.http.enabled",
    "management.services.ssh.enabled",
    "management.services.ssh.ciphers",
    "management.services.ssh.kex",
    "management.services.ssh.macs",
    "management.services.ssh.version",
    "management.password_policy.min_length",
    "management.banners.login",
    "aaa.authentication.methods",
    "aaa.servers.host",
    "interfaces.name",
    "interfaces.ip_addresses",
    "routing.routes.destination",
    "routing.routes.next_hop",
    "logging.syslog_servers.host",
    "ntp.servers.host",
    "users.privilege",
}


def verify_expected_fields() -> list[str]:
    """Return any EXPECTED_FIELDS path the NCM does not actually define."""
    from pydantic import BaseModel

    from netsecops.ncm.models import NormalisedConfig

    def leaves(model: type[BaseModel], prefix: str = "", depth: int = 0) -> set[str]:
        found: set[str] = set()
        if depth > 4:
            return found
        for name, info in model.model_fields.items():
            path = f"{prefix}.{name}" if prefix else name
            nested: type[BaseModel] | None = None
            candidates = [info.annotation, *getattr(info.annotation, "__args__", ())]
            for candidate in candidates:
                if isinstance(candidate, type) and issubclass(candidate, BaseModel):
                    nested = candidate
                    break
                for inner in getattr(candidate, "__args__", ()):
                    if isinstance(inner, type) and issubclass(inner, BaseModel):
                        nested = inner
                        break
                if nested:
                    break
            if nested is not None:
                found |= leaves(nested, path, depth + 1)
            else:
                found.add(path)
        return found

    return sorted(EXPECTED_FIELDS - leaves(NormalisedConfig))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path, help="Directory of configurations")
    parser.add_argument("--platform", help="Force a platform instead of detecting one")
    parser.add_argument("--top", type=int, default=15, help="Rows per section (default 15)")
    parser.add_argument("--json", type=Path, help="Also write the full result as JSON")
    parser.add_argument("--verbose", action="store_true", help="List every missing field")
    args = parser.parse_args()

    if not args.corpus.is_dir():
        print(f"{args.corpus} is not a directory.", file=sys.stderr)
        return 2

    if missing := verify_expected_fields():
        print("EXPECTED_FIELDS names fields the NCM does not define:", file=sys.stderr)
        for name in missing:
            print(f"    {name}", file=sys.stderr)
        print(
            "\nFix the list rather than the model — reporting a nonexistent field as",
            file=sys.stderr,
        )
        print("never populated invents a defect and hides the real ones.", file=sys.stderr)
        return 2

    reports: dict[str, PlatformReport] = defaultdict(lambda: PlatformReport(platform="?"))
    unknown: list[Path] = []

    for path in sorted(args.corpus.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in CONFIG_SUFFIXES:
            continue

        text = path.read_text(encoding="utf-8", errors="replace")
        platform = args.platform or detect_platform(path, text)
        if platform is None:
            unknown.append(path)
            continue

        report = reports[platform]
        report.platform = platform
        analyse(path, platform, report, keep_worst=5)

    if not reports:
        print(
            "No configurations recognised. Use --platform, or name directories after",
            file=sys.stderr,
        )
        print(f"a platform: {', '.join(sorted(PARSERS))}", file=sys.stderr)
        return 1

    render(reports, verbose=args.verbose, top=args.top)

    if unknown:
        print(f"\n\n{len(unknown)} file(s) no signature matched — not counted anywhere:")
        for path in unknown[:10]:
            print(f"    {path}")

    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    platform: {
                        "files": report.files,
                        "parsed": report.parsed,
                        "median_coverage": round(report.median_coverage, 2),
                        "total_lines": report.total_lines,
                        "failures": report.failures,
                        "unparsed_shapes": report.shapes.most_common(200),
                        "field_fill": {
                            name: round(count / report.parsed, 3)
                            for name, count in sorted(report.filled.items())
                            if report.parsed
                        },
                        "never_filled": sorted(EXPECTED_FIELDS - set(report.filled)),
                    }
                    for platform, report in sorted(reports.items())
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"\nWritten to {args.json}")

    # A parser that raised is a defect by FR-PARSE-03, whatever the coverage says.
    return 1 if any(report.failures for report in reports.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
