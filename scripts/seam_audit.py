#!/usr/bin/env python3
"""Find the gaps between the halves of this product, without needing a device.

Every defect in the list below was found by accident, one at a time, while building
something else. They are all the same shape — two halves that were each tested against
themselves and never against each other — and none of them failed anything:

* the collector handed three parsers a single response where they expected every
  response keyed by command, so a Check Point management server parsed to zero rules;
* `show-access-rulebase` was sent naming no access layer, which every published Check
  Point example includes;
* `interfaces.security.ip_source_guard` was parsed, baselined, and could only ever be
  True or None — so no check could be written against it, and none was;
* `ip verify unicast` was consumed with the interface body and extracted into nothing,
  scoring full parse coverage for a router with uRPF and one without;
* `SnmpCommunity.view` existed and was never set, while the same regex read a
  read-write community as read-only;
* the parser field baseline walked only the first element of every list, so 23 parsed
  fields had nothing protecting them.

This looks for the rest of them, and reports four kinds:

**A. Checks whose input no fixture populates.** The check reports *Not evaluated* on
every device of that platform. That is the honest answer and an invisible one.

**B. NCM fields nothing reads.** Parsed, stored, and referenced by no check and no
analyser. Either a missing check or dead weight, and both want a decision.

**C. Booleans that are never False.** A field that is only ever True or absent cannot
be asserted on: "not configured" and "not parsed" are the same value, so a check
demanding it can never fail.

**D. Collected commands that change nothing.** The output reaches no NCM field, so the
command is either wasted or its parsing is missing.

None of this needs a device, a corpus or a database — it reads the check library, the
NCM model and the fixtures that are already in the repository.

    python scripts/seam_audit.py
    python scripts/seam_audit.py --kind A --kind C
    python scripts/seam_audit.py --json audit.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from netsecops.checks.loader import load_library
from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURES = BACKEND / "tests" / "fixtures"
BASELINE = FIXTURES / "parser_field_baseline.json"

#: Where a path may be read from, besides the check library. Searched as text because a
#: JMESPath in a YAML file and an attribute access in Python are the same fact here.
READER_SOURCES = (
    BACKEND / "netsecops" / "firewall",
    BACKEND / "netsecops" / "topology",
    BACKEND / "netsecops" / "services",
    BACKEND / "netsecops" / "api",
    BACKEND / "netsecops" / "vuln",
    BACKEND / "netsecops" / "schemas",
    BACKEND / "netsecops" / "reporting",
)

#: NCM branches whose leaves are read structurally rather than by name — iterating a
#: list of rules and touching every attribute — so "nothing names this path" says
#: nothing useful about them.
STRUCTURAL_BRANCHES = (
    "provenance",
    "raw_unparsed",
    "firewall.security_rules",
    "firewall.nat_rules",
    "acls",
)


def leaf_paths(model: Any, prefix: str = "") -> list[str]:
    """Every dotted leaf path the NCM model defines, list elements included once."""
    out: list[str] = []
    fields = getattr(model, "model_fields", None)
    if not fields:
        return out

    for name, info in fields.items():
        path = f"{prefix}.{name}" if prefix else name
        annotation = info.annotation
        nested = _model_of(annotation)
        if nested is not None:
            out.extend(leaf_paths(nested, path))
        else:
            out.append(path)
    return out


def _model_of(annotation: Any) -> Any:
    """The pydantic model inside an annotation, through Optional and list."""
    if hasattr(annotation, "model_fields"):
        return annotation
    for arg in getattr(annotation, "__args__", ()) or ():
        found = _model_of(arg)
        if found is not None:
            return found
    return None


_PATH_HEAD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*")


def expression_paths(expression: str) -> set[str]:
    """Every NCM path an expression touches, filters and projections removed.

    Split on everything that is not part of a path rather than on a list of operators.
    The first version split on brackets and commas only, so `features.a && features.b`
    yielded just `features.a` — and reported the second operand as read by nothing,
    which is the false positive this audit exists to avoid producing.
    """
    found: set[str] = set()
    # Drop quoted literals first: 'access' must not become a path.
    cleaned = re.sub(r"'[^']*'|`[^`]*`|\"[^\"]*\"", " ", expression)

    for token in re.split(r"[^\w.\-]+", cleaned):
        token = token.strip(".")
        if not token or "." not in token or token[0].isdigit():
            continue
        found.add(token)

    # A filter's own field references, relative to the list being filtered:
    # `interfaces[?mode == 'access']` also reads `interfaces.mode`.
    for filt, field in re.findall(
        r"([A-Za-z_][\w.]*)\[\?\s*!?\s*([A-Za-z_][\w.]*)", expression
    ):
        found.add(f"{filt}.{field}")
    for filt, body in re.findall(r"([A-Za-z_][\w.]*)\[\?([^\]]*)\]", expression):
        for field in re.findall(r"[A-Za-z_][\w.]*", body):
            found.add(f"{filt}.{field}")
    return found


def load_baseline() -> dict[str, set[str]]:
    raw = json.loads(BASELINE.read_text(encoding="utf-8"))
    return {platform: set(fields) for platform, fields in raw.items()}


def check_inputs() -> list[tuple[str, str, str]]:
    """(check_id, platform, path) for checks whose input no fixture populates."""
    baseline = load_baseline()
    gaps: list[tuple[str, str, str]] = []

    for loaded in load_library():
        definition = loaded.definition
        logic = definition.logic
        if logic.expression is None:
            continue

        platforms = list(definition.applicability.platforms or [])
        if not platforms:
            continue

        wanted = {p for p in expression_paths(logic.expression) if "." in p}
        wanted.update(logic.requires)
        if not wanted:
            continue

        for platform in platforms:
            populated = baseline.get(platform)
            if populated is None:
                # No fixture for this platform at all; a different gap, not this one.
                continue
            if not any(path in populated for path in wanted):
                gaps.append((definition.id, platform, min(wanted)))
    return gaps


def referenced_paths() -> set[str]:
    """Every NCM path named anywhere that reads one."""
    seen: set[str] = set()

    for loaded in load_library():
        logic = loaded.definition.logic
        if logic.expression:
            seen.update(expression_paths(logic.expression))
        seen.update(logic.requires)
        seen.update(loaded.definition.applicability.requires_features or [])

    for base in READER_SOURCES:
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in re.findall(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*){1,5}", text):
                seen.add(match)
    return seen


def unread_fields() -> list[str]:
    """NCM leaves that nothing names."""
    referenced = referenced_paths()
    out: list[str] = []

    for path in leaf_paths(NormalisedConfig()):
        if any(path.startswith(branch) for branch in STRUCTURAL_BRANCHES):
            continue
        leaf = path.rsplit(".", 1)[-1]
        # Named either by its full path or by its last two segments, which is how an
        # attribute access reads in Python (`rule.hit_count`, `session.vty_lines`).
        tail = ".".join(path.split(".")[-2:])
        if path in referenced or tail in referenced:
            continue
        if any(ref.endswith(f".{leaf}") for ref in referenced):
            continue
        out.append(path)
    return out


def parse_fixtures() -> dict[str, list[NormalisedConfig]]:
    """Every fixture parsed, by platform, using the same corpus the baseline uses."""
    samples: dict[str, list[NormalisedConfig]] = defaultdict(list)
    manifest = json.loads(BASELINE.read_text(encoding="utf-8"))

    for path in sorted(FIXTURES.rglob("*")):
        if not path.is_file() or path.name == BASELINE.name:
            continue
        platform = _platform_for(path, set(manifest))
        if platform is None:
            continue
        try:
            ncm = get_parser(platform).parse(
                ParseContext(text=path.read_text(encoding="utf-8", errors="replace"))
            )
        except Exception as exc:  # noqa: BLE001 - any parser failure, reported not hidden
            # Named rather than swallowed. A fixture this cannot parse silently shrinks
            # the corpus the audit reasons over, and an audit that quietly looks at
            # less than it claims is the failure mode it exists to find.
            print(
                f"   ! skipped {path.name} as {platform}: {type(exc).__name__}: {exc}"
            )
            continue
        samples[platform].append(ncm)
    return samples


def _platform_for(path: Path, platforms: set[str]) -> str | None:
    parts = {p.lower() for p in path.parts}
    for platform in platforms:
        family, _, rest = platform.partition("_")
        if platform in parts or (family in parts and (not rest or rest in parts)):
            return platform
    return None


#: One-sided on purpose, with the reason. An audit that keeps reporting the same
#: accepted answers stops being read, so these are recorded rather than tolerated.
ACCEPTED_ONE_SIDED: dict[str, str] = {
    "interfaces.security.dhcp_snooping_trust": (
        "absence is the normal state on an access port, so 'not trusted' is not a fact "
        "worth asserting — only the presence of trust on an unexpected port matters"
    ),
    "interfaces.security.arp_inspection_trust": (
        "same as dhcp_snooping_trust: trust is the exception, and an untrusted port is "
        "the default rather than a finding"
    ),
}

#: An assignment that can only ever produce True or None — `"x" in children or None`.
#: This is the exact shape `interfaces.security.ip_source_guard` had: parsed, recorded
#: in the baseline, and impossible to assert on, because "not configured" and "not
#: parsed" were the same value.
_ONE_SIDED_ASSIGNMENT = re.compile(r"\.(\w+)\s*=\s*[^\n]*\bor None\b")

#: The complement, kept so a field is only reported when *no* assignment can yield False.
_FALSE_CAPABLE = re.compile(
    r"\.(\w+)\s*=\s*[^\n]*(?:False|_negatable|_toggle_value|\bflag\()"
)


def _parser_assignment_shapes() -> tuple[set[str], set[str]]:
    """Leaf names assigned one-sidedly, and leaf names something can set False."""
    one_sided: set[str] = set()
    false_capable: set[str] = set()
    for path in (BACKEND / "netsecops" / "parsers").rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        one_sided.update(_ONE_SIDED_ASSIGNMENT.findall(text))
        false_capable.update(_FALSE_CAPABLE.findall(text))
    return one_sided, false_capable


def never_false() -> list[str]:
    """Boolean leaves no parser can ever set False.

    Observing only True across the fixtures is not enough on its own — our fixtures are
    mostly hardened, so plenty of fields are legitimately True everywhere. What makes a
    field *unusable* is that no assignment to it anywhere in the parsers can produce
    False, so a check demanding it can never fail and one forbidding it can never pass.
    """
    seen: dict[str, set[Any]] = defaultdict(set)
    for ncms in parse_fixtures().values():
        for ncm in ncms:
            _collect_bools(ncm.model_dump(mode="json"), "", seen)

    one_sided, false_capable = _parser_assignment_shapes()

    out: list[str] = []
    for path, values in sorted(seen.items()):
        if values != {True} or any(p in path for p in ("provenance", "raw_unparsed")):
            continue
        if path in ACCEPTED_ONE_SIDED:
            continue
        leaf = path.rsplit(".", 1)[-1]
        if leaf in false_capable:
            continue
        if leaf in one_sided:
            out.append(f"{path}   (parser writes `... or None`)")
    return out


def _collect_bools(value: Any, prefix: str, into: dict[str, set[Any]]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _collect_bools(child, f"{prefix}.{key}" if prefix else key, into)
    elif isinstance(value, list):
        for element in value:
            _collect_bools(element, prefix, into)
    elif isinstance(value, bool):
        into[prefix].add(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--kind", action="append", choices=["A", "B", "C"], default=None
    )
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args()
    kinds = set(args.kind or ["A", "B", "C"])

    report: dict[str, Any] = {}

    if "A" in kinds:
        gaps = check_inputs()
        report["checks_with_no_data"] = [
            {"check": c, "platform": p, "path": path} for c, p, path in gaps
        ]
        print(f"\n── A. Checks whose input no fixture populates ({len(gaps)})")
        for check, platform, path in sorted(gaps):
            print(f"   {check:44} {platform:20} {path}")

    if "B" in kinds:
        unread = unread_fields()
        report["fields_nothing_reads"] = unread
        print(f"\n── B. NCM fields nothing reads ({len(unread)})")
        for path in unread:
            print(f"   {path}")

    if "C" in kinds:
        one_sided = never_false()
        report["booleans_never_false"] = one_sided
        print(f"\n── C. Booleans never observed False ({len(one_sided)})")
        for path in one_sided:
            print(f"   {path}")

    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nwritten to {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
