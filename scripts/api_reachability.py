"""P0.3 — which API operations the console can actually reach.

Reads the published OpenAPI schema (ground truth for what we ship) and scans the
frontend for the paths it requests, then reconciles the two.

The comparison is by path shape, not by exact string: a call built as
`/devices/${id}/snapshots` has to match the declared `/devices/{device_id}/snapshots`,
so both sides collapse their parameters to `*`.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from collections import defaultdict

FRONTEND = pathlib.Path(__file__).resolve().parents[1] / "frontend" / "src"


def declared() -> list[tuple[str, str]]:
    from netsecops.main import create_app

    spec = create_app().openapi()
    return sorted(
        (method.upper(), path)
        for path, item in spec["paths"].items()
        for method in item
        if method in {"get", "post", "put", "patch", "delete"}
    )


def requested() -> set[str]:
    """Every string in the console that looks like an API path.

    Deliberately generous: a path assembled from fragments should be counted as a call
    rather than reported as dead code. This audit is for finding capability nobody can
    reach, so a false "reachable" is a missed finding while a false "unreachable" is a
    wasted minute — the error is cheaper in that direction.
    """
    # The body allows everything except the closing quote, because a template literal's
    # `${...}` routinely contains spaces, quotes and ternaries — a tighter character
    # class silently drops exactly those calls, which is how an earlier version of this
    # audit reported /auth/logout as unreachable.
    #
    # Anchored on the path, with an optional leading interpolation so that
    # `${API_BASE}/auth/refresh` is seen — that miss reported /auth/refresh as
    # unreachable when the client calls it on every 401.
    #
    # The anchor has to stay. Matching *every* quoted string instead lets an apostrophe
    # in prose ("the client's token") open a match that runs to the next quote and
    # swallows the real path literals in between, which cuts the reachable count rather
    # than raising it.
    head = r"(?:\$\{[^}]*\})?"
    literal = re.compile(rf"'({head}/[^']*)'" rf"|\"({head}/[^\"]*)\"" rf"|`({head}/[^`]*)`")
    calls: set[str] = set()
    for file in FRONTEND.rglob("*"):
        if file.suffix not in {".ts", ".tsx"}:
            continue
        text = open(file, encoding="utf-8").read()
        consts = constants(text)
        for groups in literal.findall(text):
            found = next((g for g in groups if g), "")
            # Substitute module-level path constants first. `const DELIVERIES =
            # '/notifications/deliveries'` used as `${DELIVERIES}/${id}/requeue` is a
            # common shape, and treating the leading `${...}` as noise turns it into
            # /*/requeue — which matches nothing and reports a live call as dead.
            found = re.sub(r"\$\{(\w+)\}", lambda m: consts.get(m.group(1), m.group(0)), found)
            found = re.sub(r"^\$\{[^}]*\}", "", found)
            if not found.startswith("/"):
                continue
            shaped = shape(found)
            calls.add(shaped)
            # A trailing interpolation is a query string or suffix appended to the
            # route, not another path segment: `/…/rulebase${toQuery(filters)}` calls
            # /…/rulebase. Only strip it when it is glued to the last segment — a
            # genuine trailing path parameter ends in "/*" and must be kept.
            if shaped.endswith("*") and not shaped.endswith("/*"):
                calls.add(shaped[:-1].rstrip("/") or "/")
    return calls


def constants(text: str) -> dict[str, str]:
    """Module-level `const NAME = '/some/path'` bindings, for interpolation."""
    pattern = re.compile(r"""^const\s+(\w+)\s*=\s*['"`](/[^'"`$]*)['"`]""", re.MULTILINE)
    return {name: value for name, value in pattern.findall(text)}


def shape(path: str) -> str:
    path = path.removeprefix("/api/v1").removeprefix("/api")
    path = re.sub(r"\$\{[^}]*\}", "*", path)  # template expression, before the {} rule
    path = re.sub(r"\{[^}]+\}", "*", path)  # OpenAPI parameter
    path = re.sub(r"/:[a-zA-Z_]+", "/*", path)
    path = path.split("?", 1)[0]  # query string is not part of the route
    return path.rstrip("/") or "/"


def main() -> None:
    ops = declared()
    calls = requested()

    reachable, unreachable = [], []
    for method, path in ops:
        (reachable if shape(path) in calls else unreachable).append((method, path))

    print(f"Operations published in OpenAPI : {len(ops)}")
    print(f"  path referenced by the console: {len(reachable)}")
    print(f"  never referenced              : {len(unreachable)}")
    print()

    areas: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for method, path in unreachable:
        parts = shape(path).strip("/").split("/")
        areas[parts[0] if parts and parts[0] else "(root)"].append((method, path))

    print("── never referenced by the console ──")
    for area in sorted(areas, key=lambda a: (-len(areas[a]), a)):
        print(f"\n{area}  ({len(areas[area])})")
        for method, path in sorted(areas[area], key=lambda e: (e[1], e[0])):
            print(f"    {method:6} {path}")

    # Opt-in, and never beside the script: a JSON artefact written on every run ends up
    # committed by somebody eventually.
    if len(sys.argv) > 1:
        out = pathlib.Path(sys.argv[1])
        out.write_text(
            json.dumps(
                {
                    "total": len(ops),
                    "reachable": [list(e) for e in reachable],
                    "unreachable": [list(e) for e in unreachable],
                },
                indent=2,
            )
        )
        print(f"\nwritten: {out}")


if __name__ == "__main__":
    main()
