"""Loading the check library (FR-CHK-01, FR-CHK-04).

Checks live in ``netsecops/checks/library/<vendor-or-common>/<id>.yaml``, inside the
package rather than beside it, so they ship in the wheel and the Docker image without
a separate data-file step.

A malformed check file is a loud failure at load time, not a silent omission. The
alternative — skipping what will not parse — produces a system that quietly assesses
less than it claims to, and nobody notices until an auditor asks why a control has no
result.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from netsecops.checks.schema import CheckDefinition
from netsecops.core.logging import get_logger

log = get_logger(__name__)

LIBRARY_ROOT = Path(__file__).parent / "library"


class CheckLoadError(Exception):
    """A check file is malformed. Carries the path, because that is what gets fixed."""


@dataclass(frozen=True, slots=True)
class LoadedCheck:
    definition: CheckDefinition
    #: Which directory it came from — `cisco`, `common`, or a custom pack.
    pack: str
    source: Path

    @property
    def id(self) -> str:
        return self.definition.id


def _read(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CheckLoadError(f"{path}: not valid YAML — {exc}") from exc

    if not isinstance(raw, dict):
        raise CheckLoadError(
            f"{path}: expected a mapping at the top level, got {type(raw).__name__}."
        )
    return raw


def load_file(path: Path, *, pack: str | None = None) -> LoadedCheck:
    """Load and validate one check file."""
    data = _read(path)

    try:
        definition = CheckDefinition.model_validate(data)
    except ValidationError as exc:
        raise CheckLoadError(f"{path}: {explain_validation_error(exc)}") from exc

    if definition.id != path.stem:
        raise CheckLoadError(
            f"{path}: the check id is {definition.id!r} but the file is named "
            f"{path.stem!r}. They must match, so a check can be found by its id."
        )

    return LoadedCheck(definition=definition, pack=pack or path.parent.name, source=path)


def explain_validation_error(error: ValidationError) -> str:
    """Turn a Pydantic error into something a check author can act on.

    Shared with the custom-check endpoint so an author sees the same wording whether
    their definition came from a file or from the UI editor.
    """
    parts = []
    for item in error.errors():
        location = ".".join(str(piece) for piece in item["loc"]) or "(root)"
        parts.append(f"{location}: {item['msg']}")
    return "; ".join(parts)


def iter_check_files(root: Path | None = None) -> Iterator[Path]:
    base = root or LIBRARY_ROOT
    if not base.exists():
        return
    yield from sorted(base.rglob("*.yaml"))


def load_library(root: Path | None = None) -> list[LoadedCheck]:
    """Load every check, failing on the first malformed or duplicated one."""
    loaded: list[LoadedCheck] = []
    by_id: dict[str, Path] = {}

    for path in iter_check_files(root):
        check = load_file(path)
        if check.id in by_id:
            raise CheckLoadError(
                f"{path}: duplicate check id {check.id!r}, already defined in {by_id[check.id]}. "
                "Ids are the identity of every finding they produce, so they must be unique."
            )
        by_id[check.id] = path
        loaded.append(check)

    log.info("checks.loaded", count=len(loaded), packs=sorted({c.pack for c in loaded}))
    return loaded


class CheckRegistry:
    """An indexed, queryable view of the library."""

    def __init__(self, checks: list[LoadedCheck]) -> None:
        self._checks = checks
        self._by_id = {check.id: check for check in checks}

    def __len__(self) -> int:
        return len(self._checks)

    def __iter__(self) -> Iterator[LoadedCheck]:
        return iter(self._checks)

    def get(self, check_id: str) -> CheckDefinition | None:
        found = self._by_id.get(check_id)
        return found.definition if found else None

    def require(self, check_id: str) -> CheckDefinition:
        definition = self.get(check_id)
        if definition is None:
            raise KeyError(f"No check with id {check_id!r} is loaded.")
        return definition

    @property
    def ids(self) -> list[str]:
        return sorted(self._by_id)

    def definitions(self) -> list[CheckDefinition]:
        return [check.definition for check in self._checks]

    def for_pack(self, pack: str) -> list[CheckDefinition]:
        return [c.definition for c in self._checks if c.pack == pack]

    def for_platform(self, platform: str, *, vendor: str | None = None) -> list[CheckDefinition]:
        """Checks whose applicability does not exclude this platform.

        Used to answer "what would run against this device" without evaluating
        anything — the FR-CHK-06 dry run and the policy editor both need it.
        """
        selected = []
        for check in self._checks:
            rules = check.definition.applicability
            if rules.platforms and platform.lower() not in {p.lower() for p in rules.platforms}:
                continue
            if (
                vendor
                and rules.vendors
                and vendor.lower() not in {v.lower() for v in rules.vendors}
            ):
                continue
            selected.append(check.definition)
        return selected

    def by_framework(self, framework: str) -> list[CheckDefinition]:
        """Checks mapped to a compliance framework, for pivoting a report (FR-CHK-05)."""
        return [
            check.definition
            for check in self._checks
            if check.definition.references.frameworks().get(framework)
        ]

    def frameworks(self) -> set[str]:
        found: set[str] = set()
        for check in self._checks:
            found.update(check.definition.references.frameworks())
        return found


@lru_cache(maxsize=1)
def get_registry() -> CheckRegistry:
    """The shipped library, loaded once per process.

    Cached because the library is read-only at runtime: custom checks (FR-CHK-06) are
    stored in the database and merged by the service layer, not written back here.
    """
    return CheckRegistry(load_library())


__all__ = [
    "LIBRARY_ROOT",
    "CheckLoadError",
    "CheckRegistry",
    "LoadedCheck",
    "explain_validation_error",
    "get_registry",
    "load_file",
    "load_library",
]
