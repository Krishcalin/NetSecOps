"""Shipped policy packs (FR-CHK-05).

A pack is a named, versioned selection of checks — "CIS Cisco IOS L1" — that ships with
the product and is installed into an organisation's database on first run.

Installed rather than read directly, for one reason: a policy has to be *editable*. An
operator disabling one check or raising one severity must not be fighting a file that
gets overwritten on upgrade. So the pack seeds a row, and from then on the row is
authoritative. Re-running the seed adds packs that are new and leaves existing ones
alone unless the pack's version has increased.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from netsecops.checks.loader import CheckLoadError
from netsecops.core.logging import get_logger

log = get_logger(__name__)

PACKS_ROOT = Path(__file__).parent / "policies"


class PolicyEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    enabled: bool = True
    #: Raising or lowering a check's severity for this policy's context.
    severity: str | None = None
    notes: str | None = None


class PolicyPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=150)
    description: str | None = None
    source: str = Field(min_length=1, max_length=64)
    version: int = 1
    frameworks: list[str] = Field(default_factory=list)
    checks: list[PolicyEntry] = Field(min_length=1)

    @property
    def check_ids(self) -> list[str]:
        return [entry.id for entry in self.checks]


@dataclass(frozen=True, slots=True)
class LoadedPack:
    pack: PolicyPack
    source_file: Path
    unknown_checks: tuple[str, ...] = field(default=())


def load_packs(
    root: Path | None = None, *, known_check_ids: set[str] | None = None
) -> list[LoadedPack]:
    """Load every shipped policy pack, validating the checks it names exist.

    A pack naming a check that is not in the library is a packaging mistake, not a
    runtime condition, so it is reported at load time. It is surfaced rather than
    raised: a policy missing one check of forty should still install, because refusing
    to install it would leave the device assessed against nothing at all.
    """
    base = root or PACKS_ROOT
    packs: list[LoadedPack] = []

    if not base.exists():
        return packs

    for path in sorted(base.glob("*.yaml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise CheckLoadError(f"{path}: not valid YAML — {exc}") from exc

        pack = PolicyPack.model_validate(raw)

        unknown: tuple[str, ...] = ()
        if known_check_ids is not None:
            unknown = tuple(sorted(set(pack.check_ids) - known_check_ids))
            if unknown:
                log.warning(
                    "policy_pack.unknown_checks",
                    pack=pack.source,
                    checks=list(unknown),
                )

        packs.append(LoadedPack(pack=pack, source_file=path, unknown_checks=unknown))

    log.info("policy_packs.loaded", count=len(packs), packs=[p.pack.source for p in packs])
    return packs


@lru_cache(maxsize=1)
def get_packs() -> list[LoadedPack]:
    from netsecops.checks.loader import get_registry

    return load_packs(known_check_ids=set(get_registry().ids))


def pack_payload(pack: PolicyPack) -> dict[str, Any]:
    """The pack as a plain dict, for storing alongside the seeded policy."""
    return pack.model_dump(mode="json")


__all__ = [
    "PACKS_ROOT",
    "LoadedPack",
    "PolicyEntry",
    "PolicyPack",
    "get_packs",
    "load_packs",
    "pack_payload",
]
