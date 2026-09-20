"""Checking the CPE product names against evidence (FR-VUL-02).

``vuln/cpe.py`` maps each platform to the CPE vendor and product the dictionary is
*expected* to use — `cisco_asa` to `cisco:adaptive_security_appliance_software`, and so
on. Those names were written from documentation, never confirmed, and
:func:`~netsecops.vuln.cpe.unverified_products` has existed since Phase 6 as the list of
what needed confirming. Nothing called it, because confirming meant holding the NVD CPE
dictionary and the repository has none.

**It does not need one.** Every NVD advisory imported carries the real CPE strings NVD
itself uses, and those are stored on the advisory. So the names can be checked against
the corpus already in the database: a product name that appears in an imported advisory
is corroborated by NVD's own spelling, and one that never appears is not.

**What counts as a contradiction took two attempts, and the first was wrong.** The
obvious rule — advisories exist for this vendor and none names our product — flags any
product the corpus happens not to cover. Run against this repository's own fixtures it
called four Cisco names wrong purely because the corpus holds two advisories; Cisco
publishes for hundreds of products, so holding two of them contradicts nothing. That
report is worse than no report: an operator chases it, finds nothing, and stops reading.

The real failure is narrower and this targets it: a name written one way where NVD writes
it another — ``foo-bar`` against ``foo_bar`` — is not a gap in the corpus, it is one of the
two being wrong. So a contradiction requires the same name under different
**punctuation**, and anything else is *no evidence*.

(This used to illustrate that with ``nx-os`` against NVD's ``nx_os``. The dictionary was
queried on 2026-09-19 and NVD writes ``nx-os``, so the example asserted the opposite of
the truth about a mapping that is correct. Replaced with a neutral one.)

**What this method cannot find**, and the reason it is not the only check: a product name
that nothing has ever published reads as *no evidence*, which is the same answer as a
name that is right but uncovered. Two entries were wrong that way — see
:data:`~netsecops.vuln.cpe.NO_DICTIONARY_ENTRY` — and only a direct dictionary query
found them. This corroborates against the corpus; it does not confirm existence.

Not string similarity, which was the second attempt and also wrong: ``ios_xe`` and
``ios_xr`` score 0.8 against each other and are different operating systems. Vendors name
whole families that way, so similarity cannot tell a misspelling from a sibling product.

That specificity matters because the defect fails **silently**. A wrong product name
produces no error, no unparsed record and no warning: the device simply matches nothing,
which on the vulnerability page is indistinguishable from a device that has none. It is
the one defect in the matcher that makes an estate look safer than it is, and the only
way to catch it is to be precise enough that the finding is worth acting on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.logging import get_logger
from netsecops.db.models.vulnerability import VulnAdvisory
from netsecops.vuln.cpe import PRODUCTS, product_key

log = get_logger(__name__)


class Corroboration(StrEnum):
    """What the imported corpus says about one product name."""

    #: An imported advisory uses this exact vendor and product.
    CORROBORATED = "corroborated"
    #: The corpus carries a *near-miss* for this vendor — a product name close enough to
    #: ours that one of them is a misspelling of the other. `nx-os` against NVD's
    #: `nx_os`, say. This is the finding worth raising.
    CONTRADICTED = "contradicted"
    #: Nothing close was found. Says nothing either way, and must not be reported as a
    #: problem.
    NO_EVIDENCE = "no-evidence"


#: Punctuation that vendors and NVD disagree about, and which is enough on its own to
#: make a product name match nothing.
_SEPARATORS = str.maketrans("", "", "-_.")


@dataclass(slots=True)
class ProductCoverage:
    """One platform's CPE name, and whether the corpus backs it up."""

    platform: str
    vendor: str
    product: str
    status: Corroboration
    #: Product names the corpus *does* carry for this vendor. On a contradiction these
    #: are the candidates — usually the right name is visibly among them.
    vendor_products_seen: list[str] = field(default_factory=list)
    advisories_for_vendor: int = 0
    #: The near-miss that triggered a contradiction, so the report says what it thinks
    #: the name should be rather than only that something is wrong.
    closest_match: str | None = None

    @property
    def concerning(self) -> bool:
        return self.status is Corroboration.CONTRADICTED


@dataclass(slots=True)
class CpeCoverage:
    """The whole check, with the caveat that makes it readable."""

    products: list[ProductCoverage] = field(default_factory=list)
    advisories_examined: int = 0

    @property
    def contradicted(self) -> list[ProductCoverage]:
        return [entry for entry in self.products if entry.concerning]

    @property
    def limitations(self) -> list[str]:
        notes: list[str] = []
        if self.advisories_examined == 0:
            notes.append(
                "No advisories have been imported, so nothing could be checked. Every "
                "product name below is unconfirmed rather than wrong."
            )
        unknown = [e for e in self.products if e.status is Corroboration.NO_EVIDENCE]
        if unknown:
            notes.append(
                f"{len(unknown)} platform(s) have no advisory in the corpus naming their "
                "product and nothing close to it, so their CPE names could be neither "
                "confirmed nor contradicted. That is a gap in the corpus, not a fault in "
                "the name — importing advisories for those platforms is what would "
                "settle it."
            )
        return notes


def _normalise(name: str) -> str:
    """Strip the punctuation vendors and NVD disagree about.

    `nx-os` and `nx_os` are the same product written twice, and the difference is enough
    to match nothing at all.
    """
    return name.translate(_SEPARATORS)


def _closest(product: str, candidates: set[str]) -> str | None:
    """A candidate that is our name under different punctuation, or None.

    **Only punctuation.** An earlier version also accepted a high string-similarity
    score, on the reasoning that a name off by a character or two is probably a
    misspelling. The first realistic input disproved it: `ios_xe` and `ios_xr` score 0.8
    against each other and are two entirely different Cisco operating systems, so a
    corpus containing one would have reported the other as wrong.

    Fuzzy matching on product names cannot distinguish "misspelt" from "adjacent product
    in the same family", and vendors name whole families that way — `ios`, `ios_xe`,
    `ios_xr`, `nx-os`. So the rule is narrowed to the one difference that is never a
    different product: punctuation. Anything looser is reported as no-evidence, with the
    vendor's real product names listed beside it for a human to read.
    """
    if not candidates:
        return None

    normalised = _normalise(product)
    for candidate in sorted(candidates):
        if _normalise(candidate) == normalised:
            return candidate
    return None


def _vendor_product(cpe: str | None) -> tuple[str, str] | None:
    """The vendor and product of a CPE string, or None if it cannot be read."""
    if not cpe:
        return None
    key = product_key(cpe)
    if key is None:
        return None
    # `(part, vendor, product)`. The part is dropped deliberately: our table records
    # `cisco_ise` as an application and NVD sometimes files the same product under `o`,
    # and a name is corroborated by the vendor and product agreeing regardless.
    _part, vendor, product = key
    return vendor, product


class CpeCoverageService:
    """Checks the product table against the CPEs imported advisories actually use."""

    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id

    async def build(self) -> CpeCoverage:
        advisories = (
            (
                await self.session.execute(
                    select(VulnAdvisory).where(VulnAdvisory.org_id == self.org_id)
                )
            )
            .scalars()
            .all()
        )

        # vendor -> the set of product names the corpus carries for it.
        seen: dict[str, set[str]] = {}
        counts: dict[str, int] = {}

        for advisory in advisories:
            vendors_here: set[str] = set()
            # `affected` is declared as a list of dicts and the importer is the only
            # writer, so no isinstance guard here — mypy's `warn_unreachable` rightly
            # calls one dead, and a guard the type system says can never fire is a guard
            # nobody will maintain.
            for affected in advisory.affected or []:
                pair = _vendor_product(affected.get("cpe"))
                if pair is None:
                    # Fall back to the vendor/product the advisory stated in prose. It is
                    # weaker evidence than a CPE but it is the only evidence a CSAF
                    # advisory offers, and excluding it would report every CSAF-only
                    # vendor as having no evidence.
                    vendor = str(affected.get("vendor") or "").strip().lower()
                    product = str(affected.get("product") or "").strip().lower()
                    if not vendor or not product:
                        continue
                    pair = (vendor, product)

                vendor, product = pair
                seen.setdefault(vendor, set()).add(product)
                vendors_here.add(vendor)

            for vendor in vendors_here:
                counts[vendor] = counts.get(vendor, 0) + 1

        coverage = CpeCoverage(advisories_examined=len(advisories))

        for platform, name in sorted(PRODUCTS.items()):
            products_for_vendor = seen.get(name.vendor, set())
            closest: str | None = None

            if name.product in products_for_vendor:
                status = Corroboration.CORROBORATED
            elif (near := _closest(name.product, products_for_vendor)) is not None:
                # Not "this vendor has advisories and none is ours" — that is ordinary on
                # any corpus smaller than the whole of NVD. A name close enough to be a
                # misspelling is the signal.
                status, closest = Corroboration.CONTRADICTED, near
            else:
                status = Corroboration.NO_EVIDENCE

            coverage.products.append(
                ProductCoverage(
                    platform=platform,
                    vendor=name.vendor,
                    product=name.product,
                    status=status,
                    vendor_products_seen=sorted(products_for_vendor)[:20],
                    advisories_for_vendor=counts.get(name.vendor, 0),
                    closest_match=closest,
                )
            )

        log.info(
            "vuln.cpe_coverage",
            advisories=coverage.advisories_examined,
            corroborated=sum(
                1 for e in coverage.products if e.status is Corroboration.CORROBORATED
            ),
            contradicted=len(coverage.contradicted),
        )
        return coverage


def as_dict(coverage: CpeCoverage) -> dict[str, Any]:
    """Serialise for the API and for a report section."""
    return {
        "advisories_examined": coverage.advisories_examined,
        "products": [
            {
                "platform": entry.platform,
                "vendor": entry.vendor,
                "product": entry.product,
                "status": entry.status.value,
                "vendor_products_seen": entry.vendor_products_seen,
                "advisories_for_vendor": entry.advisories_for_vendor,
                # The most actionable field of the lot, and it was not being serialised:
                # the near-miss is what turns "this name is probably wrong" into "it is
                # probably meant to be this". Its own docstring says that is why it
                # exists, and neither the API nor the report was carrying it.
                "closest_match": entry.closest_match,
            }
            for entry in coverage.products
        ],
        "limitations": coverage.limitations,
    }


__all__ = [
    "Corroboration",
    "CpeCoverage",
    "CpeCoverageService",
    "ProductCoverage",
    "as_dict",
]
