"""CSAF 2.0 ingestion (FR-VUL-02).

CSAF is the format the SRS prefers, and Palo Alto, Fortinet and Cisco all publish it. A
document has two halves that must be read together:

* ``product_tree`` — nested branches that build up products from vendor, product name and
  version, each leaf carrying an opaque ``product_id``.
* ``vulnerabilities[].product_status`` — lists of those ``product_id`` values under
  ``known_affected``, ``fixed``, ``known_not_affected`` and so on.

Neither half means anything alone. A status list is a bag of identifiers like
``CSAFPID-0001``; the tree is where that resolves to "PAN-OS, versions below 11.0.3".
Resolving the two is most of this module.

**Where it goes wrong, and what is done about it.**

*A product_id in a status list that the tree never defines.* Vendors do publish these.
The identifier is real, the statement is real, and the product is unknown — so it is
recorded as an affected product with an ``UNPARSED`` constraint rather than dropped.
Dropping it makes a vulnerable device look clean.

*A version range written as prose.* CSAF has a formal ``vers`` grammar, and vendors
routinely ignore it: ``<11.0.3``, ``11.0.0 - 11.0.2``, ``all versions before 7.2.5``.
What can be read is read; what cannot keeps its text and is marked ``UNPARSED``. The
matcher then declines to rule the device out, which is the only safe direction.

*A branch with no version at all.* A ``product_name`` leaf with no version beneath it
means the whole product, which is ``ALL`` — a real answer, and different from a range
nobody could parse.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.vuln.advisory import (
    Advisory,
    AffectedProduct,
    ConstraintKind,
    Score,
    VersionConstraint,
)

log = get_logger(__name__)

#: Branch categories that name a product rather than qualify one.
_VENDOR = "vendor"
_PRODUCT_NAME = "product_name"
_PRODUCT_VERSION = "product_version"
_PRODUCT_VERSION_RANGE = "product_version_range"

#: `<11.0.3`, `<=10.2.8`, `>=10.2.0`, `>10.1`
_COMPARATOR = re.compile(r"^\s*(?P<op><=|>=|<|>)\s*(?P<version>[\w.()\-]+)\s*$")

#: `>=10.2.0 <10.2.9` — two comparators, the CSAF `vers` shape most vendors manage.
_TWO_SIDED = re.compile(
    r"^\s*(?P<lo_op>>=|>)\s*(?P<lo>[\w.()\-]+)\s+(?P<hi_op><=|<)\s*(?P<hi>[\w.()\-]+)\s*$"
)

#: `11.0.0 - 11.0.2`, an inclusive span.
_HYPHEN_SPAN = re.compile(r"^\s*(?P<lo>[\w.()]+)\s*-\s*(?P<hi>[\w.()]+)\s*$")

#: A bare version: `11.0.3`, `15.2(7)E3`, `R81.20`.
_BARE = re.compile(r"^\s*(?P<version>[\w.()\-]+)\s*$")


def parse_version_spec(raw: str) -> VersionConstraint:
    """Read a CSAF version-range string.

    Returns an ``UNPARSED`` constraint rather than guessing. That is the important half:
    a range this function silently mis-reads becomes a wrong verdict on every device
    running the product, and "I could not read this" is a supported answer everywhere
    downstream.
    """
    text = (raw or "").strip()
    if not text:
        return VersionConstraint(kind=ConstraintKind.UNPARSED, raw=raw)

    if match := _TWO_SIDED.match(text):
        # `>10.2.0` excludes its bound; the model's `introduced` is inclusive, so an
        # exclusive lower bound is not representable and the range stays unparsed rather
        # than being quietly widened by one release.
        if match["lo_op"] == ">":
            return VersionConstraint(kind=ConstraintKind.UNPARSED, raw=text)
        return VersionConstraint(
            kind=ConstraintKind.RANGE,
            raw=text,
            introduced=match["lo"],
            # `<=10.2.8` means 10.2.8 is affected, so the fix is not in it. The model's
            # `fixed` is exclusive and there is no way to name "the release after
            # 10.2.8" without inventing one, so an inclusive upper bound is left unparsed.
            fixed=match["hi"] if match["hi_op"] == "<" else None,
        )

    if match := _COMPARATOR.match(text):
        operator, version = match["op"], match["version"]
        if operator == "<":
            return VersionConstraint(kind=ConstraintKind.RANGE, raw=text, fixed=version)
        if operator == ">=":
            return VersionConstraint(kind=ConstraintKind.RANGE, raw=text, introduced=version)
        # `<=` and `>` are exclusive/inclusive in the directions the model cannot state
        # exactly. Marked unparsed rather than approximated by a release.
        return VersionConstraint(kind=ConstraintKind.UNPARSED, raw=text)

    if match := _HYPHEN_SPAN.match(text):
        # An inclusive span. The upper bound is affected, so it is not the fixed release
        # and cannot be stored as one; what is representable is the lower bound.
        return VersionConstraint(kind=ConstraintKind.UNPARSED, raw=text)

    if match := _BARE.match(text):
        return VersionConstraint(kind=ConstraintKind.EXACT, raw=text, version=match["version"])

    return VersionConstraint(kind=ConstraintKind.UNPARSED, raw=text)


class _ResolvedProduct:
    """What a ``product_id`` refers to, accumulated down the branch tree."""

    __slots__ = ("constraint", "cpe", "product", "vendor")

    def __init__(
        self,
        vendor: str | None,
        product: str | None,
        constraint: VersionConstraint,
        cpe: str | None,
    ) -> None:
        self.vendor = vendor
        self.product = product
        self.constraint = constraint
        self.cpe = cpe


def _walk_branches(
    # `list[Any]`, not `list[dict]`: this is vendor JSON, and a branch list containing a
    # string or a null is a malformed document to skip past, not a crash.
    branches: list[Any],
    *,
    vendor: str | None,
    product: str | None,
    resolved: dict[str, _ResolvedProduct],
) -> None:
    """Descend the product tree, carrying vendor and product context downward.

    Context accumulates because CSAF states each fact once, at the level it applies to:
    the vendor names itself at the top, the product below it, and the version below that.
    A leaf read without its ancestors is a version number attached to nothing.
    """
    for branch in branches:
        if not isinstance(branch, dict):
            continue

        category = str(branch.get("category") or "")
        name = str(branch.get("name") or "").strip()

        next_vendor = name if category == _VENDOR else vendor
        next_product = name if category == _PRODUCT_NAME else product

        if entry := branch.get("product"):
            if isinstance(entry, dict) and (product_id := entry.get("product_id")):
                if category == _PRODUCT_VERSION_RANGE:
                    constraint = parse_version_spec(name)
                elif category == _PRODUCT_VERSION:
                    constraint = VersionConstraint(
                        kind=ConstraintKind.EXACT, raw=name, version=name
                    )
                else:
                    # A product leaf with no version qualification: the whole product.
                    constraint = VersionConstraint(kind=ConstraintKind.ALL, raw=name or "*")

                helper = entry.get("product_identification_helper")
                cpe = helper.get("cpe") if isinstance(helper, dict) else None

                resolved[str(product_id)] = _ResolvedProduct(
                    vendor=next_vendor,
                    product=next_product,
                    constraint=constraint,
                    cpe=str(cpe) if cpe else None,
                )

        if children := branch.get("branches"):
            if isinstance(children, list):
                _walk_branches(
                    children, vendor=next_vendor, product=next_product, resolved=resolved
                )


def _product_tree(document: dict[str, Any]) -> dict[str, _ResolvedProduct]:
    resolved: dict[str, _ResolvedProduct] = {}
    tree = document.get("product_tree")
    if not isinstance(tree, dict):
        return resolved

    branches = tree.get("branches")
    if isinstance(branches, list):
        _walk_branches(branches, vendor=None, product=None, resolved=resolved)

    # `full_product_names` is the flat alternative to a tree, and some vendors use both.
    for entry in tree.get("full_product_names") or []:
        if not isinstance(entry, dict) or not (product_id := entry.get("product_id")):
            continue
        helper = entry.get("product_identification_helper")
        cpe = helper.get("cpe") if isinstance(helper, dict) else None
        resolved.setdefault(
            str(product_id),
            _ResolvedProduct(
                vendor=None,
                product=str(entry.get("name") or "") or None,
                constraint=VersionConstraint(
                    kind=ConstraintKind.ALL, raw=str(entry.get("name") or "*")
                ),
                cpe=str(cpe) if cpe else None,
            ),
        )

    return resolved


def _affected(
    product_ids: list[Any], resolved: dict[str, _ResolvedProduct], advisory: Advisory
) -> list[AffectedProduct]:
    """Turn a product_status list into affected products.

    An identifier the tree never defined is kept, not dropped. The vendor said this
    product is affected; the only thing missing is which product it is, and recording
    nothing would turn a stated vulnerability into silence.
    """
    entries: list[AffectedProduct] = []
    for raw_id in product_ids:
        product_id = str(raw_id)
        match = resolved.get(product_id)

        if match is None:
            advisory.notes_unparsed.append(
                f"product '{product_id}' is named in product_status but the product tree "
                "does not define it"
            )
            entries.append(
                AffectedProduct(
                    vendor=None,
                    product=None,
                    constraint=VersionConstraint(
                        kind=ConstraintKind.UNPARSED, raw=f"undefined product {product_id}"
                    ),
                    product_id=product_id,
                )
            )
            continue

        entries.append(
            AffectedProduct(
                vendor=match.vendor,
                product=match.product,
                constraint=match.constraint,
                cpe=match.cpe,
                product_id=product_id,
            )
        )
    return entries


def _scores(vulnerability: dict[str, Any]) -> list[Score]:
    found: list[Score] = []
    for entry in vulnerability.get("scores") or []:
        if not isinstance(entry, dict):
            continue
        for key, version in (("cvss_v4", "4.0"), ("cvss_v3", "3.1"), ("cvss_v2", "2.0")):
            payload = entry.get(key)
            if not isinstance(payload, dict):
                continue
            found.append(
                Score(
                    # The document's own `version` is preferred: a `cvss_v3` block may
                    # carry either 3.0 or 3.1, and they score differently.
                    version=str(payload.get("version") or version),
                    base_score=_as_float(payload.get("baseScore")),
                    vector=str(payload.get("vectorString"))
                    if payload.get("vectorString")
                    else None,
                    severity=str(payload.get("baseSeverity"))
                    if payload.get("baseSeverity")
                    else None,
                )
            )
    return found


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_csaf(payload: Any, *, source: str | None = None) -> Advisory | None:
    """Parse one CSAF 2.0 document.

    Returns None only when the payload is not a CSAF advisory at all. A document that is
    CSAF but partly unreadable still produces an Advisory — with its unreadable parts
    recorded in ``notes_unparsed`` — because a vendor advisory that cannot be fully
    parsed is exactly the one an operator most needs to see.

    ``payload`` is deliberately untyped: this is the first thing to touch bytes fetched
    from a vendor, and a feed that returned a list, a string or an error page must be
    rejected here rather than raising somewhere deeper.
    """
    if not isinstance(payload, dict):
        return None

    document = payload.get("document")
    if not isinstance(document, dict):
        log.debug("vuln.csaf_no_document")
        return None

    raw_tracking = document.get("tracking")
    tracking: dict[str, Any] = raw_tracking if isinstance(raw_tracking, dict) else {}
    advisory_id = str(tracking.get("id") or "").strip()
    if not advisory_id:
        # Without an identifier the advisory cannot be de-duplicated across syncs, and
        # every sync would create a fresh copy of it.
        log.warning("vuln.csaf_no_tracking_id")
        return None

    raw_publisher = document.get("publisher")
    publisher: dict[str, Any] = raw_publisher if isinstance(raw_publisher, dict) else {}
    advisory = Advisory(
        source=source or str(publisher.get("name") or "unknown"),
        advisory_id=advisory_id,
        title=str(document.get("title") or "") or None,
        published=_timestamp(tracking.get("initial_release_date")),
        modified=_timestamp(tracking.get("current_release_date")),
    )

    for note in document.get("notes") or []:
        if isinstance(note, dict) and note.get("category") in ("description", "summary"):
            advisory.description = str(note.get("text") or "") or None
            break

    advisory.references = [
        str(reference["url"])
        for reference in document.get("references") or []
        if isinstance(reference, dict) and reference.get("url")
    ]

    resolved = _product_tree(payload)

    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        advisory.notes_unparsed.append("the document declares no vulnerabilities")
        return advisory

    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue

        if cve := vulnerability.get("cve"):
            advisory.cve_ids.append(str(cve))

        cwe = vulnerability.get("cwe")
        if isinstance(cwe, dict) and cwe.get("id"):
            advisory.cwe_ids.append(str(cwe["id"]))

        advisory.scores.extend(_scores(vulnerability))

        status = vulnerability.get("product_status")
        if isinstance(status, dict):
            advisory.affected.extend(
                _affected(status.get("known_affected") or [], resolved, advisory)
            )
            advisory.fixed.extend(_affected(status.get("fixed") or [], resolved, advisory))

            if under_investigation := status.get("under_investigation"):
                # Explicitly not affected and explicitly unknown are different, and only
                # the second belongs in the record as an open question.
                advisory.notes_unparsed.append(
                    f"{len(under_investigation)} product(s) are under investigation and "
                    "the vendor has not yet stated whether they are affected"
                )

        for remediation in vulnerability.get("remediations") or []:
            if isinstance(remediation, dict) and (details := remediation.get("details")):
                advisory.remediations.append(str(details))

    return advisory


__all__ = ["parse_csaf", "parse_version_spec"]
