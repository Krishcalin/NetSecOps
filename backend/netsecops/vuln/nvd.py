"""NVD JSON 2.0 ingestion (FR-VUL-01, FR-VUL-04).

The NVD publishes what the vendor advisories do not: a single vocabulary across every
vendor, CVSS scoring that has been through analysis rather than self-assessment, and CPE
identifiers rather than product names. It is also the only source that covers vendors
with no CSAF feed at all.

A CVE's applicability lives in ``configurations`` — a list of nodes, each a list of
``cpeMatch`` entries with optional version bounds. Three things in that structure are
routinely got wrong, and each produces a wrong verdict rather than an error:

**`vulnerable: false` means "running on", not "affected".** NVD uses those entries to say
*this CVE applies to product X when it runs on platform Y*. Reading them as affected
products attaches CVEs to every operating system a vulnerable application was ever
packaged with.

**`negate` inverts a node.** A negated node says the CVE applies to everything *except*
what it lists, and treating it as a plain list inverts the verdict exactly.

**`operator: AND` between nodes is a compound condition.** "Affected when running X *and*
configured with Y" cannot be answered by matching either half. Taking either as
sufficient turns a narrow advisory into an estate-wide one.

The first is handled, the second and third are recorded as uninterpretable rather than
guessed at — the same discipline as :mod:`netsecops.vuln.csaf`. An advisory carrying a
construct this parser does not model can raise a finding but can never clear a device,
because :attr:`Advisory.fully_interpreted` goes false.
"""

from __future__ import annotations

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
from netsecops.vuln.cpe import product_key

log = get_logger(__name__)

#: Where NVD puts each CVSS version, and what to call it. Ordered newest first so the
#: richest scoring a record carries is the one read first.
_METRIC_KEYS: tuple[tuple[str, str], ...] = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


def parse_nvd_feed(payload: Any, *, source: str = "nvd") -> list[Advisory]:
    """Parse an NVD 2.0 response or offline bundle into advisories.

    One :class:`Advisory` per CVE. NVD has no advisory concept of its own, so the CVE id
    serves as the advisory id — which keeps de-duplication working the same way as for
    vendor feeds, where one advisory may carry several CVEs.
    """
    if not isinstance(payload, dict):
        return []

    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list):
        log.debug("vuln.nvd_no_vulnerabilities")
        return []

    advisories: list[Advisory] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        record = entry.get("cve")
        if isinstance(record, dict) and (advisory := parse_cve(record, source=source)):
            advisories.append(advisory)

    log.info("vuln.nvd_parsed", source=source, advisories=len(advisories))
    return advisories


def parse_cve(record: dict[str, Any], *, source: str = "nvd") -> Advisory | None:
    """Parse one NVD CVE record."""
    cve_id = str(record.get("id") or "").strip()
    if not cve_id:
        return None

    advisory = Advisory(
        source=source,
        advisory_id=cve_id,
        cve_ids=[cve_id],
        title=cve_id,
        published=_timestamp(record.get("published")),
        modified=_timestamp(record.get("lastModified")),
    )

    for description in record.get("descriptions") or []:
        if isinstance(description, dict) and description.get("lang") == "en":
            advisory.description = str(description.get("value") or "") or None
            break

    advisory.cwe_ids = _weaknesses(record)
    advisory.scores = _scores(record)
    advisory.references = [
        str(reference["url"])
        for reference in record.get("references") or []
        if isinstance(reference, dict) and reference.get("url")
    ]

    _configurations(record, advisory)

    # A CVE that reached "Rejected" is withdrawn and must not match anything.
    if str(record.get("vulnStatus") or "").strip().lower() == "rejected":
        advisory.affected = []
        advisory.notes_unparsed = []
        advisory.description = f"Withdrawn by NVD. {advisory.description or ''}".strip()

    return advisory


# ───────────────────────────── applicability ────────────────────────────────


def _configurations(record: dict[str, Any], advisory: Advisory) -> None:
    """Read `configurations` into affected products.

    Anything this parser does not model is recorded in ``notes_unparsed`` rather than
    approximated, which costs the advisory its ``fully_interpreted`` status and stops it
    clearing a device it might actually cover.
    """
    configurations = record.get("configurations")
    if not isinstance(configurations, list):
        if not advisory.affected:
            advisory.notes_unparsed.append(
                f"{advisory.advisory_id} carries no applicability data, so which "
                "products it affects cannot be determined from this record."
            )
        return

    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue

        nodes = configuration.get("nodes")
        if not isinstance(nodes, list):
            continue

        if str(configuration.get("operator") or "").upper() == "AND" and len(nodes) > 1:
            # "Affected when running X and configured with Y." Matching either half
            # alone would widen a narrow advisory across the estate.
            advisory.notes_unparsed.append(
                f"{advisory.advisory_id} states a compound (AND) applicability across "
                f"{len(nodes)} node(s), which this system does not model. Its affected "
                "products are read individually, so a match is a candidate rather than "
                "a confirmation."
            )

        for node in nodes:
            if isinstance(node, dict):
                _node(node, advisory)


def _node(node: dict[str, Any], advisory: Advisory) -> None:
    if node.get("negate") is True:
        # "Everything except these." Reading the list as affected inverts the verdict.
        advisory.notes_unparsed.append(
            f"{advisory.advisory_id} contains a negated applicability node — it applies "
            "to everything *except* the products listed. This system does not model "
            "negation, so that node is not used for matching."
        )
        return

    for criteria in node.get("cpeMatch") or []:
        if not isinstance(criteria, dict):
            continue

        if criteria.get("vulnerable") is not True:
            # A "running on" entry: context for the vulnerable product, not a product
            # that is itself affected.
            continue

        cpe = str(criteria.get("criteria") or "").strip()
        parsed = product_key(cpe) if cpe else None
        if parsed is None:
            advisory.notes_unparsed.append(
                f"{advisory.advisory_id} names an applicability entry whose CPE "
                f"({cpe!r}) could not be read."
            )
            continue

        _part, vendor, product = parsed

        advisory.affected.append(
            AffectedProduct(
                vendor=vendor,
                product=product,
                cpe=cpe,
                product_id=str(criteria.get("matchCriteriaId") or "") or None,
                constraint=_constraint(criteria, cpe),
            )
        )


def _constraint(criteria: dict[str, Any], cpe: str) -> VersionConstraint:
    """Turn NVD's four version bounds into a constraint.

    Two of the four cannot be represented exactly, and are marked unparsed rather than
    shifted by a release:

    * ``versionStartExcluding`` — an exclusive lower bound, where the model's is
      inclusive. Treating them as the same pulls in one release that is not affected.
    * ``versionEndIncluding`` — the named release *is* affected, so it is not the fixed
      one. Storing it as ``fixed`` would report every device on it as patched.

    That second one is the dangerous direction, and it is common: NVD uses
    ``versionEndIncluding`` wherever a vendor never shipped a fix.
    """
    start_including = criteria.get("versionStartIncluding")
    start_excluding = criteria.get("versionStartExcluding")
    end_excluding = criteria.get("versionEndExcluding")
    end_including = criteria.get("versionEndIncluding")

    raw = " ".join(
        part
        for part in (
            f">={start_including}" if start_including else "",
            f">{start_excluding}" if start_excluding else "",
            f"<{end_excluding}" if end_excluding else "",
            f"<={end_including}" if end_including else "",
        )
        if part
    )

    if start_excluding or end_including:
        return VersionConstraint(kind=ConstraintKind.UNPARSED, raw=raw or cpe)

    if start_including or end_excluding:
        return VersionConstraint(
            kind=ConstraintKind.RANGE,
            raw=raw,
            introduced=str(start_including) if start_including else None,
            fixed=str(end_excluding) if end_excluding else None,
        )

    # No bounds: the version sits in the CPE's own version component.
    version = _cpe_version(cpe)
    if version in (None, "*"):
        return VersionConstraint(kind=ConstraintKind.ALL, raw=cpe)
    if version == "-":
        # NA — a hardware entry with no software version. Not a version match at all.
        return VersionConstraint(kind=ConstraintKind.UNPARSED, raw=cpe)
    return VersionConstraint(kind=ConstraintKind.EXACT, raw=version, version=version)


def _cpe_version(cpe: str) -> str | None:
    """The version component of a CPE, unescaped, or None if it has none."""
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for character in cpe:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    parts.append("".join(current))

    return parts[5] if len(parts) > 5 else None


# ──────────────────────────────── metadata ──────────────────────────────────


def _scores(record: dict[str, Any]) -> list[Score]:
    metrics = record.get("metrics")
    if not isinstance(metrics, dict):
        return []

    found: list[Score] = []
    for key, default_version in _METRIC_KEYS:
        for entry in metrics.get(key) or []:
            if not isinstance(entry, dict):
                continue
            data = entry.get("cvssData")
            if not isinstance(data, dict):
                continue
            found.append(
                Score(
                    version=str(data.get("version") or default_version),
                    base_score=_as_float(data.get("baseScore")),
                    vector=str(data.get("vectorString")) if data.get("vectorString") else None,
                    # v2 puts severity on the wrapper, v3+ on cvssData. Both are read so
                    # neither loses its rating.
                    severity=str(data.get("baseSeverity") or entry.get("baseSeverity") or "")
                    or None,
                )
            )
    return found


def _weaknesses(record: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for weakness in record.get("weaknesses") or []:
        if not isinstance(weakness, dict):
            continue
        for description in weakness.get("description") or []:
            if isinstance(description, dict):
                value = str(description.get("value") or "")
                # NVD uses these placeholders where no CWE was assigned; they are not
                # weakness identifiers and must not reach a finding as though they were.
                if value.startswith("CWE-") and value not in ("CWE-noinfo", "CWE-Other"):
                    found.append(value)
    return sorted(set(found))


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


__all__ = ["parse_cve", "parse_nvd_feed"]
