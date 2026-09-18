"""The CISA Known Exploited Vulnerabilities catalogue (FR-VUL-06).

KEV answers the one question that outranks every score: *is this being exploited right
now*. A CVSS 9.8 nobody has ever attacked and a CVSS 7.5 in active ransomware use are not
the same work item, and no severity number distinguishes them.

**The catalogue is stored whole, not reduced to a flag.** Writing `kev = true` onto the
CVEs we happen to hold and discarding the rest would be smaller and would break the
moment the order of imports changed: import the catalogue, then import an NVD bundle that
introduces a new CVE, and that CVE's flag reads "never checked" even though the catalogue
sitting in the database has an entry for it. Keeping the catalogue means the answer is
derivable whenever a CVE arrives, in either order.

**Three states, and the middle one is the point.** `None` means no catalogue has ever
been imported; `False` means one has and this CVE is not in it; `True` means it is. A
product that collapses the first two reports an unchecked estate as a clean one, which is
the worst direction for a control whose whole job is prioritisation.

The catalogue is published by CISA as a single JSON document, updated continuously. It is
small — low thousands of entries — which is why storing all of it is cheap and why an
air-gapped operator can carry it on the same media as everything else (C-7).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class KevRecord:
    """One catalogue entry."""

    cve_id: str
    #: When CISA added it. Distinct from the CVE's own publication date — a CVE can sit
    #: for years before exploitation is observed, and the gap is the interesting part.
    date_added: date | None = None
    #: BOD 22-01's remediation deadline for federal agencies. Useful to everyone else as
    #: a severity signal: CISA sets it shorter for what it considers more urgent.
    due_date: date | None = None
    #: CISA records this as "Known", "Unknown" or blank — never as a boolean. Kept as
    #: three states for the same reason the flag is: "not known to be used in ransomware"
    #: and "nobody has looked" are different claims.
    known_ransomware: bool | None = None
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    required_action: str | None = None


@dataclass(frozen=True, slots=True)
class KevCatalogue:
    """A parsed catalogue, with the provenance needed to judge its age."""

    records: tuple[KevRecord, ...]
    #: CISA's own version stamp, e.g. `2024.05.01`. Recorded so the feed page can say
    #: how old the data is rather than only when it was uploaded — an operator who
    #: imported a year-old file yesterday has a fresh sync of stale facts.
    catalog_version: str | None = None
    released: str | None = None
    #: Entries the parser could not read. Surfaced, never swallowed: a catalogue that
    #: imported 900 of 1,000 entries leaves 100 CVEs reading as "not exploited".
    rejected: int = 0


def looks_like_kev(payload: Any) -> bool:
    """Whether this JSON document is a KEV catalogue.

    Needed because a KEV catalogue, an NVD 2.0 response and a CSAF advisory *all* carry a
    top-level ``vulnerabilities`` key. Getting the order wrong does not raise — it reads
    the file as the other format, finds nothing it recognises, and reports a clean empty
    import. So this tests for something only KEV has.
    """
    if not isinstance(payload, dict):
        return False
    if "catalogVersion" in payload:
        return True

    # Fallback for a catalogue slice that dropped the header: NVD nests the identifier
    # as `{"cve": {"id": ...}}` while KEV puts `cveID` directly on the entry.
    entries = payload.get("vulnerabilities")
    if isinstance(entries, list) and entries and isinstance(entries[0], dict):
        return "cveID" in entries[0]
    return False


def _as_date(value: Any) -> date | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        log.debug("kev.unreadable_date", value=text)
        return None


def _ransomware(value: Any) -> bool | None:
    """CISA's ransomware field, which is a three-state string rather than a boolean."""
    text = str(value or "").strip().lower()
    if text == "known":
        return True
    if text == "unknown":
        # CISA's own word for "we have not established this", not for "no". Mapping it to
        # False would assert something the catalogue does not.
        return None
    return False if text else None


def parse_kev_catalogue(payload: Any) -> KevCatalogue:
    """Read a CISA KEV catalogue into records."""
    if not isinstance(payload, dict):
        raise ValidationProblem(
            "A KEV catalogue is a JSON object with a `vulnerabilities` list; this is not."
        )

    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list):
        raise ValidationProblem(
            "This KEV catalogue has no `vulnerabilities` list. Nothing was imported — "
            "an empty catalogue would mark every CVE in the estate as not exploited."
        )

    records: list[KevRecord] = []
    rejected = 0

    for entry in entries:
        if not isinstance(entry, dict):
            rejected += 1
            continue

        cve_id = str(entry.get("cveID") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            rejected += 1
            continue

        records.append(
            KevRecord(
                cve_id=cve_id,
                date_added=_as_date(entry.get("dateAdded")),
                due_date=_as_date(entry.get("dueDate")),
                known_ransomware=_ransomware(entry.get("knownRansomwareCampaignUse")),
                vendor_project=(entry.get("vendorProject") or None),
                product=(entry.get("product") or None),
                vulnerability_name=(entry.get("vulnerabilityName") or None),
                required_action=(entry.get("requiredAction") or None),
            )
        )

    if not records:
        # A catalogue that parsed to nothing must not be stored. Storing it would flip
        # every CVE in the estate from "unknown" to "not exploited" on the strength of a
        # file this could not read.
        raise ValidationProblem(
            f"This KEV catalogue yielded no usable entries out of {len(entries)} offered. "
            "Nothing was imported: applying an empty catalogue would mark every CVE in "
            "the estate as not known-exploited."
        )

    catalogue = KevCatalogue(
        records=tuple(records),
        catalog_version=(payload.get("catalogVersion") or None),
        released=(payload.get("dateReleased") or None),
        rejected=rejected,
    )

    log.info(
        "kev.parsed",
        entries=len(records),
        rejected=rejected,
        catalog_version=catalogue.catalog_version,
    )
    return catalogue


__all__ = ["KevCatalogue", "KevRecord", "looks_like_kev", "parse_kev_catalogue"]
