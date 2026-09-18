"""FIRST's Exploit Prediction Scoring System (FR-VUL-06).

EPSS estimates the probability that a CVE will be exploited in the next 30 days. It
complements KEV rather than duplicating it: KEV is a record of what *has* been exploited,
EPSS a forecast of what might be. Together they answer "fix this one first" far better
than CVSS, which measures how bad exploitation would be and says nothing about whether it
is happening.

**A score is meaningless without its date.** EPSS is recomputed daily and scores move —
a CVE at 0.02 last month can be at 0.9 today after a public exploit lands. So the
model version and score date are parsed out and recorded, and a score with no date is
still imported but marked as such. An operator prioritising from three-week-old
probabilities should be able to discover that without checking when somebody uploaded a
file.

**Absent is not zero.** A CVE the feed does not mention is *unscored*, and its column
stays NULL. Writing 0.0 would say "almost certainly not exploited", which is a claim the
data does not make and the opposite of the truth for anything too new to have been
scored.

FIRST publishes the bulk feed as gzipped CSV with a comment line carrying the metadata:

    #model_version:v2023.03.01,score_date:2024-05-01T00:00:00+0000
    cve,epss,percentile
    CVE-1999-0001,0.00885,0.74178

The JSON API returns the same fields under a ``data`` key, so both are read here — an
air-gapped operator carries whichever file they were able to fetch (C-7).
"""

from __future__ import annotations

import csv
import gzip
from dataclasses import dataclass, field
from typing import Any

from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger

log = get_logger(__name__)

#: Gzip's magic bytes. FIRST's bulk download is `.csv.gz` and there is no reason to make
#: an operator decompress it by hand before uploading.
GZIP_MAGIC = b"\x1f\x8b"


@dataclass(slots=True)
class EpssScores:
    """Parsed scores, keyed by CVE, with the provenance needed to judge their age."""

    scores: dict[str, float] = field(default_factory=dict)
    percentiles: dict[str, float] = field(default_factory=dict)
    model_version: str | None = None
    #: The day the model ran, from the feed's own header — not the upload time.
    score_date: str | None = None
    rejected: int = 0

    def __len__(self) -> int:
        return len(self.scores)


def looks_like_epss_csv(raw: bytes) -> bool:
    """Whether these bytes are an EPSS CSV, decompressing first if need be."""
    try:
        text = decompress(raw)[:4096].decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return False
    lowered = text.lower()
    return "model_version" in lowered or ("cve" in lowered and "epss" in lowered)


def decompress(raw: bytes) -> bytes:
    """Gunzip if gzipped, otherwise pass through."""
    if raw[:2] == GZIP_MAGIC:
        try:
            return gzip.decompress(raw)
        except OSError as exc:
            raise ValidationProblem(
                f"This bundle looks gzipped but could not be read: {exc}"
            ) from exc
    return raw


def _score(value: Any) -> float | None:
    """A probability in [0, 1], or None.

    Out-of-range values are rejected rather than clamped. A score above 1 means the file
    is not what it claims to be, and clamping it to 1.0 would turn a corrupt feed into
    the most urgent finding in the estate.
    """
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if not 0.0 <= number <= 1.0:
        return None
    return number


def parse_epss_csv(raw: bytes) -> EpssScores:
    """Read FIRST's bulk CSV, gzipped or not."""
    text = decompress(raw).decode("utf-8", errors="replace")
    result = EpssScores()

    lines = text.splitlines()
    body: list[str] = []
    for line in lines:
        if line.startswith("#"):
            # `#model_version:v2023.03.01,score_date:2024-05-01T00:00:00+0000`
            #
            # `partition`, not `split(":")`: the score date is an ISO timestamp and
            # contains two more colons of its own, so splitting on every colon truncates
            # it to the hour and loses the date's timezone.
            for part in line.lstrip("#").split(","):
                key, _, value = part.partition(":")
                if key.strip() == "model_version":
                    result.model_version = value.strip() or None
                elif key.strip() == "score_date":
                    result.score_date = value.strip() or None
            continue
        body.append(line)

    if not body:
        raise ValidationProblem("This EPSS bundle has no rows.")

    for row in csv.DictReader(body):
        cve_id = str(row.get("cve") or "").strip().upper()
        score = _score(row.get("epss"))
        if not cve_id.startswith("CVE-") or score is None:
            result.rejected += 1
            continue

        result.scores[cve_id] = score
        if (percentile := _score(row.get("percentile"))) is not None:
            result.percentiles[cve_id] = percentile

    if not result.scores:
        raise ValidationProblem(
            f"This EPSS bundle yielded no usable scores out of {len(body)} rows. Nothing "
            "was imported."
        )

    log.info(
        "epss.parsed",
        scores=len(result.scores),
        rejected=result.rejected,
        score_date=result.score_date,
    )
    return result


def parse_epss_json(payload: Any) -> EpssScores:
    """Read the FIRST API's JSON form, which carries the same fields under `data`."""
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ValidationProblem("An EPSS JSON bundle is an object with a `data` list.")

    result = EpssScores()
    for entry in payload["data"]:
        if not isinstance(entry, dict):
            result.rejected += 1
            continue

        cve_id = str(entry.get("cve") or "").strip().upper()
        score = _score(entry.get("epss"))
        if not cve_id.startswith("CVE-") or score is None:
            result.rejected += 1
            continue

        result.scores[cve_id] = score
        if (percentile := _score(entry.get("percentile"))) is not None:
            result.percentiles[cve_id] = percentile
        result.score_date = result.score_date or (entry.get("date") or None)

    if not result.scores:
        raise ValidationProblem("This EPSS bundle yielded no usable scores. Nothing imported.")

    log.info("epss.parsed", scores=len(result.scores), rejected=result.rejected, source="json")
    return result


def looks_like_epss_json(payload: Any) -> bool:
    """Whether a parsed JSON document is the EPSS API's response shape."""
    if not isinstance(payload, dict):
        return False
    data = payload.get("data")
    if not isinstance(data, list) or not data or not isinstance(data[0], dict):
        return False
    return "epss" in data[0] and "cve" in data[0]


def read_epss(raw: bytes, payload: Any | None = None) -> EpssScores:
    """Read either form. ``payload`` is the already-parsed JSON where there was one."""
    if payload is not None and looks_like_epss_json(payload):
        return parse_epss_json(payload)
    return parse_epss_csv(raw)


__all__ = [
    "GZIP_MAGIC",
    "EpssScores",
    "decompress",
    "looks_like_epss_csv",
    "looks_like_epss_json",
    "parse_epss_csv",
    "parse_epss_json",
    "read_epss",
]
