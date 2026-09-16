"""Rendering a frozen report into a downloadable file (FR-RPT-03).

Rendering never re-reads the estate. It takes the stored `content` and formats it, so
every format of one report says the same thing — and the report's `content_hash`
identifies all of them, because they are one report.

**CSV needs a per-template decision, and that is why this is a table rather than a
generic flattener.** A report's content is nested, and there is no single correct way to
flatten it: the executive summary's useful CSV is one row per device, the exceptions
register's is one row per exception, and a generic flattener would produce neither. It
would produce `top_devices.0.hostname` column headers, which is a machine-readable
rendering of a human's spreadsheet and useful to nobody.

So each template names the collection that becomes rows and the columns that matter. A
template with no CSV projection returns JSON with an explanation rather than a blank
file — an empty spreadsheet reads as "no findings".
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from netsecops.core.errors import ValidationProblem
from netsecops.db.models.reporting import Report, ReportFormat, ReportStatus, ReportTemplate

#: template -> (key in content holding the rows, ordered column names)
#: Columns are named explicitly rather than taken from the first row's keys: a row that
#: happens to be missing an optional field would otherwise silently drop the column for
#: every row, and the reader would never know a field had existed.
CSV_PROJECTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    ReportTemplate.EXECUTIVE_SUMMARY.value: (
        "top_devices",
        ("hostname", "mgmt_ip", "platform", "criticality", "critical", "high", "findings"),
    ),
    ReportTemplate.EXCEPTIONS_REGISTER.value: (
        "exceptions",
        (
            "check_id",
            "scope",
            "device_id",
            "approver",
            "expires_at",
            "status",
            "expired_at_generation",
            "justification",
        ),
    ),
}


def content_type_for(fmt: ReportFormat) -> str:
    return {
        ReportFormat.JSON: "application/json",
        ReportFormat.CSV: "text/csv",
    }[fmt]


def filename_for(report: Report, fmt: ReportFormat) -> str:
    """A filename that says what the artefact is and when it was taken.

    The date is in the name because these files leave the product — they are mailed,
    attached to tickets and filed. `report.csv` in a downloads folder six months later
    is evidence nobody can place.
    """
    stamp = report.generated_at.strftime("%Y%m%d") if report.generated_at else "ungenerated"
    slug = report.template.replace("_", "-")
    return f"netsecops-{slug}-{stamp}-{str(report.id)[:8]}.{fmt.value}"


def render(report: Report, fmt: ReportFormat) -> bytes:
    """Format a stored report. Raises rather than emit a misleading empty file."""
    if report.status != ReportStatus.READY.value:
        raise ValidationProblem(
            f"Report {report.id} is {report.status}. Only a completed report can be "
            "downloaded — a partial one would read as a finished assessment."
        )

    if fmt is ReportFormat.JSON:
        return _json_bytes(report)
    return _csv_bytes(report)


def _json_bytes(report: Report) -> bytes:
    payload = {
        "report_id": str(report.id),
        "template": report.template,
        "title": report.title,
        "generated_at": report.generated_at.isoformat() if report.generated_at else None,
        # Travels with the file so a recipient can verify the artefact they hold is the
        # one that was generated, without access to the console.
        "content_hash": report.content_hash,
        "parameters": report.parameters,
        "content": report.content,
    }
    return json.dumps(payload, indent=2, sort_keys=True, default=str).encode("utf-8")


def _csv_bytes(report: Report) -> bytes:
    projection = CSV_PROJECTIONS.get(report.template)
    if projection is None:
        raise ValidationProblem(
            f"The {report.template!r} template has no CSV projection — its content is "
            "not a single table. Download it as JSON."
        )

    key, columns = projection
    rows: list[dict[str, Any]] = list((report.content or {}).get(key) or [])

    buffer = io.StringIO(newline="")
    # A provenance header above the table. Spreadsheet readers tolerate it, and without
    # it a CSV detached from the console is a grid of numbers with no date on it.
    buffer.write(f"# {report.title}\n")
    buffer.write(
        f"# generated_at,{report.generated_at.isoformat() if report.generated_at else ''}\n"
    )
    buffer.write(f"# report_id,{report.id}\n")
    buffer.write(f"# content_hash,{report.content_hash}\n")
    if not rows:
        buffer.write("# no rows — this is an empty result, not a failed one\n")

    writer = csv.DictWriter(buffer, fieldnames=list(columns), extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({column: row.get(column, "") for column in columns})

    return buffer.getvalue().encode("utf-8")


__all__ = ["CSV_PROJECTIONS", "content_type_for", "filename_for", "render"]
