"""Vulnerability assessment (SRS §3.10, FR-VUL-01 … FR-VUL-10).

Everything in this package answers one question — *is this device affected by this
advisory?* — and the honest answer is frequently "we cannot tell". The three-valued
discipline the rest of NetSecOps uses for configuration applies here with more force,
because a vulnerability finding is acted on: someone schedules an outage window for it.

The package is layered so that nothing above can skip the layer below:

``versions``   Vendor version strings, parsed and compared. Not a total order.
``cpe``        CPE 2.3 identifiers built from the NCM (FR-VUL-01).

Later slices add feed ingestion, the feature-aware matcher, and the finding surface.
"""

from __future__ import annotations

__all__: list[str] = []
