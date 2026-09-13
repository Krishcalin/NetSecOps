# ADR-004 — Report branding, classification labels, and which frameworks ship enabled

- **Status:** Accepted
- **Date:** 2026-09-13
- **Requirement:** FR-CHK-05, FR-REP-01 … FR-REP-04, Appendix D item 4
- **Decided by:** delegated to the implementer by the customer

## Context

Two questions were bundled together in Appendix D item 4, and they are separable.

**Branding and classification labels.** Reports leave the system. They are emailed to
executives, attached to audit evidence packs and handed to third parties. What they say
about their own sensitivity, and whose name is on them, is a decision that needs making
once rather than per report.

**Which framework packs ship enabled.** The check library carries CIS, NIST 800-53,
PCI DSS and ISO 27001 mappings on every check. A fresh installation has to decide which
of those a device is measured against by default.

## Decision — classification labels

**Reports carry a configurable classification banner, defaulting to `CONFIDENTIAL`.**

Set with `NETSECOPS_REPORT_CLASSIFICATION`. An organisation using its own scheme —
`OFFICIAL-SENSITIVE`, `INTERNAL`, `TLP:AMBER` — sets that string instead. Setting it to
an empty value removes the banner entirely, for an organisation whose policy is that
unmarked means unclassified.

The default is `CONFIDENTIAL` rather than blank because of what these documents
contain: a list of a network's weaknesses, the devices they are on, and enough
configuration excerpt to act on them. That is a target package. An unmarked document is
one nobody has to think before forwarding, and the cost of an unnecessary marking is far
lower than the cost of a missing one.

## Decision — branding

**The product name on a report is NetSecOps, with an optional customer logo and
organisation name; there is no white-label mode.**

`NETSECOPS_REPORT_ORG_NAME` and `NETSECOPS_REPORT_LOGO_PATH` add the customer's identity
alongside the product's, not instead of it. A report says which tool produced it.

This is a provenance decision rather than a marketing one. A findings report is
evidence: a reader needs to know what assessed the device, because the tool's version
determines which checks existed and how they were interpreted. A white-labelled report
that could have come from anything is worth less to the auditor reading it, and the
first question about any surprising finding is "what produced this?".

## Decision — default framework packs

**CIS ships enabled. NIST 800-53, PCI DSS and ISO 27001 ship mapped but not enabled.**

Concretely, the seeded default policy is CIS Cisco IOS L1 (ADR-002's sibling decision in
`checks/policies/`), and the compliance view offers the other three frameworks as pivots
over whatever has been assessed, rather than as active policies.

Three reasons:

**A compliance percentage nobody owns is worse than none.** Enabling four frameworks by
default means every device immediately reports four scores, none of which anyone asked
for, and at least three of which will look bad for reasons that are entirely correct —
PCI DSS applies to the cardholder data environment, not to a lab switch. People learn to
ignore the numbers, and then ignore the one that mattered.

**CIS is the one the library is actually built around.** Every check in the shipped
library carries a CIS mapping; the others are mapped where they apply, which is not
everywhere. Shipping ISO 27001 enabled would advertise coverage the library does not
have.

**Level 1 is the profile designed to be adopted without a compatibility exercise.** CIS
defines Level 2 as controls that trade functionality for defence in depth. Enabling L1
by default is a claim an installation can live with on day one; anything more is a
decision for the operator.

The other three are one policy away. `PolicyService.create` takes a list of check ids,
and `CheckRegistry.by_framework` returns exactly the checks mapped to a given framework —
so "make me a PCI DSS policy" is a query, not a data-modelling exercise.

## Consequences

- Three settings to add in Phase 7: `report_classification` (default `CONFIDENTIAL`),
  `report_org_name`, `report_logo_path`. All optional; none may fail a startup.
- The classification string must appear on every page of a PDF and in the header of an
  XLSX, not only on a cover sheet. A page separated from its cover is the normal way
  these documents travel.
- The seeded default policy stays CIS Cisco IOS L1. When Phase 4 adds Palo Alto,
  Fortinet and Check Point packs, each ships as an installable policy but only the
  platform-appropriate one becomes default for devices of that platform — a Cisco
  benchmark must never be the default for a FortiGate, where it would report a wall of
  *Not Applicable* and look like a broken product.
- The compliance endpoint already pivots by any mapped framework, so this decision costs
  nothing to reverse: enabling another pack is seeding one more policy.

## Alternatives considered

**Ship every framework enabled.** Rejected, as above: four unowned scores per device.

**Ship nothing enabled and make the operator choose.** Rejected. A fresh installation
that assesses nothing until someone builds a policy looks identical to one that is
broken, and the first-run experience is where a product earns the benefit of the doubt.

**White-label by default.** Rejected. Reports are evidence, and evidence that does not
name its source is weaker evidence.
