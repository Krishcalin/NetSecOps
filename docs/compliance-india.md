# CERT-In and CEA mappings

How the `cert_in` and `cea` framework references in the check library were arrived at,
and what a reader should and should not conclude from them.

Both fields had existed in `checks/schema.py` since Phase 3, were offered as compliance
pivots, and had **zero checks mapped to either**. `GET /compliance/cert_in` returned an
empty framework, which renders as a compliance view with nothing in it — indistinguishable
from a clean result. `tests/test_framework_coverage.py` now fails the build if any
advertised framework has no checks behind it.

## The citation style, and why there are no clause numbers

CIS, NIST 800-53, PCI DSS and ISO 27001 are numbered control catalogues, so a check can
cite `AC-4` or `1.2.1` and a reader can look it up. **Neither Indian instrument is like
that.** The CERT-In Directions are seven prose directions; the CEA guidelines are prose
organised into subject chapters. Neither numbers its requirements in a form that can be
cited the way a NIST control can.

So these two frameworks cite the **subject** rather than a clause:

```yaml
references:
  cert_in: ["Clock Synchronisation"]
  cea: ["Logging and Monitoring"]
```

A bare number here would be fabricated precision — it would look verifiable, and would
not be. `test_no_invented_clause_numbers` enforces this, so a later contributor cannot
"tidy" the subjects into numbering that was never in the source.

**This is the part to check against the gazetted texts before the mapping is put in front
of an auditor.** The subject correspondences below are defensible on reading; the exact
clause each maps to is not asserted, because that is not something this mapping claims.

## CERT-In — Directions under section 70B(6) of the IT Act, 28 April 2022

Mapped deliberately narrowly: **13 of 103 checks.**

| Subject | Checks | What it covers |
|---|:--:|---|
| Clock Synchronisation | 5 | NTP servers configured, redundant, authenticated, a fixed source interface, and a timezone set |
| Log Retention | 8 | Remote syslog configured and redundant, buffered logging, timestamps, config-change logging, and the Gaia audit log surviving a reboot |

**Why so few.** Five of the seven Directions are incident reporting timelines, points of
contact, and KYC and record-keeping obligations on service providers. They are real
obligations, and no device configuration can evidence any of them. Mapping them anyway
would inflate a compliance percentage with checks that cannot fail for the right reason —
the same error as counting a Not Evaluated check as a pass.

Two Directions do have a configuration surface, and those are the two mapped:
synchronising ICT system clocks to a traceable time source, and enabling and retaining
logs.

A note for anyone reporting against this: the log-retention direction speaks to a
**180-day rolling retention window, held within Indian jurisdiction**. NetSecOps can
evidence that a device *sends* its logs to a collector; it cannot evidence how long that
collector keeps them or where it sits. That half of the obligation is outside what a
read-only configuration assessment can see, and a report should say so rather than imply
the direction is satisfied.

## CEA — Cyber Security in Power Sector Guidelines, 2021

Mapped broadly: **all 103 checks**, grouped by subject area.

| Subject | Checks |
|---|:--:|
| Secure Configuration | 23 |
| Access Control | 21 |
| Remote Access | 17 |
| Network Security | 16 |
| Logging and Monitoring | 13 |
| Cryptography | 8 |
| Wireless Security | 5 |

Unlike the CERT-In Directions, the CEA guidelines do address secure configuration of ICT
assets directly and at length, so a broad mapping is the honest one. The consequence is
that the CEA pivot does not *filter* the library — every check appears — and its value is
the **subject breakdown**: `GET /compliance/cea` gives a per-subject pass rate rather than
a subset of applicable checks.

That is a real difference from the CIS pivot, which selects 67 of 103, and a report should
present it as such rather than as "103 of 103 CEA controls covered".

## What this mapping does not claim

- That a passing check satisfies a clause. A check evidences one configuration fact.
- That the framework is fully covered. Both instruments contain obligations — incident
  reporting, retention duration, jurisdiction, governance — with no configuration surface
  at all.
- That the subject names match the published headings verbatim. They are readable labels
  chosen for a report, not quotations.
