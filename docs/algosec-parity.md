# AlgoSec parity — what we are building, and what we are deliberately not

Read against **AlgoSec Firewall Analyzer A30.00/A30.10**, both the Administration Guide
(699 pages) and the User Guide (238 pages), on 2026-09-28. This page exists so that the
scope decisions taken that day are a record rather than a memory, and so the next person
to ask "why doesn't NetSecOps do X" gets an answer instead of a shrug.

## The one thing that is out of charter

**AlgoSec ActiveChange and FireFlow push changes to devices. NetSecOps does not, and
will not.**

SRS §8 is the product's founding constraint: every adapter is read-only, the allow-list
is closed, and the three-layer guard exists to make a write structurally impossible
rather than merely unintended. ActiveChange and the FireFlow change-execution path are
the opposite design — they exist to apply a rule to a firewall.

This is not a gap to close later. It is a different product, and the read-only guarantee
is the thing a customer's security reviewer signs off on when they read §8.2. Trading it
for parity would cost more than the feature is worth.

**What that excludes, precisely:**

| AlgoSec feature | Why it is out |
|---|---|
| ActiveChange (push a rule to a device) | Writes to a device |
| FireFlow change execution | Writes to a device |
| Rule recommendation *applied* to the device | Writes to a device |

**What it does not exclude**, and is fair game if it is ever wanted: recording a change
request, routing it for approval, auditing who asked for what, and checking a *proposed*
rule against policy before anybody applies it by hand. None of that touches a device.
It was offered on 2026-09-28 and not taken; the option stands.

## Features that need a data source we do not have

Two AlgoSec capabilities are derived from **traffic logs**, not from configuration:

- **Unused rules** — "rules that are not used according to actual traffic logs".
- **Intelligent Policy Tuner** — rules that are too wide, and objects used sparsely.

We read configuration. ACL hit counters get part of the way on the platforms that expose
them (`show access-list` on ASA, `show rule hit-count` on PAN-OS, both already parsed),
and that is genuinely useful — but a hit counter is not a log, and it cannot say *which
sources* used a rule. Anything beyond "this rule has never matched" needs a log source
that does not exist in this product yet.

Recorded here rather than left to be rediscovered as a bug.

## Where we already match

Assessed against the code on 2026-09-28, not assumed:

| AlgoSec | NetSecOps |
|---|---|
| Risky rules, any/any detection | FR-FW-02 |
| Shadowed, redundant, covered rules | FR-FW-03 |
| NAT exposure analysis | FR-FW-04 |
| Object hygiene — unused, duplicate, unattached | FR-FW-05 |
| Traffic simulation query | FR-FW-06, FR-TOPO-03 |
| Routing query | FR-TOPO-03 |
| Graphic network map, unmanaged boundary | FR-TOPO-02, FR-TOPO-06 |
| Change tracking, baselines, config comparison | FR-DRIFT-01 … FR-DRIFT-04 |
| Risk profiles, custom risk items, risk scoring | FR-CHK-01, FR-CHK-06, FR-CHK-09 |
| Regulatory compliance reporting | FR-RPT-05 |
| Scheduled analysis, e-mail notification | FR-JOB-02, FR-INT-01 |
| Users, roles, SSO, LDAP | FR-AUTH-01 … FR-AUTH-05 |
| Backup and restore | FR-ADM-02 |

## The ranked gaps, and the order chosen

Agreed 2026-09-28: **device breadth first**, because every engine above multiplies
across each platform added, and coverage is the gap a customer measures first.

1. **Device breadth — closed, 2026-09-29.** AlgoSec onboards roughly twenty vendor
   families. We had fourteen platforms; we now have twenty-five.

   Added over two days: Radware Alteon, Barracuda WAF, Juniper Junos (SRX, MX and EX on
   one platform key), F5 BIG-IP, Arista EOS, Cisco Firepower via FMC, VMware NSX-T,
   Cisco ACI, AWS, Azure and Symantec ProxySG.

   **Six of them are read from an export rather than collected.** For NSX, ACI, AWS and
   Azure that is a design decision: each needs a credential type and a transport this
   product does not have, FR-COL-11 carries them today, and the collectors are their own
   slice. The two cloud allow-lists are deliberately empty — NetSecOps holds no cloud
   credential and can send those platforms nothing at all.

   For **Firepower and Barracuda it was a correction**. Both shipped with a collection
   profile that could not be executed, because their endpoints are templated per object
   and the runner cannot expand a path per discovered object. Found by
   `test_bundled_collection_shape` on the first full-suite run after they landed.

   **A collector that can expand a path per discovered object would unblock four
   platforms at once** — FMC, Barracuda, NSX and ACI all want the same mechanism. It is
   the highest-leverage piece of collection work outstanding.

   Still absent against AlgoSec's list: Juniper Netscreen and Junos Space, WatchGuard,
   McAfee Sidewinder, Cisco CSM. All are legacy or manager-tier; none is a gap a
   customer has asked about.

   **One limitation worth stating, because it is structural rather than unfinished.**
   The four export-read platforms carry objects whose membership is not in the export
   and never will be: an AWS security group stands for the instances attached to it, an
   NSX dynamic group for whatever currently carries a tag, an Azure service tag for
   ranges Microsoft publishes, an ACI L2-only EPG for a bridge domain with no gateway.
   Those are typed so the difference from a parser failure is legible
   (`EXTERNALLY_RESOLVED_TYPES` in `firewall/model.py`).

   **Reporting "cannot evaluate" was built on 2026-09-29.** It was the right behaviour
   and the wrong behaviour was dangerous rather than merely incomplete: a rule using one
   of these objects resolved to an empty address set, so the query walked past it as a
   miss, found nothing else, and returned the implicit deny — a confident `blocked` for
   traffic nothing had established was blocked. A path crossing such a rule is now
   `partially-allowed` with the device, the rule and the object named, and the note
   distinguishes an object a re-collection would fix from one no collection ever will
   (`test_undecidable_rules.py`).

   A rule excluded on a side that *did* resolve is still a plain miss, so the caveat
   fires on the queries it applies to rather than on every query against a cloud
   rulebase.
2. **Matrices, DR sets, and group/matrix-level reports.** AlgoSec's cross-device
   constructs, and the "multi-device reasoning" gap the earlier competitive dossier
   identified as the only real engine-level one.
3. **Policy optimisation depth.** Disabled rules, time-inactive rules, rules with no
   logging and no comment, unrouted objects. Config-derivable; the log-dependent parts
   are in the section above.
4. **Compliance breadth.** We map CIS, NIST 800-53, PCI DSS, ISO 27001, CERT-In and CEA.
   AlgoSec adds HIPAA, NERC CIP, FISMA, SOX, NIST 800-41 and IAVA.
5. **Presentation.** Custom charts and dashboards, Visio export of the map, and an
   ad-hoc discover/visualise tool equivalent to the AlgoSec Reporting Tool.

## Things we are choosing not to copy

- **A distributed master/slave architecture.** AlgoSec ships one because an appliance
  analysing six hundred firewalls needs it. Our collection is already horizontally
  scalable through worker containers (FR-JOB-05), which is the same answer without a
  second deployment topology to document and support.
- **A per-device 75 MB report of 1,500 linked files.** That is a 2005 artefact. Findings
  are queryable objects here, and a report is generated from them on demand.
- **Business application mapping (AppViz).** A separate product with its own data model
  — application owners, business services, ticket integration. Not a firewall analyser
  feature, and not something to bolt on halfway.
