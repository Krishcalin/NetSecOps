# Commercial posture

**What this costs to run, what the incumbents charge, and what we should publish.**

This document exists because the one thing every vendor in this category refuses to do is
say a number. FireMon, AlgoSec and Tufin all publish "contact sales". The effect is not
mystery — their price lists are on their own resellers' websites — it is that a buyer
cannot size a budget without entering a sales process, which is the point.

Three sections: what running it actually costs, what the incumbents actually charge, and
what follows from the two.

---

## 1. Sizing

The numbers below are the reference configuration for NFR-PERF-01, not a floor. NetSecOps
is one container, one Postgres, and as many workers as you point at devices.

| Devices | vCPU | RAM | Workers | Notes |
|--------:|:----:|:---:|:-------:|-------|
| ≤ 100 | 2 | 4 GB | 1 | Single host. A laptop runs this. |
| ≤ 500 | 4 | 8 GB | 1 (20 concurrent) | Reference for NFR-PERF-01 |
| ≤ 2,000 | 8 | 16 GB | 3–4 | Scale worker replicas |
| > 2,000 | 8+ | 16 GB+ | 4+ | Add a read replica for reporting |

**Collections are IO-bound.** Most of a device session is spent waiting on the device, not
on CPU. Scale `NETSECOPS_WORKER_CONCURRENCY` and worker replicas before adding cores.

**There is a small tier, and it is the same product.** No feature is withheld from it: the
check library, path analysis, the vulnerability engine, the API and the report generator
are the same at 20 devices as at 2,000. This is worth stating because the alternative is
the norm — FireMon's published hardware specification is a flat 32-core, 96 GB appliance
whether you have fifty firewalls or five hundred, which prices a mid-sized network out of
the category before any licence is discussed.

**Database growth** is driven by artefacts and snapshots, not by findings. Identical
configurations are stored once, so a stable estate collecting daily grows far more slowly
than device-count × days would suggest. Retention is tunable in Settings (FR-ADM-01);
findings history and the audit log are never purged (DATA-02).

---

## 2. What the incumbents charge

FireMon is the right benchmark rather than AlgoSec or Tufin, because it is consistently
reviewed as the cheaper of the three. Model against the floor, not the ceiling.

FireMon publishes no price. Three of its resellers publish its price list.

**Per-device list, perpetual / annual subscription:**

| SKU | What it covers | Perpetual | Subscription |
|---|---|---:|---:|
| `SPFM-ASM` | The platform, one per app server | $10,650 | $5,000 |
| `SPFM-SMM` | One vendor management console (Panorama, FortiManager, CP SMS) | $3,993.75 | $1,875 |
| `SPFM-SMLO` | One large-office or datacentre firewall | $2,662.50 | $1,331.25 |
| `SPFM-SMSO` | One SOHO or branch device | $1,331.25 | $625 |
| `SPFM-NDM` | Network infrastructure without ACLs | $332.81 | $156.25 |

**The structural rules matter more than the numbers:**

- **Tier is device *class*, not device *count*.** SOHO : large-office : management console
  is exactly 1 : 2 : 3. There is no volume discount in the base SKUs — quantity appears
  only as separate bundle products. A growing estate pays linearly.
- **A standby in an HA pair is exactly 50% of the primary.** Consistent across ~100 rows.
- **Policy Planner and Policy Optimizer are each 50% of Security Manager** at the same
  tier — so the workflow modules roughly double the bill.
- **Support is a percentage of licence list**: 25% Silver, 35% Gold, 15% updates-only.
- **The management console is billed on top of the firewalls it manages.**

**Enterprise anchor**, identical on two independent sheets: an NSPM enterprise
subscription for **2,643 devices over 3 years** at **$7,980,615** — about
**$1,000 per device per year** at that volume, against $1,331 list for one.

**Public-sector demand**, from 68 federal awards in the USAspending API: a VA award of
$1,533,805 over three years whose modifications give a clean **$470,925/year renewal**;
IRS $1,239,086 over two years; DISA $862,775 for one.

### Read these with the caveats

- Reseller street price runs **1.09× to 1.65×** above the sheet's MSRP column with no
  constant multiplier, so that column is either a stale list or a partner-level number
  mislabelled. Do not treat one as the other.
- The bundle rows carry boilerplate descriptions that contradict their own SKUs (a Gold
  SKU described as Silver). Non-bundle rows verified clean.
- Government discount, from a Texas state cooperative sheet: **13.75% off software, 3%
  off support**.

---

## 3. What follows

### The gap is real and it is at the small end

PeerSpot's reviewer-versus-reader split measures it: **56% of the people researching this
category are SMB or mid-market, and only 31% of the people who deploy it are.** A quarter
of the interest in this category never converts, and the reason is not the software.

Three things cause it, and NetSecOps answers all three:

| Their constraint | What we do |
|---|---|
| 9–13 week implementation before anything is visible | `demo-seed` — a populated console in ten minutes, no device, no credential. See [evaluating.md](evaluating.md) |
| No trial, no free tier, no self-service | The product is open to run; the demonstration estate ships inside it |
| A flat 32-core / 96 GB appliance regardless of estate size | A 2-vCPU / 4 GB tier that is the same product |

### The competitor nobody names

**Firewall Orchestrator** (AGPL, self-hosted, multi-vendor import, recertification
workflow, GraphQL API) is the closest existing thing to NetSecOps and needs a direct
answer rather than silence. Ours: it is a policy-change workflow tool. NetSecOps is an
assessment platform — a check library, a vulnerability engine, path analysis and
compliance reporting — and it never writes to a device at all (SRS §8).

At the other end, **ManageEngine** owns published-price self-service from roughly $395 a
device. That is the price expectation a mid-market buyer arrives with.

### Recommended posture

1. **Publish a price.** The single strongest differentiator available, because it costs
   nothing to do and none of the three incumbents can follow without repricing their
   whole channel.
2. **Price per device, per year, with a published volume curve** — not per device class.
   Class-based pricing requires a conversation to establish which class each device is,
   which is itself a sales-process gate. A published curve does not.
3. **Anchor beneath the FireMon subscription floor**, not beneath its perpetual list.
   FireMon's real enterprise volume rate is about $1,000/device/year; its single-device
   large-office subscription is $1,331.
4. **Do not charge separately for the modules.** Path analysis, the vulnerability engine
   and compliance reporting are one product. FireMon's Policy Planner/Optimizer split is
   the thing customers complain about most.
5. **Do not price the standby.** An HA pair is one device's worth of policy. Charging 50%
   for the passive member is charging for the customer's resilience.

### The number is not set here

Points 1–5 are a position. The actual figure is a business decision that depends on
target segment, channel and cost base, none of which this repository knows. What it can
say is the shape:

- Below **$1,000/device/year** at volume, NetSecOps undercuts FireMon's best real
  enterprise rate while offering capabilities it does not have (native vulnerability
  detection, CPE/PSIRT/CSAF/KEV/EPSS enrichment, end-of-life).
- Below roughly **$400/device/year** at the small end, it meets the price expectation a
  mid-market buyer arrives with from ManageEngine.
- A free tier bounded by **device count** rather than by features keeps the "same product"
  claim honest. Bounding it by features reintroduces exactly the evaluation problem
  `demo-seed` exists to remove.

---

## 4. What we do not do, said plainly

A posture that claims everything is not credible. These are deliberate and permanent:

- **NetSecOps never writes to a device.** No policy push, no change implementation, no
  rule provisioning (SRS §8). That is one of FireMon's eight change-management stages;
  the other seven are read-only computation, and we do those.
- **No active discovery beyond the read-only probe set.** No SYN scanning, no SNMP
  community guessing against a list of vendor defaults, no WMI credential spraying.
- **No segmentation validation by spoofed packets.** Proving a leak path genuinely needs
  two-ended sensors and source-address spoofing. We do not do it, and we say so rather
  than implying our path analysis is equivalent.

---

## Sources

FireMon price lists (verified live, XLSX): Netsync (1,172 SKU rows, the complete one),
Presidio (7 rows, corroborates Netsync to the cent), and a 2019 Texas DIR sheet (the only
one showing government discount). Federal demand from the USAspending
`spending_by_award` API, keyword FireMon, 68 awards. Segment split from PeerSpot's
reviewer-versus-reader breakdown. Engine-level comparison in the FireMon and AlgoSec
dossiers.
