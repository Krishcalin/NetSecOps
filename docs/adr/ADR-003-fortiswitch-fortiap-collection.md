# ADR-003 — FortiSwitch and FortiAP data comes via the parent FortiGate

- **Status:** Accepted
- **Date:** 2026-09-13
- **Requirement:** FR-INV-04, FR-COL-01, FR-COL-05, Appendix D item 5
- **Decided by:** the customer, resolving the open question ahead of Phase 4

## Context

FortiSwitch and FortiAP units in a Security Fabric are managed by a FortiGate. Each unit
also has its own management interface and could in principle be collected from directly.
Appendix D asked which NetSecOps should do.

Collecting directly would mean each unit is its own device with its own credential, its
own host key and its own read-only allow-list. Collecting via the parent means one
session to the FortiGate yields the managed units as child records.

## Decision

**FortiSwitch and FortiAP data is collected via the parent FortiGate only.** NetSecOps
does not open sessions to managed switches or access points.

## Consequences

- Managed units are stored as devices with `parent_device_id` pointing at the FortiGate,
  which is the same relationship FR-INV-04 already uses for Panorama, FortiManager, FMC
  and Check Point management servers. No new model is needed; Phase 1 built this.
- The unit inherits the fabric's view of itself. What the FortiGate reports is what gets
  assessed, and where the FortiGate's information is stale or partial the assessment
  inherits that. Checks that need data the FortiGate does not expose report *Not
  Evaluated* rather than being quietly dropped.
- **No credential is stored for a managed unit.** This is the main security benefit: the
  estate's credential surface does not grow by one secret per access point, and there is
  no path by which NetSecOps could authenticate to an AP even if an adapter were
  defective.
- A unit that is *not* fabric-managed is out of scope by construction. If one appears in
  inventory it will have no parent and no collection path, so it must be visibly
  unassessed rather than appearing clean — worth an explicit check when Phase 4 builds
  the FortiOS adapter.
- Radio-level data that only the AP itself holds is not available. For the wireless
  checks in Phase 5 this means the assessable set is what the controller exposes, which
  should be stated in that phase's scope rather than discovered during it.

## Alternatives considered

**Collect directly from each unit.** Rejected. It multiplies credentials by the number
of access points — often the largest device count in an estate — for data the parent
already aggregates, and it puts NetSecOps on the management plane of hundreds of small
devices whose software is patched least often.

**Both, with direct collection as an opt-in per device.** Deferred rather than rejected.
It is the natural extension if the FortiGate's view proves insufficient, and the
`parent_device_id` model does not preclude it. Building it now would be speculative:
nothing has yet shown the aggregated data to be inadequate.
