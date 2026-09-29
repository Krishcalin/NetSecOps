# Build plan — Matrices and DR sets (AlgoSec parity gap 2)

Lined up 2026-09-29, to be executed after the compliance-breadth work lands. This is the
gap docs/algosec-parity.md ranks second: AlgoSec's cross-device constructs, and the
"multi-device reasoning" the competitive dossiers named as the only real engine-level
difference.

## What already exists — read this before designing anything

The multi-device **engine** is built. This plan does not re-implement it; it adds the
organising constructs AlgoSec wraps around an equivalent engine.

- `topology/graph.py` — `build_graph(nodes)` assembles per-device forwarding tables into
  one layer-3 graph, VRFs as separate domains (FR-TOPO-02).
- `topology/path.py` — `walk(graph, source, destination, protocol, port)` traces a packet
  across hops, consulting each device's rulebase, returning routing confidence and policy
  verdict as **two separate axes** (FR-TOPO-03/04/05). `MAX_HOPS = 32`.
- `services/segmentation.py` — already computes a zone-to-zone matrix by walking every
  declared `SegmentationRule` across the estate: `MatrixResult`/`CellResult`,
  `CellStatus` ∈ {UPHELD, VIOLATED, UNVERIFIED}, an untraceable cell is never a pass, a
  DENIED intent is proved over the whole address range, not a sample.
- `db/models/inventory.py` — `DeviceGroup` (hierarchical, ltree `path`) + `DeviceGroupMember`
  (M2M), full CRUD in `services/inventory.py`, group-scoped compliance reports in
  `services/reporting.py` (`_group_compliance` → `_group_device_ids`).
- `db/models/reporting.py` — `ReportTemplate` already has `PATH_ANALYSIS` and `SEGMENTATION`.

## The two hard constraints this plan is built around

1. **The topology graph stays estate-wide. It is never truncated to a group.**
   `services/reporting.py` (`_path_analysis`, `_segmentation`) documents why: a graph
   built from a subset stops at the first hop outside the subset and reports a real path
   as `unreachable` — a *wrong* answer dressed as a scoped one. A "group-scoped matrix"
   therefore means *the zones/endpoints presented* are the group's; **the walk still
   crosses the whole estate.** Any slice that forgets this ships the exact bug the engine
   was designed to avoid.

2. **A matrix result is computed on demand, not stored.** `db/models/segmentation.py`
   records the rule: a stored verdict is a stale claim; the frozen answer belongs in the
   report archive, not a live table. New "matrix" entities persist a *definition* (what to
   compute), never a *result*.

---

## Slice A — DR sets (greenfield; do this first)

**Why first.** It is self-contained, and it makes every path and matrix answer *more
correct* by removing a class of duplicate/standby node from the graph — so the matrix
slices below build on a correct graph rather than a doubled one.

**What AlgoSec does.** A DR set is two (or more) devices that are disaster-recovery
replicas. AFA analyses them as **one logical device**: the standby's near-identical
rulebase is not a second device, paths through the pair count once, and the standby is
represented as part of the set rather than as an independent estate node.

**What we build.**

- **Model** (`db/models/dr.py`, migration `0018_dr_sets.py`):
  - `DrSet(UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin)` — `name` (unique per org),
    `description`.
  - `DrSetMember` — PK `(dr_set_id, device_id)`, `role: DrRole ∈ {PRIMARY, STANDBY}`,
    exactly one PRIMARY per set (partial unique index / service-enforced). CASCADE on
    device delete.
- **Suggestion, never auto-creation** (`services/dr.py`): resolve `DeviceFacts.ha.peer`
  (free-text hostname/mgmt-IP, `ncm/models.py:HighAvailability`) against `Device`
  hostname/management address and *propose* candidate DR sets for a user to confirm.
  `ha.peer` is unverified parser output, so it seeds a suggestion, it does not decide
  one — consistent with the product's no-surprise posture.
- **Topology dedup** (`services/topology.py:_nodes`): after loading devices, collapse each
  DR set's members into a single `DeviceNode` built from the **primary's** latest snapshot,
  but **union the interface-address ownership** of all members (and any shared VIP/floating
  address) into that one node's `_owners` entries. A next hop pointing at the standby's
  address must resolve to the one logical node, or the dedup reintroduces the very
  unreachable-at-standby bug we are removing. Fingerprint (`_fingerprint`) must include DR-set
  membership so the graph cache invalidates when a set changes.
- **Representation, not suppression, of divergence.** We do not today raise inter-peer
  drift, so there is nothing to silence. Instead add a *positive* check —
  **DR peer consistency**: diff the primary's and standby's rulebase/hardening facts and
  warn where a standby has diverged from the primary it is meant to replicate. This is the
  useful half of what AlgoSec's "treat as one" hides, surfaced deliberately.
- **API** (`api/v1/dr.py`): CRUD for DR sets + a `GET /dr-sets/suggestions` endpoint over
  the `ha.peer` resolver. `require(Permission.DEVICE_WRITE)` + `verify_csrf` on writes;
  `AuditService` on every mutation. New `Permission` members if DR management wants its own
  grant, else reuse DEVICE_READ/WRITE.
- **Tests**: a two-device DR set collapses to one node; a next hop at the standby's IP
  still resolves; a path that crossed both members now counts one hop; the suggestion
  resolver matches on hostname and mgmt-IP and never on a blank `peer`; peer-consistency
  warns on a diverged standby and stays quiet on an identical one.

**Acceptance**: with a primary+standby declared, `walk()` produces the same verdict as if
only the primary existed, and the estate device count in reports reflects the logical set.

---

## Slice B — Group-scoped connectivity matrix (the AlgoSec "Matrix" view)

Our segmentation engine **verifies declared intent**. AlgoSec's matrix also **discovers**:
it shows the full zone-to-zone reachability of a group's devices, whether or not anyone
declared a rule about it. That discovery view is the missing capability.

- **B0 — derive zones from devices** (`services/topology.py` already parses
  `DeviceNode.zones` and interface networks): a service that, given a `DeviceGroup`,
  produces the set of zones/connected networks its devices own. This is what lets a matrix
  be "about a group" without hand-declared address-space zones (which stay supported).
- **B — all-pairs walk** (extend `services/segmentation.py` or a new `services/matrix.py`):
  for the derived zones, `walk()` every ordered pair **over the estate graph**, reusing the
  range-aware, unverified-is-not-a-pass discipline already in `_judge`/`_evaluate_cell`.
  Cap pairs as `MAX_PREFIX_PAIRS` does today. Output is an N×N reachability grid:
  allowed / blocked / partial / unverified per cell, each with its traced hops.
- **Scope semantics, stated on the result**: "zones belong to group G; paths cross the
  whole estate." Never truncate the graph (constraint 1).
- **Tests**: derived zones match a group's interfaces; an all-pairs matrix over a 3-zone
  group is 6 directed cells; a cell whose path leaves the estate is `unverified`, not
  `blocked`; a permit assembled across two firewalls shows allowed.

---

## Slice C — Named, saved matrices (thin layer over B)

- **Model** (`db/models/matrix.py`, migration `0019_connectivity_matrix.py`):
  `ConnectivityMatrix(name, org_id, device_group_id → DeviceGroup, options JSONB)` —
  stores the *definition* only (which group, protocol/port set, whether to include
  discovered vs declared zones). No result column (constraint 2).
- **API** (`api/v1/matrix.py`): CRUD for definitions + `GET /matrices/{id}/result` which
  computes on demand via Slice B.
- **Reporting**: add `ReportTemplate.CONNECTIVITY_MATRIX`, so a frozen matrix answer lands
  in the report archive (where frozen answers belong), reusing the `_segmentation` freezing
  precedent.
- **Frontend**: a matrix page mirroring the existing segmentation/path views; grid cells
  colour by verdict, click-through to the traced hops.

---

## Order and rationale

1. **Slice A (DR sets)** — correctness dividend for everything downstream; smallest,
   self-contained; greenfield model + a focused topology change.
2. **Slice B (group-scoped discovery matrix)** — the visible AlgoSec-parity capability;
   reuses the walk engine and segmentation discipline.
3. **Slice C (named matrices + report template)** — persistence and presentation over B.

A/B are independent and could be built in either order or in parallel; A is recommended
first only because it makes B's answers more correct. C strictly depends on B.

**Out of scope, and why** (unchanged from algosec-parity.md): traffic-log-derived matrix
features (unused rules, Intelligent Policy Tuner) still need a log source we do not have;
nothing here writes to a device, so §8 is untouched.
