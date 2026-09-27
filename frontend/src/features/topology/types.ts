/** Topology types, mirroring netsecops/schemas/topology.py. */

export interface Hop {
  device_id: string;
  hostname: string;
  platform: string | null;
  matched_route: string | null;
  next_hop: string | null;
  egress_interface: string | null;
  ingress_zone: string | null;
  egress_zone: string | null;
  /** Null where the device carries no rulebase — a router is a hop, not a decision.
   *  Distinct from 'allow', and rendered differently, because showing them the same
   *  counts a device that inspected nothing as a control that was checked. */
  action: string | null;
  rule_name: string | null;
  rule_order: number | null;
  limitations: string[];
  /** What this device's NAT did — "destination 203.0.113.10 → 10.20.0.10" — or null.
   *  Every hop after one that translates was traced with the rewritten addresses, so
   *  this is where a reader sees the question change part-way along the path. */
  translation: string | null;
}

export type Routing = 'unreachable' | 'same-zone' | 'routed' | 'partially-routed' | 'unknown';
export type Policy = 'allowed' | 'blocked' | 'partially-allowed' | 'not-routed';

export interface PathResult {
  source: string;
  destination: string;
  protocol: string;
  port: number;
  /** Two axes, never one. They fail independently, and a single verdict has to lie
   *  about one of them. */
  routing: Routing;
  policy: Policy;
  hops: Hop[];
  stopped_at_prefix: string | null;
  stopped_at_next_hop: string | null;
  stopped_at_device: string | null;
  /** Translations the walk followed: "edge-fw: destination 203.0.113.10 → 10.20.0.10".
   *
   *  Informational, not a caveat. The hops after each of these were evaluated against
   *  the rewritten addresses, which is the right question — so a followed translation
   *  does not weaken the verdict. */
  translated_at: string[];
  /** NAT that may apply and could not be followed — a pool chosen per session, an
   *  object nothing defines, a form no parser reads. This one does weaken everything
   *  after it, and non-empty means the policy verdict is `partially-allowed`. */
  translation_unknown_at: string[];
  /** Hostnames where equal-cost routes diverged. The trace took one; the others were
   *  never walked, and a firewall on an unwalked branch is not in this answer. */
  branched_at: string[];
  notes: string[];
}

export interface MissingDevice {
  address: string;
  referenced_by: string[];
  prefixes: string[];
  carries_default_route: boolean;
  score: number;
  adjacent_to: string | null;
  reason: string;
}

export interface MapInterface {
  name: string;
  addresses: string[];
  zone: string | null;
}

export interface MapNode {
  id: string;
  /** `device` or `unmanaged`. The second is an address routes point at that no device
   *  in the inventory answers for — a hole in the evidence, and never drawn as a box
   *  like the others. */
  kind: 'device' | 'unmanaged';
  label: string;
  group: string;
  /** Breadth-first distance from the estate boundary. The column the box sits in. */
  tier: number;
  platform: string | null;
  vendor: string | null;
  device_class: string | null;
  criticality: string | null;
  status: string | null;
  site: string | null;
  has_rulebase: boolean;
  /** Carries rules in force on traffic crossing it. Narrower than `has_rulebase`, and
   *  what the map is drawn from: an access list bound to nothing — a vty filter, a
   *  leftover — filters no transit traffic, so its device is not a control and must
   *  not be badged as one. */
  inspects: boolean;
  routes: number;
  /** False where the snapshot predates route parsing: no routes anybody read, which is
   *  not the same as having none. */
  routes_known: boolean;
  interfaces: MapInterface[];
  /** Every interface. `interfaces` holds only the addressed ones, so a 48-port switch
   *  shows one SVI and this says the other forty-seven exist. */
  interface_count: number;
  findings: Record<string, number>;
  has_snapshot: boolean;
  referenced_by: string[];
  carries_default_route: boolean;
}

export interface MapLink {
  id: string;
  source: string;
  target: string;
  via: string[];
  prefixes: number;
  carries_default: boolean;
  /** False where only one end routes to the other. A real asymmetry, drawn as one. */
  bidirectional: boolean;
  source_interface: string | null;
  target_interface: string | null;
  crosses_firewall: boolean;
}

export interface MapGroup {
  id: string;
  label: string;
  /** `site` | `hostname` | `index` — where the label came from, so an inferred name is
   *  not read as something somebody configured. */
  label_source: string;
  devices: number;
  firewalls: number;
  unmanaged: number;
  links: number;
  tiers: number;
}

export interface EstateMap {
  nodes: MapNode[];
  links: MapLink[];
  groups: MapGroup[];
  devices: number;
  unmanaged: number;
  devices_without_route_data: number;
  isolated: number;
  omitted_groups: string[];
  omitted_devices: number;
}

export interface TopologySummary {
  devices: number;
  devices_with_routes: number;
  devices_without_route_data: number;
  devices_with_rulebase: number;
  routes: number;
  unmanaged_next_hops: number;
}

/** How each value reads, and how it is coloured.
 *
 *  **The partial states are amber, and they are the reason this table exists.** The
 *  severity palette's `medium` and `low` render identically, so mapping `allowed` and
 *  `partially-allowed` onto those would make the two indistinguishable — which is the
 *  single thing this design must not do. `high` is the warning tone, visually distinct
 *  from both `success` and the muted `unknown`.
 *
 *  Only a definitive answer earns `success`: traced end to end, or stopped by a rule.
 *  Everything provisional is amber, and everything the product could not determine is
 *  muted. */
export const ROUTING_LABELS: Record<Routing, { label: string; tone: string; meaning: string }> = {
  routed: {
    label: 'Routed',
    tone: 'success',
    meaning: 'Traced end to end across devices in the inventory.',
  },
  'partially-routed': {
    label: 'Partially routed',
    tone: 'high',
    meaning: 'Traced until the path left the managed estate.',
  },
  'same-zone': {
    label: 'Same subnet',
    tone: 'info',
    meaning: 'Both addresses are on one attached subnet, so nothing routes between them.',
  },
  unreachable: {
    label: 'Unreachable',
    tone: 'info',
    meaning: 'A device with a readable table has no route to the destination.',
  },
  unknown: {
    label: 'Unknown',
    tone: 'unknown',
    meaning: 'Something prevented a trace: a table never collected, truncated, or a loop.',
  },
};

export const POLICY_LABELS: Record<Policy, { label: string; tone: string; meaning: string }> = {
  allowed: {
    label: 'Allowed',
    tone: 'success',
    meaning: 'Every firewall on the fully traced path permits this traffic.',
  },
  blocked: {
    label: 'Blocked',
    tone: 'denied',
    meaning: 'A device on the path denies it. The packet does not reach anything beyond.',
  },
  'partially-allowed': {
    label: 'Partially allowed',
    tone: 'high',
    meaning:
      'Every firewall found permits it, but the path was not traced to the end — so this is not a statement that the traffic gets through.',
  },
  'not-routed': {
    label: 'Not routed',
    tone: 'info',
    meaning: 'There is no path to evaluate policy over.',
  },
};
