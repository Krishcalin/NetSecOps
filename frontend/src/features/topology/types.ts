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
  /** Hostnames of devices carrying NAT rules that the path continued past.
   *
   *  Presence only — the translation itself is not modelled, because `original` and
   *  `translated` mean different things on PAN-OS, FortiOS, Check Point and ASA. So an
   *  address may have changed at these hops in a way the trace did not follow, and the
   *  answer past them is about the address as written, not as it arrived. */
  translated_at: string[];
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
