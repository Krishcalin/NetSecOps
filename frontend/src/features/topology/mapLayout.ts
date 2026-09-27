/** Placing the estate map's boxes and strands.
 *
 * Split out from the component and kept pure, for two reasons. The first is that this
 * is the part with the arithmetic in it, and arithmetic is worth testing without a DOM.
 * The second matters more: **the layout has to be deterministic.** The same estate must
 * produce the same picture on every run, or two screenshots of an unchanged network
 * cannot be compared — which is most of what somebody wants a map for. So there is no
 * physics simulation and no randomness anywhere below; position comes from the tier the
 * backend computed and from the hostname, and nothing else.
 *
 * **Bundling never hides a rulebase.** Leaf devices that hang off one parent collapse
 * into a single box with a count, because fifty access switches in a column is a wall
 * rather than a picture. A device carrying a rulebase is exempt no matter how it is
 * attached: a firewall is a control, and a map that quietly folds controls out of sight
 * is worse than one that is hard to read.
 *
 * **Unmanaged boundary nodes are never bundled either.** They are the single most
 * useful thing on the picture — each one names a device somebody would have to onboard
 * to learn more — and they are also the rarest, so there is nothing to gain by it.
 */

import type { EstateMap, MapGroup, MapLink, MapNode } from './types';

export const NODE_W = 168;
export const NODE_H = 44;
export const ROW_GAP = 14;
export const COL_GAP = 78;
export const BAND_GAP = 40;
export const BAND_PAD_TOP = 30;
export const BAND_PAD = 18;
export const ROW_H = NODE_H + ROW_GAP;
export const COL_W = NODE_W + COL_GAP;

/** Room above the first band for the column headings. */
export const HEADER_H = 30;

/** Below this, a bundle costs a click and saves nothing. */
export const MIN_BUNDLE = 3;

/** What a column is, in words.
 *
 * The number is a breadth-first depth from the estate boundary, and "tier 2" means
 * nothing to a reader. Negative depth is the boundary itself — addresses the estate
 * routes to and does not manage — which sits outside the edge rather than inside it.
 */
export function tierLabel(tier: number): string {
  if (tier < 0) return 'Outside the estate';
  if (tier === 0) return 'Estate edge';
  return `${tier} hop${tier === 1 ? '' : 's'} in`;
}

export interface PlacedNode {
  key: string;
  x: number;
  y: number;
  /** A single device, or several folded into one box. */
  node: MapNode;
  members: MapNode[];
  bundled: boolean;
  /** For a bundle: the id of the device its members all hang off. */
  parent: string | null;
}

export interface PlacedLink {
  key: string;
  link: MapLink;
  /** Endpoint centres, already resolved through any bundling. */
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  /** Both ends of the strand, as placed-node keys, for highlighting. */
  from: string;
  to: string;
  /** How many underlying links this strand stands for, once bundled. */
  count: number;
}

export interface PlacedBand {
  group: MapGroup;
  y: number;
  height: number;
  width: number;
}

export interface MapLayout {
  width: number;
  height: number;
  nodes: PlacedNode[];
  links: PlacedLink[];
  bands: PlacedBand[];
  /** Column index → the tier it draws, and where its heading sits. Tiers can start
   *  negative (the boundary sits outside the edge), so the columns are shifted rather
   *  than the tiers rewritten. */
  tiers: { tier: number; x: number; label: string }[];
}

export interface LayoutOptions {
  /** Group ids to draw. Empty means every group. */
  groups?: string[];
  /** Bundle keys the reader has opened. */
  expanded?: ReadonlySet<string>;
  /** Draw every device individually. */
  expandAll?: boolean;
}

/** The key a bundle is addressed by, stable across renders. */
export function bundleKey(parentId: string, tier: number): string {
  return `bundle:${parentId}:${tier}`;
}

export function layoutMap(map: EstateMap, options: LayoutOptions = {}): MapLayout {
  const wanted = new Set(options.groups ?? []);
  const nodes = wanted.size === 0 ? map.nodes : map.nodes.filter((n) => wanted.has(n.group));
  const visible = new Set(nodes.map((n) => n.id));
  const links = map.links.filter((l) => visible.has(l.source) && visible.has(l.target));

  const degree = new Map<string, number>();
  const neighbours = new Map<string, string[]>();
  const join = (a: string, b: string) => {
    degree.set(a, (degree.get(a) ?? 0) + 1);
    neighbours.set(a, [...(neighbours.get(a) ?? []), b]);
  };
  for (const link of links) {
    join(link.source, link.target);
    join(link.target, link.source);
  }

  // ── which boxes are folded together ──────────────────────────────────────
  const folded = new Map<string, string>(); // node id → bundle key
  const bundles = new Map<string, { parent: string; tier: number; members: MapNode[] }>();

  if (!options.expandAll) {
    const candidates = new Map<string, MapNode[]>();
    for (const node of nodes) {
      const parent = neighbours.get(node.id)?.[0];
      const foldable =
        node.kind === 'device' &&
        // `inspects`, not `has_rulebase`: an access switch whose only access list is a
        // vty filter has a rulebase and is not a control, and keeping every one of them
        // unfolded would put the wall of boxes back that bundling exists to remove.
        !node.inspects &&
        (degree.get(node.id) ?? 0) === 1 &&
        parent !== undefined &&
        !parent.startsWith('unmanaged:');
      if (!foldable || parent === undefined) continue;
      const key = bundleKey(parent, node.tier);
      candidates.set(key, [...(candidates.get(key) ?? []), node]);
    }

    for (const [key, members] of candidates) {
      if (members.length < MIN_BUNDLE || options.expanded?.has(key)) continue;
      const ordered = [...members].sort((a, b) => a.label.localeCompare(b.label));
      bundles.set(key, {
        parent: ordered[0] ? (neighbours.get(ordered[0].id)?.[0] ?? '') : '',
        tier: ordered[0]?.tier ?? 0,
        members: ordered,
      });
      for (const member of ordered) folded.set(member.id, key);
    }
  }

  // ── columns ──────────────────────────────────────────────────────────────
  const tiers = [...new Set(nodes.map((n) => n.tier))].sort((a, b) => a - b);
  const columnOf = new Map(tiers.map((tier, index) => [tier, index]));

  type Entry = {
    key: string;
    node: MapNode;
    members: MapNode[];
    bundled: boolean;
    parent: string | null;
  };
  const cells = new Map<string, Entry[]>(); // `${group}:${column}` → entries

  const push = (group: string, tier: number, entry: Entry) => {
    const key = `${group}:${columnOf.get(tier) ?? 0}`;
    cells.set(key, [...(cells.get(key) ?? []), entry]);
  };

  for (const node of nodes) {
    if (folded.has(node.id)) continue;
    push(node.group, node.tier, {
      key: node.id,
      node,
      members: [node],
      bundled: false,
      parent: null,
    });
  }
  for (const [key, bundle] of bundles) {
    const first = bundle.members[0];
    if (!first) continue;
    push(first.group, bundle.tier, {
      key,
      // The bundle borrows its first member's shape — same group, tier and class — and
      // relabels itself with the count. Everything else about it is read from
      // `members`, so nothing downstream has to special-case a synthetic node.
      node: { ...first, id: key, label: `${bundle.members.length} × ${describe(bundle.members)}` },
      members: bundle.members,
      bundled: true,
      parent: bundle.parent,
    });
  }

  for (const entries of cells.values()) {
    entries.sort((a, b) => a.node.label.localeCompare(b.node.label, undefined, { numeric: true }));
  }

  // ── bands, one per group, stacked ────────────────────────────────────────
  const groups = map.groups
    .filter((group) => wanted.size === 0 || wanted.has(group.id))
    .filter((group) => nodes.some((node) => node.group === group.id));

  const columnCount = Math.max(tiers.length, 1);
  const width = BAND_PAD * 2 + columnCount * NODE_W + (columnCount - 1) * COL_GAP;

  const bands: PlacedBand[] = [];
  const placed: PlacedNode[] = [];
  const centres = new Map<string, { x: number; y: number }>();

  let y = HEADER_H;
  for (const group of groups) {
    const columns = Array.from(
      { length: columnCount },
      (_, index) => cells.get(`${group.id}:${index}`) ?? [],
    );
    const tallest = Math.max(1, ...columns.map((column) => column.length));
    const height = BAND_PAD_TOP + BAND_PAD + tallest * NODE_H + (tallest - 1) * ROW_GAP;

    bands.push({ group, y, height, width });

    columns.forEach((column, index) => {
      // Each column is centred in its band rather than top-aligned, so a tier holding
      // one device sits opposite the middle of the tier it feeds instead of at the top
      // corner with a strand running diagonally across everything.
      const stack = column.length * NODE_H + Math.max(0, column.length - 1) * ROW_GAP;
      const top = y + BAND_PAD_TOP + (height - BAND_PAD_TOP - BAND_PAD - stack) / 2;
      column.forEach((entry, row) => {
        const x = BAND_PAD + index * COL_W;
        const boxY = top + row * ROW_H;
        placed.push({ ...entry, x, y: boxY });
        centres.set(entry.key, { x: x + NODE_W / 2, y: boxY + NODE_H / 2 });
      });
    });

    y += height + BAND_GAP;
  }

  // ── strands ──────────────────────────────────────────────────────────────
  const merged = new Map<string, PlacedLink>();
  for (const link of links) {
    const from = folded.get(link.source) ?? link.source;
    const to = folded.get(link.target) ?? link.target;
    // A link between two members of one bundle would be a strand from a box to itself.
    if (from === to) continue;

    const a = centres.get(from);
    const b = centres.get(to);
    if (!a || !b) continue;

    // Many switches folded into one box means many links folded into one strand, and
    // the count is what stops that reading as a single cable.
    const key = from < to ? `${from}~${to}` : `${to}~${from}`;
    const existing = merged.get(key);
    if (existing) {
      existing.count += 1;
      continue;
    }
    merged.set(key, { key, link, x1: a.x, y1: a.y, x2: b.x, y2: b.y, from, to, count: 1 });
  }

  return {
    width,
    height: Math.max(y - BAND_GAP / 2, NODE_H + BAND_GAP),
    nodes: placed,
    links: [...merged.values()],
    bands,
    tiers: tiers.map((tier, index) => ({
      tier,
      x: BAND_PAD + index * COL_W + NODE_W / 2,
      label: tierLabel(tier),
    })),
  };
}

/** What a bundle calls the things inside it. */
function describe(members: MapNode[]): string {
  const classes = new Set(members.map((member) => member.device_class ?? 'device'));
  if (classes.size === 1) {
    const only = [...classes][0] ?? 'device';
    return only === 'switch' ? 'switches' : `${only}s`;
  }
  return 'devices';
}

/** A curved strand between two boxes.
 *
 * Horizontal control points rather than a straight line, so strands leaving one box
 * fan apart instead of overlapping into a single thick wedge — which is the difference
 * between seeing nine links and seeing one.
 */
export function strandPath(link: PlacedLink): string {
  const dx = Math.max(Math.abs(link.x2 - link.x1) * 0.45, 24);
  const direction = link.x2 >= link.x1 ? 1 : -1;
  return `M ${link.x1} ${link.y1} C ${link.x1 + dx * direction} ${link.y1}, ${link.x2 - dx * direction} ${link.y2}, ${link.x2} ${link.y2}`;
}

/** Severity, worst first, for the risk dot on a box. */
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

export function worstSeverity(findings: Record<string, number>): string | null {
  for (const severity of SEVERITY_ORDER) {
    if ((findings[severity] ?? 0) > 0) return severity;
  }
  return null;
}

export function totalFindings(findings: Record<string, number>): number {
  return Object.values(findings).reduce((sum, count) => sum + count, 0);
}

/** `10.20.0.1/255.255.255.0` and `10.20.0.1/24` are the same address written two ways,
 *  and both reach the map because different parsers record different forms. Shown side
 *  by side in one list they read as a defect, so the dotted form is folded into the
 *  prefix length — losslessly, and only when it really is a contiguous mask. */
export function tidyAddress(address: string): string {
  const [ip, mask] = address.split('/');
  if (!ip || !mask || !mask.includes('.')) return address;

  const octets = mask.split('.').map(Number);
  if (octets.length !== 4 || octets.some((part) => Number.isNaN(part) || part < 0 || part > 255)) {
    return address;
  }
  const bits = octets.reduce((value, octet) => value * 256 + octet, 0);
  const length = 32 - Math.log2((~bits >>> 0) + 1);
  if (!Number.isInteger(length) || length < 0 || length > 32) return address;
  return `${ip}/${length}`;
}
