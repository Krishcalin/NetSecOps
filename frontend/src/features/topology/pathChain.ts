/** Turning a path result into the chain a diagram draws (FR-TOPO-03).
 *
 * Kept apart from the drawing on purpose. The question this answers — *does the packet
 * reach the destination, and if not where does it stop* — is the one thing the diagram
 * can silently invert, and it is decided here once rather than implied by three
 * separate pieces of drawing code that can disagree with each other and with the
 * verdict pills above them.
 *
 * Separating it also means it can be tested as data, without asserting on rectangles.
 */

import type { PathResult } from './types';

export interface Cell {
  kind: 'endpoint' | 'hop' | 'unknown';
  title: string;
  subtitle: string | null;
  /** `none` is a hop that carries no rulebase — a router is a hop, not a decision. */
  decision: 'deny' | 'allow' | 'none';
  reached: boolean;
  /** Drawn under the node: NAT and equal-cost markers. */
  markers: string[];
}

export interface Chain {
  cells: Cell[];
  /** Index in `cells` after which nothing flows, or null. Set by a deny. */
  brokenAfter: number | null;
}

/** Hostnames named at the start of an entry like "edge-fw: destination … → …". */
function hostnamesIn(entries: string[]): Set<string> {
  return new Set(entries.map((entry) => entry.split(':')[0]?.trim() ?? '').filter(Boolean));
}

export function buildChain(result: PathResult): Chain {
  const translated = hostnamesIn(result.translated_at);
  const unknown = hostnamesIn(result.translation_unknown_at);
  const branched = new Set(result.branched_at);

  const cells: Cell[] = [
    {
      kind: 'endpoint',
      title: result.source,
      subtitle: 'source',
      decision: 'none',
      reached: true,
      markers: [],
    },
  ];

  let brokenAfter: number | null = null;

  result.hops.forEach((hop, index) => {
    const decision = hop.action === null ? 'none' : hop.action === 'deny' ? 'deny' : 'allow';
    const markers: string[] = [];
    // A translation the walk followed and one it could not are marked differently.
    // They used to be one thing, and the distinction is the difference between "the
    // address changed here, and we followed it" and "the address may have changed here
    // and everything after this is doubtful".
    if (translated.has(hop.hostname)) markers.push('NAT');
    if (unknown.has(hop.hostname)) markers.push('NAT?');
    if (branched.has(hop.hostname)) markers.push('ECMP');

    cells.push({
      kind: 'hop',
      title: hop.hostname,
      subtitle:
        hop.ingress_zone || hop.egress_zone
          ? `${hop.ingress_zone ?? '—'} → ${hop.egress_zone ?? '—'}`
          : (hop.platform ?? null),
      decision,
      // Every hop in the list was reached — the walk only records hops it got to.
      reached: true,
      markers,
    });

    // Nothing flows past a deny, so the chain ends here whatever follows.
    if (decision === 'deny' && brokenAfter === null) brokenAfter = index + 1;
  });

  if (brokenAfter !== null) {
    cells.push({
      kind: 'endpoint',
      title: result.destination,
      subtitle: 'never reached',
      decision: 'none',
      reached: false,
      markers: [],
    });
  } else if (result.stopped_at_next_hop) {
    // The trace ran out of estate. There may be another firewall beyond this, so the
    // chain ends in an explicit unknown rather than running on to the destination.
    cells.push({
      kind: 'unknown',
      title: result.stopped_at_next_hop,
      subtitle: 'not in inventory',
      decision: 'none',
      reached: false,
      markers: [],
    });
    cells.push({
      kind: 'endpoint',
      title: result.destination,
      subtitle: 'beyond the trace',
      decision: 'none',
      reached: false,
      markers: [],
    });
  } else {
    cells.push({
      kind: 'endpoint',
      title: result.destination,
      subtitle: 'destination',
      decision: 'none',
      reached: result.routing === 'routed' || result.routing === 'same-zone',
      markers: [],
    });
  }

  return { cells, brokenAfter };
}

/** The path in a sentence — the diagram, for anyone who cannot see it.
 *
 * Carries the same conclusion as the picture rather than a label like "path diagram",
 * because a text alternative that names the image instead of stating its content
 * leaves a screen reader user with nothing.
 */
export function describeChain(result: PathResult, cells: Cell[]): string {
  const via = cells
    .filter((cell) => cell.kind === 'hop')
    .map((cell) => {
      const verb =
        cell.decision === 'deny' ? 'denies' : cell.decision === 'allow' ? 'permits' : 'forwards';
      return `${cell.title} ${verb}`;
    });

  const route = via.length > 0 ? ` via ${via.join(', then ')}` : '';
  const ending = cells[cells.length - 1]?.reached
    ? 'reaching the destination'
    : 'not reaching the destination';

  return `Path from ${result.source} to ${result.destination} on ${result.protocol} port ${result.port}${route}, ${ending}.`;
}
