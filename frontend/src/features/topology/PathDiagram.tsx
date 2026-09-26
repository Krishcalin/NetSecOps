/** The path, drawn (FR-TOPO-03).
 *
 * The hop table says everything this does and is the authoritative reading of a path.
 * What a table cannot do is make the *shape* of the answer legible at a glance: where
 * the packet stopped, which hop decided, and whether the chain actually reaches the
 * destination. Those are spatial facts, and people read them from a picture in about a
 * second and from a five-column table in considerably longer.
 *
 * Four things this is careful not to draw.
 *
 * **Nothing is drawn past a deny.** A packet stopped at hop three does not reach the
 * destination, so the chain ends there with a stop marker and the destination is drawn
 * unreached. An unbroken arrow running to the destination under a "blocked" verdict
 * would contradict the verdict, and the picture is what people believe.
 *
 * **A trace that ran out of estate ends in a dashed unknown**, not at the destination.
 * `partially-routed` means the path left the managed estate — there may be another
 * firewall out there, and drawing the chain as complete would assert there is not.
 *
 * **A hop that formed no opinion looks different from one that permitted.** A router
 * with no rulebase is a hop, not a control. Drawing them alike counts a device that
 * inspected nothing as a check that passed.
 *
 * **The state is never carried by colour alone** (WCAG 1.4.1). Each node's decision is
 * marked by its outline style and a glyph as well as its tone, and the diagram as a
 * whole is one `role="img"` with a text alternative that states the path in words. The
 * table below it remains the full, navigable equivalent.
 */

import { useId } from 'react';

import { buildChain, describeChain } from './pathChain';
import type { PathResult } from './types';

const NODE_W = 132;
const NODE_H = 58;
const GAP = 54;
const PAD = 8;
const LANE_Y = 46;
function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export function PathDiagram({ result }: { result: PathResult }) {
  const { cells, brokenAfter } = buildChain(result);

  // `useId` because ids have to be unique in the document and nothing stops a future
  // page rendering two paths side by side — at which point a hardcoded id would
  // silently give the second diagram the first one's description.
  const uid = useId();
  const titleId = `${uid}-title`;
  const descId = `${uid}-desc`;
  const arrowId = `${uid}-arrow`;

  const width = PAD * 2 + cells.length * NODE_W + (cells.length - 1) * GAP;
  const height = 132;
  const description = describeChain(result, cells);

  const xOf = (index: number) => PAD + index * (NODE_W + GAP);

  return (
    <div className="pathdiagram">
      <svg
        className="pathdiagram__svg"
        viewBox={`0 0 ${width} ${height}`}
        width={width}
        height={height}
        role="img"
        // Name and description kept on separate attributes. Pointing `aria-labelledby`
        // at both elements folds the whole sentence into the *name* and leaves the
        // description empty, which is how this was written first — the name then reads
        // as a paragraph and nothing carries the detail.
        aria-labelledby={titleId}
        aria-describedby={descId}
      >
        <title id={titleId}>Path diagram</title>
        <desc id={descId}>{description}</desc>

        <defs>
          <marker
            id={arrowId}
            viewBox="0 0 8 8"
            refX="7"
            refY="4"
            markerWidth="6"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 8 4 L 0 8 z" className="pathdiagram__arrowhead" />
          </marker>
        </defs>

        {cells.slice(0, -1).map((_from, index) => {
          const from = xOf(index) + NODE_W;
          const to = xOf(index + 1);
          // Solid while the packet is still travelling; dashed once the chain is
          // broken or speculative, so a reader can see where certainty ends.
          const severed = brokenAfter !== null && index >= brokenAfter;
          const speculative = severed || !cells[index + 1]?.reached;

          return (
            <g key={`edge-${index}`}>
              <line
                x1={from}
                y1={LANE_Y + NODE_H / 2}
                x2={to}
                y2={LANE_Y + NODE_H / 2}
                className={`pathdiagram__edge${speculative ? ' pathdiagram__edge--broken' : ''}`}
                markerEnd={severed ? undefined : `url(#${arrowId})`}
              />
              {severed && index === brokenAfter && (
                // The stop bar. A deny is the end of the packet's journey and the
                // picture has to show that, not taper off into a lighter arrow.
                <line
                  x1={from + GAP / 2}
                  y1={LANE_Y + 6}
                  x2={from + GAP / 2}
                  y2={LANE_Y + NODE_H - 6}
                  className="pathdiagram__stop"
                />
              )}
            </g>
          );
        })}

        {cells.map((cell, index) => (
          <g key={`node-${index}`} transform={`translate(${xOf(index)}, ${LANE_Y})`}>
            <rect
              width={NODE_W}
              height={NODE_H}
              rx="6"
              className={[
                'pathdiagram__node',
                `pathdiagram__node--${cell.kind}`,
                `pathdiagram__node--${cell.decision}`,
                cell.reached ? '' : 'pathdiagram__node--unreached',
              ]
                .filter(Boolean)
                .join(' ')}
            />
            <text x={NODE_W / 2} y={23} className="pathdiagram__title">
              {truncate(cell.title, 17)}
            </text>
            {cell.subtitle && (
              <text x={NODE_W / 2} y={40} className="pathdiagram__subtitle">
                {truncate(cell.subtitle, 22)}
              </text>
            )}
            {/* The glyph, so the decision is not carried by tone alone. */}
            {cell.decision !== 'none' && (
              <text x={NODE_W - 10} y={NODE_H - 6} className="pathdiagram__glyph">
                {cell.decision === 'deny' ? '✕' : '✓'}
              </text>
            )}
            {cell.markers.length > 0 && (
              <text x={NODE_W / 2} y={NODE_H + 16} className="pathdiagram__marker">
                {cell.markers.join(' · ')}
              </text>
            )}
          </g>
        ))}
      </svg>

      {/* Spelled out under the picture as well as inside it. The markers are two
          letters on a diagram and each one changes what the answer means. */}
      {(result.translated_at.length > 0 || result.branched_at.length > 0) && (
        <ul className="pathdiagram__key">
          {result.translated_at.length > 0 && (
            <li>
              <strong>NAT</strong> — {result.translated_at.join(', ')} carry NAT rules. The
              translation itself is not modelled, so an address may have changed here in a way the
              trace did not follow.
            </li>
          )}
          {result.branched_at.length > 0 && (
            <li>
              <strong>ECMP</strong> — {result.branched_at.join(', ')} had equal-cost routes. This
              trace took one of them; a firewall on a branch it did not take is not in this answer.
            </li>
          )}
        </ul>
      )}
    </div>
  );
}
