/** The estate, drawn (FR-TOPO-02).
 *
 * Every strand on this picture is a route whose next hop is configured on an interface
 * of the device at the other end. Nothing here is inferred from a shared subnet, a
 * naming convention or a guess — which is why a device can sit on the map connected to
 * nothing at all, and why the addresses the estate routes to and cannot account for are
 * drawn as boxes of their own rather than left off.
 *
 * Four things this is careful about.
 *
 * **A device whose rulebase is in force is never folded into a bundle.** Fifty access
 * switches collapse into one box because otherwise the column is a wall; a firewall does
 * not, however it is attached. Folding a control out of sight is worse than a crowded
 * map. "In force" and "has rules" are different tests and the narrower one is right
 * here: an `access-class` on the vty lines filters management access, not traffic, so
 * the switch carrying one is not a control and the box would be a lie.
 *
 * **Nothing is carried by colour alone** (WCAG 1.4.1). Each box states its class in
 * words, a rulebase is marked with a glyph as well as an outline, and the finding count
 * is a number rather than a shade. The list beside the map is the navigable equivalent
 * and carries the same facts.
 *
 * **A one-way strand is drawn as one.** A route from A to B with nothing coming back is
 * a real and common asymmetry, and straightening it into a plain line would hide it.
 *
 * **Interface names appear when a box is selected**, not always: they are the reason to
 * open a device, and rendering six hundred of them at once produces a picture nobody
 * can read.
 */

import { useCallback, useEffect, useId, useRef, useState } from 'react';

import {
  HEADER_H,
  NODE_H,
  NODE_W,
  strandPath,
  totalFindings,
  worstSeverity,
  type MapLayout,
  type PlacedLink,
  type PlacedNode,
} from './mapLayout';

const CLASS_TAG: Record<string, string> = {
  firewall: 'FW',
  router: 'RTR',
  switch: 'SW',
  load_balancer: 'LB',
  wireless_controller: 'WLC',
  proxy: 'PRX',
};

const MIN_SCALE = 0.15;
const MAX_SCALE = 2.5;

interface Props {
  layout: MapLayout;
  selected: string | null;
  onSelect: (key: string | null) => void;
  onToggleBundle: (key: string) => void;
  /** Node ids matching the current search. Empty means no search is active. */
  matches: ReadonlySet<string>;
}

export function EstateMapView({ layout, selected, onSelect, onToggleBundle, matches }: Props) {
  const uid = useId();
  const arrow = `${uid}-arrow`;
  const frame = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ scale: 1, x: 0, y: 0 });
  const [full, setFull] = useState(false);
  const drag = useRef<{ x: number; y: number; ox: number; oy: number } | null>(null);

  const fit = useCallback(() => {
    const box = frame.current?.getBoundingClientRect();
    if (!box) return;
    const scale = Math.min(
      (box.width - 32) / Math.max(layout.width, 1),
      (box.height - 32) / Math.max(layout.height, 1),
      1,
    );
    const clamped = Math.max(MIN_SCALE, Math.min(MAX_SCALE, scale));
    setView({
      scale: clamped,
      x: (box.width - layout.width * clamped) / 2,
      y: 16,
    });
  }, [layout.width, layout.height]);

  // Re-fit whenever the drawing changes shape — a different group, or a bundle opened.
  useEffect(fit, [fit]);

  /** Going full screen more than doubles the frame, so the scale fitted to the panel is
   *  wrong the instant it opens — and the map would appear not to have grown at all.
   *  Measured after a frame, because the new size does not exist until the browser has
   *  laid the dialog out. */
  useEffect(() => {
    if (typeof requestAnimationFrame !== 'function') {
      fit();
      return;
    }
    const id = requestAnimationFrame(fit);
    return () => cancelAnimationFrame(id);
  }, [full, fit]);

  /** Escape closes it, and the page behind stops scrolling while it is open.
   *
   * Both are what makes this a dialog rather than a large div: a full-screen view with
   * no keyboard way out traps anybody not using a mouse, and a page that scrolls behind
   * a fixed overlay moves the thing you return to.
   */
  useEffect(() => {
    if (!full) return;

    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setFull(false);
    };
    window.addEventListener('keydown', onKey);

    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = previous;
    };
  }, [full]);

  const zoomBy = (factor: number) => {
    setView((current) => {
      const box = frame.current?.getBoundingClientRect();
      const scale = Math.max(MIN_SCALE, Math.min(MAX_SCALE, current.scale * factor));
      if (!box) return { ...current, scale };
      // Zoom about the centre of the frame, so the thing being looked at stays put.
      const cx = box.width / 2;
      const cy = box.height / 2;
      const ratio = scale / current.scale;
      return { scale, x: cx - (cx - current.x) * ratio, y: cy - (cy - current.y) * ratio };
    });
  };

  const related = new Set<string>();
  if (selected) {
    related.add(selected);
    for (const link of layout.links) {
      if (link.from === selected) related.add(link.to);
      if (link.to === selected) related.add(link.from);
    }
  }

  const description =
    `${layout.nodes.length} boxes across ${layout.bands.length} group(s), ` +
    `${layout.links.length} connections, laid out left to right from the estate edge inwards. ` +
    'The list beside this picture carries the same devices and is the navigable equivalent.';

  return (
    <div
      className={full ? 'estatemap estatemap--full' : 'estatemap'}
      // Only a dialog when it is covering the page. Announcing a panel that is simply
      // part of the page as modal is worse than not announcing it at all.
      role={full ? 'dialog' : undefined}
      aria-modal={full || undefined}
      aria-label={full ? 'Network map, full screen' : undefined}
    >
      <div className="estatemap__tools">
        {/* First, and the only filled button here. Zooming inside a 640px frame is the
            thing that does not work on a six-hundred-device estate — the reason to
            reach for the controls at all is that the picture is too small to read. */}
        <button className="button button--small" onClick={() => setFull((open) => !open)}>
          {full ? 'Exit full screen' : 'Full screen'}
        </button>
        <button className="button button--ghost button--small" onClick={() => zoomBy(1.25)}>
          Zoom in
        </button>
        <button className="button button--ghost button--small" onClick={() => zoomBy(0.8)}>
          Zoom out
        </button>
        <button className="button button--ghost button--small" onClick={fit}>
          Fit
        </button>
        <span className="finding__note">{Math.round(view.scale * 100)}%</span>
        {selected && (
          <button className="button button--ghost button--small" onClick={() => onSelect(null)}>
            Clear selection
          </button>
        )}
        {full && <span className="finding__note">Esc to close</span>}
      </div>

      <div
        className="estatemap__frame"
        ref={frame}
        onPointerDown={(event) => {
          if (event.button !== 0) return;
          drag.current = { x: event.clientX, y: event.clientY, ox: view.x, oy: view.y };
          // Optional: pointer capture keeps a drag alive when the cursor leaves the
          // frame, and is simply absent in some environments. Panning still works
          // without it, so a missing method must not take the whole page down.
          event.currentTarget.setPointerCapture?.(event.pointerId);
        }}
        onPointerMove={(event) => {
          const start = drag.current;
          if (!start) return;
          setView((current) => ({
            ...current,
            x: start.ox + (event.clientX - start.x),
            y: start.oy + (event.clientY - start.y),
          }));
        }}
        onPointerUp={() => {
          drag.current = null;
        }}
        onPointerLeave={() => {
          drag.current = null;
        }}
      >
        <svg
          className="estatemap__svg"
          role="img"
          aria-label="Network map"
          // The picture is one image with a text alternative, and the device list beside
          // it is the keyboard path. Six hundred focusable boxes would be six hundred tab
          // stops between the toolbar and everything after it.
          aria-describedby={`${uid}-desc`}
        >
          <desc id={`${uid}-desc`}>{description}</desc>
          <defs>
            <marker
              id={arrow}
              viewBox="0 0 8 8"
              refX="7"
              refY="4"
              markerWidth="5"
              markerHeight="5"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 8 4 L 0 8 z" className="estatemap__arrowhead" />
            </marker>
          </defs>

          <g transform={`translate(${view.x}, ${view.y}) scale(${view.scale})`}>
            {/* Columns named rather than numbered. "Tier 2" is a breadth-first depth
                and means nothing; "2 hops in" is the same fact in words. */}
            {layout.tiers.map((column) => (
              <text
                key={column.tier}
                className="estatemap__colhead"
                x={column.x}
                y={HEADER_H - 12}
                textAnchor="middle"
              >
                {column.label}
              </text>
            ))}

            {layout.bands.map((band) => (
              <g key={band.group.id}>
                <rect
                  className="estatemap__band"
                  x={0}
                  y={band.y}
                  width={band.width}
                  height={band.height}
                  rx="10"
                />
                <text className="estatemap__bandlabel" x={14} y={band.y + 20}>
                  {band.group.label}
                  <tspan className="estatemap__bandmeta">
                    {'  '}
                    {band.group.devices} device{band.group.devices === 1 ? '' : 's'}
                    {band.group.firewalls > 0 && `, ${band.group.firewalls} with a rulebase`}
                    {band.group.label_source !== 'site' && ' · name inferred from hostnames'}
                  </tspan>
                </text>
              </g>
            ))}

            {layout.links.map((link) => (
              <Strand
                key={link.key}
                link={link}
                arrow={arrow}
                dim={selected !== null && link.from !== selected && link.to !== selected}
                showEnds={selected !== null && (link.from === selected || link.to === selected)}
              />
            ))}

            {layout.nodes.map((placed) => (
              <Box
                key={placed.key}
                placed={placed}
                selected={placed.key === selected}
                dim={
                  (selected !== null && !related.has(placed.key)) ||
                  (matches.size > 0 && !placed.members.some((member) => matches.has(member.id)))
                }
                onSelect={onSelect}
                onToggleBundle={onToggleBundle}
              />
            ))}
          </g>
        </svg>
      </div>

      <ul className="estatemap__legend">
        <li>
          <span className="estatemap__swatch estatemap__swatch--firewall" aria-hidden="true" />
          <strong>▣</strong> carries a rulebase that is in force — traffic across it was inspected
        </li>
        <li>
          <span className="estatemap__swatch estatemap__swatch--router" aria-hidden="true" />
          no mark: forwards without an opinion, including an access list bound to nothing
        </li>
        <li>
          <span className="estatemap__swatch estatemap__swatch--unmanaged" aria-hidden="true" />
          an address the estate routes to and no inventoried device answers for
        </li>
        <li>
          <span className="estatemap__swatch estatemap__swatch--oneway" aria-hidden="true" />
          an arrow means only one end routes to the other
        </li>
      </ul>
    </div>
  );
}

function Strand({
  link,
  arrow,
  dim,
  showEnds,
}: {
  link: PlacedLink;
  arrow: string;
  dim: boolean;
  showEnds: boolean;
}) {
  const classes = [
    'estatemap__strand',
    link.link.carries_default ? 'estatemap__strand--default' : '',
    link.link.crosses_firewall ? 'estatemap__strand--inspected' : '',
    dim ? 'is-dim' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <g>
      <path
        className={classes}
        d={strandPath(link)}
        markerEnd={link.link.bidirectional ? undefined : `url(#${arrow})`}
      />
      {showEnds && (
        <>
          {link.link.source_interface && (
            <text className="estatemap__endlabel" x={link.x1} y={link.y1 - 6}>
              {link.link.source_interface}
            </text>
          )}
          {link.link.target_interface && (
            <text className="estatemap__endlabel" x={link.x2} y={link.y2 - 6} textAnchor="end">
              {link.link.target_interface}
            </text>
          )}
        </>
      )}
      {link.count > 1 && (
        <text
          className="estatemap__count"
          x={(link.x1 + link.x2) / 2}
          y={(link.y1 + link.y2) / 2 - 4}
          textAnchor="middle"
        >
          ×{link.count}
        </text>
      )}
    </g>
  );
}

function Box({
  placed,
  selected,
  dim,
  onSelect,
  onToggleBundle,
}: {
  placed: PlacedNode;
  selected: boolean;
  dim: boolean;
  onSelect: (key: string) => void;
  onToggleBundle: (key: string) => void;
}) {
  const { node } = placed;
  const tag = node.kind === 'unmanaged' ? '?' : (CLASS_TAG[node.device_class ?? ''] ?? 'DEV');
  const findings = placed.members.reduce((sum, member) => sum + totalFindings(member.findings), 0);
  const worst = worstSeverity(
    placed.members.reduce<Record<string, number>>((all, member) => {
      for (const [severity, count] of Object.entries(member.findings)) {
        all[severity] = (all[severity] ?? 0) + count;
      }
      return all;
    }, {}),
  );

  const classes = [
    'estatemap__box',
    `estatemap__box--${node.kind}`,
    node.inspects ? 'estatemap__box--firewall' : `estatemap__box--${node.device_class ?? 'device'}`,
    selected ? 'is-selected' : '',
    dim ? 'is-dim' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <g
      transform={`translate(${placed.x}, ${placed.y})`}
      className="estatemap__node"
      onClick={() => (placed.bundled ? onToggleBundle(placed.key) : onSelect(placed.key))}
    >
      <rect className={classes} width={NODE_W} height={NODE_H} rx="6" />
      <text className="estatemap__tag" x={10} y={18}>
        {tag}
      </text>
      <text className="estatemap__label" x={38} y={18}>
        {truncate(node.label, 19)}
      </text>
      <text className="estatemap__sub" x={10} y={34}>
        {placed.bundled
          ? 'click to expand'
          : node.kind === 'unmanaged'
            ? node.carries_default_route
              ? 'unmanaged · default route'
              : 'unmanaged next hop'
            : truncate(node.platform ?? node.vendor ?? 'no platform recorded', 24)}
      </text>
      {node.inspects && (
        // A glyph as well as the outline: the outline is a colour, and the fact that
        // this device inspects traffic must not depend on seeing it.
        <text className="estatemap__shield" x={NODE_W - 10} y={34} textAnchor="end">
          ▣
        </text>
      )}
      {findings > 0 && worst && (
        <text
          className={`estatemap__risk estatemap__risk--${worst}`}
          x={NODE_W - 10}
          y={18}
          textAnchor="end"
        >
          {findings}
        </text>
      )}
    </g>
  );
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}
