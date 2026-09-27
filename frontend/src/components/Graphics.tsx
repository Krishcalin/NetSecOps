/** The small graphics a dashboard is made of (IF-UI-02).
 *
 * Four shapes, drawn with CSS and inline SVG rather than a charting library. That is
 * partly the dependency budget and mostly that a chart library's defaults are wrong
 * for this product: it would happily draw a pie of "compliant vs non-compliant" out of
 * a figure whose whole point is that the unevaluated third belongs in neither slice.
 *
 * Every one of these is paired with the number it draws. A reader never has to
 * estimate a value off an arc, a colour-blind reader gets the same information as
 * everybody else (WCAG 1.4.1), and a screen reader gets a sentence rather than an
 * `<svg>`. The picture is the fast path, not the only one.
 */

import type { ReactNode } from 'react';
import { NavLink } from 'react-router-dom';

import { Icon, IconChip, type IconName } from './Icon';

/** A conic-gradient ring around a figure.
 *
 * `value` is a percentage. `null` means the figure could not be computed — drawn as an
 * empty track with a dash in it, never as zero, because "nothing was evaluated" and
 * "everything failed" are opposite facts and a 0% ring asserts the second.
 */
export function Dial({
  value,
  label,
  caption,
  tone,
  size = 132,
}: {
  value: number | null;
  label: string;
  caption?: string;
  tone: string;
  size?: number;
}) {
  const pct = value === null ? 0 : Math.max(0, Math.min(100, value));
  const ring = Math.round(size * 0.085);
  const text = value === null ? '—' : `${Math.round(pct)}%`;

  return (
    <div className="dial" style={{ width: size, height: size }}>
      <div
        className="dial__track"
        style={{
          background:
            value === null
              ? 'var(--surface-muted)'
              : `conic-gradient(${tone} ${pct * 3.6}deg, var(--surface-muted) ${pct * 3.6}deg)`,
        }}
      />
      <div className="dial__well" style={{ inset: ring }}>
        <span
          className="dial__value"
          style={{ color: value === null ? 'var(--text-faint)' : tone }}
        >
          {text}
        </span>
        <span className="dial__label">{label}</span>
      </div>
      {caption && <span className="visually-hidden">{caption}</span>}
    </div>
  );
}

export interface BarPart {
  label: string;
  value: number;
  tone: string;
}

/** A single stacked proportion bar, with its own legend underneath.
 *
 * The legend is not optional decoration: it carries each segment's name and count, so
 * the bar is a summary of numbers that are also present rather than the only place
 * they appear.
 */
export function StackBar({ parts, total }: { parts: BarPart[]; total?: number }) {
  const sum = total ?? parts.reduce((all, part) => all + part.value, 0);
  const present = parts.filter((part) => part.value > 0);

  return (
    <div className="stackbar">
      <div
        className="stackbar__track"
        role="img"
        aria-label={
          sum === 0
            ? 'Nothing to show'
            : present.map((part) => `${part.value} ${part.label}`).join(', ')
        }
      >
        {sum === 0 ? (
          <span className="stackbar__empty" />
        ) : (
          present.map((part) => (
            <span
              key={part.label}
              className="stackbar__part"
              style={{ width: `${(part.value / sum) * 100}%`, background: part.tone }}
            />
          ))
        )}
      </div>
      {/* Divs rather than a list, and hidden from assistive technology: the bar above
          already carries every one of these figures in its text alternative, so a
          screen reader that also walked the legend would hear the whole distribution
          twice. It was a `<ul>` first, which additionally put five list items into
          every page that queries its own lists by role.

          Hidden here means hidden from *assistive technology only*. It is exactly as
          visible as it was, and it is what a sighted reader uses instead of estimating
          a value off a coloured segment. */}
      <div className="stackbar__key" aria-hidden="true">
        {parts.map((part) => (
          <span key={part.label} className="stackbar__entry">
            <span className="stackbar__swatch" style={{ background: part.tone }} />
            <span className="stackbar__count">{part.value.toLocaleString()}</span>
            <span className="stackbar__name">{part.label}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/** A headline number that is also a link to the list it counts.
 *
 * The rule the old dashboard was built on and this keeps: **the destination has to
 * reproduce the count**. A number you cannot click is one you re-derive by hand, and a
 * tile landing you somewhere that shows a different figure is worse than no tile.
 */
export function StatTile({
  icon,
  label,
  value,
  hint,
  to,
  tone = 'var(--accent)',
}: {
  icon: IconName;
  label: string;
  /** `undefined` while loading — rendered as a dash, never as zero. */
  value: number | string | undefined;
  hint: string;
  to: string;
  tone?: string;
}) {
  const shown =
    value === undefined ? '—' : typeof value === 'number' ? value.toLocaleString() : value;

  return (
    <NavLink className="stattile" to={to}>
      <span className="stattile__top">
        <IconChip name={icon} tone={tone} />
        <Icon name="arrow-right" size={15} className="stattile__go" />
      </span>
      <span className="stattile__value" style={{ color: value ? tone : 'var(--text)' }}>
        {shown}
      </span>
      <span className="stattile__label">{label}</span>
      <span className="stattile__hint">{hint}</span>
    </NavLink>
  );
}

/** A small figure in the strip under a list page's heading.
 *
 * Deliberately not a link, unlike the dashboard's tile. On a list page the rows the
 * figure counts are already directly below it, so navigating away would be the wrong
 * thing for a click to do — and a tile that looks like the dashboard's and behaves
 * differently is worse than one that plainly does not.
 */
export function SummaryCell({
  icon,
  label,
  value,
  note,
  tone = 'var(--accent)',
}: {
  icon: IconName;
  label: string;
  /** `undefined` while loading — a dash, never a nought. */
  value: number | string | undefined;
  note?: string;
  tone?: string;
}) {
  const shown =
    value === undefined ? '—' : typeof value === 'number' ? value.toLocaleString() : value;

  return (
    <div className="summary__cell">
      <span className="summary__top">
        <IconChip name={icon} tone={tone} size={15} />
        <span className="summary__value" style={{ color: value ? tone : 'var(--text)' }}>
          {shown}
        </span>
      </span>
      <span className="summary__label">{label}</span>
      {note && <span className="summary__note">{note}</span>}
    </div>
  );
}

/** A panel with a titled head and an optional link out of it. */
export function Panel({
  icon,
  title,
  to,
  cta,
  tone,
  children,
}: {
  icon: IconName;
  title: string;
  to?: string;
  cta?: string;
  tone?: string;
  children: ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel__head">
        <IconChip name={icon} tone={tone ?? 'var(--accent)'} size={17} />
        <h2 className="panel__title">{title}</h2>
        {to && (
          <NavLink className="panel__cta" to={to}>
            {cta ?? 'View all'}
            <Icon name="arrow-right" size={13} />
          </NavLink>
        )}
      </div>
      <div className="panel__body">{children}</div>
    </section>
  );
}

export interface SeriesPoint {
  label: string;
  /** `null` means no reading, which is drawn as a break in the line rather than a zero.
   *  On a risk chart the two are opposite facts: nobody assessed, versus nothing wrong. */
  value: number | null;
}

/** Two counts a day, drawn as paired bars from a shared baseline.
 *
 * Bars rather than lines, because these are events on a day and not a level that
 * persisted through it — a line implies the value existed between the points, which for
 * "findings first seen" is meaningless. Days with nothing on them are still drawn, as
 * empty space at their own position, so a quiet fortnight looks like a quiet fortnight
 * and not like two adjacent busy days.
 *
 * The totals sit in the caption because the bars are unlabelled: at ninety days there is
 * no room for a number on each, and a reader who needs the exact figure for one day has
 * the tooltip, while a reader who needs the shape has the shape.
 */
export function DualBars({
  up,
  down,
  upLabel,
  downLabel,
  upTone,
  downTone,
}: {
  up: SeriesPoint[];
  down: SeriesPoint[];
  upLabel: string;
  downLabel: string;
  upTone: string;
  downTone: string;
}) {
  const peak = Math.max(1, ...up.map((p) => p.value ?? 0), ...down.map((p) => p.value ?? 0));
  const upTotal = up.reduce((all, p) => all + (p.value ?? 0), 0);
  const downTotal = down.reduce((all, p) => all + (p.value ?? 0), 0);

  return (
    <figure className="bars">
      <div
        className="bars__plot"
        role="img"
        aria-label={`${upTotal} ${upLabel} and ${downTotal} ${downLabel} over ${up.length} days.`}
      >
        {up.map((point, index) => {
          const other = down[index]?.value ?? 0;
          const mine = point.value ?? 0;
          return (
            <span
              className="bars__day"
              key={point.label}
              title={`${point.label}: ${mine} ${upLabel}, ${other} ${downLabel}`}
            >
              <span className="bars__half bars__half--up">
                <span
                  className="bars__bar"
                  style={{ height: `${(mine / peak) * 100}%`, background: upTone }}
                />
              </span>
              <span className="bars__half bars__half--down">
                <span
                  className="bars__bar"
                  style={{ height: `${(other / peak) * 100}%`, background: downTone }}
                />
              </span>
            </span>
          );
        })}
      </div>
      <figcaption className="bars__caption">
        {/* The figures the bars stand for, in text. Nothing on this chart is coloured
            without also being counted, so it survives greyscale (WCAG 1.4.1). */}
        <span className="bars__legend">
          <span className="bars__swatch" style={{ background: upTone }} aria-hidden="true" />
          {upTotal.toLocaleString()} {upLabel}
        </span>
        <span className="bars__legend">
          <span className="bars__swatch" style={{ background: downTone }} aria-hidden="true" />
          {downTotal.toLocaleString()} {downLabel}
        </span>
        <span className="bars__span">
          {up[0]?.label} — {up[up.length - 1]?.label}
        </span>
      </figcaption>
    </figure>
  );
}

/** A small line of readings over time, with its latest value beside it.
 *
 * For risk, which *is* a level — it held between assessments — so a line is honest here
 * where it would not be for counts. A single reading draws a dot rather than a line,
 * because one point is not a direction and a flat segment would claim it was.
 */
export function Sparkline({
  points,
  tone,
  height = 40,
}: {
  points: SeriesPoint[];
  tone: string;
  height?: number;
}) {
  const real = points.filter((p): p is { label: string; value: number } => p.value !== null);

  if (real.length === 0) {
    return <p className="sparkline sparkline--empty">No readings yet.</p>;
  }

  const width = 220;
  const highest = Math.max(...real.map((p) => p.value));
  const lowest = Math.min(...real.map((p) => p.value));
  // A flat series would otherwise divide by zero and vanish; drawn down the middle.
  const span = highest - lowest || 1;
  const step = real.length > 1 ? width / (real.length - 1) : 0;

  const coords = real.map((point, index) => ({
    x: real.length > 1 ? index * step : width / 2,
    y: height - ((point.value - lowest) / span) * (height - 6) - 3,
    point,
  }));

  const last = coords[coords.length - 1];

  return (
    <div className="sparkline">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        width="100%"
        height={height}
        preserveAspectRatio="none"
        role="img"
        aria-label={`${real.length} readings, most recent ${last?.point.value} on ${last?.point.label}.`}
      >
        {coords.length > 1 && (
          <polyline
            fill="none"
            stroke={tone}
            strokeWidth="2"
            strokeLinejoin="round"
            strokeLinecap="round"
            points={coords.map((c) => `${c.x},${c.y}`).join(' ')}
          />
        )}
        {last && <circle cx={last.x} cy={last.y} r="3" fill={tone} />}
      </svg>
    </div>
  );
}

/** One label/value row inside a panel. */
export function Readout({
  label,
  value,
  tone,
  note,
}: {
  label: string;
  value: ReactNode;
  tone?: string;
  note?: string;
}) {
  return (
    <div className="readout">
      <span className="readout__label">{label}</span>
      <span className="readout__value" style={tone ? { color: tone } : undefined}>
        {value}
      </span>
      {note && <span className="readout__note">{note}</span>}
    </div>
  );
}
