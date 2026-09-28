/** The grade pill and the estate risk line, shared by Risk Trends and the dashboard.
 *
 * Both lived inside `RiskTrendsPage` until the dashboard needed them too. Moved rather
 * than copied, for the reason this codebase moves anything: a second copy is free to
 * band a score differently, or to draw a gap in the readings as a nought, and it is the
 * copy somebody is looking at. The grade on the front page and the grade on the Risk
 * Trends page have to be the same claim or neither is worth making.
 */

import type { CSSProperties } from 'react';

import { Icon } from '../../components/Icon';
import { DIRECTION_LABELS, GRADE_TONES, type EstateRiskTrend, type Grade } from './types';

/** The letter, at the size a letter deserves. */
export function GradePill({ grade, size = 'md' }: { grade: Grade | null; size?: 'md' | 'lg' }) {
  // `== null`, so an absent field reads the same as an explicit null. They mean the
  // same thing to a reader — nobody has graded this — and the alternative is a pill
  // containing nothing at all.
  if (grade == null) {
    // Never assessed. A dash rather than a greyed-out letter, because a faint `A` is
    // still an `A` to anybody skimming.
    return (
      <span className={`grade grade--${size} grade--none`} title="Never assessed">
        —
      </span>
    );
  }
  return (
    <span
      className={`grade grade--${size}`}
      style={{ '--grade': GRADE_TONES[grade] } as CSSProperties}
    >
      {grade}
    </span>
  );
}

/** The estate's score over time, drawn as a line of daily readings.
 *
 * A line rather than bars, and that is the honest shape here: a risk score is a level
 * that held between assessments, so the space between two readings really was at that
 * value. Days before anything was assessed are a break in the line, never a nought —
 * a clean estate and no estate are opposite facts.
 *
 * `height` is the one thing the two callers disagree about: the dashboard gives this
 * roughly half the width it has on Risk Trends, and a line drawn at full height in a
 * narrow box reads as far steeper than the same data does beside it.
 */
export function RiskLine({ trend, height = 130 }: { trend: EstateRiskTrend; height?: number }) {
  // Defaulted rather than assumed. A response without `points` — an in-flight query, a
  // shape the server changed, a proxy returning a stub — used to throw here, and one
  // chart throwing takes the whole dashboard down with it. The honest empty state below
  // is the right answer to "no readings" however the absence arose.
  const points = trend.points ?? [];
  const real = points.filter((p) => p.score !== null);

  if (real.length === 0) {
    return (
      <p className="empty">
        No device in scope has been assessed yet, so there is no score to plot. That is not a score
        of zero — nothing has looked.
      </p>
    );
  }

  const width = 640;
  const pad = 6;
  const step = points.length > 1 ? width / (points.length - 1) : 0;
  // The axis is the scale, not the data: 0–100 fixed, so a quiet month does not get
  // magnified into a dramatic slope by an auto-fitted range.
  const y = (score: number) => pad + ((100 - score) / 100) * (height - pad * 2);

  // Each unbroken run is its own polyline, so a gap in the readings renders as a gap
  // rather than as a straight line drawn across the days nobody measured.
  const runs: { x: number; y: number }[][] = [];
  let run: { x: number; y: number }[] = [];
  points.forEach((point, index) => {
    if (point.score === null) {
      if (run.length) runs.push(run);
      run = [];
      return;
    }
    run.push({ x: index * step, y: y(point.score) });
  });
  if (run.length) runs.push(run);

  const last = real[real.length - 1]!;
  const first = real[0]!;

  return (
    <figure className="riskline">
      <svg
        className="riskline__plot"
        viewBox={`0 0 ${width} ${height}`}
        width="100%"
        height={height}
        preserveAspectRatio="none"
        role="img"
        aria-label={`Estate risk from ${first.score} on ${first.day} to ${last.score} on ${last.day}, ${DIRECTION_LABELS[trend.direction]}.`}
      >
        {/* Quarter lines, so a reader can place a value without a printed axis. */}
        {[0, 25, 50, 75, 100].map((mark) => (
          <line
            key={mark}
            x1={0}
            x2={width}
            y1={y(mark)}
            y2={y(mark)}
            className={mark === 0 || mark === 100 ? 'riskline__edge' : 'riskline__rule'}
          />
        ))}
        {runs.map((coords, index) => (
          <polyline
            key={index}
            className="riskline__line"
            fill="none"
            points={coords.map((c) => `${c.x},${c.y}`).join(' ')}
          />
        ))}
        {runs.length > 0 && (
          <circle
            className="riskline__head"
            cx={runs[runs.length - 1]!.at(-1)!.x}
            cy={runs[runs.length - 1]!.at(-1)!.y}
            r={4}
          />
        )}
      </svg>
      <figcaption className="riskline__caption">
        {/* Both ends in text, so the figure is never estimated off the line, and the
            population with them — a score from three devices and one from three
            hundred are not comparable. */}
        <span>
          {first.score} on {new Date(first.day).toLocaleDateString()}
        </span>
        <span className="riskline__arrow" aria-hidden="true">
          <Icon name="arrow-right" size={13} />
        </span>
        <span>
          {last.score} on {new Date(last.day).toLocaleDateString()}
        </span>
        <span className="riskline__pop">
          across {last.devices.toLocaleString()} assessed{' '}
          {last.devices === 1 ? 'device' : 'devices'}
        </span>
      </figcaption>
    </figure>
  );
}
