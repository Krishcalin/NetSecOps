/** Risk Trends — direction, closure priority and a letter per appliance.
 *
 * The rest of the console lists objects as they stand. This page answers three
 * questions nothing else does: is the estate improving, what should be fixed first,
 * and how bad is each individual box. All three are read off data the product has been
 * writing since Phase 3 — `risk_scores` keeps a row per computation, and severity and
 * criticality are already on every finding and every device.
 *
 * **Nothing here is a new measurement**, which is the constraint the whole page is
 * built inside. A letter beside a firewall's name is the strongest claim this product
 * makes in the fewest characters, so:
 *
 * * The grade is the stored risk score in a band. The bands arrive in the response,
 *   computed by the same function that assigned the letters, and the page prints what
 *   each one means — so a reader can always cash `D` out into a fact about the device.
 * * The priority is the severity weight times the criticality multiplier the score is
 *   already summed from. The grid is in the response too, computed, and shown.
 * * A device nobody has assessed has no letter at all. Not `A`, which would call it
 *   clean, and not `F`, which would call it broken.
 *
 * **Colour is a verdict here, unlike everywhere else.** `sections.ts` keeps the
 * navigation hues outside the severity ramp precisely so a page header is never read
 * as a judgement; a grade is the opposite case, and uses the ramp so that an `F` and a
 * Critical finding are the same red. Every letter, code and count is also printed, so
 * the colour is never the only carrier (WCAG 1.4.1).
 */

import { useQuery } from '@tanstack/react-query';
import { NavLink } from 'react-router-dom';

import { api } from '../api/client';
import { PageHeader } from '../components/PageHeader';
import { DualBars, Panel, Readout, SummaryCell } from '../components/Graphics';
import { Icon } from '../components/Icon';
import {
  CLASS_LABELS,
  CLASS_SINGULAR,
  DIRECTION_LABELS,
  GRADE_TONES,
  PRIORITY_TONES,
  type DeviceGrade,
  type EstateRiskTrend,
  type Grade,
  type GradeReport,
  type MatrixCell,
  type Priority,
  type PriorityReport,
} from '../features/risk/types';
import type { FindingTrend } from '../features/findings/types';
import { useUrlFilters } from './useUrlFilters';

/** Every `DeviceClass` the API accepts, so the page's own picker reaches the five the
 *  sidebar does not name. Mirrors `InventoryPage`'s list deliberately: both drive the
 *  same `device_class` parameter, and a reader who filtered the inventory to switches
 *  should find the same word here. */
const DEVICE_CLASSES = [
  'router',
  'switch',
  'firewall',
  'wireless_controller',
  'wireless_ap',
  'manager',
  'aaa_server',
  'unknown',
];

const WINDOW_DAYS = 90;

/** The letter, at the size a letter deserves. */
function GradePill({ grade, size = 'md' }: { grade: Grade | null; size?: 'md' | 'lg' }) {
  if (grade === null) {
    // Never assessed. A dash rather than a greyed-out letter, because a faint `A` is
    // still an `A` to anybody skimming.
    return (
      <span className={`grade grade--${size} grade--none`} title="Never assessed">
        —
      </span>
    );
  }
  return (
    <span className={`grade grade--${size}`} style={{ '--grade': GRADE_TONES[grade] } as React.CSSProperties}>
      {grade}
    </span>
  );
}

function PriorityTag({ code }: { code: Priority | null }) {
  if (code === null) return <span className="muted">—</span>;
  return (
    <span className="ptag" style={{ '--ptag': PRIORITY_TONES[code] } as React.CSSProperties}>
      {code}
    </span>
  );
}

function days(value: number | null): string {
  if (value === null) return '—';
  return value === 1 ? '1 day' : `${value.toLocaleString()} days`;
}

/** The estate's score over time, drawn as a line of daily readings.
 *
 * A line rather than bars, and that is the honest shape here: a risk score is a level
 * that held between assessments, so the space between two readings really was at that
 * value. Days before anything was assessed are a break in the line, never a nought —
 * a clean estate and no estate are opposite facts.
 */
function RiskLine({ trend }: { trend: EstateRiskTrend }) {
  const points = trend.points;
  const real = points.filter((p) => p.score !== null);

  if (real.length === 0) {
    return (
      <p className="empty">
        No device in scope has been assessed yet, so there is no score to plot. That is not a
        score of zero — nothing has looked.
      </p>
    );
  }

  const width = 640;
  const height = 130;
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

/** The grid the priorities were bucketed with, exactly as the server computed it. */
function PriorityMatrix({ cells }: { cells: MatrixCell[] }) {
  const severities = [...new Set(cells.map((c) => c.severity))];
  const criticalities = [...new Set(cells.map((c) => c.criticality))];
  const at = (severity: string, criticality: string) =>
    cells.find((c) => c.severity === severity && c.criticality === criticality);

  return (
    // Five columns of short cells still outgrow a phone. Its own scroller, so the
    // table slides rather than the page — the one exception the layout rules allow.
    <div className="matrix-wrap">
      <table className="matrix">
        <caption className="matrix__caption">
          Finding severity down, device criticality across. Each cell is the severity
          weight times the criticality multiplier — the same product the risk score is
          summed from — and the band it reaches.
        </caption>
        <thead>
          <tr>
            <th scope="col">Severity</th>
            {criticalities.map((criticality) => (
              <th key={criticality} scope="col">
                {criticality}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {severities.map((severity) => (
            <tr key={severity}>
              <th scope="row">{severity}</th>
              {criticalities.map((criticality) => {
                const cell = at(severity, criticality);
                return (
                  <td key={criticality}>
                    {cell && (
                      <span
                        className="matrix__cell"
                        style={
                          { '--ptag': PRIORITY_TONES[cell.priority] } as React.CSSProperties
                        }
                      >
                        <strong>{cell.priority}</strong>
                        <em>{cell.weight}</em>
                      </span>
                    )}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function GradeRow({ device }: { device: DeviceGrade }) {
  return (
    <tr>
      <td className="grades__grade">
        <GradePill grade={device.grade} />
      </td>
      <td>
        <NavLink className="grades__name" to={`/inventory/${device.device_id}/config`}>
          {device.hostname ?? device.mgmt_ip}
        </NavLink>
        <span className="grades__sub">
          {CLASS_SINGULAR[device.device_class] ?? device.device_class} ·{' '}
          {device.criticality} criticality
        </span>
      </td>
      <td className="num">{device.score ?? <span className="muted">not assessed</span>}</td>
      <td className="num">{device.open_findings.toLocaleString()}</td>
      <td>
        <PriorityTag code={device.worst_priority} />
      </td>
      <td className="grades__when">
        {device.assessed_at ? (
          new Date(device.assessed_at).toLocaleDateString()
        ) : (
          <span className="muted">never</span>
        )}
      </td>
    </tr>
  );
}

export function RiskTrendsPage() {
  // In the URL rather than in state, so the sidebar's "Firewalls" is a real link and a
  // filtered view can be sent to somebody.
  const filters = useUrlFilters({ device_class: '' });
  const deviceClass = filters.read('device_class');
  const className = deviceClass ? CLASS_LABELS[deviceClass] : undefined;
  const classQuery = deviceClass ? `?device_class=${deviceClass}` : '';

  const risk = useQuery({
    // The estate trend is not filtered by class: it is the roll-up of everything in
    // scope, and narrowing it would quietly answer a different question under the same
    // heading. The class filter belongs to the two panels that list devices.
    queryKey: ['estate-risk', WINDOW_DAYS],
    queryFn: () => api.get<EstateRiskTrend>(`/risk/trend?days=${WINDOW_DAYS}`),
  });
  const findings = useQuery({
    queryKey: ['findings-trend', WINDOW_DAYS],
    queryFn: () => api.get<FindingTrend>(`/findings/trend?days=${WINDOW_DAYS}`),
  });
  const priorities = useQuery({
    queryKey: ['risk-priorities', deviceClass],
    queryFn: () => api.get<PriorityReport>(`/risk/priorities${classQuery}`),
  });
  const grades = useQuery({
    queryKey: ['risk-grades', deviceClass],
    queryFn: () => api.get<GradeReport>(`/risk/grades${classQuery}`),
  });

  const trend = risk.data;
  const report = grades.data;
  const buckets = priorities.data;

  return (
    <div className="page">
      <PageHeader
        icon="trend"
        title={className ? `Risk Trends — ${className}` : 'Risk Trends'}
        subtitle="Whether the estate is improving, what to fix first, and a letter for every appliance. Nothing here is a new measurement — the grade is the stored risk score in a band, and the priority is the severity and criticality the score is already built from."
        actions={
          <label className="field field--inline">
            <span className="field__label">Type</span>
            <select
              className="field__input"
              value={deviceClass}
              onChange={(event) => filters.write({ device_class: event.target.value })}
            >
              <option value="">All types</option>
              {DEVICE_CLASSES.map((value) => (
                <option key={value} value={value}>
                  {CLASS_LABELS[value] ?? value}
                </option>
              ))}
            </select>
          </label>
        }
      />

      <div className="summary">
        <SummaryCell
          icon="trend"
          label="Estate risk"
          value={trend?.latest_score ?? undefined}
          note={
            trend
              ? `out of 100, ${DIRECTION_LABELS[trend.direction]} — 0 is clean`
              : 'the roll-up of every assessed device'
          }
          tone={trend?.latest_grade ? GRADE_TONES[trend.latest_grade] : 'var(--sec-trends)'}
        />
        <SummaryCell
          icon="alert"
          label="Open findings"
          value={buckets?.total_open}
          note={
            buckets
              ? `${buckets.buckets.find((b) => b.code === 'P1')?.open.toLocaleString() ?? 0} of them P1`
              : 'waiting to be closed'
          }
          tone="var(--sev-high)"
        />
        <SummaryCell
          icon="grade"
          label="Graded devices"
          value={report ? report.total_devices - report.ungraded : undefined}
          note={
            report?.ungraded
              ? `${report.ungraded.toLocaleString()} never assessed, and so ungraded`
              : 'every device in scope has a reading'
          }
          tone="var(--sec-trends)"
        />
        <SummaryCell
          icon="clock"
          label="Median time to close"
          value={findings.data ? days(findings.data.median_days_to_resolve) : undefined}
          note="from first sighting to a resolution that still stands"
          tone="var(--sev-info)"
        />
      </div>

      <Panel icon="trend" title="Estate risk over time" tone="var(--sec-trends)">
        {risk.isError ? (
          <p className="empty">The risk trend could not be loaded.</p>
        ) : trend ? (
          <RiskLine trend={trend} />
        ) : (
          <p className="empty">Loading the risk history…</p>
        )}
        <p className="panel__note">
          One point per day, carrying each device&rsquo;s most recent reading forward — a
          risk score is a level that held until the next assessment replaced it, not an
          event on the day it was computed. The estate figure is weighted towards the
          worst device, so one bad firewall is not averaged away by a hundred clean
          switches.
        </p>
      </Panel>

      <Panel
        icon="finding"
        title="Findings opened and closed"
        tone="var(--sec-trends)"
        to="/findings"
        cta="Open findings"
      >
        {findings.data ? (
          <>
            <DualBars
              up={findings.data.points.map((point) => ({
                label: new Date(point.day).toLocaleDateString(),
                value: point.first_seen,
              }))}
              down={findings.data.points.map((point) => ({
                label: new Date(point.day).toLocaleDateString(),
                value: point.resolved,
              }))}
              upLabel="first seen"
              downLabel="closed for good"
              upTone="var(--sev-high)"
              downTone="var(--sev-low)"
            />
            <p className="panel__note">
              Bars, not a line: these are events on a day rather than a level that
              persisted through it. &ldquo;Closed for good&rdquo; counts only resolutions
              that still stand — reopening a finding clears its resolution date, so a fix
              later undone is not in it.{' '}
              {findings.data.reopened_now > 0 && (
                <strong>
                  {findings.data.reopened_now.toLocaleString()}{' '}
                  {findings.data.reopened_now === 1 ? 'finding has' : 'findings have'} come
                  back, which is the size of what this series cannot see.
                </strong>
              )}
            </p>
          </>
        ) : (
          <p className="empty">Loading the findings history…</p>
        )}
      </Panel>

      <Panel
        icon="alert"
        title="Closure priority"
        tone="var(--sec-trends)"
        to="/findings?status=open"
        cta="All open findings"
      >
        {buckets ? (
          <>
            {/* Deliberately not links, unlike the dashboard's tiles. The rule those
                are built on is that the destination has to reproduce the count, and
                the findings list cannot be filtered to a priority band — it has no
                such filter, because a band is severity against device criticality
                rather than a column. Four tiles that all landed on the same list
                showing a different figure would be worse than four that do nothing.
                The panel's own link goes to the whole list and claims nothing. */}
            <div className="pbands">
              {buckets.buckets.map((bucket) => {
                const band = buckets.bands.find((b) => b.code === bucket.code);
                return (
                  <div
                    key={bucket.code}
                    className="pband"
                    style={{ '--ptag': PRIORITY_TONES[bucket.code] } as React.CSSProperties}
                  >
                    <span className="pband__head">
                      <span className="pband__code">{bucket.code}</span>
                      <span className="pband__label">{band?.label}</span>
                    </span>
                    <span className="pband__count">{bucket.open.toLocaleString()}</span>
                    <span className="pband__meaning">{band?.meaning}</span>
                    <span className="pband__facts">
                      {bucket.open === 0 ? (
                        'Nothing waiting.'
                      ) : (
                        <>
                          On {bucket.devices.toLocaleString()}{' '}
                          {bucket.devices === 1 ? 'device' : 'devices'}, open{' '}
                          {days(bucket.mean_age_days)} on average
                          {bucket.oldest_first_seen && (
                            <>
                              ; oldest since{' '}
                              {new Date(bucket.oldest_first_seen).toLocaleDateString()}
                            </>
                          )}
                          .
                          {/* Both figures, so a nought in "overdue" can be read
                              correctly: nothing late, or nobody setting dates. */}
                          {bucket.with_due_date === 0
                            ? ' No due dates set.'
                            : ` ${bucket.overdue.toLocaleString()} of ${bucket.with_due_date.toLocaleString()} dated past due.`}
                        </>
                      )}
                    </span>
                  </div>
                );
              })}
            </div>
            <details className="explain">
              <summary>How a priority is decided</summary>
              <PriorityMatrix cells={buckets.matrix} />
            </details>
          </>
        ) : (
          <p className="empty">Loading the priority buckets…</p>
        )}
      </Panel>

      <Panel
        icon="grade"
        title={className ? `${className} by grade` : 'Devices by grade'}
        tone="var(--sec-trends)"
      >
        {report ? (
          <>
            <div className="spread">
              {report.bands
                .slice()
                .reverse()
                .map((band) => (
                  <div
                    key={band.letter}
                    className="spread__band"
                    style={{ '--grade': GRADE_TONES[band.letter] } as React.CSSProperties}
                  >
                    <span className="spread__letter">{band.letter}</span>
                    <span className="spread__count">
                      {(report.by_grade[band.letter] ?? 0).toLocaleString()}
                    </span>
                    <span className="spread__range">
                      score {band.floor}–{band.ceiling}
                    </span>
                    <span className="spread__meaning">{band.meaning}</span>
                  </div>
                ))}
              <div className="spread__band spread__band--none">
                <span className="spread__letter">—</span>
                <span className="spread__count">{report.ungraded.toLocaleString()}</span>
                <span className="spread__range">no score</span>
                <span className="spread__meaning">
                  Never assessed. Not graded A, which would call them clean.
                </span>
              </div>
            </div>

            <div className="readouts">
              <Readout
                label="Estate grade"
                value={
                  <span className="readout__grade">
                    <GradePill grade={report.estate_grade} size="lg" />
                    {report.estate_score !== null && <em>{report.estate_score} / 100</em>}
                  </span>
                }
                note="Weighted towards the worst device, not averaged."
              />
            </div>

            {report.devices.length === 0 ? (
              // The message instead of the table, not below it: a header row over
              // nothing reads as a list that failed to load.
              <p className="empty">No devices in scope{className ? ' of this type' : ''}.</p>
            ) : (
              <div className="table-wrap">
                <table className="table grades">
                  <caption className="table__caption">
                    Worst first. A device with no score has no letter — the only true
                    statement about it is that nobody has looked.
                  </caption>
                  <thead>
                    <tr>
                      <th scope="col">Grade</th>
                      <th scope="col">Device</th>
                      <th scope="col" className="num">
                        Score
                      </th>
                      <th scope="col" className="num">
                        Open
                      </th>
                      <th scope="col">Priority</th>
                      <th scope="col">Assessed</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.devices.map((device) => (
                      <GradeRow key={device.device_id} device={device} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {report.devices.length < report.total_devices && (
              // Silent truncation on a page whose whole job is ranking would be a table
              // that looks like the estate and is the top of it.
              <p className="panel__note">
                Showing the worst {report.devices.length.toLocaleString()} of{' '}
                {report.total_devices.toLocaleString()} devices. The distribution and the
                estate grade above cover all of them.
              </p>
            )}
          </>
        ) : (
          <p className="empty">Loading the grades…</p>
        )}
      </Panel>
    </div>
  );
}
