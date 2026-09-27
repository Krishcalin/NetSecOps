/** A device's risk score, and where it has been (FR-CHK-09).
 *
 * `risk_scores` has kept a row per assessment since Phase 3 — the model says in as many
 * words that it is stored per computation *because* a single current number cannot tell
 * an operator whether things are improving. Until now nothing read it, and the console
 * showed neither the number nor the direction.
 *
 * Three things this is careful about, all the same kind of care:
 *
 * **Never assessed is not a score of zero.** Zero on a scale where zero is clean would
 * describe a device nobody has looked at as the healthiest thing in the estate.
 *
 * **The score counts down**, so a falling line is good news and the word beside it
 * points the opposite way to the number. The direction is decided by the server, not
 * inferred from the last two points here, so a report and this panel cannot describe
 * the same two figures differently.
 *
 * **One reading is not a direction.** A single assessment draws a dot and says so,
 * rather than a flat line that claims nothing has changed.
 */

import { useQuery } from '@tanstack/react-query';

import { api } from '../../api/client';
import { Readout, Sparkline } from '../../components/Graphics';
import type { DeviceRisk, RiskTrend } from './types';

/** Spelled out rather than drawn as an arrow alone: a direction carried by a glyph is
 *  one a screen reader skips, and an arrow on a count-down scale is ambiguous anyway. */
const DIRECTION_LABELS: Record<string, string> = {
  improving: 'improving',
  worsening: 'getting worse',
  steady: 'unchanged',
  unknown: 'no direction yet',
};

export function RiskPanel({ deviceId }: { deviceId: string }) {
  const current = useQuery({
    queryKey: ['device-risk', deviceId],
    queryFn: () => api.get<DeviceRisk>(`/devices/${deviceId}/risk`),
  });
  const history = useQuery({
    queryKey: ['device-risk-history', deviceId],
    queryFn: () => api.get<RiskTrend>(`/devices/${deviceId}/risk/history?days=180`),
  });

  if (current.isError) return null;

  const risk = current.data;
  const points = history.data?.points ?? [];
  const direction = history.data?.direction ?? 'unknown';
  const unassessed = current.isSuccess && risk?.score == null;

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">Risk</h2>
        {risk?.assessed_at && (
          <span className="card__hint">
            Last assessed {new Date(risk.assessed_at).toLocaleDateString()}
          </span>
        )}
      </div>

      {unassessed ? (
        <p className="card__hint">
          This device has never been assessed, so it has no score. That is not the same as scoring
          zero — nothing has looked at it.
        </p>
      ) : (
        <div className="risk">
          <div className="risk__now">
            <strong className="risk__score">{risk?.score ?? '—'}</strong>
            <span className="risk__of">out of 100</span>
            <span className={`risk__direction risk__direction--${direction}`}>
              {DIRECTION_LABELS[direction]}
            </span>
          </div>

          <div className="risk__history">
            <Sparkline
              points={points.map((point) => ({
                label: new Date(point.at).toLocaleDateString(),
                value: point.score,
              }))}
              tone="var(--sev-high)"
            />
            <span className="risk__caption">
              {points.length > 1
                ? `${points.length} assessments since ${new Date(points[0]!.at).toLocaleDateString()}`
                : 'One assessment so far — a direction needs two.'}
            </span>
          </div>
        </div>
      )}

      {risk && !unassessed && (
        <div className="readouts">
          <Readout
            label="Checks decided"
            value={`${risk.checks_passed} passed, ${risk.checks_failed} failed`}
            // The unevaluated third named outright. It belongs in neither half, and a
            // panel that silently dropped it would make a partly-assessed device look
            // fully assessed.
            note={
              risk.checks_not_evaluated
                ? `${risk.checks_not_evaluated} could not be evaluated and are in neither figure`
                : undefined
            }
          />
          <Readout
            label="Compliance"
            value={risk.compliance_percent != null ? `${risk.compliance_percent}%` : '—'}
            note="of the checks that produced a verdict"
          />
        </div>
      )}
    </section>
  );
}
