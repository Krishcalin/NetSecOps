/** The certificate expiry timeline (FR-AAA-06).
 *
 * The certificate worth finding on this page is the EAP one: when it expires, every
 * EAP-TLS and PEAP client on the network fails authentication at once, and for the
 * first hour it looks like a wireless fault rather than a certificate fault. So the
 * usage is shown on every row, and the list is ordered by urgency rather than by device.
 *
 * **Undated certificates stay on the list.** They sort last — they belong at the bottom
 * of something read top-down — but they are present and counted, because a timeline
 * assembled by dropping the dates it could not read is shorter than reality, and a
 * short timeline looks exactly like good news.
 *
 * **Servers that contributed nothing are named above the table.** An empty timeline
 * produced by a certificate endpoint returning 403 is indistinguishable from a healthy
 * one, and that is the failure this panel has to be able to admit.
 */

import { certificateState, describeRemaining } from './types';
import type { CertificateTimeline as Timeline } from './types';

const STATE_PILL: Record<string, string> = {
  expired: 'pill--critical',
  urgent: 'pill--high',
  soon: 'pill--medium',
  ok: 'pill--success',
  undated: 'pill--low',
};

const STATE_LABEL: Record<string, string> = {
  expired: 'expired',
  urgent: 'expiring',
  soon: 'due',
  ok: 'valid',
  undated: 'no date',
};

export function CertificateTimeline({ timeline }: { timeline: Timeline }) {
  return (
    <section className="card">
      <header className="card__header">
        <h2 className="card__title">Certificate expiry</h2>
        <span className="muted">
          {timeline.total} certificate{timeline.total === 1 ? '' : 's'} collected
        </span>
      </header>

      <div className="card-grid">
        <div className="stat">
          <strong>{timeline.expired}</strong>
          <span>already expired</span>
        </div>
        <div className="stat">
          <strong>{timeline.expiring_soon}</strong>
          <span>within {timeline.soon_days} days</span>
        </div>
        <div className="stat">
          <strong>{timeline.expiring_within_horizon}</strong>
          <span>within {timeline.horizon_days} days</span>
        </div>
        {/* Shown whenever it is non-zero rather than only when it is large: one
            certificate nobody can date is one certificate nobody is watching. */}
        {timeline.undated > 0 && (
          <div className="stat">
            <strong>{timeline.undated}</strong>
            <span>no readable date</span>
          </div>
        )}
      </div>

      {timeline.servers_without_certificates.length > 0 && (
        <p className="alert alert--warning" role="status">
          No certificate was collected from{' '}
          <strong>{timeline.servers_without_certificates.join(', ')}</strong>. This
          timeline is blind to those servers, so a certificate expiring on one of them
          would not appear here.
        </p>
      )}

      {timeline.entries.length === 0 ? (
        <p className="empty">
          No certificate has been collected from any device yet. That is not the same as
          nothing expiring &mdash; run a collection against your AAA servers.
        </p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Certificate</th>
                <th>Device</th>
                <th>Used for</th>
                <th>Expires</th>
                <th>Issuer</th>
              </tr>
            </thead>
            <tbody>
              {timeline.entries.map((entry, index) => {
                const state = certificateState(entry, timeline);
                return (
                  <tr key={`${entry.device_id}-${entry.name ?? index}`}>
                    <td>
                      <strong>{entry.name ?? entry.subject ?? 'unnamed'}</strong>
                      {entry.self_signed && (
                        <span className="pill pill--medium" title="Self-signed">
                          self-signed
                        </span>
                      )}
                    </td>
                    <td>{entry.device}</td>
                    <td className="muted">
                      {entry.usage.length > 0 ? entry.usage.join(', ') : '—'}
                    </td>
                    <td>
                      <span className={`pill ${STATE_PILL[state]}`}>{STATE_LABEL[state]}</span>{' '}
                      {describeRemaining(entry)}
                    </td>
                    <td className="muted">{entry.issuer ?? '—'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
