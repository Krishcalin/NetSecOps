/** Findings list and detail (FR-FIND-03, FR-FIND-04).
 *
 * The list opens worst-first and active-only, because the question it answers is "what
 * should I do next", not "what is there". The detail panel is the substance: a finding
 * an operator cannot verify is one they will not act on, so it leads with the evidence
 * — the operator's own configuration lines — and follows with why the check exists at
 * all.
 */

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { NavLink } from 'react-router-dom';

import { api } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import type { Finding, FindingDetail, FindingStatus, Severity } from '../features/findings/types';
import { SETTABLE_STATUSES, STATUS_LABELS } from '../features/findings/types';
import type { Paginated } from '../features/inventory/types';

const PAGE_SIZE = 25;

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Framework keys the API returns, with the names people actually use. */
const FRAMEWORK_LABELS: Record<string, string> = {
  cis: 'CIS',
  nist_800_53: 'NIST 800-53',
  pci_dss: 'PCI DSS',
  iso_27001: 'ISO 27001',
  cert_in: 'CERT-In',
  cea: 'CEA',
};

function severityClass(severity: string): string {
  return `pill pill--${severity}`;
}

function EvidenceBlock({ finding }: { finding: FindingDetail }) {
  const lines = finding.evidence?.lines ?? [];

  if (lines.length === 0) {
    return (
      <p className="empty">
        This check reasons over the parsed configuration rather than a single line, so there is no
        excerpt to show.{' '}
        {finding.evidence?.observed != null && (
          <>
            It observed: <code>{JSON.stringify(finding.evidence.observed)}</code>.
          </>
        )}
      </p>
    );
  }

  return (
    <div className="evidence">
      {finding.evidence.expected && (
        <p className="evidence__expected">Expected: {finding.evidence.expected}</p>
      )}
      <pre className="evidence__lines">
        {lines.map((line, index) => (
          <div key={`${line.path}-${index}`} className="evidence__line">
            <span className="evidence__gutter">{line.line_start ?? '—'}</span>
            <span className="evidence__text">{line.excerpt}</span>
          </div>
        ))}
      </pre>
      {/* Jump-to-line into the config viewer, which is what IF-UI-04 exists for. */}
      {lines[0]?.line_start != null && (
        <NavLink
          className="button button--ghost button--small"
          to={`/inventory/${finding.device_id}/config`}
        >
          Open the configuration
        </NavLink>
      )}
    </div>
  );
}

function FindingPanel({ findingId, onClose }: { findingId: string; onClose: () => void }) {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const detail = useQuery({
    queryKey: ['finding', findingId],
    queryFn: () => api.get<FindingDetail>(`/findings/${findingId}`),
  });

  const setStatus = useMutation({
    mutationFn: (status: FindingStatus) => api.patch<Finding>(`/findings/${findingId}`, { status }),
    onSuccess: () => {
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ['findings'] });
      void queryClient.invalidateQueries({ queryKey: ['finding', findingId] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : 'The update failed.'),
  });

  if (detail.isLoading) return <p className="page-loading">Loading…</p>;
  if (!detail.data) return null;

  const finding = detail.data;
  const frameworks = Object.entries(finding.references ?? {}).filter(
    ([key, values]) => FRAMEWORK_LABELS[key] && values.length > 0,
  );

  return (
    <section className="card finding">
      <div className="card__header">
        <h2 className="card__title">
          <span className={severityClass(finding.severity)}>{finding.severity}</span>{' '}
          {finding.title}
        </h2>
        <button className="button button--ghost button--small" onClick={onClose}>
          Close
        </button>
      </div>

      <p className="finding__description">{finding.description}</p>

      <div className="finding__meta">
        <span>
          First seen{' '}
          {finding.first_seen_at ? new Date(finding.first_seen_at).toLocaleDateString() : '—'}
        </span>
        <span>Seen {finding.occurrences}×</span>
        <span>Status {STATUS_LABELS[finding.status]}</span>
        {finding.check_id && <code>{finding.check_id}</code>}
      </div>

      <h3 className="finding__heading">Evidence</h3>
      <EvidenceBlock finding={finding} />

      {finding.rationale && (
        <>
          <h3 className="finding__heading">Why this matters</h3>
          <p className="finding__prose">{finding.rationale}</p>
        </>
      )}

      {finding.remediation && (
        <>
          <h3 className="finding__heading">How to fix it</h3>
          {/* Guidance only. NetSecOps never applies a change to a device (SRS §8). */}
          <p className="finding__prose">{finding.remediation}</p>
        </>
      )}

      {frameworks.length > 0 && (
        <>
          <h3 className="finding__heading">Controls</h3>
          <ul className="finding__frameworks">
            {frameworks.map(([key, values]) => (
              <li key={key}>
                <strong>{FRAMEWORK_LABELS[key]}</strong> {values.join(', ')}
              </li>
            ))}
          </ul>
        </>
      )}

      {can('finding:write') && (
        <div className="finding__actions">
          {error && (
            <div className="alert alert--error" role="alert">
              {error}
            </div>
          )}
          {SETTABLE_STATUSES.filter((s) => s !== finding.status).map((status) => (
            <button
              key={status}
              className="button button--ghost button--small"
              disabled={setStatus.isPending}
              onClick={() => setStatus.mutate(status)}
            >
              Mark {STATUS_LABELS[status].toLowerCase()}
            </button>
          ))}
          <p className="finding__note">
            A finding is marked resolved by its check passing on a later assessment, not by hand —
            so that the status is a measurement rather than a claim.
          </p>
        </div>
      )}
    </section>
  );
}

export function FindingsPage() {
  const [severity, setSeverity] = useState<string>('');
  const [activeOnly, setActiveOnly] = useState(true);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);

  const findings = useQuery({
    queryKey: ['findings', severity, activeOnly, offset],
    queryFn: () => {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(offset),
        active_only: String(activeOnly),
      });
      if (severity) params.set('severity', severity);
      return api.get<Paginated<Finding>>(`/findings?${params}`);
    },
  });

  const total = findings.data?.meta.total ?? 0;

  return (
    <div className="page">
      <header className="page__header">
        <h1>Findings</h1>
        <p className="page__subtitle">
          What the checks concluded, worst first. Every finding shows the configuration line behind
          it.
        </p>
      </header>

      <div className="toolbar">
        <select
          className="field__input field__input--small"
          value={severity}
          onChange={(event) => {
            setSeverity(event.target.value);
            setOffset(0);
          }}
          aria-label="Filter by severity"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>

        <label className="toolbar__check">
          <input
            type="checkbox"
            checked={activeOnly}
            onChange={(event) => {
              setActiveOnly(event.target.checked);
              setOffset(0);
            }}
          />
          Open findings only
        </label>
      </div>

      {findings.isLoading ? (
        <p className="page-loading">Loading…</p>
      ) : total === 0 ? (
        <p className="empty">
          No findings. Either nothing has been assessed yet, or every check passed — the device
          pages show which.
        </p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Finding</th>
                <th>Check</th>
                <th>Status</th>
                <th>Last seen</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {findings.data?.data.map((finding) => (
                <tr
                  key={finding.id}
                  className={finding.id === selected ? 'table__row--active' : ''}
                >
                  <td>
                    <span className={severityClass(finding.severity)}>{finding.severity}</span>
                  </td>
                  <td>{finding.title}</td>
                  <td className="mono">{finding.check_id ?? finding.kind}</td>
                  <td>{STATUS_LABELS[finding.status]}</td>
                  <td>
                    {finding.last_seen_at
                      ? new Date(finding.last_seen_at).toLocaleDateString()
                      : '—'}
                  </td>
                  <td>
                    <button
                      className="button button--ghost button--small"
                      onClick={() => setSelected(selected === finding.id ? null : finding.id)}
                    >
                      {selected === finding.id ? 'Hide' : 'Details'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && <FindingPanel findingId={selected} onClose={() => setSelected(null)} />}

      <div className="pager">
        <button
          className="button button--ghost button--small"
          disabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
        >
          Previous
        </button>
        <span className="pager__status">
          {total === 0 ? '0' : `${offset + 1}–${Math.min(offset + PAGE_SIZE, total)}`} of{' '}
          {total.toLocaleString()}
        </span>
        <button
          className="button button--ghost button--small"
          disabled={offset + PAGE_SIZE >= total}
          onClick={() => setOffset(offset + PAGE_SIZE)}
        >
          Next
        </button>
      </div>
    </div>
  );
}
