/** Assessment run history (FR-JOB-04).
 *
 * Failures are shown with their FR-COL-07 error class, because "unreachable" and
 * "auth failed" send an operator to completely different places.
 */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { api } from '../api/client';
import type { Job, JobDetail, JobStatus, Paginated } from '../features/inventory/types';

const PAGE_SIZE = 25;

const STATUS_PILL: Record<JobStatus, string> = {
  queued: 'pill',
  running: 'pill',
  paused: 'pill',
  cancelling: 'pill',
  cancelled: 'pill',
  succeeded: 'pill pill--success',
  partial: 'pill pill--failure',
  failed: 'pill pill--failure',
};

const ERROR_CLASS_HELP: Record<string, string> = {
  unreachable: 'The device did not answer — check routing and firewalls.',
  auth_failed: 'The credential was rejected — check the device account.',
  authz_denied: 'Authenticated, but the account may not run the command.',
  timeout: 'The device answered too slowly.',
  host_key_changed: 'The host key changed. Verify the device before re-running.',
  readonly_violation: 'NetSecOps attempted something outside its allow-list. Report this.',
  internal_error: 'An unexpected error. The correlation id is in the audit log.',
};

export function JobsPage() {
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  const jobs = useQuery({
    queryKey: ['jobs', offset],
    queryFn: () =>
      api.get<Paginated<Job>>(
        `/jobs?${new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) })}`,
      ),
    // A running job's counters change; refresh while the list is on screen.
    refetchInterval: 5000,
  });

  const detail = useQuery({
    queryKey: ['job', expanded],
    queryFn: () => api.get<JobDetail>(`/jobs/${expanded}`),
    enabled: expanded !== null,
  });

  const total = jobs.data?.meta.total ?? 0;

  return (
    <div className="page">
      <header className="page__header">
        <h1>Assessments</h1>
        <p className="page__subtitle">
          Every run, with per-device outcomes. Commands issued are in the audit log.
        </p>
      </header>

      {jobs.isLoading ? (
        <p className="page-loading">Loading…</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Started</th>
                <th>Type</th>
                <th>Status</th>
                <th>Devices</th>
                <th>Succeeded</th>
                <th>Failed</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {jobs.data?.data.map((job) => (
                <tr key={job.id}>
                  <td className="mono">
                    {job.started_at ? new Date(job.started_at).toLocaleString() : 'queued'}
                  </td>
                  <td className="mono">{job.job_type}</td>
                  <td>
                    <span className={STATUS_PILL[job.status]}>{job.status}</span>
                  </td>
                  <td>{job.stats.total ?? 0}</td>
                  <td>{job.stats.succeeded ?? 0}</td>
                  <td>{job.stats.failed ?? 0}</td>
                  <td>
                    <button
                      className="button button--ghost button--small"
                      onClick={() => setExpanded(expanded === job.id ? null : job.id)}
                    >
                      {expanded === job.id ? 'Hide' : 'Details'}
                    </button>
                  </td>
                </tr>
              ))}
              {jobs.data?.data.length === 0 && (
                <tr>
                  <td colSpan={7} className="table__empty">
                    No assessments have run yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {expanded && detail.data && (
        <section className="card">
          <h2 className="card__title">Per-device outcomes</h2>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Status</th>
                  <th>Commands</th>
                  <th>Duration</th>
                  <th>Problem</th>
                </tr>
              </thead>
              <tbody>
                {detail.data.devices.map((result) => (
                  <tr key={result.id}>
                    <td className="mono">{result.device_id.slice(0, 8)}</td>
                    <td>
                      <span
                        className={`pill pill--${
                          result.status === 'succeeded' ? 'success' : 'failure'
                        }`}
                      >
                        {result.status}
                      </span>
                    </td>
                    <td>{result.command_count}</td>
                    <td>{result.duration_ms != null ? `${result.duration_ms} ms` : '—'}</td>
                    <td>
                      {result.error_class ? (
                        <span title={ERROR_CLASS_HELP[result.error_class] ?? ''}>
                          <strong className="mono">{result.error_class}</strong>
                          {result.error_message ? ` — ${result.error_message}` : ''}
                        </span>
                      ) : (
                        '—'
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

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
