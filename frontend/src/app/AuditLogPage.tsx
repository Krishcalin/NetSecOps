/** Audit log viewer (FR-AUD-01, FR-AUD-02). */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { api } from '../api/client';

interface AuditEntry {
  id: number;
  ts: string;
  actor_username: string | null;
  action: string;
  outcome: string;
  object_type: string | null;
  object_id: string | null;
  ip_address: string | null;
  correlation_id: string | null;
  hash: string;
}

interface AuditPage {
  data: AuditEntry[];
  meta: { total: number; limit: number; offset: number };
}

const PAGE_SIZE = 50;

export function AuditLogPage() {
  const [offset, setOffset] = useState(0);
  const [action, setAction] = useState('');

  const query = useQuery({
    queryKey: ['audit-log', offset, action],
    queryFn: () => {
      const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) });
      if (action) params.set('action', action);
      return api.get<AuditPage>(`/audit-log?${params}`);
    },
  });

  const verification = useQuery({
    queryKey: ['audit-chain'],
    queryFn: () =>
      api.get<{ total: number; valid: boolean; reason: string | null }>('/audit-log/verify'),
  });

  const total = query.data?.meta.total ?? 0;

  return (
    <div className="page">
      <header className="page__header">
        <h1>Audit log</h1>
        <p className="page__subtitle">
          Append-only and hash-chained. Every privileged action and every command sent to a device
          is recorded here.
        </p>
      </header>

      {verification.data && (
        <div
          className={`alert ${verification.data.valid ? 'alert--ok' : 'alert--error'}`}
          role="status"
        >
          {verification.data.valid
            ? `Chain verified across ${verification.data.total.toLocaleString()} records.`
            : `CHAIN BROKEN: ${verification.data.reason}`}
        </div>
      )}

      <div className="toolbar">
        <label className="field field--inline">
          <span className="field__label">Filter by action</span>
          <input
            className="field__input"
            value={action}
            placeholder="e.g. login.failure"
            onChange={(e) => {
              setAction(e.target.value);
              setOffset(0);
            }}
          />
        </label>
      </div>

      {query.isLoading ? (
        <p className="page-loading">Loading…</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Time (UTC)</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Outcome</th>
                <th>Object</th>
                <th>Source IP</th>
              </tr>
            </thead>
            <tbody>
              {query.data?.data.map((entry) => (
                <tr key={entry.id}>
                  <td className="mono">
                    {new Date(entry.ts).toISOString().replace('T', ' ').slice(0, 19)}
                  </td>
                  <td>{entry.actor_username ?? '—'}</td>
                  <td className="mono">{entry.action}</td>
                  <td>
                    <span className={`pill pill--${entry.outcome}`}>{entry.outcome}</span>
                  </td>
                  <td className="mono">
                    {entry.object_type
                      ? `${entry.object_type}/${entry.object_id?.slice(0, 8)}`
                      : '—'}
                  </td>
                  <td className="mono">{entry.ip_address ?? '—'}</td>
                </tr>
              ))}
              {query.data?.data.length === 0 && (
                <tr>
                  <td colSpan={6} className="table__empty">
                    No audit records match this filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
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
