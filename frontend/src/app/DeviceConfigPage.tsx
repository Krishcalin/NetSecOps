/** A device's configuration history, diff and baseline (FR-DRIFT-01 … FR-DRIFT-03).
 *
 * The drift banner leads, because "has anything changed since we agreed this was
 * correct" is the question this page exists to answer. The snapshot list and viewer
 * are below it, for when the answer is yes and the operator needs the detail.
 */

import { useMemo, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { api, ApiError, request } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import { ConfigViewer } from '../features/snapshots/ConfigViewer';
import { DiffViewer } from '../features/snapshots/DiffViewer';
import { EvidencePanel } from '../features/snapshots/EvidencePanel';
import type { DeviceDetail, Paginated } from '../features/inventory/types';
import type {
  ConfigDiff,
  ConfigUploadResponse,
  Drift,
  Snapshot,
  SnapshotDetail,
} from '../features/snapshots/types';

function coverageLabel(snapshot: Snapshot): string {
  if (snapshot.parse_coverage == null) return 'not parsed';
  return `${snapshot.parse_coverage}% parsed`;
}

function DriftBanner({ drift }: { drift: Drift }) {
  if (!drift.baseline_snapshot_id) {
    return (
      <div className="alert" role="status">
        <strong>No baseline pinned.</strong> Pin a snapshot below to define what this device&rsquo;s
        configuration should look like. Later collections that differ raise a drift finding.
      </div>
    );
  }

  if (!drift.changed) {
    return (
      <div className="alert alert--ok" role="status">
        <strong>Matches baseline.</strong> {drift.headline}
      </div>
    );
  }

  return (
    <div className="alert alert--warning" role="alert">
      <strong>Drift from baseline ({drift.severity}).</strong> {drift.headline}
      {drift.semantic.length > 1 && (
        <span className="alert__more"> …and {drift.semantic.length - 1} more change(s).</span>
      )}
    </div>
  );
}

export function DeviceConfigPage() {
  const { deviceId = '' } = useParams();
  const { can } = useAuth();
  const queryClient = useQueryClient();

  const [selected, setSelected] = useState<string | null>(null);
  const [compareTo, setCompareTo] = useState<string | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const canPin = can('device:write');

  const device = useQuery({
    queryKey: ['device', deviceId],
    queryFn: () => api.get<DeviceDetail>(`/devices/${deviceId}`),
  });

  const snapshots = useQuery({
    queryKey: ['snapshots', deviceId],
    queryFn: () => api.get<Paginated<Snapshot>>(`/devices/${deviceId}/snapshots?limit=50`),
  });

  const drift = useQuery({
    queryKey: ['drift', deviceId],
    queryFn: () => api.get<Drift>(`/devices/${deviceId}/drift`),
  });

  const rows = snapshots.data?.data ?? [];
  // Default to the newest snapshot rather than making the operator pick one first.
  const activeId = selected ?? rows[0]?.id ?? null;
  const active = rows.find((row) => row.id === activeId) ?? null;
  const baseline = rows.find((row) => row.is_baseline) ?? null;

  const detail = useQuery({
    queryKey: ['snapshot', activeId],
    queryFn: () => api.get<SnapshotDetail>(`/snapshots/${activeId}`),
    enabled: activeId !== null,
  });

  const against = compareTo ?? baseline?.id ?? null;
  const comparable = activeId !== null && against !== null && against !== activeId;

  const diff = useQuery({
    queryKey: ['diff', activeId, against],
    queryFn: () => api.get<ConfigDiff>(`/snapshots/${activeId}/diff?against=${against}`),
    enabled: comparable,
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['snapshots', deviceId] });
    void queryClient.invalidateQueries({ queryKey: ['drift', deviceId] });
  };

  const pin = useMutation({
    mutationFn: (snapshotId: string) => api.post<Snapshot>(`/snapshots/${snapshotId}/baseline`),
    onSuccess: invalidate,
  });

  const clearBaseline = useMutation({
    mutationFn: () => api.delete<void>(`/devices/${deviceId}/baseline`),
    onSuccess: invalidate,
  });

  const upload = useMutation({
    mutationFn: (file: File) => {
      const form = new FormData();
      form.append('file', file);
      return request<ConfigUploadResponse>(`/devices/${deviceId}/configs`, {
        method: 'POST',
        body: form,
        rawBody: true,
      });
    },
    onSuccess: (result) => {
      setUploadError(null);
      setSelected(result.snapshot_id);
      invalidate();
    },
    onError: (error) =>
      setUploadError(error instanceof ApiError ? error.message : 'The upload failed.'),
  });

  const changedLines = useMemo(() => {
    if (!diff.data) return undefined;
    const added = new Set(diff.data.added);
    const lines = new Set<number>();
    diff.data.after_lines.forEach((line, index) => {
      if (added.has(line.trim())) lines.add(index + 1);
    });
    return lines;
  }, [diff.data]);

  return (
    <div className="page">
      <header className="page__header">
        <h1>{device.data?.hostname || device.data?.mgmt_ip || 'Device'} — configuration</h1>
        <p className="page__subtitle">
          Snapshots are stored with secrets redacted. Identical configurations are kept once.{' '}
          <Link to="/inventory">Back to inventory</Link>
        </p>
      </header>

      {drift.data && <DriftBanner drift={drift.data} />}

      <section className="card">
        <div className="card__header">
          <h2 className="card__title">Snapshots</h2>
          {canPin && (
            <label className="button button--ghost button--small">
              Upload a configuration
              <input
                type="file"
                accept=".cfg,.txt,.conf,.xml,.json,text/plain"
                hidden
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  if (file) upload.mutate(file);
                  // Reset so selecting the same file twice still fires a change event.
                  event.target.value = '';
                }}
              />
            </label>
          )}
        </div>

        {uploadError && (
          <div className="alert alert--error" role="alert">
            {uploadError}
          </div>
        )}
        {upload.isPending && <p className="page-loading">Parsing…</p>}
        {upload.data?.deduplicated && (
          <div className="alert" role="status">
            That configuration was already stored — the existing snapshot was reused.
          </div>
        )}

        {snapshots.isLoading ? (
          <p className="page-loading">Loading…</p>
        ) : rows.length === 0 ? (
          <p className="empty">
            No configuration has been collected from this device yet. Run a collection, or upload a
            configuration file to assess it offline.
          </p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Collected</th>
                  <th>Seen</th>
                  <th>Parsed</th>
                  <th>Hash</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id} className={row.id === activeId ? 'table__row--active' : ''}>
                    <td className="mono">
                      {new Date(row.created_at).toLocaleString()}
                      {row.is_baseline && <span className="pill pill--success">baseline</span>}
                    </td>
                    <td>{row.seen_count}×</td>
                    <td>
                      <span
                        className={(row.parse_coverage ?? 0) >= 90 ? 'pill pill--success' : 'pill'}
                        title={`${row.unparsed_count} line(s) the parser did not recognise`}
                      >
                        {coverageLabel(row)}
                      </span>
                    </td>
                    <td className="mono">{row.config_hash.slice(0, 12)}</td>
                    <td className="table__actions">
                      <button
                        className="button button--ghost button--small"
                        onClick={() => setSelected(row.id)}
                      >
                        View
                      </button>
                      <button
                        className="button button--ghost button--small"
                        disabled={row.id === activeId}
                        onClick={() => setCompareTo(row.id)}
                      >
                        Compare
                      </button>
                      {canPin &&
                        (row.is_baseline ? (
                          <button
                            className="button button--ghost button--small"
                            onClick={() => clearBaseline.mutate()}
                          >
                            Unpin
                          </button>
                        ) : (
                          <button
                            className="button button--ghost button--small"
                            onClick={() => pin.mutate(row.id)}
                          >
                            Pin as baseline
                          </button>
                        ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {comparable && diff.data && (
        <section className="card">
          <div className="card__header">
            <h2 className="card__title">Changes</h2>
            {compareTo && (
              <button
                className="button button--ghost button--small"
                onClick={() => setCompareTo(null)}
              >
                Compare against baseline instead
              </button>
            )}
          </div>
          <DiffViewer
            diff={diff.data}
            beforeLabel={against === baseline?.id ? 'Baseline' : 'Earlier snapshot'}
            afterLabel="Selected"
          />
        </section>
      )}

      {detail.data && (
        <section className="card">
          <h2 className="card__title">Configuration</h2>
          <ConfigViewer
            config={detail.data.config_redacted}
            highlightLines={changedLines}
            caption={`${detail.data.parser_platform ?? 'unknown platform'} · ${coverageLabel(
              detail.data,
            )}`}
          />
        </section>
      )}

      {active && <EvidencePanel collectionId={active.collection_id} />}
    </div>
  );
}
