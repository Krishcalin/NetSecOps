/** Policies — which checks apply where (FR-CHK-05, FR-CHK-06).
 *
 * A policy is the only thing that decides whether a check ever runs. Six endpoints shipped
 * with no surface, which meant an installation ran whatever the seeded default policy
 * contained and nothing could change it: a check could not be turned off for a platform
 * that legitimately does not do that thing, a severity could not be re-graded to match
 * what the estate actually treats as urgent, and a group could not be given a policy of
 * its own.
 *
 * Two things this page is careful about:
 *
 * **Disabling a check inside a policy is not the same as an exception**, and they are
 * adjacent enough to be confused. Disabling says "this rule does not apply to these
 * devices" and is permanent until changed. An exception says "it applies, we are
 * knowingly not complying, and here is who agreed and when it lapses". The page says so
 * where the control is, because choosing the wrong one loses either the finding or the
 * audit trail.
 *
 * **A default policy is what covers devices no assignment reaches.** Changing it changes
 * what is assessed on every unassigned device, which is usually most of them, so it is
 * stated rather than presented as a toggle among others.
 */

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { ApiError, api } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import type { CheckSummary, PolicyDetail, Policy } from '../features/checks/types';
import type { DeviceGroup } from '../features/inventory/types';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function message(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.problem.detail : fallback;
}

// ─────────────────────────────── create ──────────────────────────────────────

function CreatePolicy({ checks, onCreated }: { checks: CheckSummary[]; onCreated: () => void }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [selected, setSelected] = useState<string[]>([]);
  const [search, setSearch] = useState('');
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () =>
      api.post<Policy>('/policies', {
        name: name.trim(),
        description: description.trim() || null,
        check_ids: selected,
      }),
    onSuccess: () => {
      setError(null);
      setName('');
      setDescription('');
      setSelected([]);
      onCreated();
    },
    onError: (err) => setError(message(err, 'The policy could not be created.')),
  });

  const needle = search.trim().toLowerCase();
  const visible = needle
    ? checks.filter(
        (check) =>
          check.id.toLowerCase().includes(needle) || check.title.toLowerCase().includes(needle),
      )
    : checks;

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">Create a policy</h2>
      </div>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      <div className="form-grid">
        <label className="field">
          <span className="field__label">Name</span>
          <input
            className="field__input"
            value={name}
            aria-label="Policy name"
            onChange={(event) => setName(event.target.value)}
          />
        </label>
        <label className="field">
          <span className="field__label">Description</span>
          <input
            className="field__input"
            value={description}
            aria-label="Policy description"
            onChange={(event) => setDescription(event.target.value)}
          />
        </label>
      </div>

      <div className="toolbar">
        <input
          className="field__input field__input--small"
          value={search}
          aria-label="Search checks to include"
          placeholder="Search the library"
          onChange={(event) => setSearch(event.target.value)}
        />
        <span className="muted">
          {selected.length} check{selected.length === 1 ? '' : 's'} selected
        </span>
        <button
          className="button button--ghost button--small"
          onClick={() => setSelected(visible.map((check) => check.id))}
        >
          Select all shown
        </button>
        <button className="button button--ghost button--small" onClick={() => setSelected([])}>
          Clear
        </button>
      </div>

      <div className="checkbox-grid checkbox-grid--scroll">
        {visible.map((check) => (
          <label className="checkbox" key={check.id}>
            <input
              type="checkbox"
              checked={selected.includes(check.id)}
              aria-label={check.id}
              onChange={() =>
                setSelected(
                  selected.includes(check.id)
                    ? selected.filter((id) => id !== check.id)
                    : [...selected, check.id],
                )
              }
            />
            <span>
              {check.title}
              <span className="mono muted"> {check.id}</span>
            </span>
          </label>
        ))}
      </div>

      <div className="toolbar">
        <button
          className="button button--small"
          disabled={!name.trim() || selected.length === 0 || create.isPending}
          onClick={() => create.mutate()}
        >
          Create policy
        </button>
        {selected.length === 0 && (
          <span className="field__help">
            A policy with no checks assesses nothing, so it is not accepted.
          </span>
        )}
      </div>
    </section>
  );
}

// ─────────────────────────────── detail ──────────────────────────────────────

function PolicyEntries({
  policyId,
  checks,
  groups,
  canWrite,
}: {
  policyId: string;
  checks: CheckSummary[];
  groups: DeviceGroup[];
  canWrite: boolean;
}) {
  const queryClient = useQueryClient();
  const [groupId, setGroupId] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [assigned, setAssigned] = useState<string | null>(null);

  const detail = useQuery({
    queryKey: ['policy', policyId],
    queryFn: () => api.get<PolicyDetail>(`/policies/${policyId}`),
  });

  const refresh = () => {
    setError(null);
    void queryClient.invalidateQueries({ queryKey: ['policy', policyId] });
    void queryClient.invalidateQueries({ queryKey: ['policies'] });
  };

  const setCheck = useMutation({
    mutationFn: (body: { checkId: string; enabled?: boolean; severity?: string | null }) =>
      api.put(`/policies/${policyId}/checks/${encodeURIComponent(body.checkId)}`, {
        enabled: body.enabled,
        severity_override: body.severity,
      }),
    onSuccess: refresh,
    onError: (err) => setError(message(err, 'The check could not be changed.')),
  });

  const assign = useMutation({
    mutationFn: () =>
      api.post<void>(`/policies/${policyId}/assignments`, { device_group_id: groupId }),
    onSuccess: () => {
      setAssigned(groups.find((g) => g.id === groupId)?.name ?? 'that group');
      setGroupId('');
      refresh();
    },
    onError: (err) => setError(message(err, 'The policy could not be assigned.')),
  });

  const makeDefault = useMutation({
    mutationFn: () => api.post<Policy>(`/policies/${policyId}/default`),
    onSuccess: refresh,
    onError: (err) => setError(message(err, 'The default could not be changed.')),
  });

  if (detail.isLoading) {
    return <p className="page-loading">Loading…</p>;
  }
  if (!detail.data) {
    return <p className="empty">That policy could not be loaded.</p>;
  }

  const policy = detail.data;
  const title = (checkId: string) => checks.find((c) => c.id === checkId)?.title ?? checkId;

  return (
    <div className="stack">
      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      <h3 className="finding__heading">Where it applies</h3>
      {policy.is_default ? (
        <p className="field__help">
          This is the default policy: it covers every device no assignment reaches, which is usually
          most of them.
        </p>
      ) : (
        canWrite && (
          <div className="toolbar">
            <button
              className="button button--ghost button--small"
              disabled={makeDefault.isPending}
              onClick={() => makeDefault.mutate()}
            >
              Make this the default
            </button>
            <span className="field__help">
              Changing the default changes what is assessed on every unassigned device.
            </span>
          </div>
        )
      )}

      {assigned && (
        <div className="alert alert--ok" role="status">
          Applied to {assigned}. It takes effect at the next assessment of those devices.
        </div>
      )}

      {canWrite && (
        <div className="toolbar">
          <select
            className="field__input field__input--small"
            value={groupId}
            aria-label="Apply to a device group"
            onChange={(event) => setGroupId(event.target.value)}
          >
            <option value="">Apply to a device group…</option>
            {groups.map((group) => (
              <option key={group.id} value={group.id}>
                {group.name}
              </option>
            ))}
          </select>
          <button
            className="button button--ghost button--small"
            disabled={!groupId || assign.isPending}
            onClick={() => assign.mutate()}
          >
            Apply
          </button>
        </div>
      )}

      <h3 className="finding__heading">
        Checks in this policy ({policy.entries.filter((e) => e.enabled).length} of{' '}
        {policy.entries.length} enabled)
      </h3>
      <p className="field__help">
        Disabling a check here says it does not apply to these devices, permanently. If it does
        apply and you are knowingly not complying, file an exception instead — that keeps the
        finding, and records who accepted the risk and when it lapses.
      </p>

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Check</th>
              <th>Enabled</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            {policy.entries.map((entry) => (
              <tr key={entry.check_id} className={entry.enabled ? undefined : 'row--muted'}>
                <td>
                  {title(entry.check_id)}
                  <div className="mono muted">{entry.check_id}</div>
                </td>
                <td>
                  <input
                    type="checkbox"
                    checked={entry.enabled}
                    disabled={!canWrite || setCheck.isPending}
                    aria-label={`${entry.check_id} enabled`}
                    onChange={(event) =>
                      setCheck.mutate({ checkId: entry.check_id, enabled: event.target.checked })
                    }
                  />
                </td>
                <td>
                  <select
                    className="field__input field__input--small"
                    value={entry.severity_override ?? ''}
                    disabled={!canWrite || setCheck.isPending}
                    aria-label={`${entry.check_id} severity`}
                    onChange={(event) =>
                      setCheck.mutate({
                        checkId: entry.check_id,
                        severity: event.target.value || null,
                      })
                    }
                  >
                    {/* The check's own severity, unless this policy says otherwise. Blank
                        is not "none" — it is "whatever the check says". */}
                    <option value="">as the check defines it</option>
                    {SEVERITIES.map((severity) => (
                      <option key={severity} value={severity}>
                        {severity}
                      </option>
                    ))}
                  </select>
                </td>
              </tr>
            ))}
            {policy.entries.length === 0 && (
              <tr>
                <td colSpan={3} className="table__empty">
                  This policy contains no checks, so it assesses nothing.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─────────────────────────────── page ────────────────────────────────────────

export function PoliciesPage() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState<string | null>(null);

  const canWrite = can('policy:write');

  const policies = useQuery({
    queryKey: ['policies'],
    queryFn: () => api.get<Policy[]>('/policies'),
  });

  const checks = useQuery({
    queryKey: ['checks', '', ''],
    queryFn: () => api.get<CheckSummary[]>('/checks'),
  });

  const groups = useQuery({
    queryKey: ['policy-groups'],
    queryFn: () => api.get<DeviceGroup[]>('/device-groups'),
  });

  const rows = policies.data ?? [];
  const checkRows = checks.data ?? [];
  const groupRows = groups.data ?? [];

  return (
    <div className="page">
      <header className="page__header">
        <h1>Policies</h1>
        <p className="page__subtitle">
          Which checks run against which devices. A check that is in no policy never runs.
        </p>
      </header>

      {canWrite && (
        <CreatePolicy
          checks={checkRows}
          onCreated={() => void queryClient.invalidateQueries({ queryKey: ['policies'] })}
        />
      )}

      {policies.isLoading ? (
        <p className="page-loading">Loading…</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Policy</th>
                <th>Source</th>
                <th>Frameworks</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((policy) => (
                <tr key={policy.id} className={policy.enabled ? undefined : 'row--muted'}>
                  <td>
                    {policy.name}
                    {policy.is_default && <span className="pill pill--success">default</span>}
                    {!policy.enabled && <span className="pill pill--failure">disabled</span>}
                    {policy.description && <div className="muted">{policy.description}</div>}
                  </td>
                  <td className="mono">{policy.source}</td>
                  <td className="muted">
                    {policy.frameworks.length > 0 ? policy.frameworks.join(', ') : '—'}
                  </td>
                  <td className="table__actions">
                    <button
                      className="button button--ghost button--small"
                      onClick={() => setExpanded(expanded === policy.id ? null : policy.id)}
                    >
                      {expanded === policy.id ? 'Hide' : 'Open'}
                    </button>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={4} className="table__empty">
                    No policy is defined, so no assessment has anything to run.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {expanded && (
        <section className="card">
          <div className="card__header">
            <h2 className="card__title">{rows.find((p) => p.id === expanded)?.name}</h2>
          </div>
          <PolicyEntries
            key={expanded}
            policyId={expanded}
            checks={checkRows}
            groups={groupRows}
            canWrite={canWrite}
          />
        </section>
      )}
    </div>
  );
}
