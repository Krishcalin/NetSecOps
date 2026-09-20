/** The exception register (FR-CHK-07).
 *
 * Three endpoints, no surface, and of everything that was unreachable this is the one
 * whose absence changes behaviour rather than convenience. A finding that an organisation
 * has knowingly accepted has exactly two fates: it is recorded as accepted, with a reason,
 * an approver and an end date — or it is ignored. Without this page there was no way to do
 * the first, so every accepted risk became an unexplained open finding that people learn
 * to scroll past, and the dashboard's count stopped meaning anything.
 *
 * The register is the product of it. Not a suppression mechanism with a register attached:
 * the register *is* the point, which is why the page leads with what is in force and when
 * each one lapses, rather than with the form.
 *
 * **Every exception expires.** The API requires it, and this page says why where it asks:
 * an acceptance with no end date is a check quietly deleted, and nobody ever revisits it.
 *
 * **Scope is stated in words, not inferred from which id is set.** `device`, `group` and
 * `global` are three different promises about how much of the estate stops being assessed
 * for this check, and the widest of them is one click away from the narrowest.
 */

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { ApiError, api } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import type { CheckSummary, Exception, ExceptionScope } from '../features/checks/types';
import type { Device, DeviceGroup, Paginated } from '../features/inventory/types';

const SCOPES: { value: ExceptionScope; label: string; note: string }[] = [
  {
    value: 'device',
    label: 'One device',
    note: 'This check stops producing findings on that device only.',
  },
  {
    value: 'group',
    label: 'A device group',
    note: 'Every device in the group, including ones added to it later.',
  },
  {
    value: 'global',
    label: 'The whole estate',
    note: 'Every device NetSecOps assesses, now and in future. Consider disabling the check in the policy instead — that is the honest way to say a rule does not apply, and it does not expire silently.',
  },
];

function message(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.problem.detail : fallback;
}

/** Whole days until `iso`, negative once it has passed. */
function daysUntil(iso: string): number {
  return Math.ceil((new Date(iso).getTime() - Date.now()) / 86_400_000);
}

// ─────────────────────────────── create ──────────────────────────────────────

function FileException({
  checks,
  devices,
  groups,
  onFiled,
}: {
  checks: CheckSummary[];
  devices: Device[];
  groups: DeviceGroup[];
  onFiled: () => void;
}) {
  const [checkId, setCheckId] = useState('');
  const [scope, setScope] = useState<ExceptionScope>('device');
  const [deviceId, setDeviceId] = useState('');
  const [groupId, setGroupId] = useState('');
  const [justification, setJustification] = useState('');
  const [approver, setApprover] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () =>
      api.post<Exception>('/exceptions', {
        check_id: checkId,
        scope,
        device_id: scope === 'device' ? deviceId : null,
        device_group_id: scope === 'group' ? groupId : null,
        justification: justification.trim(),
        approver: approver.trim() || null,
        expires_at: new Date(expiresAt).toISOString(),
      }),
    onSuccess: () => {
      setError(null);
      setCheckId('');
      setJustification('');
      setApprover('');
      setExpiresAt('');
      onFiled();
    },
    onError: (err) => setError(message(err, 'The exception could not be filed.')),
  });

  const chosen = SCOPES.find((s) => s.value === scope)!;
  const targetChosen = scope === 'device' ? !!deviceId : scope === 'group' ? !!groupId : true;

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">Accept a risk</h2>
      </div>
      <p className="field__help">
        This suppresses a check's findings for as long as the exception runs. It does not change the
        check, and it does not change what the device is doing — it records that somebody decided to
        live with it, and until when.
      </p>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      <div className="form-grid">
        <label className="field">
          <span className="field__label">Check</span>
          <select
            className="field__input"
            value={checkId}
            aria-label="Check"
            onChange={(event) => setCheckId(event.target.value)}
          >
            <option value="">Choose a check…</option>
            {checks.map((check) => (
              <option key={check.id} value={check.id}>
                {check.title} ({check.id})
              </option>
            ))}
          </select>
        </label>

        <label className="field">
          <span className="field__label">Scope</span>
          <select
            className="field__input"
            value={scope}
            aria-label="Scope"
            onChange={(event) => setScope(event.target.value as ExceptionScope)}
          >
            {SCOPES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          <span className="field__help">{chosen.note}</span>
        </label>

        {scope === 'device' && (
          <label className="field">
            <span className="field__label">Device</span>
            <select
              className="field__input"
              value={deviceId}
              aria-label="Device"
              onChange={(event) => setDeviceId(event.target.value)}
            >
              <option value="">Choose a device…</option>
              {devices.map((device) => (
                <option key={device.id} value={device.id}>
                  {device.hostname ?? device.mgmt_ip}
                </option>
              ))}
            </select>
          </label>
        )}

        {scope === 'group' && (
          <label className="field">
            <span className="field__label">Device group</span>
            <select
              className="field__input"
              value={groupId}
              aria-label="Device group"
              onChange={(event) => setGroupId(event.target.value)}
            >
              <option value="">Choose a group…</option>
              {groups.map((group) => (
                <option key={group.id} value={group.id}>
                  {group.name}
                </option>
              ))}
            </select>
          </label>
        )}

        <label className="field">
          <span className="field__label">Approver</span>
          <input
            className="field__input"
            value={approver}
            aria-label="Approver"
            onChange={(event) => setApprover(event.target.value)}
          />
          <span className="field__help">Who accepted the risk, not who is filing this.</span>
        </label>

        <label className="field">
          <span className="field__label">Expires</span>
          <input
            className="field__input"
            type="date"
            value={expiresAt}
            aria-label="Expires"
            onChange={(event) => setExpiresAt(event.target.value)}
          />
          <span className="field__help">
            Required. An acceptance with no end date is a check quietly deleted.
          </span>
        </label>
      </div>

      <label className="field">
        <span className="field__label">Justification</span>
        <textarea
          className="field__input"
          rows={3}
          value={justification}
          aria-label="Justification"
          onChange={(event) => setJustification(event.target.value)}
        />
        <span className="field__help">
          Written for whoever reviews this at expiry, who will not remember the context.
        </span>
      </label>

      <div className="toolbar">
        <button
          className="button button--small"
          disabled={
            !checkId || !justification.trim() || !expiresAt || !targetChosen || create.isPending
          }
          onClick={() => create.mutate()}
        >
          File the exception
        </button>
      </div>
    </section>
  );
}

// ─────────────────────────────── page ────────────────────────────────────────

export function ExceptionsPage() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [activeOnly, setActiveOnly] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const canWrite = can('exception:write');

  const exceptions = useQuery({
    queryKey: ['exceptions', activeOnly],
    queryFn: () => api.get<Exception[]>(`/exceptions?active_only=${activeOnly}`),
  });

  const checks = useQuery({
    queryKey: ['checks', '', ''],
    queryFn: () => api.get<CheckSummary[]>('/checks'),
  });

  const devices = useQuery({
    queryKey: ['exception-devices'],
    queryFn: () => api.get<Paginated<Device>>('/devices?limit=200'),
  });

  const groups = useQuery({
    queryKey: ['exception-groups'],
    queryFn: () => api.get<DeviceGroup[]>('/device-groups'),
  });

  const refresh = () => {
    setError(null);
    void queryClient.invalidateQueries({ queryKey: ['exceptions'] });
  };

  const revoke = useMutation({
    mutationFn: (id: string) => api.delete<Exception>(`/exceptions/${id}`),
    onSuccess: refresh,
    onError: (err) => setError(message(err, 'The exception could not be revoked.')),
  });

  const rows = exceptions.data ?? [];
  const checkRows = checks.data ?? [];
  const deviceRows = devices.data?.data ?? [];
  const groupRows = groups.data ?? [];

  const checkTitle = (id: string) => checkRows.find((c) => c.id === id)?.title ?? id;
  const target = (row: Exception) => {
    if (row.scope === 'global') return 'the whole estate';
    if (row.device_id) {
      const device = deviceRows.find((d) => d.id === row.device_id);
      return device ? (device.hostname ?? device.mgmt_ip) : row.device_id.slice(0, 8);
    }
    if (row.device_group_id) {
      const group = groupRows.find((g) => g.id === row.device_group_id);
      return `${group?.name ?? row.device_group_id.slice(0, 8)} (group)`;
    }
    return '—';
  };

  return (
    <div className="page">
      <header className="page__header">
        <h1>Exceptions</h1>
        <p className="page__subtitle">
          Risks this organisation has accepted on purpose — what, where, who agreed, and until when.
        </p>
      </header>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      <div className="toolbar">
        <label className="toolbar__check">
          <input
            type="checkbox"
            checked={activeOnly}
            aria-label="Only exceptions in force"
            onChange={(event) => setActiveOnly(event.target.checked)}
          />
          Only ones in force
        </label>
      </div>

      {exceptions.isLoading ? (
        <p className="page-loading">Loading…</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Check</th>
                <th>Applies to</th>
                <th>Justification</th>
                <th>Approver</th>
                <th>Expires</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const remaining = daysUntil(row.expires_at);
                const live = row.status === 'active' && remaining > 0;
                return (
                  <tr key={row.id} className={live ? undefined : 'row--muted'}>
                    <td>
                      {checkTitle(row.check_id)}
                      <div className="mono muted">{row.check_id}</div>
                    </td>
                    <td>
                      {target(row)}
                      {row.scope === 'global' && <span className="pill pill--high">global</span>}
                    </td>
                    <td>{row.justification}</td>
                    <td>
                      {row.approver ?? (
                        // The field is optional on the API and the whole value of the
                        // register is that somebody's name is against the decision.
                        <span className="pill pill--unknown">nobody named</span>
                      )}
                    </td>
                    <td className="mono">
                      {new Date(row.expires_at).toLocaleDateString()}
                      {live ? (
                        <div className={remaining <= 14 ? 'pill pill--medium' : 'muted'}>
                          {remaining} day{remaining === 1 ? '' : 's'} left
                        </div>
                      ) : (
                        <div className="muted">
                          {row.status === 'active' ? 'lapsed' : row.status}
                        </div>
                      )}
                    </td>
                    <td className="table__actions">
                      {canWrite && live && (
                        <button
                          className="button button--ghost button--small"
                          disabled={revoke.isPending}
                          onClick={() => revoke.mutate(row.id)}
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="table__empty">
                    {activeOnly
                      ? 'No exception is in force. Every finding you see is one nobody has accepted.'
                      : 'No exception has ever been filed.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {canWrite && (
        <FileException
          checks={checkRows}
          devices={deviceRows}
          groups={groupRows}
          onFiled={refresh}
        />
      )}
    </div>
  );
}
