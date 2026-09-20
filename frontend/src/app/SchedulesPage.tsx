/** Recurring assessments (FR-JOB-02).
 *
 * The scheduler process ships, runs, and had nothing that could create work for it. Every
 * assessment in a NetSecOps installation was therefore something a person remembered to
 * start — which is the difference between a tool that watches an estate and one that
 * answers questions about it when asked.
 *
 * **`next_run_at` is the point of the list, not a detail on it.** A cron expression is the
 * easiest thing on this page to get wrong and the hardest to notice: `0 2 * * 0` and
 * `0 2 * * *` differ by one character and by a factor of seven, and nothing downstream
 * complains. The server computes the next run before storing the row, so the list can say
 * what the expression actually means rather than echoing it back.
 *
 * **Creating one is behind `job:execute`, not a lesser permission**, which is the
 * server's rule and this page follows it rather than softening it: a schedule is a
 * standing instruction to touch the estate, and somebody who may not run a job once
 * should not be able to arrange for one to run every night.
 */

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { ApiError, api } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import type { DeviceGroup } from '../features/inventory/types';

/** Mirrors `JobType`. Only the types that make sense as standing work are offered —
 *  `credential_test` and `vuln_rematch` are things somebody does deliberately, once. */
const JOB_TYPES = [
  { value: 'collect_and_assess', label: 'Collect and assess' },
  { value: 'collect', label: 'Collect configuration only' },
  { value: 'assess_only', label: 'Assess the stored configuration' },
  { value: 'discovery', label: 'Discovery sweep' },
  { value: 'feed_sync', label: 'Vulnerability feed sync' },
  { value: 'report', label: 'Generate a report' },
];

/** Common expressions, offered as a starting point. Cron is the API's contract, so the
 *  field stays free text — this is a shortcut, not a wrapper that hides it. */
const CRON_PRESETS = [
  { cron: '0 2 * * *', label: 'Every night at 02:00' },
  { cron: '0 2 * * 0', label: 'Weekly, Sunday at 02:00' },
  { cron: '0 3 1 * *', label: 'Monthly, the 1st at 03:00' },
  { cron: '0 */6 * * *', label: 'Every six hours' },
];

interface Schedule {
  id: string;
  name: string;
  description: string | null;
  job_type: string;
  scope: Record<string, unknown>;
  cron: string;
  timezone: string;
  enabled: boolean;
  blackout: Record<string, unknown> | null;
  next_run_at: string | null;
  last_run_at: string | null;
  last_job_id: string | null;
  created_at: string;
}

function message(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.problem.detail : fallback;
}

// ─────────────────────────────── create ──────────────────────────────────────

function CreateSchedule({ groups, onCreated }: { groups: DeviceGroup[]; onCreated: () => void }) {
  const [name, setName] = useState('');
  const [jobType, setJobType] = useState(JOB_TYPES[0]!.value);
  const [cron, setCron] = useState('0 2 * * *');
  const [timezone, setTimezone] = useState(
    // The browser's zone, because a schedule written at a desk means local time to the
    // person writing it. UTC as the fallback matches the API's default.
    Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
  );
  const [groupIds, setGroupIds] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () =>
      api.post<Schedule>('/schedules', {
        name: name.trim(),
        job_type: jobType,
        cron: cron.trim(),
        timezone,
        scope: { device_ids: [], group_ids: groupIds, tags: [], include_archived: false },
      }),
    onSuccess: () => {
      setError(null);
      setName('');
      setGroupIds([]);
      onCreated();
    },
    onError: (err) => setError(message(err, 'The schedule could not be created.')),
  });

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">Schedule an assessment</h2>
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
            aria-label="Schedule name"
            onChange={(event) => setName(event.target.value)}
          />
        </label>
        <label className="field">
          <span className="field__label">What it runs</span>
          <select
            className="field__input"
            value={jobType}
            aria-label="Job type"
            onChange={(event) => setJobType(event.target.value)}
          >
            {JOB_TYPES.map((type) => (
              <option key={type.value} value={type.value}>
                {type.label}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span className="field__label">Cron</span>
          <input
            className="field__input mono"
            value={cron}
            aria-label="Cron expression"
            onChange={(event) => setCron(event.target.value)}
          />
          <span className="field__help">
            Five fields: minute, hour, day of month, month, day of week.
          </span>
        </label>
        <label className="field">
          <span className="field__label">Timezone</span>
          <input
            className="field__input"
            value={timezone}
            aria-label="Timezone"
            onChange={(event) => setTimezone(event.target.value)}
          />
          <span className="field__help">
            An IANA name. It decides what "02:00" means across a daylight-saving change.
          </span>
        </label>
      </div>

      <div className="toolbar">
        {CRON_PRESETS.map((preset) => (
          <button
            key={preset.cron}
            className="button button--ghost button--small"
            onClick={() => setCron(preset.cron)}
          >
            {preset.label}
          </button>
        ))}
      </div>

      <fieldset className="field">
        <legend className="field__label">Which devices</legend>
        {groups.length === 0 ? (
          <p className="field__help">
            No Device Groups exist yet. Leave this empty and the schedule covers the whole estate.
          </p>
        ) : (
          <div className="checkbox-grid">
            {groups.map((group) => (
              <label className="checkbox" key={group.id}>
                <input
                  type="checkbox"
                  checked={groupIds.includes(group.id)}
                  aria-label={group.name}
                  onChange={() =>
                    setGroupIds(
                      groupIds.includes(group.id)
                        ? groupIds.filter((id) => id !== group.id)
                        : [...groupIds, group.id],
                    )
                  }
                />
                <span>{group.name}</span>
              </label>
            ))}
          </div>
        )}
        {groupIds.length === 0 && groups.length > 0 && (
          // An empty scope is the widest one, and it does not look like it.
          <span className="field__help">
            No group selected, so this runs against every device in the estate.
          </span>
        )}
      </fieldset>

      <div className="toolbar">
        <button
          className="button button--small"
          disabled={!name.trim() || !cron.trim() || create.isPending}
          onClick={() => create.mutate()}
        >
          Create schedule
        </button>
      </div>
    </section>
  );
}

// ─────────────────────────────── page ────────────────────────────────────────

export function SchedulesPage() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canWrite = can('job:execute');

  const schedules = useQuery({
    queryKey: ['schedules'],
    queryFn: () => api.get<Schedule[]>('/schedules'),
  });

  const groups = useQuery({
    queryKey: ['schedule-groups'],
    queryFn: () => api.get<DeviceGroup[]>('/device-groups'),
  });

  const refresh = () => {
    setError(null);
    void queryClient.invalidateQueries({ queryKey: ['schedules'] });
  };

  const setEnabled = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.patch<Schedule>(`/schedules/${id}`, { enabled }),
    onSuccess: refresh,
    onError: (err) => setError(message(err, 'The schedule could not be changed.')),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.delete<void>(`/schedules/${id}`),
    onSuccess: () => {
      setConfirmDelete(null);
      refresh();
    },
    onError: (err) => setError(message(err, 'The schedule could not be removed.')),
  });

  const rows = schedules.data ?? [];
  const groupRows = groups.data ?? [];
  const groupName = (id: string) => groupRows.find((g) => g.id === id)?.name ?? id.slice(0, 8);

  const scopeOf = (schedule: Schedule) => {
    const ids = (schedule.scope.group_ids as string[] | undefined) ?? [];
    const tags = (schedule.scope.tags as string[] | undefined) ?? [];
    const devices = (schedule.scope.device_ids as string[] | undefined) ?? [];
    if (ids.length) return ids.map(groupName).join(', ');
    if (tags.length) return tags.join(', ');
    if (devices.length) return `${devices.length} device${devices.length === 1 ? '' : 's'}`;
    return 'the whole estate';
  };

  return (
    <div className="page">
      <header className="page__header">
        <h1>Schedules</h1>
        <p className="page__subtitle">
          Work that runs unattended. Without one, every assessment is something somebody remembered
          to start.
        </p>
      </header>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      {schedules.isLoading ? (
        <p className="page-loading">Loading…</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Schedule</th>
                <th>Runs</th>
                <th>Covers</th>
                <th>Next run</th>
                <th>Last run</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((schedule) => (
                <tr key={schedule.id} className={schedule.enabled ? undefined : 'row--muted'}>
                  <td>
                    {schedule.name}
                    {!schedule.enabled && <span className="pill pill--failure">paused</span>}
                    {schedule.description && <div className="muted">{schedule.description}</div>}
                  </td>
                  <td className="mono">
                    {schedule.job_type}
                    <div className="muted">
                      {schedule.cron} {schedule.timezone}
                    </div>
                  </td>
                  <td>{scopeOf(schedule)}</td>
                  <td className="mono">
                    {/* The server computes this from the expression before storing it, and
                        it is the only way to catch a cron that means something other than
                        what was intended. */}
                    {schedule.enabled ? (
                      schedule.next_run_at ? (
                        new Date(schedule.next_run_at).toLocaleString()
                      ) : (
                        <span className="pill pill--unknown">never — check the expression</span>
                      )
                    ) : (
                      <span className="muted">paused</span>
                    )}
                  </td>
                  <td className="mono">
                    {schedule.last_run_at
                      ? new Date(schedule.last_run_at).toLocaleString()
                      : 'never run'}
                  </td>
                  <td className="table__actions">
                    {canWrite && (
                      <>
                        <button
                          className="button button--ghost button--small"
                          disabled={setEnabled.isPending}
                          onClick={() =>
                            setEnabled.mutate({ id: schedule.id, enabled: !schedule.enabled })
                          }
                        >
                          {schedule.enabled ? 'Pause' : 'Resume'}
                        </button>
                        {confirmDelete === schedule.id ? (
                          <>
                            <button
                              className="button button--ghost button--small"
                              disabled={remove.isPending}
                              onClick={() => remove.mutate(schedule.id)}
                            >
                              Yes, remove
                            </button>
                            <button
                              className="button button--ghost button--small"
                              onClick={() => setConfirmDelete(null)}
                            >
                              Cancel
                            </button>
                          </>
                        ) : (
                          <button
                            className="button button--ghost button--small"
                            onClick={() => setConfirmDelete(schedule.id)}
                          >
                            Remove
                          </button>
                        )}
                      </>
                    )}
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="table__empty">
                    Nothing is scheduled. Every assessment has to be started by hand.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {canWrite && <CreateSchedule groups={groupRows} onCreated={refresh} />}
    </div>
  );
}
