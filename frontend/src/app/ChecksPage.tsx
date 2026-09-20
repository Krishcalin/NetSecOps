/** The check library, and the two ways to ask it a question (FR-CHK-04, FR-CHK-06).
 *
 * A hundred and three checks shipped and none of them were visible. That is worse than it
 * sounds: a check library nobody can read is a set of assertions about your estate that
 * you are asked to trust without seeing, and the first question anybody asks about a
 * failed finding — "what exactly did it look at?" — had no answer short of the source
 * tree.
 *
 * Three panels, and the order is the order somebody works in:
 *
 * **Browse** the library, filtered the way an operator narrows it: by platform, because a
 * check that does not apply to your kit is noise; by framework, because that is how an
 * audit asks; by tag and free text for everything else.
 *
 * **Ask** where an expression holds, across the estate. This is the question being asked
 * while working out what a check should say, and the same JMESPath the library is written
 * in — so a query that finds the devices you care about is a predicate you can paste into
 * a check.
 *
 * **Draft** a check and see its verdict before it exists. The preview writes nothing at
 * all: no check, no result row, no finding, no risk score.
 *
 * One limitation, stated because it will be noticed: the library's detail view shows a
 * check's expression but not its whole definition — `GET /checks/{id}` does not return
 * `applicability` or the assertion — so a shipped check cannot be copied here as a
 * starting point for a custom one. The draft editor seeds a template instead.
 */

import { useMemo, useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';

import { ApiError, api } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import type {
  AssessmentPreview,
  CheckDetail,
  CheckSummary,
  EstateQueryResponse,
} from '../features/checks/types';
import { SEVERITY_ORDER, OUTCOME_LABELS } from '../features/checks/types';
import type { Device, Paginated } from '../features/inventory/types';

/** Seeded into the draft editor. Deliberately a complete, runnable check rather than an
 *  empty object: the fastest way to learn the shape is to run one and change it. */
const TEMPLATE = `{
  "id": "custom-ssh-version-2",
  "title": "SSH is restricted to protocol version 2",
  "description": "The device does not accept SSH version 1.",
  "rationale": "Why this matters, in a sentence an operator can act on.",
  "severity": "high",
  "applicability": { "vendors": ["cisco"] },
  "logic": {
    "type": "ncm",
    "expression": "management.ssh.version",
    "assert": { "equals": 2 },
    "missing": "not_evaluated"
  },
  "remediation": "ip ssh version 2",
  "references": { "nist_800_53": ["AC-17"] },
  "tags": ["custom", "ssh"]
}`;

function message(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.problem.detail : fallback;
}

function OutcomePill({ preview }: { preview: AssessmentPreview }) {
  return (
    <div className="alert" role="status">
      <strong>
        {OUTCOME_LABELS[preview.outcome]} — {preview.severity}
      </strong>
      <div>{preview.message}</div>
      {preview.reason && <div className="muted">{preview.reason}</div>}
      <p className="field__help">
        Nothing was written. No result row, no finding, no change to any risk score.
      </p>
    </div>
  );
}

// ────────────────────────────── the library ──────────────────────────────────

function CheckDetailPanel({ checkId, devices }: { checkId: string; devices: Device[] }) {
  const [deviceId, setDeviceId] = useState('');
  const [preview, setPreview] = useState<AssessmentPreview | null>(null);
  const [error, setError] = useState<string | null>(null);

  const detail = useQuery({
    queryKey: ['check', checkId],
    queryFn: () => api.get<CheckDetail>(`/checks/${encodeURIComponent(checkId)}`),
  });

  const run = useMutation({
    mutationFn: () =>
      api.post<AssessmentPreview>(
        `/checks/${encodeURIComponent(checkId)}/preview?device_id=${deviceId}`,
      ),
    onSuccess: (result) => {
      setError(null);
      setPreview(result);
    },
    onError: (err) => {
      setPreview(null);
      setError(message(err, 'The check could not be run.'));
    },
  });

  if (detail.isLoading) {
    return <p className="page-loading">Loading…</p>;
  }
  if (!detail.data) {
    return <p className="empty">That check could not be loaded.</p>;
  }

  const check = detail.data;

  return (
    <div className="stack">
      <p>{check.description}</p>

      <h3 className="finding__heading">Why it matters</h3>
      <p>{check.rationale}</p>

      <h3 className="finding__heading">How to fix it</h3>
      <p>{check.remediation}</p>

      {check.expression && (
        <>
          <h3 className="finding__heading">What it looks at</h3>
          {/* Shown because "what exactly did this check inspect" is the first question
              asked about a finding, and the answer used to live only in the source. */}
          <p className="mono secret-block">{check.expression}</p>
        </>
      )}

      {Object.keys(check.frameworks).length > 0 && (
        <>
          <h3 className="finding__heading">Maps to</h3>
          <ul className="device-list">
            {Object.entries(check.frameworks).map(([framework, controls]) => (
              <li key={framework}>
                <span className="mono">{framework}</span> — {controls.join(', ')}
              </li>
            ))}
          </ul>
        </>
      )}

      <h3 className="finding__heading">Try it against a device</h3>
      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}
      <div className="toolbar">
        <select
          className="field__input field__input--small"
          value={deviceId}
          aria-label="Device to check"
          onChange={(event) => setDeviceId(event.target.value)}
        >
          <option value="">Choose a device…</option>
          {devices.map((device) => (
            <option key={device.id} value={device.id}>
              {device.hostname ?? device.mgmt_ip}
            </option>
          ))}
        </select>
        <button
          className="button button--ghost button--small"
          disabled={!deviceId || run.isPending}
          onClick={() => run.mutate()}
        >
          Run it
        </button>
      </div>
      {preview && <OutcomePill preview={preview} />}
    </div>
  );
}

function CheckLibrary({ devices }: { devices: Device[] }) {
  const [search, setSearch] = useState('');
  const [platform, setPlatform] = useState('');
  const [framework, setFramework] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);

  const checks = useQuery({
    queryKey: ['checks', platform, framework],
    queryFn: () => {
      const params = new URLSearchParams();
      if (platform) params.set('platform', platform);
      if (framework) params.set('framework', framework);
      const query = params.toString();
      return api.get<CheckSummary[]>(`/checks${query ? `?${query}` : ''}`);
    },
  });

  // Memoised only so the two `useMemo`s below have a stable dependency — `?? []` would
  // hand them a new array on every render and recompute both each time.
  const rows = useMemo(() => checks.data ?? [], [checks.data]);

  // Derived from what came back rather than fetched: the set of frameworks that matter is
  // the set the loaded checks actually map to, and an option that filters to nothing is
  // worse than no option.
  const frameworks = useMemo(
    () => [...new Set(rows.flatMap((check) => Object.keys(check.frameworks)))].sort(),
    [rows],
  );
  const platforms = useMemo(
    () => [...new Set(rows.flatMap((check) => check.platforms))].sort(),
    [rows],
  );

  const needle = search.trim().toLowerCase();
  const visible = needle
    ? rows.filter(
        (check) =>
          check.id.toLowerCase().includes(needle) ||
          check.title.toLowerCase().includes(needle) ||
          check.tags.some((tag) => tag.toLowerCase().includes(needle)),
      )
    : rows;

  const bySeverity = [...visible].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">The library</h2>
      </div>

      <div className="toolbar">
        <input
          className="field__input field__input--small"
          value={search}
          aria-label="Search checks"
          placeholder="Search by id, title or tag"
          onChange={(event) => setSearch(event.target.value)}
        />
        <select
          className="field__input field__input--small"
          value={platform}
          aria-label="Platform"
          onChange={(event) => setPlatform(event.target.value)}
        >
          <option value="">Every platform</option>
          {platforms.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
        <select
          className="field__input field__input--small"
          value={framework}
          aria-label="Framework"
          onChange={(event) => setFramework(event.target.value)}
        >
          <option value="">Every framework</option>
          {frameworks.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
        <span className="muted">
          {bySeverity.length} of {rows.length}
        </span>
      </div>

      {checks.isLoading ? (
        <p className="page-loading">Loading…</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Check</th>
                <th>Severity</th>
                <th>Applies to</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {bySeverity.map((check) => (
                <tr key={check.id}>
                  <td>
                    {check.title}
                    <div className="mono muted">{check.id}</div>
                    {check.is_custom && <span className="pill">custom</span>}
                    {!check.enabled_by_default && (
                      // A check off by default is in the library and not in any
                      // assessment unless a policy turns it on, which is not visible
                      // anywhere else.
                      <span className="pill pill--unknown">off by default</span>
                    )}
                  </td>
                  <td>
                    <span className={`pill pill--${check.severity}`}>{check.severity}</span>
                  </td>
                  <td className="muted">
                    {check.platforms.length > 0
                      ? check.platforms.join(', ')
                      : check.vendors.length > 0
                        ? check.vendors.join(', ')
                        : 'any device'}
                  </td>
                  <td className="table__actions">
                    <button
                      className="button button--ghost button--small"
                      onClick={() => setExpanded(expanded === check.id ? null : check.id)}
                    >
                      {expanded === check.id ? 'Hide' : 'Details'}
                    </button>
                  </td>
                </tr>
              ))}
              {bySeverity.length === 0 && (
                <tr>
                  <td colSpan={4} className="table__empty">
                    No check matches those filters.
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
            <h2 className="card__title">{rows.find((c) => c.id === expanded)?.title}</h2>
          </div>
          <CheckDetailPanel key={expanded} checkId={expanded} devices={devices} />
        </section>
      )}
    </section>
  );
}

// ──────────────────────────── estate query ───────────────────────────────────

function EstateQuery() {
  const [expression, setExpression] = useState('');
  const [matchingOnly, setMatchingOnly] = useState(false);
  const [result, setResult] = useState<EstateQueryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = useMutation({
    mutationFn: () =>
      api.post<EstateQueryResponse>('/checks/query', {
        expression: expression.trim(),
        matching_only: matchingOnly,
      }),
    onSuccess: (response) => {
      setError(null);
      setResult(response);
    },
    onError: (err) => {
      setResult(null);
      setError(message(err, 'The query could not be run.'));
    },
  });

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">Ask the estate</h2>
      </div>
      <p className="field__help">
        One JMESPath expression, run against every device's latest configuration. The same language
        the library is written in, so anything that selects here can be pasted into a check.
      </p>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      <label className="field">
        <span className="field__label">Expression</span>
        <input
          className="field__input mono"
          value={expression}
          aria-label="Expression"
          placeholder="management.ssh.version"
          onChange={(event) => setExpression(event.target.value)}
        />
      </label>

      <div className="toolbar">
        <label className="toolbar__check">
          <input
            type="checkbox"
            checked={matchingOnly}
            aria-label="Only devices that selected something"
            onChange={(event) => setMatchingOnly(event.target.checked)}
          />
          Only devices that selected something
        </label>
        <button
          className="button button--small"
          disabled={!expression.trim() || run.isPending}
          onClick={() => run.mutate()}
        >
          Run query
        </button>
      </div>

      {result && (
        <>
          <p className="field__help">
            {result.devices_considered} device{result.devices_considered === 1 ? '' : 's'}{' '}
            considered
            {result.devices_not_evaluated > 0 && (
              // Said plainly, because the alternative reading of a short result list is
              // "nothing in my estate does this".
              <strong>
                {' '}
                · {result.devices_not_evaluated} could not be asked, so this is not a statement
                about them
              </strong>
            )}
          </p>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Platform</th>
                  <th>Selected</th>
                </tr>
              </thead>
              <tbody>
                {result.rows.map((row) => (
                  <tr key={row.device_id} className={row.not_evaluated ? 'row--muted' : undefined}>
                    <td>{row.hostname ?? row.device_id.slice(0, 8)}</td>
                    <td className="mono">{row.platform ?? '—'}</td>
                    <td className="mono">
                      {row.not_evaluated ? (
                        <span className="muted">{row.not_evaluated}</span>
                      ) : (
                        JSON.stringify(row.value)
                      )}
                    </td>
                  </tr>
                ))}
                {result.rows.length === 0 && (
                  <tr>
                    <td colSpan={3} className="table__empty">
                      Nothing selected on any device that could be asked.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}

// ──────────────────────────── drafting a check ───────────────────────────────

function DraftCheck({ devices }: { devices: Device[] }) {
  const [definition, setDefinition] = useState(TEMPLATE);
  const [deviceId, setDeviceId] = useState('');
  const [preview, setPreview] = useState<AssessmentPreview | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function parse(): Record<string, unknown> | null {
    try {
      return JSON.parse(definition) as Record<string, unknown>;
    } catch (err) {
      setPreview(null);
      setError(
        // A parse error is the author's typo, not the server's opinion, and saying so
        // saves a round trip that would come back as a less specific message.
        `That is not valid JSON, so it was not sent: ${err instanceof Error ? err.message : err}`,
      );
      return null;
    }
  }

  const run = useMutation({
    mutationFn: (parsed: Record<string, unknown>) =>
      api.post<AssessmentPreview>('/checks/preview', {
        definition: parsed,
        device_id: deviceId,
      }),
    onSuccess: (result) => {
      setError(null);
      setPreview(result);
    },
    onError: (err) => {
      setPreview(null);
      setError(message(err, 'The draft could not be run.'));
    },
  });

  const save = useMutation({
    mutationFn: (parsed: Record<string, unknown>) =>
      api.post<{ check_id: string }>('/checks', { definition: parsed }),
    onSuccess: (result) => {
      setError(null);
      setSaved(result.check_id);
    },
    onError: (err) => {
      setSaved(null);
      setError(message(err, 'The check could not be saved.'));
    },
  });

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">Draft a check</h2>
      </div>
      <p className="field__help">
        Run it before it exists. The preview writes nothing — no check, no finding, no risk score —
        so a definition can be tuned without leaving half-finished checks in the library.
      </p>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}
      {saved && (
        <div className="alert alert--ok" role="status">
          Saved as <span className="mono">{saved}</span>. It is in the library, and runs when a
          policy includes it.
        </div>
      )}

      <label className="field">
        <span className="field__label">Definition</span>
        <textarea
          className="field__input mono"
          rows={18}
          value={definition}
          aria-label="Definition"
          spellCheck={false}
          onChange={(event) => {
            setDefinition(event.target.value);
            setSaved(null);
          }}
        />
      </label>

      <div className="toolbar">
        <select
          className="field__input field__input--small"
          value={deviceId}
          aria-label="Device to draft against"
          onChange={(event) => setDeviceId(event.target.value)}
        >
          <option value="">Choose a device…</option>
          {devices.map((device) => (
            <option key={device.id} value={device.id}>
              {device.hostname ?? device.mgmt_ip}
            </option>
          ))}
        </select>
        <button
          className="button button--small"
          disabled={!deviceId || run.isPending}
          onClick={() => {
            const parsed = parse();
            if (parsed) run.mutate(parsed);
          }}
        >
          Preview
        </button>
        <button
          className="button button--ghost button--small"
          disabled={save.isPending}
          onClick={() => {
            const parsed = parse();
            if (parsed) save.mutate(parsed);
          }}
        >
          Save to the library
        </button>
      </div>

      {preview && <OutcomePill preview={preview} />}
    </section>
  );
}

// ─────────────────────────────── page ────────────────────────────────────────

export function ChecksPage() {
  const { can } = useAuth();

  const devices = useQuery({
    queryKey: ['check-devices'],
    queryFn: () => api.get<Paginated<Device>>('/devices?limit=200'),
  });

  const deviceRows = devices.data?.data ?? [];

  return (
    <div className="page">
      <header className="page__header">
        <h1>Checks</h1>
        <p className="page__subtitle">
          What NetSecOps asserts about a configuration, what it looks at to decide, and how to add
          one of your own.
        </p>
      </header>

      <CheckLibrary devices={deviceRows} />
      <EstateQuery />
      {can('check:write') && <DraftCheck devices={deviceRows} />}
    </div>
  );
}
