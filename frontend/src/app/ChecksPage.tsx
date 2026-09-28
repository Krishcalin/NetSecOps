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
import { Modal } from '../components/Modal';
import { PageHeader } from '../components/PageHeader';

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

/** A golden-config template (FR-DRIFT-04), the second shape a definition can take.
 *
 *  It is offered here because it cannot be offered anywhere else: an expression check
 *  asks one question of the parsed configuration and ships in the library, whereas a
 *  golden template says what *your* build looks like, so no library can contain one and
 *  this editor is the only way anybody gets one. Left undiscoverable it is a feature that
 *  exists in the schema and never in an estate. */
const GOLDEN_TEMPLATE = `{
  "id": "custom-access-switch-build",
  "title": "Access switches match the standard build",
  "description": "The agreed configuration for an access switch.",
  "rationale": "A device that has drifted from the standard build is one nobody owns.",
  "severity": "medium",
  "applicability": { "platforms": ["cisco_ios"] },
  "logic": {
    "type": "golden",
    "blocks": [
      { "name": "AAA", "lines": ["aaa new-model"] },
      {
        "name": "VTY hardening",
        "lines": ["exec-timeout 5 0", "transport input ssh"],
        "contiguous": true
      },
      { "name": "No telnet", "expect": "absent", "lines": ["transport input telnet"] }
    ],
    "missing": "not_evaluated"
  },
  "remediation": "Bring the configuration back in line with the standard build.",
  "references": { "nist_800_53": ["CM-2", "CM-6"] },
  "tags": ["custom", "golden"]
}`;

const STARTING_POINTS = [
  { id: 'expression', label: 'Expression check', body: TEMPLATE },
  { id: 'golden', label: 'Golden config', body: GOLDEN_TEMPLATE },
] as const;

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
      <p className="finding__prose">{check.description}</p>

      {/* Side by side where there is room, for the same reason the finding panel's
          are: stacked, each paragraph used about half the width of the card and left
          the rest of the row empty. */}
      <div className="finding__explain">
        <section className="finding__section">
          <h3 className="finding__heading">Why it matters</h3>
          <p className="finding__prose">{check.rationale}</p>
        </section>

        <section className="finding__section">
          <h3 className="finding__heading">How to fix it</h3>
          <p className="finding__prose">{check.remediation}</p>
        </section>
      </div>

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
  // `expanded` is the id, not the row: the dialog outlives a filter change that would
  // drop the row from `rows`, and holding the object would leave it rendering a check
  // the table no longer lists.

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
                      // No longer a toggle. The detail opens over the table instead of
                      // below it, so there is nothing left on screen for a second press
                      // to hide — the dialog's own Close is the way out, and a button
                      // that says "Hide" while a dialog covers it names the wrong
                      // control.
                      onClick={() => setExpanded(check.id)}
                      aria-haspopup="dialog"
                    >
                      Details
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

      {/* Over the table rather than under it.

          The detail used to render as a card below a list that is hundreds of rows
          long, so pressing Details on a row near the bottom appended a panel further
          down still — off screen, with nothing to say it had opened. A dialog puts the
          answer where the question was asked.

          `wide`, because this panel is a table of devices and their results. The
          default measure is capped for prose and would squeeze those columns into the
          truncation the dialog exists to escape. */}
      {expanded && (
        <Modal
          label={rows.find((c) => c.id === expanded)?.title ?? 'Check detail'}
          size="wide"
          onClose={() => setExpanded(null)}
        >
          <CheckHeading check={rows.find((c) => c.id === expanded)} />
          <CheckDetailPanel key={expanded} checkId={expanded} devices={devices} />
        </Modal>
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
        <span className="field__label">Start from</span>
        <select
          className="field__input field__input--small"
          value=""
          aria-label="Start from"
          onChange={(event) => {
            const chosen = STARTING_POINTS.find((point) => point.id === event.target.value);
            if (!chosen) return;
            setDefinition(chosen.body);
            setSaved(null);
            setPreview(null);
          }}
        >
          <option value="">Keep what is in the editor</option>
          {STARTING_POINTS.map((point) => (
            <option key={point.id} value={point.id}>
              {point.label}
            </option>
          ))}
        </select>
        <span className="field__help">
          An expression check asks one question of the parsed configuration. A golden config
          compares the device against blocks of lines that must be present or absent — the shape to
          use for a build standard, which no shipped check can express. Choosing one replaces
          everything in the editor.
        </span>
      </label>

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

/** What the row said, repeated inside the dialog that covers it.
 *
 * The dialog sits over the table, so without this the reader has the check's results
 * and not the check — its id, how bad it is, and what it applies to are all on the row
 * now hidden behind the panel.
 *
 * Deliberately *not* the description, rationale or remediation: `CheckDetailPanel`
 * already renders all three, and a heading that repeated the description put the same
 * sentence on screen twice.
 */
function CheckHeading({ check }: { check: CheckSummary | undefined }) {
  if (!check) return null;

  const appliesTo =
    check.platforms.length > 0
      ? check.platforms.join(', ')
      : check.vendors.length > 0
        ? check.vendors.join(', ')
        : 'any device';

  const frameworks = Object.entries(check.frameworks).filter(([, ids]) => ids.length > 0);

  return (
    <header className="dialog__head">
      <h2 className="dialog__title">{check.title}</h2>
      <p className="dialog__sub">
        <span className="mono">{check.id}</span> · <span>{check.severity}</span> · applies to{' '}
        {appliesTo}
      </p>
      {frameworks.length > 0 && (
        <p className="dialog__sub">
          {/* The mapping is the reason a check exists on a lot of estates, and it was
              reachable only from the compliance page. */}
          {frameworks.map(([framework, ids]) => (
            <span key={framework} className="pill">
              {framework}: {ids.join(', ')}
            </span>
          ))}
        </p>
      )}
    </header>
  );
}

export function ChecksPage() {
  const { can } = useAuth();

  const devices = useQuery({
    queryKey: ['check-devices'],
    queryFn: () => api.get<Paginated<Device>>('/devices?limit=200'),
  });

  const deviceRows = devices.data?.data ?? [];

  return (
    <div className="page">
      <PageHeader
        icon="check"
        title="Checks"
        subtitle="What NetSecOps asserts about a configuration, what it looks at to decide, and how to add one of your own."
      />

      <CheckLibrary devices={deviceRows} />
      <EstateQuery />
      {can('check:write') && <DraftCheck devices={deviceRows} />}
    </div>
  );
}
