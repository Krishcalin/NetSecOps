/** Firewall analysis: the rulebase viewer, filters, rule query and export (FR-FW-06, FR-FW-07).
 *
 * The summary leads, because "what is wrong with this rulebase" is the question the
 * page exists to answer, and the counts are over the whole rulebase even when the table
 * below is filtered — a filtered count would make the problem look smaller than it is
 * precisely when someone narrows the view to work on it.
 */

import { useEffect, useMemo, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';

import { api, ApiError, request } from '../api/client';
import { EstateRules } from '../features/firewall/EstateRules';
import { RulebaseViewer } from '../features/firewall/RulebaseViewer';
import { issueLabel } from '../features/firewall/types';
import type {
  EstateRules as EstateRulesPayload,
  Rulebase,
  RuleQueryResponse,
} from '../features/firewall/types';
import type { DeviceDetail, Paginated } from '../features/inventory/types';

interface Filters {
  search: string;
  action: string;
  zone: string;
  issue: string;
  include_disabled: boolean;
  with_issues_only: boolean;
}

const EMPTY: Filters = {
  search: '',
  action: '',
  zone: '',
  issue: '',
  include_disabled: true,
  with_issues_only: false,
};

/** Issues worth offering as estate-wide starting points.
 *
 * A fixed list rather than one derived from a loaded rulebase: on the estate view no
 * single rulebase is in hand to derive it from, and an empty dropdown would make the
 * feature look broken before the first query. */
const ESTATE_ISSUES = [
  'any_any_any',
  'no_logging',
  'no_profiles',
  'inspection_not_decrypted',
  'shadowed',
  'never_hit',
  'insecure_service',
] as const;

function toQuery(filters: Filters): string {
  const params = new URLSearchParams();
  if (filters.search) params.set('search', filters.search);
  if (filters.action) params.set('action', filters.action);
  if (filters.zone) params.set('zone', filters.zone);
  if (filters.issue) params.set('issue', filters.issue);
  if (!filters.include_disabled) params.set('include_disabled', 'false');
  if (filters.with_issues_only) params.set('with_issues_only', 'true');
  const text = params.toString();
  return text ? `?${text}` : '';
}

function Summary({ rulebase }: { rulebase: Rulebase }) {
  const { summary } = rulebase;

  const headline = useMemo(() => {
    const entries = [
      ...Object.entries(summary.relationships),
      ...Object.entries(summary.policy_issues),
      ...Object.entries(summary.nat_issues),
    ].filter(([, count]) => count > 0);
    entries.sort((a, b) => b[1] - a[1]);
    return entries;
  }, [summary]);

  return (
    <section className="card">
      <header className="card__header">
        <h2 className="card__title">Rulebase analysis</h2>
        <span className="muted">
          {summary.rules_analysed} of {summary.rules_total} rules analysed in {summary.analysis_ms}{' '}
          ms
        </span>
      </header>

      <div className="card-grid">
        {headline.length === 0 ? (
          <p className="empty">No rule relationship or policy problem was found.</p>
        ) : (
          headline.map(([issue, count]) => (
            <div className="stat" key={issue}>
              <strong>{count.toLocaleString()}</strong>
              <span>{issueLabel(issue)}</span>
            </div>
          ))
        )}
      </div>

      {/* Stated rather than left to the documentation: an unqualified "no shadowed
          rules" would be read as a guarantee it is not. */}
      {summary.limitations.length > 0 && (
        <details className="rulebase__limits">
          <summary>What this analysis does not cover ({summary.limitations.length})</summary>
          <ul>
            {summary.limitations.map((text) => (
              <li key={text}>{text}</li>
            ))}
          </ul>
        </details>
      )}

      {summary.truncated && (
        <p className="alert alert--warning" role="status">
          The pairwise analysis hit its cap, so not every example is listed. The counts above are
          still exact.
        </p>
      )}
    </section>
  );
}

function RuleQuery({ deviceId }: { deviceId: string }) {
  const [form, setForm] = useState({
    source: '10.0.0.10',
    destination: '10.20.0.10',
    protocol: 'tcp',
    port: 443,
  });
  const [result, setResult] = useState<RuleQueryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  const run = async (event: React.FormEvent) => {
    event.preventDefault();
    setRunning(true);
    setError(null);
    try {
      setResult(await api.post<RuleQueryResponse>(`/devices/${deviceId}/firewall/query`, form));
    } catch (caught) {
      setResult(null);
      setError(caught instanceof ApiError ? caught.problem.detail : 'The query failed.');
    } finally {
      setRunning(false);
    }
  };

  return (
    <section className="card">
      <header className="card__header">
        <h2 className="card__title">Which rule would match?</h2>
      </header>
      <p className="muted">
        Simulated against the stored configuration. Nothing is sent to the device.
      </p>

      <form className="toolbar" onSubmit={run}>
        <label className="field field--inline">
          <span className="field__label">Source</span>
          <input
            className="field__input field__input--small"
            value={form.source}
            onChange={(e) => setForm({ ...form, source: e.target.value })}
          />
        </label>
        <label className="field field--inline">
          <span className="field__label">Destination</span>
          <input
            className="field__input field__input--small"
            value={form.destination}
            onChange={(e) => setForm({ ...form, destination: e.target.value })}
          />
        </label>
        <label className="field field--inline">
          <span className="field__label">Protocol</span>
          <select
            className="field__input field__input--small"
            value={form.protocol}
            onChange={(e) => setForm({ ...form, protocol: e.target.value })}
          >
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="icmp">icmp</option>
          </select>
        </label>
        <label className="field field--inline">
          <span className="field__label">Port</span>
          <input
            className="field__input field__input--small"
            type="number"
            min={0}
            max={65535}
            value={form.port}
            onChange={(e) => setForm({ ...form, port: Number(e.target.value) })}
          />
        </label>
        <button className="button button--primary" type="submit" disabled={running}>
          {running ? 'Checking…' : 'Check'}
        </button>
      </form>

      {error && (
        <p className="alert alert--error" role="alert">
          {error}
        </p>
      )}

      {result && (
        <div className="query-result">
          {result.matched ? (
            <p>
              <strong>
                Rule #{result.matched.order} ({result.matched.name})
              </strong>{' '}
              would match, and would <strong>{result.matched.action}</strong> the traffic.
            </p>
          ) : (
            <p>
              <strong>No rule matches.</strong> The traffic would fall through to the
              platform&rsquo;s default, which differs by vendor.
            </p>
          )}

          {result.also_matched.length > 0 && (
            <p className="muted">
              {result.also_matched.length} later rule(s) would also have matched:{' '}
              {result.also_matched.map((r) => `#${r.order} ${r.name}`).join(', ')}. They never fire,
              because the rule above wins.
            </p>
          )}

          {/* Returned with every answer. A bare rule number reads as a guarantee. */}
          <ul className="rulebase__limits-inline">
            {result.limitations.map((text) => (
              <li key={text} className="muted">
                {text}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

export function FirewallPage() {
  const { deviceId: routeDeviceId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [focusOrder, setFocusOrder] = useState<number | null>(null);
  const [exporting, setExporting] = useState(false);

  const deviceId = routeDeviceId ?? searchParams.get('device') ?? '';

  // Only firewalls carry a rulebase, so the picker does not offer switches — a device
  // that can only ever answer "no rulebase" is not a useful choice.
  const devices = useQuery({
    queryKey: ['devices', 'firewalls'],
    queryFn: () => api.get<Paginated<DeviceDetail>>('/devices?limit=200&device_class=firewall'),
    enabled: !routeDeviceId,
  });

  const rulebase = useQuery({
    queryKey: ['rulebase', deviceId, filters],
    queryFn: () => api.get<Rulebase>(`/devices/${deviceId}/firewall/rulebase${toQuery(filters)}`),
    enabled: Boolean(deviceId),
  });

  // The estate question, asked only when no single device is in view. Each firewall's
  // whole rulebase is analysed to answer it, so this is not a cheap request and is not
  // issued alongside the per-device one.
  const estate = useQuery({
    queryKey: ['estate-rules', filters],
    queryFn: () => api.get<EstateRulesPayload>(`/firewall/rules${toQuery(filters)}`),
    enabled: !deviceId && !routeDeviceId,
  });

  useEffect(() => {
    setFocusOrder(null);
  }, [deviceId]);

  const exportCsv = async () => {
    setExporting(true);
    try {
      const response = await request<Response>(
        `/devices/${deviceId}/firewall/export${toQuery(filters)}`,
        { method: 'GET', parseAs: 'response' },
      );
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `rulebase-${deviceId}.csv`;
      anchor.click();
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
    }
  };

  const issueOptions = useMemo(() => {
    const summary = rulebase.data?.summary;
    if (!summary) return [];
    return Object.entries({
      ...summary.relationships,
      ...summary.policy_issues,
    })
      .filter(([, count]) => count > 0)
      .map(([issue]) => issue)
      .sort();
  }, [rulebase.data]);

  return (
    <div className="page">
      <header className="page__header">
        <h1>Firewall analysis</h1>
        <p className="page__subtitle">
          Rule relationships, policy problems and NAT exposure, shown in evaluation order.
        </p>
      </header>

      {!routeDeviceId && (
        <section className="card">
          <label className="field field--inline">
            <span className="field__label">Firewall</span>
            <select
              className="field__input"
              value={deviceId}
              onChange={(e) => setSearchParams(e.target.value ? { device: e.target.value } : {})}
            >
              <option value="">Choose a device…</option>
              {devices.data?.data.map((device) => (
                <option key={device.id} value={device.id}>
                  {device.hostname ?? device.mgmt_ip} ({device.platform ?? 'unknown platform'})
                </option>
              ))}
            </select>
          </label>
          {devices.isSuccess && devices.data.data.length === 0 && (
            <p className="empty">
              No firewalls in inventory yet. <Link to="/inventory">Add one</Link> and run a
              collection.
            </p>
          )}
        </section>
      )}

      {/* No device chosen is not an empty state any more. It is the estate question —
          "which firewalls anywhere have this" — which is the one thing every route
          before this could not answer. Choosing a device narrows to its full rulebase
          with the relationship analysis attached. */}
      {!deviceId && (
        <>
          <section className="card">
            <div className="toolbar">
              <label className="field field--inline">
                <span className="field__label">Issue</span>
                <select
                  className="field__input field__input--small"
                  value={filters.issue}
                  onChange={(e) => setFilters({ ...filters, issue: e.target.value })}
                >
                  <option value="">Any issue</option>
                  {ESTATE_ISSUES.map((issue) => (
                    <option key={issue} value={issue}>
                      {issue}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field field--inline">
                <span className="field__label">Action</span>
                <select
                  className="field__input field__input--small"
                  value={filters.action}
                  onChange={(e) => setFilters({ ...filters, action: e.target.value })}
                >
                  <option value="">Any action</option>
                  <option value="allow">allow</option>
                  <option value="deny">deny</option>
                </select>
              </label>
              <label className="toolbar__check">
                <input
                  type="checkbox"
                  checked={filters.with_issues_only}
                  onChange={(e) => setFilters({ ...filters, with_issues_only: e.target.checked })}
                />
                Only rules with issues
              </label>
            </div>
          </section>

          {estate.isLoading && <p className="page-loading">Searching every firewall…</p>}
          {estate.isError && (
            <p className="alert alert--error" role="alert">
              {estate.error instanceof ApiError
                ? estate.error.problem.detail
                : 'The estate could not be searched.'}
            </p>
          )}
          {estate.data && <EstateRules data={estate.data} />}
        </>
      )}

      {rulebase.isError && (
        <p className="alert alert--error" role="alert">
          {rulebase.error instanceof ApiError
            ? rulebase.error.problem.detail
            : 'The rulebase could not be loaded.'}
        </p>
      )}

      {rulebase.isLoading && deviceId && <p className="page-loading">Analysing rulebase…</p>}

      {rulebase.data && (
        <>
          <Summary rulebase={rulebase.data} />

          <section className="card">
            <div className="toolbar">
              <label className="field field--inline">
                <span className="field__label">Search</span>
                <input
                  className="field__input field__input--small"
                  placeholder="name, object, zone"
                  value={filters.search}
                  onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                />
              </label>

              <label className="field field--inline">
                <span className="field__label">Action</span>
                <select
                  className="field__input field__input--small"
                  value={filters.action}
                  onChange={(e) => setFilters({ ...filters, action: e.target.value })}
                >
                  <option value="">any</option>
                  <option value="allow">permits</option>
                  <option value="deny">denies</option>
                </select>
              </label>

              <label className="field field--inline">
                <span className="field__label">Zone</span>
                <select
                  className="field__input field__input--small"
                  value={filters.zone}
                  onChange={(e) => setFilters({ ...filters, zone: e.target.value })}
                >
                  <option value="">any</option>
                  {rulebase.data.zones.map((zone) => (
                    <option key={zone} value={zone}>
                      {zone}
                    </option>
                  ))}
                </select>
              </label>

              <label className="field field--inline">
                <span className="field__label">Problem</span>
                <select
                  className="field__input field__input--small"
                  value={filters.issue}
                  onChange={(e) => setFilters({ ...filters, issue: e.target.value })}
                >
                  <option value="">any</option>
                  {issueOptions.map((issue) => (
                    <option key={issue} value={issue}>
                      {issueLabel(issue)}
                    </option>
                  ))}
                </select>
              </label>

              <label className="toolbar__check">
                <input
                  type="checkbox"
                  checked={filters.with_issues_only}
                  onChange={(e) => setFilters({ ...filters, with_issues_only: e.target.checked })}
                />
                Only rules with problems
              </label>

              <label className="toolbar__check">
                <input
                  type="checkbox"
                  checked={filters.include_disabled}
                  onChange={(e) => setFilters({ ...filters, include_disabled: e.target.checked })}
                />
                Include disabled
              </label>

              <button
                type="button"
                className="button button--ghost button--small"
                onClick={() => setFilters(EMPTY)}
              >
                Clear
              </button>

              <button
                type="button"
                className="button button--small"
                onClick={exportCsv}
                disabled={exporting}
              >
                {exporting ? 'Exporting…' : 'Export CSV'}
              </button>
            </div>

            <RulebaseViewer
              rulebase={rulebase.data}
              focusOrder={focusOrder}
              onFocusOrder={setFocusOrder}
            />
          </section>

          {rulebase.data.nat_rules.length > 0 && (
            <section className="card">
              <header className="card__header">
                <h2 className="card__title">NAT</h2>
                {!rulebase.data.summary.exposure_analysed && (
                  <span className="muted">
                    No zone was identified as facing an untrusted network, so exposure was not
                    analysed.
                  </span>
                )}
              </header>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Name</th>
                      <th>Original</th>
                      <th>Translated</th>
                      <th>Direction</th>
                      <th>Problems</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rulebase.data.nat_rules.map((nat) => (
                      <tr key={nat.order}>
                        <td>{nat.order}</td>
                        <td>{nat.name}</td>
                        <td className="mono">{nat.original}</td>
                        <td className="mono">{nat.translated}</td>
                        <td>{nat.direction}</td>
                        <td>
                          {nat.issues.map((issue, index) => (
                            <span
                              key={`${issue.issue}-${index}`}
                              className={`pill pill--${issue.severity}`}
                              title={issue.message}
                            >
                              {issueLabel(issue.issue)}
                            </span>
                          ))}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {rulebase.data.hygiene.length > 0 && (
            <section className="card">
              <header className="card__header">
                <h2 className="card__title">Object hygiene</h2>
              </header>
              <ul className="rule__issues">
                {rulebase.data.hygiene.map((finding, index) => (
                  <li className="rule__issue" key={`${finding.issue}-${index}`}>
                    <span className={`pill pill--${finding.severity}`}>
                      {issueLabel(finding.issue)}
                    </span>
                    <span className="rule__issue-text">
                      <strong className="mono">{finding.name}</strong> — {finding.message}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          <RuleQuery deviceId={deviceId} />
        </>
      )}
    </div>
  );
}
