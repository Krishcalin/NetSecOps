/** Discovery scopes and the pending-review queue (FR-DISC-01, FR-DISC-04).
 *
 * Two things this page has to make plain, because both are easy to design away:
 *
 * **The queue opens with what is least understood.** Sorted by ascending confidence,
 * which looks wrong until you remember what the queue is for. A low score is not "this
 * is probably not a device" — it is "the fingerprinter could not tell", and those are
 * exactly the entries that need a person. Sorting the other way puts the easy ones on
 * page one and the genuinely unknown devices where nobody scrolls.
 *
 * **The Run button says what it is about to do before it does it.** It sits in the scope
 * row next to the resolved address count and the rate, so the two numbers that decide how
 * long this takes and how loud it is are the ones under the operator's cursor. Starting a
 * run is the most outward-facing thing this read-only product does — packets to somebody
 * else's network — and it is confirmed rather than fired on a single click.
 *
 * **A run's caveats are shown beside its counters, never instead of them.** "0 hosts
 * found" and "0 hosts found, and no echo request could be sent" are different answers. A
 * runs table that showed only the numbers would make an estate nobody could detect read
 * exactly like a quiet one.
 */

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { api } from '../api/client';
import { ApiError } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import type { DiscoveredHost, DiscoveryRun, DiscoveryScope } from '../features/discovery/types';
import { SIGNAL_LABELS, confidenceBand } from '../features/discovery/types';

interface PendingResponse {
  data: DiscoveredHost[];
  meta: { count: number; limit: number };
}

const DEVICE_CLASSES = [
  'unknown',
  'switch',
  'router',
  'firewall',
  'wireless_controller',
  'aaa_server',
];

function FingerprintEvidence({ host }: { host: DiscoveredHost }) {
  const signals = Object.entries(host.fingerprint ?? {});

  if (signals.length === 0) {
    return (
      <p className="empty">
        This host answered but produced no identifying signal — no SSH banner, no TLS certificate,
        no HTTP marker. That is why its confidence is {host.confidence}.
      </p>
    );
  }

  return (
    <dl className="evidence__signals">
      {signals.map(([key, value]) => (
        <div key={key}>
          <dt>{SIGNAL_LABELS[key] ?? key}</dt>
          <dd className="mono">{typeof value === 'string' ? value : JSON.stringify(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function ReviewPanel({ host: listed, onDone }: { host: DiscoveredHost; onDone: () => void }) {
  const queryClient = useQueryClient();

  // Re-read the host as the panel opens rather than trusting the row the list was built
  // from. The list is a snapshot of whenever it loaded and a review panel can sit open
  // for a long time; what is being decided here is the device's *platform*, and a wrong
  // platform selects the wrong collection profile and with it the wrong command
  // allow-list. That is the one mistake on this page whose blast radius reaches past
  // the inventory, so it is worth a request to make the evidence current at the moment
  // of the decision.
  const detail = useQuery({
    queryKey: ['discovered-host', listed.id],
    queryFn: () => api.get<DiscoveredHost>(`/discovery/pending/${listed.id}`),
    // The listed row is the same schema, so there is something correct to render while
    // the re-read is in flight rather than a spinner over a decision form.
    placeholderData: listed,
  });
  const host = detail.data ?? listed;

  const [vendor, setVendor] = useState(host.vendor ?? '');
  const [platform, setPlatform] = useState(host.platform ?? '');
  const [hostname, setHostname] = useState(host.hostname ?? '');
  const [deviceClass, setDeviceClass] = useState('unknown');
  const [note, setNote] = useState('');
  const [error, setError] = useState<string | null>(null);

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: ['discovery-pending'] });
    onDone();
  }

  const approve = useMutation({
    mutationFn: () =>
      api.post(`/discovery/pending/${host.id}/approve`, {
        vendor: vendor || null,
        platform: platform || null,
        hostname: hostname || null,
        device_class: deviceClass,
      }),
    onSuccess: invalidate,
    onError: (err) =>
      setError(err instanceof ApiError ? err.problem.detail : 'The approval failed.'),
  });

  const reject = useMutation({
    mutationFn: () => api.post(`/discovery/pending/${host.id}/reject`, { note }),
    onSuccess: invalidate,
    onError: (err) =>
      setError(err instanceof ApiError ? err.problem.detail : 'The rejection failed.'),
  });

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">
          <span className="mono">{host.address}</span>{' '}
          <span className={`pill pill--${confidenceBand(host.confidence)}`}>
            {host.confidence}% confident
          </span>
        </h2>
        <button className="button button--ghost button--small" onClick={onDone}>
          Close
        </button>
      </div>

      <h3 className="finding__heading">What the probes saw</h3>
      <FingerprintEvidence host={host} />

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      <h3 className="finding__heading">Onboard as a device</h3>
      <p className="finding__note">
        The vendor and platform below are the fingerprinter&rsquo;s guess, not a verdict. Correct
        them if they are wrong: the platform selects the collection profile and with it the
        read-only command allow-list, so a wrong one is the single mistake here that reaches past
        the inventory.
      </p>

      <div className="form-grid">
        <label className="field">
          <span className="field__label">Hostname</span>
          <input
            className="field__input"
            value={hostname}
            onChange={(event) => setHostname(event.target.value)}
          />
        </label>
        <label className="field">
          <span className="field__label">Vendor</span>
          <input
            className="field__input"
            value={vendor}
            onChange={(event) => setVendor(event.target.value)}
          />
        </label>
        <label className="field">
          <span className="field__label">Platform</span>
          <input
            className="field__input"
            value={platform}
            onChange={(event) => setPlatform(event.target.value)}
          />
        </label>
        <label className="field">
          <span className="field__label">Device class</span>
          <select
            className="field__input"
            value={deviceClass}
            onChange={(event) => setDeviceClass(event.target.value)}
          >
            {DEVICE_CLASSES.map((value) => (
              <option key={value} value={value}>
                {value.replace('_', ' ')}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="finding__actions">
        <button
          className="button"
          disabled={approve.isPending || reject.isPending}
          onClick={() => approve.mutate()}
        >
          Approve and onboard
        </button>
      </div>

      <h3 className="finding__heading">Or mark it as not ours</h3>
      <p className="finding__note">
        A reason is required. &ldquo;Rejected&rdquo; on its own tells the next person nothing, and
        the question they will have — a printer, or a switch nobody has got round to — is what
        decides whether they reopen it.
      </p>
      <label className="field">
        <span className="field__label">Reason</span>
        <input
          className="field__input"
          value={note}
          placeholder="Site printer, confirmed with facilities"
          onChange={(event) => setNote(event.target.value)}
        />
      </label>
      <div className="finding__actions">
        <button
          className="button button--ghost"
          disabled={!note.trim() || approve.isPending || reject.isPending}
          onClick={() => reject.mutate()}
        >
          Reject
        </button>
      </div>
    </section>
  );
}

function RunButton({ scope }: { scope: DiscoveryScope }) {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const start = useMutation({
    mutationFn: () => api.post(`/discovery/scopes/${scope.id}/runs`, {}),
    onSuccess: () => {
      setConfirming(false);
      void queryClient.invalidateQueries({ queryKey: ['discovery-runs'] });
    },
    onError: (err) =>
      setError(err instanceof ApiError ? err.problem.detail : 'The run could not be started.'),
  });

  if (!scope.enabled) {
    return <span className="pill pill--info">disabled</span>;
  }

  if (error) {
    return (
      <span className="alert alert--error" role="alert">
        {error}
      </span>
    );
  }

  if (!confirming) {
    return (
      <button className="button button--ghost button--small" onClick={() => setConfirming(true)}>
        Run
      </button>
    );
  }

  // Confirmed rather than fired on one click, and the confirmation states the two numbers
  // that matter: how many addresses will be contacted, and how fast. An operator who has
  // mistyped a prefix length finds out here rather than from the customer.
  return (
    <div className="finding__actions">
      <span className="finding__note">
        Probe {scope.address_count?.toLocaleString() ?? 'an unresolvable number of'} addresses at up
        to {scope.rate_limit_per_second}/s?
      </span>
      <button
        className="button button--small"
        disabled={start.isPending}
        onClick={() => start.mutate()}
      >
        {start.isPending ? 'Starting…' : 'Start'}
      </button>
      <button className="button button--ghost button--small" onClick={() => setConfirming(false)}>
        Cancel
      </button>
    </div>
  );
}

/** Remove a scope — the addresses this installation is permitted to probe.
 *
 * Asked for twice, because a scope is the permission itself: deleting one is how you
 * stop probing a range that turned out not to be yours, and doing it by accident removes
 * the record of what was agreed. Past runs and the hosts they found are unaffected; only
 * the standing permission goes.
 */
function RemoveScopeButton({ scope }: { scope: DiscoveryScope }) {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const remove = useMutation({
    mutationFn: () => api.delete<void>(`/discovery/scopes/${scope.id}`),
    onSuccess: () => {
      setConfirming(false);
      void queryClient.invalidateQueries({ queryKey: ['discovery-scopes'] });
    },
    onError: (err) =>
      setError(err instanceof ApiError ? err.problem.detail : 'The scope could not be removed.'),
  });

  if (error) {
    return (
      <span className="alert alert--error" role="alert">
        {error}
      </span>
    );
  }

  if (!confirming) {
    return (
      <button className="button button--ghost button--small" onClick={() => setConfirming(true)}>
        Remove
      </button>
    );
  }

  return (
    <>
      <button
        className="button button--ghost button--small"
        disabled={remove.isPending}
        onClick={() => remove.mutate()}
      >
        Yes, remove
      </button>
      <button className="button button--ghost button--small" onClick={() => setConfirming(false)}>
        Cancel
      </button>
    </>
  );
}

function ScopeTable({ scopes, canRun }: { scopes: DiscoveryScope[]; canRun: boolean }) {
  if (scopes.length === 0) {
    return (
      <p className="empty">
        No discovery scope is defined. A scope names the addresses that may be probed — nothing is
        probed without one.
      </p>
    );
  }

  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Targets</th>
            <th>Excluded</th>
            <th>Addresses</th>
            <th>TCP ports</th>
            <th>Rate</th>
            <th>SNMP</th>
            <th>Auto-onboard</th>
            {canRun && <th />}
          </tr>
        </thead>
        <tbody>
          {scopes.map((scope) => (
            <tr key={scope.id}>
              <td>{scope.name}</td>
              <td className="mono">{scope.targets.join(', ')}</td>
              <td className="mono">
                {scope.exclusions.length > 0 ? scope.exclusions.join(', ') : '—'}
              </td>
              <td>
                {/* The number to sanity-check before anything runs: 10.0.0.0/8 is one
                    character from 10.0.0.0/18 and sixteen million probes from it. */}
                {scope.address_count?.toLocaleString() ?? 'not resolvable'}
              </td>
              <td className="mono">{scope.tcp_ports.join(', ')}</td>
              <td>{scope.rate_limit_per_second}/s</td>
              {/* "configured" no longer means "read": the flag is honoured by the probe
                  allow-list, but no SNMP credential can be stored against a scope yet. */}
              <td>{scope.snmp_configured ? 'requested, not read' : 'not probed'}</td>
              <td>
                {scope.auto_onboard ? (
                  <span className="pill pill--medium">on</span>
                ) : (
                  <span className="pill pill--info">review first</span>
                )}
              </td>
              {canRun && (
                <td className="table__actions">
                  <RunButton scope={scope} />
                  <RemoveScopeButton scope={scope} />
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function DiscoveryPage() {
  const { can } = useAuth();
  const [selected, setSelected] = useState<string | null>(null);

  const scopes = useQuery({
    queryKey: ['discovery-scopes'],
    queryFn: () => api.get<DiscoveryScope[]>('/discovery/scopes'),
  });

  const runs = useQuery({
    queryKey: ['discovery-runs'],
    queryFn: () => api.get<DiscoveryRun[]>('/discovery/runs'),
  });

  const pending = useQuery({
    queryKey: ['discovery-pending'],
    queryFn: () => api.get<PendingResponse>('/discovery/pending'),
  });

  const hosts = pending.data?.data ?? [];
  const selectedHost = hosts.find((host) => host.id === selected) ?? null;

  return (
    <div className="page">
      <header className="page__header">
        <h1>Discovery</h1>
        <p className="page__subtitle">
          Reachability and fingerprinting only — ICMP, a short TCP connect list, an SSH banner, a
          TLS certificate and optionally one SNMP OID. No port sweep, no exploitation, no credential
          guessing.
        </p>
      </header>

      <div className="alert alert--info" role="note">
        Every run is paced (FR-DISC-05). A scope's rate is a ceiling on how often a host is
        contacted, not a target — 50 a second by default — and it is what keeps a run
        distinguishable from a port scan. SNMP is not yet read: no SNMP credential can be stored
        against a scope, so hosts will score lower than they otherwise would and more of them will
        need a person. Runs say so individually.
      </div>

      <section className="card">
        <div className="card__header">
          <h2 className="card__title">Scopes</h2>
        </div>
        {scopes.isLoading ? (
          <p className="page-loading">Loading…</p>
        ) : (
          <ScopeTable scopes={scopes.data ?? []} canRun={can('discovery:write')} />
        )}
      </section>

      <section className="card">
        <div className="card__header">
          <h2 className="card__title">
            Pending review{hosts.length > 0 ? ` (${hosts.length})` : ''}
          </h2>
        </div>
        {pending.isLoading ? (
          <p className="page-loading">Loading…</p>
        ) : hosts.length === 0 ? (
          <p className="empty">
            Nothing is waiting for review. Once runs can be started, hosts that answer a probe land
            here before they become devices — nothing is assessed without approval unless a scope is
            marked auto-onboard.
          </p>
        ) : (
          <>
            <p className="finding__note">
              Least understood first. A low confidence score means the fingerprinter could not tell
              what this is, not that it is unimportant — those are the entries that need a person.
            </p>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Confidence</th>
                    <th>Address</th>
                    <th>Guessed as</th>
                    <th>Hostname</th>
                    <th>First seen</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {hosts.map((host) => (
                    <tr key={host.id} className={host.id === selected ? 'table__row--active' : ''}>
                      <td>
                        <span className={`pill pill--${confidenceBand(host.confidence)}`}>
                          {host.confidence}%
                        </span>
                      </td>
                      <td className="mono">{host.address}</td>
                      <td>
                        {host.vendor || host.platform
                          ? `${host.vendor ?? '—'} ${host.platform ?? ''}`.trim()
                          : 'unidentified'}
                      </td>
                      <td>{host.hostname ?? '—'}</td>
                      <td>
                        {host.first_seen_at
                          ? new Date(host.first_seen_at).toLocaleDateString()
                          : '—'}
                      </td>
                      <td>
                        {can('discovery:write') && (
                          <button
                            className="button button--ghost button--small"
                            onClick={() => setSelected(selected === host.id ? null : host.id)}
                          >
                            {selected === host.id ? 'Hide' : 'Review'}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </section>

      {selectedHost && <ReviewPanel host={selectedHost} onDone={() => setSelected(null)} />}

      <section className="card">
        <div className="card__header">
          <h2 className="card__title">Runs</h2>
        </div>
        {runs.isLoading ? (
          <p className="page-loading">Loading…</p>
        ) : (runs.data ?? []).length === 0 ? (
          <p className="empty">No runs have happened yet. Start one from a scope above.</p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Status</th>
                  <th>Probed</th>
                  <th>Found</th>
                  <th>Unidentified</th>
                  <th>Caveats</th>
                </tr>
              </thead>
              <tbody>
                {(runs.data ?? []).map((run) => (
                  <tr key={run.id}>
                    <td>{new Date(run.started_at).toLocaleString()}</td>
                    <td>{run.status}</td>
                    <td>{run.addresses_probed.toLocaleString()}</td>
                    <td>{run.hosts_found.toLocaleString()}</td>
                    <td>{run.hosts_unidentified.toLocaleString()}</td>
                    {/* Beside the counters, never instead of them. A run that found
                        nothing because it could not ask must not print like a run that
                        found nothing because there was nothing there. */}
                    <td>
                      {(run.notes ?? []).length === 0 ? (
                        '—'
                      ) : (
                        <ul className="finding__note">
                          {(run.notes ?? []).map((note) => (
                            <li key={note}>{note}</li>
                          ))}
                        </ul>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
