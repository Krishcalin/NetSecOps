/** AAA posture: coverage, protocols, orphaned clients and certificate expiry (FR-AAA-06).
 *
 * The four panels belong on one page because each is the context for the others. 94%
 * coverage is good news until you notice the missing 6% is the datacentre; a list of
 * expiring certificates is administrivia until you notice the one expiring in nine days
 * is the EAP certificate every wireless client authenticates against.
 *
 * **Coverage renders "unknown", never 0%, when nothing was assessable.** That is the
 * single most important line in this file. Zero and "we have not looked" look identical
 * on a dashboard and send an operator to opposite places — one to a rollout project, the
 * other to a broken collector.
 *
 * **Analysing is a button, not a page load.** The read endpoints write nothing, so
 * refreshing this page cannot change finding history and two people opening it at once
 * cannot race each other. Storing the findings is an explicit action.
 */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { api, ApiError } from '../api/client';
import { CertificateTimeline } from '../features/aaa/CertificateTimeline';
import { describeTriState } from '../features/aaa/types';
import type { AaaPosture, Correlation } from '../features/aaa/types';
import { useAuth } from '../features/auth/useAuth';

function Coverage({ posture }: { posture: AaaPosture }) {
  const { coverage_percentage: percentage } = posture;

  return (
    <section className="card">
      <header className="card__header">
        <h2 className="card__title">Central authentication coverage</h2>
      </header>

      <div className="card-grid">
        <div className="stat">
          {/* Never `percentage ?? 0`. The null is the answer. */}
          <strong>{percentage === null ? 'unknown' : `${percentage}%`}</strong>
          <span>of assessable devices</span>
        </div>
        <div className="stat">
          <strong>{posture.devices_with_central_auth}</strong>
          <span>use an AAA server</span>
        </div>
        <div className="stat">
          <strong>{posture.devices_total}</strong>
          <span>devices in inventory</span>
        </div>
        {posture.devices_not_evaluated > 0 && (
          <div className="stat">
            <strong>{posture.devices_not_evaluated}</strong>
            <span>could not be assessed</span>
          </div>
        )}
      </div>

      {percentage === null && posture.devices_total > 0 && (
        <p className="alert alert--warning" role="status">
          No device has an AAA configuration NetSecOps could read, so coverage has no honest
          denominator. This is not 0% &mdash; it is the absence of the data needed to answer. Run a
          collection first.
        </p>
      )}

      {posture.transports.length > 0 && (
        <p className="muted">
          {posture.transports
            .map((t) => `${t.devices} device${t.devices === 1 ? '' : 's'} use ${t.kind}`)
            .join(', ')}
          .
        </p>
      )}
    </section>
  );
}

function Protocols({ posture }: { posture: AaaPosture }) {
  const weak = posture.accepted_protocols.filter((p) => p.weak);

  return (
    <section className="card">
      <header className="card__header">
        <h2 className="card__title">Protocols accepted</h2>
        {/* "Accepted", not "in use": nothing here observes a live authentication, and
            calling it usage would claim an observation we never made. */}
        <span className="muted">What the AAA servers will accept if a client offers it</span>
      </header>

      {posture.accepted_protocols.length === 0 ? (
        <p className="empty">
          {posture.servers.length === 0
            ? 'No AAA server has been collected from, so nothing is known about what the estate will accept.'
            : 'No AAA server exposed its allowed-protocol set. The panel is empty because the data is missing, not because nothing is accepted.'}
        </p>
      ) : (
        <>
          {weak.length > 0 && (
            <p className="alert alert--error" role="alert">
              {weak.length} weak protocol{weak.length === 1 ? ' is' : 's are'} still accepted:{' '}
              <strong>{weak.map((p) => p.name).join(', ')}</strong>. One policy still accepting
              these is a way in regardless of what the others require.
            </p>
          )}
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>Accepted by</th>
                </tr>
              </thead>
              <tbody>
                {posture.accepted_protocols.map((protocol) => (
                  <tr key={protocol.name}>
                    <td>
                      {protocol.weak && <span className="pill pill--high">weak</span>}{' '}
                      {protocol.name}
                    </td>
                    <td className="muted">{protocol.servers.join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}

function Servers({ posture }: { posture: AaaPosture }) {
  if (posture.servers.length === 0) return null;

  return (
    <section className="card">
      <header className="card__header">
        <h2 className="card__title">AAA servers</h2>
      </header>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Server</th>
              <th>Product</th>
              <th>Clients</th>
              <th>Identity stores</th>
              <th>Admin MFA</th>
              <th>Certificates</th>
              <th>Collected</th>
            </tr>
          </thead>
          <tbody>
            {posture.servers.map((server) => (
              <tr key={server.device_id}>
                <td>
                  <Link to={`/inventory/${server.device_id}/config`}>
                    {server.hostname ?? server.device_id}
                  </Link>
                </td>
                <td>{server.product ?? 'unknown'}</td>
                <td>{server.clients}</td>
                <td>{server.identity_stores}</td>
                <td>
                  {/* Three states. FreeRADIUS and tac_plus have no such concept, and
                      "no" would invent a finding on every one of them. */}
                  {server.admin_mfa_enabled === false ? (
                    <span className="pill pill--high">no</span>
                  ) : (
                    <span className="muted">{describeTriState(server.admin_mfa_enabled)}</span>
                  )}
                </td>
                <td>{server.certificates}</td>
                <td className="muted">
                  {server.snapshot_age_days === null
                    ? 'never'
                    : server.snapshot_age_days === 0
                      ? 'today'
                      : `${server.snapshot_age_days} days ago`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function CorrelationPanel({ correlation }: { correlation: Correlation }) {
  const {
    orphaned_clients: orphans,
    unregistered_devices: unregistered,
    unknown_servers: unknown,
    reused_secrets: reused,
  } = correlation;

  return (
    <section className="card">
      <header className="card__header">
        <h2 className="card__title">Across the estate</h2>
        <span className="muted">
          {correlation.servers_examined} AAA server
          {correlation.servers_examined === 1 ? '' : 's'} examined
        </span>
      </header>

      {!correlation.registration_analysed && (
        <p className="alert alert--warning" role="status">
          No AAA server has been collected from, so NetSecOps cannot tell which devices are
          registered as clients. Nothing below is a statement that they are not &mdash; it is the
          absence of the data needed to ask.
        </p>
      )}

      <div className="card-grid">
        <div className="stat">
          <strong>{orphans.length}</strong>
          <span>authenticate but are not in inventory</span>
        </div>
        <div className="stat">
          <strong>{correlation.registration_analysed ? unregistered.length : '—'}</strong>
          <span>in inventory, on no client list</span>
        </div>
        <div className="stat">
          <strong>{unknown.length}</strong>
          <span>servers nobody assesses</span>
        </div>
        <div className="stat">
          <strong>{reused.length}</strong>
          <span>shared secrets reused</span>
        </div>
      </div>

      {orphans.length > 0 && (
        <>
          <h3 className="card__title">Devices an AAA server knows and we do not</h3>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Address</th>
                  <th>Known to</th>
                  <th>Snapshot age</th>
                </tr>
              </thead>
              <tbody>
                {orphans.map((client) => (
                  <tr key={`${client.server}-${client.name}`}>
                    <td>{client.name}</td>
                    <td className="mono">{client.address ?? '—'}</td>
                    <td>{client.server}</td>
                    <td className="muted">
                      {/* A stale server snapshot makes a newly-added device look like an
                          orphan. Showing the age lets a reader tell the two apart. */}
                      {client.server_snapshot_age_days === null
                        ? 'unknown'
                        : `${client.server_snapshot_age_days} days`}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {unknown.length > 0 && (
        <>
          <h3 className="card__title">AAA servers not in inventory</h3>
          <ul className="rulebase__limits-inline">
            {unknown.map((server) => (
              <li key={server.address}>
                <strong className="mono">{server.address}</strong> ({server.kind}) &mdash; used by{' '}
                {server.used_by.join(', ')}
              </li>
            ))}
          </ul>
        </>
      )}

      {reused.length > 0 && (
        <>
          <h3 className="card__title">Shared secrets configured more than once</h3>
          <ul className="rulebase__limits-inline">
            {reused.map((secret) => (
              <li key={secret.fingerprint}>
                One key across <strong>{secret.clients}</strong> clients:{' '}
                {secret.used_by.join(', ')}
              </li>
            ))}
          </ul>
        </>
      )}

      {correlation.secrets_not_exposable > 0 && (
        <p className="muted">
          {correlation.secrets_not_exposable} client(s) have a shared secret their server does not
          expose, so reuse is <strong>unknown</strong> for those rather than absent. Cisco ISE and
          FortiAuthenticator both return a masked value.
        </p>
      )}
    </section>
  );
}

export function AaaPage() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [message, setMessage] = useState<string | null>(null);

  const posture = useQuery({
    queryKey: ['aaa', 'posture'],
    queryFn: () => api.get<AaaPosture>('/aaa/posture'),
  });

  const assess = useMutation({
    mutationFn: () => api.post<Correlation>('/aaa/assess', {}),
    onSuccess: async () => {
      setMessage('The correlation has been stored. Each finding now appears on its device.');
      await queryClient.invalidateQueries({ queryKey: ['aaa', 'posture'] });
    },
    onError: (error) => {
      setMessage(
        error instanceof ApiError ? error.problem.detail : 'The assessment could not be run.',
      );
    },
  });

  // Hidden rather than disabled for a reader: the button's whole purpose is to write,
  // and offering it to someone who cannot is an invitation to a 403.
  const canWrite = can('finding:write');
  const openFindings = Object.values(posture.data?.open_findings ?? {}).reduce(
    (total, count) => total + count,
    0,
  );

  return (
    <div className="page">
      <header className="page__header">
        <h1>AAA posture</h1>
        <p className="page__subtitle">
          Who authenticates where, what the servers will accept, and which certificates stop working
          soon.
        </p>
      </header>

      {posture.isError && (
        <p className="alert alert--error" role="alert">
          {posture.error instanceof ApiError
            ? posture.error.problem.detail
            : 'The AAA posture could not be loaded.'}
        </p>
      )}

      {posture.isLoading && <p className="page-loading">Correlating the estate&hellip;</p>}

      {posture.data && (
        <>
          <section className="card">
            <div className="toolbar">
              <span className="muted">
                {openFindings > 0 ? (
                  <>
                    <Link to="/findings?kind=aaa">{openFindings} open AAA finding(s)</Link>
                  </>
                ) : (
                  'No open AAA findings.'
                )}
              </span>
              {canWrite && (
                <button
                  type="button"
                  className="button button--primary button--small"
                  onClick={() => assess.mutate()}
                  disabled={assess.isPending}
                >
                  {assess.isPending ? 'Analysing…' : 'Store as findings'}
                </button>
              )}
            </div>
            {message && (
              <p className="alert alert--ok" role="status">
                {message}
              </p>
            )}
          </section>

          <Coverage posture={posture.data} />
          <Protocols posture={posture.data} />
          <CorrelationPanel correlation={posture.data.correlation} />
          <CertificateTimeline timeline={posture.data.certificates} />
          <Servers posture={posture.data} />

          {/* Last, and always rendered when non-empty. Every panel above can reach zero
              through missing data, and a reader who cannot tell that from a clean
              result will act on the wrong one. */}
          {posture.data.limitations.length > 0 && (
            <section className="card card--muted">
              <header className="card__header">
                <h2 className="card__title">
                  What this page could not determine ({posture.data.limitations.length})
                </h2>
              </header>
              <ul className="rulebase__limits-inline">
                {posture.data.limitations.map((text) => (
                  <li key={text} className="muted">
                    {text}
                  </li>
                ))}
              </ul>
            </section>
          )}
        </>
      )}
    </div>
  );
}
