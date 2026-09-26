/** Path analysis and the missing-device report (FR-TOPO-03 … FR-TOPO-06).
 *
 * **The result is shown as two verdicts side by side, and never merged.** Routing and
 * policy fail independently, and every attempt to render one badge has to decide what
 * "every firewall permits this, and I lost the path halfway" means — which is exactly the
 * decision the product must not make on the operator's behalf. The two badges carry their
 * own meanings underneath them for the same reason.
 *
 * **`partially-allowed` is coloured as a caution, not a success.** It is the case an
 * operator most wants to read as "yes", and a green badge would let them. Someone opens a
 * firewall on the strength of these answers.
 *
 * **A router with no rulebase renders differently from a firewall that permitted.** Both
 * pass traffic; only one of them looked at it. Rendering them alike would count a device
 * that inspected nothing as a control that was checked.
 */

import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';

import { api, ApiError } from '../api/client';
import { PathDiagram } from '../features/topology/PathDiagram';
import type { MissingDevice, PathResult, TopologySummary } from '../features/topology/types';
import { POLICY_LABELS, ROUTING_LABELS } from '../features/topology/types';

function Verdict({
  heading,
  label,
  tone,
  meaning,
}: {
  heading: string;
  label: string;
  tone: string;
  meaning: string;
}) {
  return (
    <div className="verdict">
      <span className="verdict__heading">{heading}</span>
      <span className={`pill pill--${tone}`}>{label}</span>
      <p className="finding__note">{meaning}</p>
    </div>
  );
}

function HopRow({ hop, index }: { hop: PathResult['hops'][number]; index: number }) {
  return (
    <tr>
      <td>{index + 1}</td>
      <td>
        {hop.hostname}
        {hop.platform && <span className="finding__note"> {hop.platform}</span>}
      </td>
      <td className="mono">
        {hop.matched_route ?? '—'}
        {/* Returned by the API since this endpoint shipped and never shown. "Which
            way did it leave" is most of what makes a route line checkable against
            the device. */}
        {(hop.next_hop || hop.egress_interface) && (
          <span className="finding__note">
            {hop.next_hop && ` via ${hop.next_hop}`}
            {hop.egress_interface && ` out ${hop.egress_interface}`}
          </span>
        )}
        {/* Where the question changed. Every hop below this one was evaluated against
            different addresses, and without this the table reads as though one packet
            crossed the whole path unchanged. */}
        {hop.translation && <span className="hop__nat">NAT: {hop.translation}</span>}
      </td>
      <td>
        {hop.ingress_zone || hop.egress_zone
          ? `${hop.ingress_zone ?? '—'} → ${hop.egress_zone ?? '—'}`
          : '—'}
      </td>
      <td>
        {/* Three states, not two: denied, permitted, and "this device has no rulebase
            and formed no opinion". The third must not read as a permit. */}
        {hop.action === null ? (
          <span className="finding__note">no rulebase</span>
        ) : hop.action === 'deny' ? (
          <span className="pill pill--high">denied</span>
        ) : (
          <span className="pill pill--low">permitted</span>
        )}
        {hop.rule_name && <span className="finding__note"> {hop.rule_name}</span>}
        {/* Carried in the payload from the start and never rendered. These say what
            the simulation could not model at this specific hop — App-ID narrowing, a
            rulebase bound to nothing — so a permit here is weaker than it looks and
            the reader has to be told at the hop, not in a page-level footnote. */}
        {hop.limitations.length > 0 && (
          <ul className="finding__note">
            {hop.limitations.map((limit) => (
              <li key={limit}>{limit}</li>
            ))}
          </ul>
        )}
      </td>
    </tr>
  );
}

function PathAnswer({ result }: { result: PathResult }) {
  const routing = ROUTING_LABELS[result.routing];
  const policy = POLICY_LABELS[result.policy];

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">
          <span className="mono">{result.source}</span> →{' '}
          <span className="mono">{result.destination}</span>{' '}
          <span className="finding__note">
            {result.protocol}/{result.port}
          </span>
        </h2>
      </div>

      <div className="verdict-pair">
        <Verdict heading="Routing" {...routing} />
        <Verdict heading="Policy" {...policy} />
      </div>

      {result.stopped_at_next_hop && (
        <div className="alert alert--info" role="note">
          The trace stopped at <strong>{result.stopped_at_device}</strong>, which routes{' '}
          <span className="mono">{result.stopped_at_prefix}</span> via{' '}
          <span className="mono">{result.stopped_at_next_hop}</span> — an address no device in the
          inventory answers for. Onboarding that device would extend this answer.
        </div>
      )}

      {/* The picture first, the table below it. The diagram makes the shape of the
          answer readable at a glance; the table is the authoritative reading and the
          navigable equivalent, so neither replaces the other. */}
      {result.hops.length > 0 && <PathDiagram result={result} />}

      {result.hops.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            {/* This page carries two tables and neither had a name, so a screen
                reader's table list read "table" twice. */}
            <caption className="visually-hidden">
              Hops from {result.source} to {result.destination}, in path order
            </caption>
            <thead>
              <tr>
                <th>#</th>
                <th>Device</th>
                <th>Route taken</th>
                <th>Zones</th>
                <th>Decision</th>
              </tr>
            </thead>
            <tbody>
              {result.hops.map((hop, index) => (
                <HopRow key={`${hop.device_id}-${index}`} hop={hop} index={index} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {result.notes.length > 0 && (
        <>
          <h3 className="finding__heading">What this answer does not cover</h3>
          {/* Beside the verdict, never behind a disclosure control. Most of what makes a
              path answer trustworthy is in here, and a caveat nobody opens is a caveat
              nobody reads. */}
          <ul className="finding__note">
            {result.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

export function TopologyPage() {
  const [source, setSource] = useState('');
  const [destination, setDestination] = useState('');
  const [protocol, setProtocol] = useState('tcp');
  const [port, setPort] = useState(443);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PathResult | null>(null);

  const summary = useQuery({
    queryKey: ['topology-summary'],
    queryFn: () => api.get<TopologySummary>('/topology/summary'),
  });

  const missing = useQuery({
    queryKey: ['topology-missing'],
    queryFn: () => api.get<MissingDevice[]>('/topology/missing-devices'),
  });

  const trace = useMutation({
    mutationFn: () =>
      api.post<PathResult>('/topology/path', {
        source,
        destination,
        protocol,
        port,
      }),
    onSuccess: (answer) => {
      setError(null);
      setResult(answer);
    },
    onError: (err) => {
      setResult(null);
      setError(err instanceof ApiError ? err.problem.detail : 'The path query failed.');
    },
  });

  const stats = summary.data;

  return (
    <div className="page">
      <header className="page__header">
        <h1>Path analysis</h1>
        <p className="page__subtitle">
          Can this host reach that one, and what decides. Traced across the stored configurations of
          every device in the inventory — nothing is sent, and no packet leaves this server.
        </p>
      </header>

      {stats && stats.devices_without_route_data > 0 && (
        <div className="alert alert--info" role="note">
          {stats.devices_without_route_data} of {stats.devices} device(s) were collected before
          forwarding tables were parsed, so they contribute no routes. A path that should have
          crossed one of them will stop early rather than being wrong — re-collect them to close the
          gap.
        </div>
      )}

      <section className="card">
        <div className="card__header">
          <h2 className="card__title">Trace a packet</h2>
        </div>
        <div className="form-grid">
          <label className="field">
            <span className="field__label">Source address</span>
            <input
              className="field__input mono"
              value={source}
              placeholder="10.10.0.5"
              onChange={(event) => setSource(event.target.value)}
            />
          </label>
          <label className="field">
            <span className="field__label">Destination address</span>
            <input
              className="field__input mono"
              value={destination}
              placeholder="10.20.0.5"
              onChange={(event) => setDestination(event.target.value)}
            />
          </label>
          <label className="field">
            <span className="field__label">Protocol</span>
            <select
              className="field__input"
              value={protocol}
              onChange={(event) => setProtocol(event.target.value)}
            >
              {['tcp', 'udp', 'icmp'].map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span className="field__label">Port</span>
            <input
              className="field__input"
              type="number"
              value={port}
              onChange={(event) => setPort(Number(event.target.value))}
            />
          </label>
        </div>

        <p className="finding__note">
          Literal addresses only. Names are not resolved, so that what was analysed is what was
          asked.
        </p>

        <div className="finding__actions">
          <button
            className="button"
            disabled={!source.trim() || !destination.trim() || trace.isPending}
            onClick={() => trace.mutate()}
          >
            {trace.isPending ? 'Tracing…' : 'Trace'}
          </button>
        </div>

        {error && (
          <div className="alert alert--error" role="alert">
            {error}
          </div>
        )}
      </section>

      {result && <PathAnswer result={result} />}

      <section className="card">
        <div className="card__header">
          <h2 className="card__title">Where the map stops</h2>
        </div>
        <p className="finding__note">
          Addresses that routes point at and no device in the inventory answers for, ranked by how
          much reachability each one conceals. These are evidence, not a work queue: an unmanaged
          next hop may be an ISP router, a customer handoff, or a virtual address no single box
          owns.
        </p>

        {missing.isLoading ? (
          <p className="page-loading">Loading…</p>
        ) : (missing.data ?? []).length === 0 ? (
          <p className="empty">
            Every next hop in the estate belongs to a device in the inventory. Path analysis will
            not stop early for want of a device.
          </p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <caption className="visually-hidden">
                Unmanaged next hops, ranked by how much reachability each conceals
              </caption>
              <thead>
                <tr>
                  <th>Address</th>
                  <th>Routed to by</th>
                  <th>Prefixes</th>
                  <th>Why it ranks here</th>
                </tr>
              </thead>
              <tbody>
                {(missing.data ?? []).map((item) => (
                  <tr key={item.address}>
                    <td className="mono">
                      {item.address}
                      {item.carries_default_route && (
                        <span className="pill pill--medium">default route</span>
                      )}
                    </td>
                    <td>{item.referenced_by.join(', ')}</td>
                    <td className="mono">{item.prefixes.slice(0, 3).join(', ')}</td>
                    <td className="finding__note">{item.reason}</td>
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
