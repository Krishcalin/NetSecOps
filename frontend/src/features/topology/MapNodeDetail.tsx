/** What one box on the map actually is.
 *
 * The map answers "how is this wired"; this answers "what is this, and what does it
 * see". Interfaces are the substance of it — a firewall's zones and addresses are what
 * every rule on it is written against — and they are the one thing the picture cannot
 * show for six hundred devices at once.
 *
 * **An empty finding count is not a clean device.** It is a device that either passed
 * every check that applies to it or has never been checked, and nothing on the map can
 * tell those apart, so the panel says so instead of showing a reassuring zero.
 */

import { Link } from 'react-router-dom';

import { SEVERITY_ORDER, tidyAddress, totalFindings } from './mapLayout';
import type { EstateMap, MapNode } from './types';

interface Props {
  node: MapNode;
  map: EstateMap;
  onSelect: (id: string) => void;
}

export function MapNodeDetail({ node, map, onSelect }: Props) {
  const labels = new Map(map.nodes.map((entry) => [entry.id, entry.label]));
  const links = map.links.filter((link) => link.source === node.id || link.target === node.id);
  const findings = totalFindings(node.findings);

  if (node.kind === 'unmanaged') {
    return (
      <section className="card">
        <div className="card__header">
          <h2 className="card__title mono">{node.label}</h2>
        </div>
        <p className="finding__note">
          Routes in this estate point at this address and no device in the inventory answers for it,
          so every path that reaches here stops. That is a result, not a failure — it names exactly
          which device somebody would have to onboard to learn more. It may equally be an ISP
          router, a customer handoff, or a virtual address no single box owns.
        </p>
        <dl className="detail-grid">
          <dt>Routed to by</dt>
          <dd>
            {node.referenced_by.map((id) => (
              <button key={id} className="link-button" onClick={() => onSelect(id)}>
                {labels.get(id) ?? id}
              </button>
            ))}
          </dd>
          <dt>Carries a default route</dt>
          <dd>{node.carries_default_route ? 'Yes' : 'No'}</dd>
        </dl>
      </section>
    );
  }

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">{node.label}</h2>
        <div className="card__actions">
          <Link className="button button--ghost button--small" to={`/inventory/${node.id}/config`}>
            Configuration
          </Link>
          {/* Offered whenever rules exist, in force or not: an access list bound to
              nothing is exactly the thing somebody opens the rulebase viewer to check. */}
          {node.has_rulebase && (
            <Link
              className="button button--ghost button--small"
              to={`/inventory/${node.id}/firewall`}
            >
              Rulebase
            </Link>
          )}
          {node.interfaces[0]?.addresses[0] && (
            // Prefilled rather than merely linked: the whole reason to open a device on
            // a map is usually to ask what it can reach, and retyping an address read
            // off the screen is where a typo turns into a wrong answer.
            <Link
              className="button button--small"
              to={`/topology?source=${encodeURIComponent(address(node))}`}
            >
              Trace from here
            </Link>
          )}
        </div>
      </div>

      <dl className="detail-grid">
        <dt>Class</dt>
        <dd>
          {node.device_class ?? 'unknown'}
          {node.inspects ? (
            ' · carries a rulebase that is in force'
          ) : node.has_rulebase ? (
            // The distinction the map itself cannot draw, and the one that decides
            // whether this device is a control: an access list that exists and is bound
            // to no interface filters management access, or nothing at all.
            <span className="finding__note">
              {' '}
              · has rules, none bound to an interface — they filter no traffic crossing this device
            </span>
          ) : (
            ' · no rulebase'
          )}
        </dd>
        <dt>Platform</dt>
        <dd>
          {node.platform ?? 'not recorded'}
          {node.vendor && ` (${node.vendor})`}
        </dd>
        <dt>Criticality</dt>
        <dd>{node.criticality ?? 'not set'}</dd>
        <dt>Routes</dt>
        <dd>
          {node.routes_known
            ? `${node.routes} in the forwarding table`
            : 'never parsed — this device was collected before forwarding tables were read, so it contributes nothing to any path'}
        </dd>
        <dt>Open findings</dt>
        <dd>
          {findings === 0 ? (
            <span className="finding__note">
              None open.{' '}
              {node.has_snapshot
                ? 'That means every check that applies here passed, or none has run — the map cannot tell those apart.'
                : 'No configuration has ever been stored for this device, so nothing has been checked.'}
            </span>
          ) : (
            <span className="pill-row">
              {SEVERITY_ORDER.filter((severity) => (node.findings[severity] ?? 0) > 0).map(
                (severity) => (
                  <span key={severity} className={`pill pill--${severity}`}>
                    {node.findings[severity]} {severity}
                  </span>
                ),
              )}
            </span>
          )}
        </dd>
      </dl>

      <h3 className="finding__heading">
        Interfaces
        {node.interface_count > node.interfaces.length && (
          <span className="finding__note">
            {' '}
            {node.interfaces.length} addressed, of {node.interface_count} configured
          </span>
        )}
      </h3>
      {node.interfaces.length === 0 ? (
        <p className="empty">
          No addressed interface reached the normalised model. The device is on the map and joins
          nothing, which is the same as being invisible to path analysis.
        </p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <caption className="visually-hidden">Addressed interfaces on {node.label}</caption>
            <thead>
              <tr>
                <th>Interface</th>
                <th>Addresses</th>
                <th>Zone</th>
              </tr>
            </thead>
            <tbody>
              {/* Keyed by position as well as name: nothing guarantees a device's
                  interface names are unique once they have been through a parser, and
                  two rows sharing a React key render as one. */}
              {node.interfaces.map((iface, index) => (
                <tr key={`${iface.name}-${index}`}>
                  <td className="mono">{iface.name}</td>
                  <td className="mono">{iface.addresses.map(tidyAddress).join(', ')}</td>
                  <td>{iface.zone ?? <span className="finding__note">no zone</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h3 className="finding__heading">Connected to</h3>
      {links.length === 0 ? (
        <p className="empty">
          Nothing in the inventory routes to this device and it routes to nothing. Either it is
          genuinely standalone — a management server forwards nothing — or its routes were never
          collected.
        </p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <caption className="visually-hidden">Devices adjacent to {node.label}</caption>
            <thead>
              <tr>
                <th>Neighbour</th>
                <th>Out of</th>
                <th>Into</th>
                <th>Via</th>
                <th>Prefixes</th>
              </tr>
            </thead>
            <tbody>
              {links.map((link) => {
                const other = link.source === node.id ? link.target : link.source;
                const near =
                  link.source === node.id ? link.source_interface : link.target_interface;
                const far = link.source === node.id ? link.target_interface : link.source_interface;
                return (
                  <tr key={link.id}>
                    <td>
                      <button className="link-button" onClick={() => onSelect(other)}>
                        {labels.get(other) ?? other}
                      </button>
                      {/* One direction only is an asymmetry worth naming: traffic
                          leaves here and nothing comes back by this route. */}
                      {!link.bidirectional && (
                        <span className="finding__note"> one-way — only one end routes here</span>
                      )}
                    </td>
                    <td className="mono">{near ?? '—'}</td>
                    <td className="mono">{far ?? '—'}</td>
                    <td className="mono">{link.via.join(', ')}</td>
                    <td>
                      {link.prefixes}
                      {link.carries_default && (
                        <span className="pill pill--medium">default route</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/** The address a trace should start from: the first one on the first addressed
 *  interface, stripped of its mask. */
function address(node: MapNode): string {
  const first = node.interfaces[0]?.addresses[0] ?? '';
  return first.split('/')[0] ?? '';
}
