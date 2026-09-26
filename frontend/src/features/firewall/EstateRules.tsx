/** Rules matching one filter across every firewall (FR-FW-07).
 *
 * "Show me every any-any-any rule in the estate" could not be asked before this. Every
 * firewall route was scoped to one device, so the question meant opening each firewall
 * in turn and re-applying the same filter by hand — even though the analysis had
 * already produced the issue key on every one of them.
 *
 * Two things this deliberately does not do.
 *
 * **It does not merge the estate into one sortable table**, which is the obvious shape
 * for a list like this and the wrong one. A rule is shadowed because of *where it sits*,
 * so order within a device is meaning; a severity-sorted estate table would quietly
 * destroy the fact that makes half its own rows true. Rules stay grouped by device and
 * in evaluation order.
 *
 * **It does not hide the devices it could not read.** A firewall with no snapshot, or
 * one whose policy failed to parse, is listed with the reason — because "no device has
 * this rule" and "no device we could read has this rule" are different claims, and only
 * the second one is ever true here.
 */

import { Link } from 'react-router-dom';

import type { EstateRules as EstateRulesPayload } from './types';

function DeviceGroup({ row }: { row: EstateRulesPayload['devices'][number] }) {
  const name = row.hostname ?? row.device_id;

  if (row.not_searched) {
    return (
      <li className="estate__device estate__device--unsearched">
        <div className="estate__head">
          <h3 className="estate__name">{name}</h3>
          <span className="pill pill--unknown">not searched</span>
        </div>
        <p className="estate__reason">{row.not_searched}</p>
      </li>
    );
  }

  return (
    <li className="estate__device">
      <div className="estate__head">
        <h3 className="estate__name">
          <Link to={`/firewall?device=${row.device_id}`}>{name}</Link>
        </h3>
        <span className="estate__count">
          {row.matched} of {row.rules_total} rules
        </span>
        {row.rules_not_retrieved ? (
          // The device's rulebase arrived short, so "no match here" is not a finding
          // about the device — it is a finding about what we received.
          <span className="pill pill--warn">{row.rules_not_retrieved} rules never retrieved</span>
        ) : null}
      </div>

      {row.matched === 0 ? (
        <p className="estate__reason">No rule on this firewall matches.</p>
      ) : (
        <table className="table estate__rules">
          <caption className="visually-hidden">
            Matching rules on {name}, in evaluation order
          </caption>
          <thead>
            <tr>
              <th scope="col">#</th>
              <th scope="col">Name</th>
              <th scope="col">Action</th>
              <th scope="col">Source</th>
              <th scope="col">Destination</th>
              <th scope="col">Service</th>
              <th scope="col">Breadth</th>
              <th scope="col">Issues</th>
            </tr>
          </thead>
          <tbody>
            {row.rules.map((rule) => (
              <tr key={rule.order}>
                <td className="mono">{rule.order}</td>
                <td>{rule.name}</td>
                <td>{rule.action}</td>
                <td className="mono">{rule.source}</td>
                <td className="mono">{rule.destination}</td>
                {/* An em dash, not 0, for a deny rule — the score does not apply to
                    it, and 0 would rank it as the tightest thing in the estate. */}
                <td className="mono">{rule.services}</td>
                <td>
                  {rule.permissiveness ? (
                    <>
                      {rule.permissiveness.understated && '≥'}
                      {rule.permissiveness.score}
                      <span className="visually-hidden"> breadth, {rule.permissiveness.band}</span>
                    </>
                  ) : (
                    <>
                      <span aria-hidden="true">—</span>
                      <span className="visually-hidden">breadth not scored, this rule denies</span>
                    </>
                  )}
                </td>
                <td>
                  {rule.issues.length === 0
                    ? '—'
                    : rule.issues.map((issue) => issue.issue).join(', ')}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </li>
  );
}

export function EstateRules({ data }: { data: EstateRulesPayload }) {
  return (
    <section className="card">
      <h2 className="card__title">Across the estate</h2>

      <p className="estate__summary">
        <strong>{data.matched_total}</strong> matching {data.matched_total === 1 ? 'rule' : 'rules'}{' '}
        on {data.devices_searched} {data.devices_searched === 1 ? 'firewall' : 'firewalls'}
        {data.devices_not_searched > 0 && (
          <>
            {' · '}
            <strong>{data.devices_not_searched}</strong> could not be searched
          </>
        )}
      </p>

      {/* Stated on every result, not only when something went wrong. An unqualified
          "nothing matches" would be read as a guarantee about the whole estate. */}
      {data.limitations.length > 0 && (
        <ul className="estate__limitations" role="note">
          {data.limitations.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}

      {data.devices.length === 0 ? (
        <p className="empty">No firewalls in inventory yet.</p>
      ) : (
        <ul className="estate__list">
          {data.devices.map((row) => (
            <DeviceGroup key={String(row.device_id)} row={row} />
          ))}
        </ul>
      )}
    </section>
  );
}
