/** What a device can see on the wire, from CDP and LLDP (FR-TOPO-01).
 *
 * **This is the only panel in the product showing an adjacency that was stated rather
 * than inferred.** Everywhere else — the map, the path walk, the missing-device report —
 * an edge exists because a route's next hop fell inside an interface's subnet, which
 * concludes that two devices are connected. A neighbour entry is one of them saying so.
 * The two disagree often enough to matter: a routed adjacency crossing an unmanaged
 * access switch has no cable behind it, and a cable into a port nobody routes over does
 * not appear on the map at all.
 *
 * **The empty state carries the weight here.** A list of no neighbours has four causes
 * that look identical, and only one of them is "this device has no neighbours": the
 * protocols may be disabled, they may be enabled and nothing answered, the device may
 * never have been collected, or it may have been collected before these commands were
 * issued. Showing an empty table for all four is the failure this codebase is named
 * for, so the panel says which one it is looking at and never guesses.
 *
 * **A match is shown with how it was made.** A full hostname, a short hostname and a
 * management address are three different strengths of claim arriving in one field, and
 * rendering them alike invites the weakest to be read as the strongest.
 */

import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';

import { api } from '../../api/client';
import { MATCH_LABELS, type DeviceNeighbours, type Neighbour } from './types';

/** Why the table is empty, in the device's own terms.
 *
 * Returns null where there *are* neighbours. Everything else is a distinct fact and
 * gets its own sentence — in particular "enabled and nothing answered" is a real
 * finding on a switch that should have uplinks, and is invisible if it reads the same
 * as "disabled".
 */
function emptyReason(data: DeviceNeighbours): string | null {
  if (data.neighbours.length > 0) return null;

  if (!data.snapshot_id) {
    return 'Nothing has been collected from this device yet, so there is nothing to report. This is not a statement that it has no neighbours.';
  }

  const enabled = [
    data.cdp_enabled ? 'CDP' : null,
    data.lldp_enabled ? 'LLDP' : null,
  ].filter(Boolean);

  if (enabled.length > 0) {
    return `${enabled.join(' and ')} ${enabled.length > 1 ? 'are' : 'is'} enabled and the device reported no neighbours. On a switch with uplinks that is worth looking at — a discovery protocol filtered on the ports that matter reports nothing while appearing to be on.`;
  }

  if (data.cdp_enabled === false && data.lldp_enabled === false) {
    return 'Both CDP and LLDP are disabled on this device, so it reports no neighbours and cannot. Layer-2 adjacency for it has to come from the devices around it.';
  }

  return 'This device reported no neighbours, and whether the discovery protocols are enabled could not be determined from its configuration — so an empty list here is not evidence either way.';
}

function NeighbourRow({ entry }: { entry: Neighbour }) {
  return (
    <tr>
      <td className="mono">{entry.local_interface}</td>
      <td>
        <span className={`pill pill--${entry.protocol === 'cdp' ? 'info' : 'neutral'}`}>
          {entry.protocol.toUpperCase()}
        </span>
      </td>
      <td>
        {entry.device_id ? (
          <>
            <Link to={`/inventory/${entry.device_id}/config`}>{entry.remote_device}</Link>
            <span className="card__hint"> {MATCH_LABELS[entry.matched_by ?? ''] ?? ''}</span>
          </>
        ) : (
          /* Not an error and not a gap to chase: the far end may be a phone, an access
             point, a customer handoff, or a switch nobody has onboarded. Said plainly so
             it is not read as a collection failure. */
          <>
            {entry.remote_device ?? <em>did not say</em>}
            <span className="card__hint"> not in the inventory</span>
          </>
        )}
      </td>
      <td className="mono">{entry.remote_interface ?? '—'}</td>
      <td className="mono">{entry.remote_address ?? '—'}</td>
      <td>
        {entry.platform ?? '—'}
        {entry.capabilities.length > 0 && (
          <span className="card__hint"> {entry.capabilities.join(' · ')}</span>
        )}
      </td>
    </tr>
  );
}

export function NeighboursPanel({ deviceId }: { deviceId: string }) {
  const query = useQuery({
    queryKey: ['device-neighbours', deviceId],
    queryFn: () => api.get<DeviceNeighbours>(`/devices/${deviceId}/neighbours`),
  });

  // Silent rather than an error banner: a reader without SNAPSHOT_READ has no business
  // being told what they cannot see, and the rest of the page still works.
  if (query.isError) return null;

  const data = query.data;
  const reason = data ? emptyReason(data) : null;

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">Neighbours</h2>
        {data && data.neighbours.length > 0 && (
          <span className="card__hint">
            {data.matched} of {data.neighbours.length} resolve to a device in this inventory
          </span>
        )}
      </div>

      <p className="card__hint">
        Reported by the device itself over CDP and LLDP — a cable it says is there, rather
        than a path inferred from its routing table. The two protocols are listed
        separately because they frequently disagree about the same link.
      </p>

      {query.isLoading ? (
        <p className="page-loading">Loading…</p>
      ) : reason ? (
        <p className="empty">{reason}</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Local port</th>
                <th>Protocol</th>
                <th>Far end</th>
                <th>Its port</th>
                <th>Address</th>
                <th>Platform</th>
              </tr>
            </thead>
            <tbody>
              {data?.neighbours.map((entry, index) => (
                <NeighbourRow
                  // Nothing on a neighbour entry is unique on its own: one port can carry
                  // a CDP and an LLDP entry for the same far end, and a trunk to a stack
                  // reports several. Protocol plus port plus index is stable for a render.
                  key={`${entry.protocol}-${entry.local_interface}-${index}`}
                  entry={entry}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
