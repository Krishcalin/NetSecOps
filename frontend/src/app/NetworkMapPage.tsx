/** The network map (FR-TOPO-02).
 *
 * Path analysis answers one question at a time and assumes you already know which one
 * to ask. This is the page you open before that: the whole estate, wired the way its
 * own routing tables say it is wired.
 *
 * **It opens on one group, not on all of them.** A six-hundred-device estate drawn at
 * once is a grey smear, and a picture nobody can read is worse than a list. The group
 * list says exactly what is not being shown and switching is one click, so nothing is
 * hidden — it is just not all drawn at the same size.
 *
 * **Groups are components of the routing graph, and their names usually are not.** Two
 * devices are in one group when a packet can actually travel between them. The label is
 * a site where one is configured and a shared hostname prefix otherwise, and the page
 * says which so nobody reads "london" as a site that somebody defined.
 */

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { api } from '../api/client';
import { EstateMapView } from '../features/topology/EstateMapView';
import { MapNodeDetail } from '../features/topology/MapNodeDetail';
import { layoutMap, totalFindings } from '../features/topology/mapLayout';
import type { EstateMap } from '../features/topology/types';
import { PageHeader } from '../components/PageHeader';

const ALL = '__all__';

export function NetworkMapPage() {
  const [group, setGroup] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());

  const query = useQuery({
    queryKey: ['topology-map'],
    queryFn: () => api.get<EstateMap>('/topology/map?limit=5000'),
  });

  const map = query.data;

  // The largest group, with the label as the tie-break so two equal groups do not swap
  // places between loads. Chosen here rather than stored, because a default that
  // depends on what somebody looked at last is a different picture each visit.
  const fallback = useMemo(() => {
    if (!map || map.groups.length === 0) return null;
    return [...map.groups].sort(
      (a, b) => b.devices - a.devices || a.label.localeCompare(b.label),
    )[0]!.id;
  }, [map]);

  const active = group ?? fallback;
  // Memoised because it is the layout's dependency: rebuilt every render, it would
  // re-lay six hundred boxes out on every keystroke in the search box.
  const showing = useMemo(() => (active === ALL || active === null ? [] : [active]), [active]);

  const matches = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!map || term.length === 0) return new Set<string>();
    return new Set(
      map.nodes
        .filter(
          (node) =>
            node.label.toLowerCase().includes(term) ||
            (node.platform ?? '').toLowerCase().includes(term) ||
            node.interfaces.some((iface) =>
              iface.addresses.some((address) => address.includes(term)),
            ),
        )
        .map((node) => node.id),
    );
  }, [map, search]);

  const layout = useMemo(
    () => (map ? layoutMap(map, { groups: showing, expanded }) : null),
    [map, showing, expanded],
  );

  const selectedNode = map?.nodes.find((node) => node.id === selected) ?? null;

  if (query.isLoading) return <div className="page-loading">Loading the map…</div>;
  if (query.isError || !map || !layout) {
    return (
      <div className="page">
        <div className="alert alert--error" role="alert">
          The map could not be built. Path analysis and the device inventory are unaffected.
        </div>
      </div>
    );
  }

  const drawn = map.groups.find((entry) => entry.id === active);

  return (
    <div className="page">
      <PageHeader
        icon="map"
        title="Network map"
        subtitle="Every device in the inventory, joined where one device's route points at another one's interface address. Assembled entirely from stored configuration — nothing is sent, no topology protocol is walked, and no packet leaves this server."
      />

      <div className="map-stats">
        <Stat label="Devices" value={map.devices} />
        <Stat label="Connections" value={map.links.length} />
        <Stat label="Groups" value={map.groups.length} />
        <Stat
          label="Boundary addresses"
          value={map.unmanaged}
          note="routed to, and not in the inventory"
        />
        <Stat
          label="Joined to nothing"
          value={map.isolated}
          note="standalone, or never collected"
        />
      </div>

      {map.devices_without_route_data > 0 && (
        <div className="alert alert--info" role="note">
          {map.devices_without_route_data} device(s) were collected before forwarding tables were
          parsed. They are on the map and contribute no strands — a connection they should have made
          is simply absent rather than wrong.
        </div>
      )}

      {map.omitted_devices > 0 && (
        <div className="alert alert--warning" role="note">
          {map.omitted_devices} device(s) in {map.omitted_groups.length} group(s) are not on this
          map: the estate exceeded the request limit. Whole groups were dropped rather than parts of
          them, because half a component is a picture of a network that does not exist. Omitted:{' '}
          {map.omitted_groups.join(', ')}.
        </div>
      )}

      <div className="map-shell">
        <aside className="map-side">
          <label className="field">
            <span className="field__label">Find a device</span>
            <input
              className="field__input"
              value={search}
              placeholder="hostname, platform or address"
              onChange={(event) => setSearch(event.target.value)}
            />
          </label>

          <h2 className="finding__heading">Groups</h2>
          <p className="finding__note">
            A group is a set of devices a packet can actually travel between — a connected component
            of the routing graph, not a tag or a folder.
          </p>
          <div className="map-grouplist">
            <button
              className={`map-group${active === ALL ? ' is-active' : ''}`}
              onClick={() => {
                setGroup(ALL);
                setSelected(null);
              }}
            >
              <span className="map-group__name">All groups</span>
              <span className="map-group__meta">
                {map.devices} devices — large and slow to read
              </span>
            </button>
            {map.groups.map((entry) => (
              <button
                key={entry.id}
                className={`map-group${active === entry.id ? ' is-active' : ''}`}
                onClick={() => {
                  setGroup(entry.id);
                  setSelected(null);
                }}
              >
                <span className="map-group__name">{entry.label}</span>
                <span className="map-group__meta">
                  {entry.devices} device{entry.devices === 1 ? '' : 's'}
                  {entry.firewalls > 0 && `, ${entry.firewalls} with a rulebase`}
                  {entry.unmanaged > 0 && `, ${entry.unmanaged} boundary`}
                  {entry.label_source !== 'site' && ' · inferred name'}
                </span>
              </button>
            ))}
          </div>

          {search.trim().length > 0 && (
            <>
              <h2 className="finding__heading">
                {matches.size} match{matches.size === 1 ? '' : 'es'}
              </h2>
              {/* Also the keyboard path onto the picture. The map itself is one image
                  with a text alternative; this list is where a device is reached, and
                  selecting one here highlights it there. */}
              <ul className="map-matchlist">
                {map.nodes
                  .filter((node) => matches.has(node.id))
                  .slice(0, 50)
                  .map((node) => (
                    <li key={node.id}>
                      <button
                        className="link-button"
                        onClick={() => {
                          setGroup(node.group);
                          setSelected(node.id);
                        }}
                      >
                        {node.label}
                      </button>
                      <span className="finding__note">
                        {' '}
                        {node.device_class ?? node.kind}
                        {totalFindings(node.findings) > 0 &&
                          ` · ${totalFindings(node.findings)} open`}
                      </span>
                    </li>
                  ))}
              </ul>
              {matches.size > 50 && <p className="finding__note">First 50 shown.</p>}
            </>
          )}
        </aside>

        <div className="map-main">
          {drawn && (
            <p className="finding__note">
              Showing <strong>{drawn.label}</strong> — {drawn.devices} device
              {drawn.devices === 1 ? '' : 's'} over {drawn.tiers} tier
              {drawn.tiers === 1 ? '' : 's'}, laid out from the estate edge inwards.{' '}
              {drawn.label_source === 'site'
                ? 'Named after the site it is assigned to.'
                : 'Named after what its hostnames have in common — nothing configured says this is a site.'}
            </p>
          )}
          <EstateMapView
            layout={layout}
            selected={selected}
            matches={matches}
            onSelect={setSelected}
            onToggleBundle={(key) =>
              setExpanded((current) => {
                const next = new Set(current);
                if (next.has(key)) next.delete(key);
                else next.add(key);
                return next;
              })
            }
          />
        </div>
      </div>

      {selectedNode && <MapNodeDetail node={selectedNode} map={map} onSelect={setSelected} />}
    </div>
  );
}

function Stat({ label, value, note }: { label: string; value: number; note?: string }) {
  return (
    <div className="map-stat">
      <span className="map-stat__value">{value}</span>
      <span className="map-stat__label">{label}</span>
      {note && <span className="map-stat__note">{note}</span>}
    </div>
  );
}
