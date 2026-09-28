/** Device inventory (FR-INV-01, FR-INV-04, FR-INV-07, FR-INV-08).
 *
 * A device imported from a manager arrives here **already in inventory and excluded from
 * every job** until somebody approves it. Nothing surfaced that, so the promotion path
 * had no end: a Panorama import put devices in the database that appeared in this table
 * exactly like the rest, were never collected from, and produced no finding — which is
 * the same screen as a device with nothing wrong.
 *
 * So the queue is above the table rather than a filter on it. A pending device is not a
 * variety of inventory row; it is a decision somebody owes.
 */

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { NavLink } from 'react-router-dom';

import { ApiError, api } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import type { Device, DeviceGroup, Paginated, PendingDevice } from '../features/inventory/types';
import {
  DEVICE_CLASSES,
  STATUS_PILLS,
  VENDOR_LABELS,
  classLabel,
} from '../features/inventory/types';
import { PageHeader } from '../components/PageHeader';
import { useUrlFilters } from './useUrlFilters';

const PAGE_SIZE = 25;

function message(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.problem.detail : fallback;
}

/** FR-INV-04 — what a manager imported, awaiting a human.
 *
 * The manager's attribution is shown in full because that is what the decision rests on.
 * Approving admits the device to assessment, which means NetSecOps starts connecting to
 * it; the model, serial and OS version are how somebody tells "a firewall we run" from
 * "a firewall the managed-service provider runs that happens to be in this Panorama".
 */
function PendingReview() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const pending = useQuery({
    queryKey: ['devices-pending-review'],
    queryFn: () => api.get<PendingDevice[]>('/devices/pending-review'),
  });

  const approve = useMutation({
    mutationFn: (deviceId: string) => api.post<PendingDevice>(`/devices/${deviceId}/approve`),
    onSuccess: () => {
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ['devices-pending-review'] });
      void queryClient.invalidateQueries({ queryKey: ['devices'] });
    },
    onError: (err) => setError(message(err, 'The device could not be approved.')),
  });

  const rows = pending.data ?? [];
  if (rows.length === 0) {
    // Silent when the queue is empty. An "all clear" banner on every visit is one people
    // stop reading, and this needs to be noticed on the day it is not empty.
    return null;
  }

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">
          {rows.length} device{rows.length === 1 ? '' : 's'} awaiting approval
        </h2>
      </div>
      <p className="field__help">
        Imported from a manager and excluded from every job until approved, so nothing has connected
        to them yet. Approving admits a device to assessment — check that each one is yours to reach
        before you do.
      </p>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Management IP</th>
              <th>Platform</th>
              <th>Model</th>
              <th>Version</th>
              <th>Serial</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((device) => (
              <tr key={device.id}>
                <td>{device.hostname ?? <span className="muted">unnamed</span>}</td>
                <td className="mono">{String(device.mgmt_ip)}</td>
                <td className="mono">
                  {device.platform ?? <span className="muted">not classified</span>}
                </td>
                <td className="mono">{device.model ?? '—'}</td>
                <td className="mono">{device.os_version ?? '—'}</td>
                <td className="mono">{device.serial_number ?? '—'}</td>
                <td className="table__actions">
                  {can('device:write') && (
                    <button
                      className="button button--small"
                      disabled={approve.isPending}
                      onClick={() => approve.mutate(device.id)}
                    >
                      Approve
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/** What a device was derived from, and what was derived from it (FR-INV-04).
 *
 * `parent_device_id` shipped in Phase 1 and nothing ever rendered it, because a UUID
 * tells an operator nothing. A firewall imported from a Panorama and an access point
 * derived from a wireless controller both appeared as rows with an unexplained origin
 * — and the access points made it acute, because one controller contributes hundreds
 * at a time.
 *
 * Both directions, because one without the other is not worth much: the child names
 * its parent, and the parent offers a way into its children. A count with nothing to
 * click is a number, and a filter nobody knows to ask for is not a feature.
 */
function DeviceOrigin({
  device,
  onFilter,
}: {
  device: Device;
  onFilter: (id: string) => void;
}) {
  if (device.parent_device_id && device.parent_hostname) {
    // Named by relationship rather than by the word "parent". A controller serves its
    // access points and a manager manages its firewalls; both are `parent_device_id`
    // and they are not the same sentence.
    const relation =
      device.parent_device_class === 'wireless_controller' ? 'served by' : 'managed by';

    return (
      <span className="origin">
        {relation}{' '}
        <button
          type="button"
          className="origin__link"
          onClick={() => onFilter(device.parent_device_id!)}
        >
          {device.parent_hostname}
        </button>
      </span>
    );
  }

  if (device.child_count > 0) {
    return (
      <span className="origin">
        <button type="button" className="origin__link" onClick={() => onFilter(device.id)}>
          {device.child_count.toLocaleString()}{' '}
          {device.child_count === 1 ? 'derived device' : 'derived devices'}
        </button>
      </span>
    );
  }

  return null;
}

export function InventoryPage() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState('');
  const [groupId, setGroupId] = useState('');
  // In the URL rather than in component state, so the sidebar's "Switches" is a real
  // link — and so a filtered inventory can be sent to somebody.
  const filters = useUrlFilters({ device_class: '', parent_id: '' });
  const deviceClass = filters.read('device_class');
  const className = deviceClass ? classLabel(deviceClass, 'plural') : undefined;
  // In the URL like the type filter, and for the same two reasons: a controller's
  // access points are a view worth sending to somebody, and the back button should
  // leave it rather than leave the page.
  const parentId = filters.read('parent_id');
  const [confirmArchive, setConfirmArchive] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const archive = useMutation({
    mutationFn: (deviceId: string) => api.post<Device>(`/devices/${deviceId}/archive`),
    onSuccess: () => {
      setError(null);
      setConfirmArchive(null);
      void queryClient.invalidateQueries({ queryKey: ['devices'] });
    },
    onError: (err) => setError(message(err, 'The device could not be archived.')),
  });

  const groups = useQuery({
    queryKey: ['device-groups'],
    queryFn: () => api.get<DeviceGroup[]>('/device-groups'),
  });

  const devices = useQuery({
    queryKey: ['devices', offset, search, groupId, deviceClass, parentId],
    queryFn: () => {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(offset),
      });
      if (search) params.set('search', search);
      if (groupId) params.set('group_id', groupId);
      if (deviceClass) params.set('device_class', deviceClass);
      if (parentId) params.set('parent_id', parentId);
      return api.get<Paginated<Device>>(`/devices?${params}`);
    },
  });

  const total = devices.data?.meta.total ?? 0;

  const setParentFilter = (id: string) => {
    filters.write({ parent_id: id });
    setOffset(0);
  };

  // The name of the device being filtered on, taken from the rows themselves: a child
  // carries its parent's name, and a parent filtered to its own children is not on the
  // page. Falls back to nothing rather than to the id — a banner reading "derived from
  // 8f3c-…" is the UUID problem this whole change is about.
  const parentName = parentId
    ? devices.data?.data.find((d) => d.parent_device_id === parentId)?.parent_hostname
    : undefined;

  return (
    <div className="page">
      {/* The heading names the filtered view, so a reader arriving from the sidebar —
          or from a link somebody sent them — is told what they are looking at rather
          than being shown a short inventory with no explanation for its shortness. */}
      <PageHeader
        icon="inventory"
        title={className ?? 'Inventory'}
        subtitle={
          className
            ? `${className} you have access to. NetSecOps reads from these and never writes to them.`
            : 'Devices you have access to. NetSecOps reads from these and never writes to them.'
        }
      />

      {/* A filtered view says so and offers the way out. Without this the page is a
          short inventory with no explanation for its shortness — the same failure the
          heading above avoids for the type filter, and worse here because nothing in
          the toolbar shows a parent filter is in force. */}
      {parentId && (
        <div className="alert alert--info" role="status">
          Showing only devices derived from{' '}
          <strong>{parentName ?? 'one controller or manager'}</strong>.{' '}
          <button
            type="button"
            className="button button--ghost button--small"
            onClick={() => setParentFilter('')}
          >
            Show all devices
          </button>
        </div>
      )}

      <div className="toolbar">
        <label className="field field--inline">
          <span className="field__label">Search</span>
          <input
            className="field__input"
            value={search}
            placeholder="hostname, IP or serial"
            onChange={(e) => {
              setSearch(e.target.value);
              setOffset(0);
            }}
          />
        </label>

        {/* On the page as well as in the sidebar, and reading from the same URL
            parameter — so the two cannot disagree, and the five classes the sidebar
            does not name are still reachable. */}
        <label className="field field--inline">
          <span className="field__label">Type</span>
          <select
            className="field__input"
            value={deviceClass}
            onChange={(event) => {
              filters.write({ device_class: event.target.value });
              setOffset(0);
            }}
          >
            <option value="">All types</option>
            {DEVICE_CLASSES.map((value) => (
              <option key={value} value={value}>
                {classLabel(value, 'plural')}
              </option>
            ))}
          </select>
        </label>

        <label className="field field--inline">
          <span className="field__label">Group</span>
          <select
            className="field__input"
            value={groupId}
            onChange={(e) => {
              setGroupId(e.target.value);
              setOffset(0);
            }}
          >
            <option value="">All groups</option>
            {groups.data?.map((group) => (
              <option key={group.id} value={group.id}>
                {group.name}
              </option>
            ))}
          </select>
        </label>

        {can('device:write') && (
          <NavLink className="button button--primary button--small" to="/inventory/import">
            Import CSV
          </NavLink>
        )}
        {/* Not behind `device:write`: the group filter directly above this is useless
            until groups exist, and seeing what they are is a read. */}
        <NavLink className="button button--ghost button--small" to="/inventory/organisation">
          Sites, groups and tags
        </NavLink>
      </div>

      <PendingReview />

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      {devices.isLoading ? (
        <p className="page-loading">Loading…</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>Management IP</th>
                <th>Vendor</th>
                <th>Platform</th>
                <th>Status</th>
                <th>Criticality</th>
                <th>Last collected</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {devices.data?.data.map((device) => (
                <tr
                  key={device.id}
                  className={device.status === 'active' ? undefined : 'row--muted'}
                >
                  {/* The origin goes under the name rather than in a column of its
                      own. Almost every row has nothing to say here, so a column would
                      be mostly empty and would cost width on a table that already has
                      more than it can spend. */}
                  <td>
                    {device.hostname ?? <span className="muted">unnamed</span>}
                    <DeviceOrigin device={device} onFilter={setParentFilter} />
                  </td>
                  <td className="mono">{device.mgmt_ip}</td>
                  <td>{VENDOR_LABELS[device.vendor]}</td>
                  <td className="mono">
                    {device.platform ?? <span className="muted">not classified</span>}
                  </td>
                  <td>
                    {/* Stated rather than implied by an empty "last collected". Three
                        of the four statuses mean the device is excluded from every
                        job, so it will never have been collected from — and without
                        this they all produce the same blank row.

                        Read from a map rather than a ternary chain. The chain ended in
                        an `else` that said "active", so a status it had not heard of
                        rendered as the one thing it definitely was not: `inventory_only`
                        arrived and every access point in the estate reported itself as
                        a device under assessment. */}
                    {STATUS_PILLS[device.status] ? (
                      <span className={`pill pill--${STATUS_PILLS[device.status]!.tone}`}>
                        {STATUS_PILLS[device.status]!.label}
                      </span>
                    ) : (
                      <span className="muted">active</span>
                    )}
                  </td>
                  <td>
                    <span className={`pill pill--${device.criticality}`}>{device.criticality}</span>
                  </td>
                  <td>
                    {device.last_collected_at ? (
                      new Date(device.last_collected_at).toLocaleString()
                    ) : (
                      <span className="muted">never</span>
                    )}
                  </td>
                  <td className="table__actions">
                    <NavLink
                      className="button button--ghost button--small"
                      to={`/inventory/${device.id}/config`}
                    >
                      Configuration
                    </NavLink>
                    {/* Not offered for an access point derived from a controller.
                        Archiving one would be undone by that controller's next
                        collection, which re-derives the list — a control that looks
                        like it worked and is reverted twenty minutes later is worse
                        than no control. Removing the access point is done by taking
                        it off the controller. */}
                    {can('device:write') &&
                      device.status !== 'archived' &&
                      device.status !== 'inventory_only' &&
                      (confirmArchive === device.id ? (
                        <>
                          <button
                            className="button button--ghost button--small"
                            disabled={archive.isPending}
                            onClick={() => archive.mutate(device.id)}
                          >
                            Yes, archive
                          </button>
                          <button
                            className="button button--ghost button--small"
                            onClick={() => setConfirmArchive(null)}
                          >
                            Cancel
                          </button>
                        </>
                      ) : (
                        <button
                          className="button button--ghost button--small"
                          onClick={() => setConfirmArchive(device.id)}
                        >
                          Archive
                        </button>
                      ))}
                  </td>
                </tr>
              ))}
              {devices.data?.data.length === 0 && (
                <tr>
                  <td colSpan={8} className="table__empty">
                    {search || groupId
                      ? 'No devices match this filter.'
                      : 'No devices yet. Import a CSV or add one to get started.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      <div className="pager">
        <button
          className="button button--ghost button--small"
          disabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
        >
          Previous
        </button>
        <span className="pager__status">
          {total === 0 ? '0' : `${offset + 1}–${Math.min(offset + PAGE_SIZE, total)}`} of{' '}
          {total.toLocaleString()}
        </span>
        <button
          className="button button--ghost button--small"
          disabled={offset + PAGE_SIZE >= total}
          onClick={() => setOffset(offset + PAGE_SIZE)}
        >
          Next
        </button>
      </div>
    </div>
  );
}
