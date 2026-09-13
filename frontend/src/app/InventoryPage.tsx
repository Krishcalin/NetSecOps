/** Device inventory (FR-INV-01, FR-INV-07, FR-INV-08). */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { NavLink } from 'react-router-dom';

import { api } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import type { Device, DeviceGroup, Paginated } from '../features/inventory/types';
import { VENDOR_LABELS } from '../features/inventory/types';

const PAGE_SIZE = 25;

export function InventoryPage() {
  const { can } = useAuth();
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState('');
  const [groupId, setGroupId] = useState('');

  const groups = useQuery({
    queryKey: ['device-groups'],
    queryFn: () => api.get<DeviceGroup[]>('/device-groups'),
  });

  const devices = useQuery({
    queryKey: ['devices', offset, search, groupId],
    queryFn: () => {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(offset),
      });
      if (search) params.set('search', search);
      if (groupId) params.set('group_id', groupId);
      return api.get<Paginated<Device>>(`/devices?${params}`);
    },
  });

  const total = devices.data?.meta.total ?? 0;

  return (
    <div className="page">
      <header className="page__header">
        <h1>Inventory</h1>
        <p className="page__subtitle">
          Devices you have access to. NetSecOps reads from these and never writes to them.
        </p>
      </header>

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
      </div>

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
                <th>Criticality</th>
                <th>Last collected</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {devices.data?.data.map((device) => (
                <tr key={device.id}>
                  <td>{device.hostname ?? <span className="muted">unnamed</span>}</td>
                  <td className="mono">{device.mgmt_ip}</td>
                  <td>{VENDOR_LABELS[device.vendor]}</td>
                  <td className="mono">
                    {device.platform ?? <span className="muted">not classified</span>}
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
                  <td>
                    <NavLink
                      className="button button--ghost button--small"
                      to={`/inventory/${device.id}/config`}
                    >
                      Configuration
                    </NavLink>
                  </td>
                </tr>
              ))}
              {devices.data?.data.length === 0 && (
                <tr>
                  <td colSpan={7} className="table__empty">
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
