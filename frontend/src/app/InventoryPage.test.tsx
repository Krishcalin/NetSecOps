/** The promotion path's other end (FR-INV-04).
 *
 * A device imported from a manager lands in inventory already excluded from every job.
 * Nothing surfaced that, so a Panorama import produced rows that looked exactly like
 * every other row, were never collected from, and yielded no finding — which is the same
 * screen as a device with nothing wrong.
 *
 * So these are mostly about a distinction surviving to the table: awaiting approval,
 * archived and active are three different reasons for an empty "last collected", and
 * rendering them the same is what made the queue invisible.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { InventoryPage } from './InventoryPage';
import { api } from '../api/client';

let granted = new Set(['device:read', 'device:write']);

vi.mock('../features/auth/useAuth', () => ({
  useAuth: () => ({ can: (permission: string) => granted.has(permission) }),
}));

const ACTIVE = {
  id: 'd1',
  mgmt_ip: '10.0.0.1',
  hostname: 'core-sw-01',
  vendor: 'cisco',
  platform: 'cisco_ios',
  criticality: 'high',
  status: 'active',
  last_collected_at: '2026-09-20T09:00:00Z',
};

const PENDING_IN_TABLE = {
  ...ACTIVE,
  id: 'd2',
  hostname: 'imported-fw-01',
  status: 'pending_review',
  last_collected_at: null,
};

const PENDING = {
  id: 'd2',
  hostname: 'imported-fw-01',
  mgmt_ip: '10.0.0.2',
  vendor: 'paloalto',
  platform: 'panos',
  device_class: 'firewall',
  serial_number: '00112233',
  model: 'PA-3220',
  os_version: '11.0.2',
  parent_device_id: 'mgr1',
  facts: {},
};

let devices: unknown[] = [];
let pending: unknown[] = [];

/** The main inventory table — the one with a Status column.
 *
 * The approval queue is a table too and shares hostnames with it, so an unscoped row
 * lookup finds whichever comes first in the DOM. */
function inventoryTable(): HTMLElement {
  const table = screen
    .getAllByRole('table')
    .find((candidate) => within(candidate).queryByText('Status') !== null);
  if (!table) throw new Error('no table with a Status column');
  return table;
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <InventoryPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('InventoryPage', () => {
  beforeEach(() => {
    granted = new Set(['device:read', 'device:write']);
    devices = [ACTIVE, PENDING_IN_TABLE];
    pending = [PENDING];
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/devices/pending-review')) return pending as never;
      if (path.startsWith('/devices')) {
        return { data: devices, meta: { total: devices.length } } as never;
      }
      if (path.startsWith('/device-groups')) return [] as never;
      return { data: [], meta: { total: 0 } } as never;
    });
  });

  afterEach(() => vi.restoreAllMocks());

  describe('the approval queue', () => {
    it('is shown above the table, not buried as a filter', async () => {
      // A pending device is not a variety of inventory row. It is a decision somebody
      // owes, and it was previously indistinguishable from an ordinary device.
      renderPage();

      expect(await screen.findByText(/awaiting approval/)).toBeInTheDocument();
    });

    it('shows what the manager said, because that is what the decision rests on', async () => {
      // Approving admits the device to assessment, which means NetSecOps starts
      // connecting to it. The model and serial are how somebody tells "a firewall we
      // run" from "one that happens to be in this Panorama".
      renderPage();

      const row = (await screen.findByText('imported-fw-01')).closest('tr')!;
      expect(within(row).getByText('PA-3220')).toBeInTheDocument();
      expect(within(row).getByText('00112233')).toBeInTheDocument();
    });

    it('approves the device it was asked about', async () => {
      const post = vi.spyOn(api, 'post').mockResolvedValue(PENDING as never);
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Approve' }));

      expect(post).toHaveBeenCalledWith('/devices/d2/approve');
    });

    it('says nothing at all when the queue is empty', async () => {
      // An "all clear" banner on every visit is one people stop reading, and this has
      // to be noticed on the day it is not empty.
      pending = [];
      renderPage();

      await screen.findByText('core-sw-01');
      expect(screen.queryByRole('heading', { name: /awaiting approval/ })).not.toBeInTheDocument();
    });

    it('offers no approval to someone who may only read', async () => {
      granted = new Set(['device:read']);
      renderPage();

      await screen.findByText(/awaiting approval/);
      expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    });
  });

  describe('status in the table', () => {
    it('distinguishes the three reasons a device has never been collected from', async () => {
      renderPage();

      await screen.findByText('core-sw-01');
      const row = within(inventoryTable()).getByText('imported-fw-01').closest('tr')!;
      expect(within(row).getByText('awaiting approval')).toBeInTheDocument();
      expect(within(row).getByText('never')).toBeInTheDocument();
    });

    it('marks an archived device rather than hiding it', async () => {
      devices = [{ ...ACTIVE, id: 'd3', hostname: 'retired-sw', status: 'archived' }];
      renderPage();

      await screen.findByText('retired-sw');
      const row = within(inventoryTable()).getByText('retired-sw').closest('tr')!;
      expect(within(row).getByText('archived')).toBeInTheDocument();
    });
  });

  describe('archiving', () => {
    it('asks first, because it removes the device from every job', async () => {
      const post = vi.spyOn(api, 'post').mockResolvedValue(ACTIVE as never);
      renderPage();

      const row = (await screen.findByText('core-sw-01')).closest('tr')!;
      await userEvent.click(within(row).getByRole('button', { name: 'Archive' }));
      expect(post).not.toHaveBeenCalled();

      await userEvent.click(within(row).getByRole('button', { name: 'Yes, archive' }));
      expect(post).toHaveBeenCalledWith('/devices/d1/archive');
    });

    it('is not offered on a device already archived', async () => {
      devices = [{ ...ACTIVE, status: 'archived' }];
      renderPage();

      await screen.findByText('core-sw-01');
      expect(screen.queryByRole('button', { name: 'Archive' })).not.toBeInTheDocument();
    });

    it('surfaces a refusal rather than failing silently', async () => {
      const { ApiError } = await import('../api/client');
      vi.spyOn(api, 'post').mockRejectedValue(
        new ApiError({
          type: 'about:blank',
          title: 'Conflict',
          status: 409,
          detail: 'A collection is running against this device.',
        }),
      );
      renderPage();

      const row = (await screen.findByText('core-sw-01')).closest('tr')!;
      await userEvent.click(within(row).getByRole('button', { name: 'Archive' }));
      await userEvent.click(within(row).getByRole('button', { name: 'Yes, archive' }));

      await waitFor(() =>
        expect(screen.getByRole('alert')).toHaveTextContent(/collection is running/),
      );
    });
  });
});
