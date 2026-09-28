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

function renderPage(url = '/inventory') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[url]}>
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

  describe('filtering by appliance type', () => {
    /** The sidebar's Routers, Switches and Firewalls are links into this page, so the
     *  filter has to live in the URL. In component state they would be a control the
     *  navigation could not reach — and the links would land on an unfiltered list
     *  that looks like the filter silently failed. */

    it('asks the API for only that class', async () => {
      const get = vi.spyOn(api, 'get');
      renderPage('/inventory?device_class=router');

      await waitFor(() => {
        const asked = get.mock.calls.map((call) => String(call[0])).find((u) => u.startsWith('/devices?'));
        expect(asked).toContain('device_class=router');
      });
    });

    it('asks for everything when no class is chosen', async () => {
      const get = vi.spyOn(api, 'get');
      renderPage();

      await waitFor(() => {
        const asked = get.mock.calls.map((call) => String(call[0])).find((u) => u.startsWith('/devices?'));
        expect(asked).toBeDefined();
        expect(asked).not.toContain('device_class');
      });
    });

    it('names the filtered view in the heading', async () => {
      // Otherwise a reader arriving from the sidebar sees a short inventory with no
      // explanation for its shortness.
      renderPage('/inventory?device_class=firewall');

      expect(await screen.findByRole('heading', { name: 'Firewalls', level: 1 })).toBeInTheDocument();
    });

    it('keeps the page control and the URL in agreement', async () => {
      // Two ways in — the sidebar and this select — reading one parameter, so they
      // cannot show different things.
      renderPage('/inventory?device_class=switch');

      const select = await screen.findByLabelText('Type');
      expect(select).toHaveValue('switch');
    });

    it('offers every device class, not just the three the sidebar names', async () => {
      // Seven of the ten have no navigation entry, so this control is the only way to
      // reach them — a class missing from both is one the product stores and nobody
      // can list. Pinned as the whole set rather than a few spot checks, because a
      // dropped entry is invisible: the option is simply not there.
      //
      // `deviceClasses.test.ts` checks the same list against the backend enum. This
      // one checks it reaches the control, which is the half that went wrong when
      // `load_balancer` and `waf` were added to a vocabulary that existed four times.
      renderPage();

      const select = await screen.findByLabelText('Type');
      const offered = within(select)
        .getAllByRole<HTMLOptionElement>('option')
        .map((option) => option.value);

      expect(offered).toEqual([
        '',
        'router',
        'switch',
        'firewall',
        'wireless_controller',
        'wireless_ap',
        'load_balancer',
        'waf',
        'manager',
        'aaa_server',
        'unknown',
      ]);
    });
  });

  describe('where a derived device came from', () => {
    /** `parent_device_id` shipped in Phase 1 and nothing rendered it for three
     *  phases, because a UUID tells an operator nothing. A firewall imported from a
     *  Panorama and an access point derived from a controller both appeared as rows
     *  with an unexplained origin — and one controller contributes hundreds at once.
     *
     *  Both directions are needed. A child that names its parent, with no way into
     *  the parent's other children, leaves somebody filtering by hand; a count with
     *  nothing to click is a number. */

    const CONTROLLER = {
      ...ACTIVE,
      id: 'c1',
      hostname: 'wlc-01',
      device_class: 'wireless_controller',
      parent_device_id: null,
      parent_hostname: null,
      parent_device_class: null,
      child_count: 3,
    };

    const ACCESS_POINT = {
      ...ACTIVE,
      id: 'ap1',
      hostname: 'AP-Floor1',
      device_class: 'wireless_ap',
      status: 'inventory_only',
      parent_device_id: 'c1',
      parent_hostname: 'wlc-01',
      parent_device_class: 'wireless_controller',
      child_count: 0,
    };

    const MANAGED_FIREWALL = {
      ...ACTIVE,
      id: 'fw1',
      hostname: 'edge-fw-01',
      parent_device_id: 'pano1',
      parent_hostname: 'panorama-01',
      parent_device_class: 'manager',
      child_count: 0,
    };

    it('names the controller an access point was derived from', async () => {
      devices = [CONTROLLER, ACCESS_POINT];
      renderPage();

      const row = (await screen.findByText('AP-Floor1')).closest('tr') as HTMLElement;
      expect(within(row).getByRole('button', { name: 'wlc-01' })).toBeInTheDocument();
      expect(row).toHaveTextContent('served by');
    });

    it('calls a manager relationship by its own name', async () => {
      // A controller serves its access points and a Panorama manages its firewalls.
      // Both are `parent_device_id`; they are not the same sentence, and only
      // `parent_device_class` separates them.
      devices = [MANAGED_FIREWALL];
      renderPage();

      const row = (await screen.findByText('edge-fw-01')).closest('tr') as HTMLElement;
      expect(row).toHaveTextContent('managed by');
      expect(row).not.toHaveTextContent('served by');
    });

    it('offers a way into a parent’s derived devices', async () => {
      devices = [CONTROLLER, ACCESS_POINT];
      renderPage();

      // Found by the button rather than by the controller's name: "wlc-01" appears
      // twice on this page, once as the controller's own row and once as the access
      // point's origin, which is the whole point of the feature.
      const link = await screen.findByRole('button', { name: '3 derived devices' });

      expect(link.closest('tr')).toHaveTextContent('wlc-01');
    });

    it('says nothing at all for an ordinary device', async () => {
      // Almost every row. A label on each one is a label nobody reads, and it is why
      // this is a sub-line rather than a column.
      devices = [{ ...ACTIVE, parent_device_id: null, parent_hostname: null, child_count: 0 }];
      renderPage();

      const row = (await screen.findByText('core-sw-01')).closest('tr') as HTMLElement;
      expect(within(row).queryByRole('button', { name: /derived|wlc/ })).toBeNull();
    });

    it('asks the server for one parent’s devices when the link is used', async () => {
      devices = [CONTROLLER, ACCESS_POINT];
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: '3 derived devices' }));

      await waitFor(() =>
        expect(vi.mocked(api.get).mock.calls.map((call) => call[0])).toContainEqual(
          expect.stringContaining('parent_id=c1'),
        ),
      );
    });

    it('explains a filtered view and offers the way out', async () => {
      // Otherwise it is a short inventory with no explanation for its shortness, and
      // nothing in the toolbar shows a parent filter is in force.
      devices = [ACCESS_POINT];
      renderPage('/inventory?parent_id=c1');

      // `findBy`, not `getBy`: the banner renders on the URL parameter alone, before
      // the rows it takes the name from have arrived.
      expect(await screen.findByText('wlc-01', { selector: 'strong' })).toBeInTheDocument();
      expect(screen.getByText(/Showing only devices derived from/)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Show all devices' })).toBeInTheDocument();
    });

    it('does not put a raw id in the banner when the name is unknown', async () => {
      // The banner names the parent from the rows themselves. With none to read it
      // says so in words — a banner reading "derived from 8f3c-…" is the UUID problem
      // this whole change is about.
      devices = [];
      renderPage('/inventory?parent_id=c1');

      expect(
        await screen.findByText(/one controller or manager/),
      ).toBeInTheDocument();
      expect(screen.queryByText(/c1/)).toBeNull();
    });
  });
});
