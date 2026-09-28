/** Component tests for the neighbour panel (FR-TOPO-01, TEST-05).
 *
 * **The empty states are the point of this file, not the table.** A list of no
 * neighbours has four causes and only one of them means the device has none: the
 * protocols are disabled, they are enabled and nothing answered, nothing has been
 * collected, or the configuration did not say. Rendering one empty table for all four
 * is this codebase's named failure mode, and it is a simplification any redesign
 * reaches for — so each cause is asserted to produce different words.
 *
 * The second property is that a neighbour resolved to a device in the inventory reads
 * differently from one that is not, and that *how* it was resolved survives. A full
 * hostname, a short hostname and a management address are three strengths of claim
 * arriving in one field, and flattening them lets the weakest be read as the strongest.
 */

import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { NeighboursPanel } from './NeighboursPanel';

const DEVICE_ID = '11111111-1111-1111-1111-111111111111';
const SNAPSHOT_ID = '22222222-2222-2222-2222-222222222222';
const CORE_ID = '33333333-3333-3333-3333-333333333333';

function neighbour(over: Record<string, unknown> = {}) {
  return {
    protocol: 'cdp',
    local_interface: 'GigabitEthernet0/1',
    remote_device: 'core-sw01.example.local',
    remote_interface: 'GigabitEthernet1/0/24',
    remote_address: '10.10.10.1',
    platform: 'cisco WS-C3850-24T',
    capabilities: ['Switch', 'IGMP'],
    device_id: CORE_ID,
    matched_by: 'hostname',
    ...over,
  };
}

function payload(over: Record<string, unknown> = {}) {
  return {
    device_id: DEVICE_ID,
    snapshot_id: SNAPSHOT_ID,
    cdp_enabled: true,
    lldp_enabled: true,
    neighbours: [],
    matched: 0,
    unmanaged: 0,
    ...over,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': status >= 400 ? 'application/problem+json' : 'application/json' },
  });
}

describe('NeighboursPanel', () => {
  let body: unknown;

  beforeEach(() => {
    body = payload();
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes('/neighbours')) return Promise.resolve(jsonResponse(body));
        return Promise.resolve(jsonResponse({}, 404));
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  function renderPanel() {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <NeighboursPanel deviceId={DEVICE_ID} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
  }

  describe('the four reasons a list is empty', () => {
    it('says nothing has been collected, and that this is not a claim of no neighbours', async () => {
      body = payload({ snapshot_id: null, cdp_enabled: null, lldp_enabled: null });
      renderPanel();

      await waitFor(() => expect(screen.getByText(/Nothing has been collected/)).toBeTruthy());
      expect(screen.getByText(/not a statement that it has no neighbours/)).toBeTruthy();
    });

    it('distinguishes enabled-and-silent, which is the one worth acting on', async () => {
      body = payload({ cdp_enabled: true, lldp_enabled: false });
      renderPanel();

      // The interesting case: a protocol filtered on the ports that matter reports
      // nothing while appearing to be on, and is invisible if it reads as "disabled".
      await waitFor(() => expect(screen.getByText(/CDP is enabled/)).toBeTruthy());
      expect(screen.getByText(/worth looking at/)).toBeTruthy();
    });

    it('says when both protocols are off, and that the answer must come from elsewhere', async () => {
      body = payload({ cdp_enabled: false, lldp_enabled: false });
      renderPanel();

      await waitFor(() =>
        expect(screen.getByText(/Both CDP and LLDP are disabled/)).toBeTruthy(),
      );
      expect(screen.getByText(/from the devices around it/)).toBeTruthy();
    });

    it('does not claim either way when the configuration did not say', async () => {
      body = payload({ cdp_enabled: null, lldp_enabled: null });
      renderPanel();

      await waitFor(() => expect(screen.getByText(/could not be determined/)).toBeTruthy());
      expect(screen.getByText(/not evidence either way/)).toBeTruthy();
    });

    it('gives each cause different words', async () => {
      // Guards the simplification directly rather than by implication: one shared empty
      // string for all four would pass every test above that only checks for a phrase in
      // its own case.
      const cases = [
        payload({ snapshot_id: null }),
        payload({ cdp_enabled: true, lldp_enabled: false }),
        payload({ cdp_enabled: false, lldp_enabled: false }),
        payload({ cdp_enabled: null, lldp_enabled: null }),
      ];

      const seen = new Set<string>();
      for (const value of cases) {
        body = value;
        const { unmount } = renderPanel();
        await waitFor(() => expect(document.querySelector('.empty')).toBeTruthy());
        seen.add(document.querySelector('.empty')!.textContent!);
        unmount();
      }

      expect(seen.size).toBe(4);
    });
  });

  describe('a neighbour that resolves to a device', () => {
    beforeEach(() => {
      body = payload({ neighbours: [neighbour()], matched: 1, unmanaged: 0 });
    });

    it('links to that device rather than printing a name', async () => {
      renderPanel();

      const link = await screen.findByRole('link', { name: 'core-sw01.example.local' });
      expect(link.getAttribute('href')).toBe(`/inventory/${CORE_ID}/config`);
    });

    it('says how the match was made', async () => {
      renderPanel();
      await waitFor(() => expect(screen.getByText(/matched by hostname/)).toBeTruthy());
    });

    it('counts how many of them are managed', async () => {
      renderPanel();
      await waitFor(() =>
        expect(screen.getByText(/1 of 1 resolve to a device in this inventory/)).toBeTruthy(),
      );
    });
  });

  describe('a neighbour that does not', () => {
    it('is shown as outside the inventory, not as a failure', async () => {
      body = payload({
        neighbours: [
          neighbour({ remote_device: 'SEP001A2B3C4D5E', device_id: null, matched_by: null }),
        ],
        matched: 0,
        unmanaged: 1,
      });
      renderPanel();

      await waitFor(() => expect(screen.getByText('SEP001A2B3C4D5E')).toBeTruthy());
      expect(screen.getByText(/not in the inventory/)).toBeTruthy();
      expect(screen.queryByRole('link', { name: 'SEP001A2B3C4D5E' })).toBeNull();
    });

    it('still appears when it would not say what it is', async () => {
      // LLDP on a default-configured device answers `not advertised` to almost
      // everything. The two ports are still true, and "something is plugged in here and
      // will not say what" is more useful than dropping the row.
      body = payload({
        neighbours: [
          neighbour({
            protocol: 'lldp',
            local_interface: 'Gi0/7',
            remote_device: null,
            remote_interface: '0050.5699.1a2b',
            remote_address: null,
            platform: null,
            capabilities: [],
            device_id: null,
            matched_by: null,
          }),
        ],
        unmanaged: 1,
      });
      renderPanel();

      await waitFor(() => expect(screen.getByText('Gi0/7')).toBeTruthy());
      expect(screen.getByText('did not say')).toBeTruthy();
    });
  });

  it('keeps the two protocols as separate rows', async () => {
    // CDP and LLDP disagree about the same link often enough that merging them loses
    // which one saw what. Both reach the panel labelled.
    body = payload({
      neighbours: [
        neighbour(),
        neighbour({ protocol: 'lldp', remote_interface: 'Gi1/0/24', matched_by: 'short-hostname' }),
      ],
      matched: 2,
    });
    renderPanel();

    await waitFor(() => expect(screen.getByText('CDP')).toBeTruthy());
    expect(screen.getByText('LLDP')).toBeTruthy();
    expect(screen.getByText(/matched by short name/)).toBeTruthy();
  });

  it('renders nothing at all when the request fails', async () => {
    // A reader without the permission has no business being told what they cannot see,
    // and the rest of the device page still works.
    body = null;
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(jsonResponse({ detail: 'forbidden' }, 403))),
    );
    const { container } = renderPanel();

    await waitFor(() => expect(container.querySelector('.card')).toBeNull());
  });
});
