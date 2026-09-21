/** Component tests for the discovery view (FR-DISC-01, FR-DISC-04, TEST-05).
 *
 * Two properties are worth pinning, and both are the sort a redesign quietly reverses.
 *
 * **The queue opens with what is least understood.** Ascending confidence looks like a
 * mistake until you remember what the queue is for: a low score means the fingerprinter
 * could not tell, and those entries are the ones needing a person. The obvious fix —
 * "sort best matches first" — buries them.
 *
 * **Starting a run is confirmed, and the confirmation names the numbers.** It is the most
 * outward-facing action in a read-only product — packets to somebody else's network — and
 * the count and rate are what an operator needs in front of them to notice a mistyped
 * prefix length. A single-click Run would be the easy design and the wrong one.
 *
 * **A run's caveats appear beside its counters.** A run that found nothing because it
 * could not ask must not print like a run that found nothing because there was nothing
 * there.
 */

import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DiscoveryPage } from '../../app/DiscoveryPage';
import { AuthProvider } from '../auth/AuthProvider';

const ME = {
  id: 'u1',
  username: 'analyst',
  email: 'analyst@example.com',
  full_name: 'Analyst',
  roles: ['security_analyst'],
  permissions: ['discovery:read', 'discovery:write', 'device:read'],
  must_change_password: false,
  mfa_enabled: false,
};

const SCOPE = {
  id: 's1',
  name: 'branch-edge',
  description: null,
  targets: ['198.51.100.0/24'],
  exclusions: ['198.51.100.0/25'],
  tcp_ports: [22, 443],
  rate_limit_per_second: 50,
  snmp_configured: false,
  auto_onboard: false,
  enabled: true,
  created_at: '2026-09-01T10:00:00Z',
  address_count: 126,
};

const CONFIDENT_HOST = {
  id: 'h-high',
  address: '198.51.100.10',
  run_id: null,
  status: 'pending',
  vendor: 'cisco',
  platform: 'cisco_ios',
  hostname: 'sw-guess',
  confidence: 90,
  fingerprint: { ssh_banner: 'SSH-2.0-Cisco-1.25' },
  device_id: null,
  first_seen_at: '2026-09-10T10:00:00Z',
  last_seen_at: '2026-09-12T10:00:00Z',
  reviewed_at: null,
  review_note: null,
};

/** The one that most needs a human, and would be on page two if sorted the other way. */
const MYSTERY_HOST = {
  ...CONFIDENT_HOST,
  id: 'h-low',
  address: '198.51.100.11',
  vendor: null,
  platform: null,
  hostname: null,
  confidence: 15,
  fingerprint: {},
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': status >= 400 ? 'application/problem+json' : 'application/json' },
  });
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AuthProvider>
          <DiscoveryPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('DiscoveryPage', () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let hosts: unknown[];

  beforeEach(() => {
    // Returned in the order the API gives them: ascending confidence.
    hosts = [MYSTERY_HOST, CONFIDENT_HOST];

    fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/auth/me')) return Promise.resolve(jsonResponse(ME));
      if (url.includes('/discovery/scopes')) return Promise.resolve(jsonResponse([SCOPE]));
      if (url.includes('/discovery/runs')) return Promise.resolve(jsonResponse([]));
      // The detail endpoint first: `/discovery/pending/{id}` also contains
      // `/discovery/pending`, and answering it with the list's paginated envelope gives
      // the review panel an object with no fingerprint on it.
      const detail = /\/discovery\/pending\/([^/?]+)$/.exec(url);
      if (detail) {
        const match = hosts.find((host) => (host as { id: string }).id === detail[1]);
        return Promise.resolve(match ? jsonResponse(match) : jsonResponse({}, 404));
      }
      if (url.includes('/discovery/pending')) {
        return Promise.resolve(
          jsonResponse({ data: hosts, meta: { count: hosts.length, limit: 200 } }),
        );
      }
      return Promise.resolve(jsonResponse({}, 404));
    });
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  describe('scopes', () => {
    it('shows the address count after exclusions are subtracted', async () => {
      renderPage();
      await screen.findByText('branch-edge');

      // The number to sanity-check before anything runs.
      expect(screen.getByText('126')).toBeInTheDocument();
    });

    it('shows that review is required when auto-onboard is off', async () => {
      renderPage();
      await screen.findByText('branch-edge');

      expect(screen.getByText('review first')).toBeInTheDocument();
    });

    it('says SNMP is not probed without a configured credential', async () => {
      renderPage();
      await screen.findByText('branch-edge');

      expect(screen.getByText('not probed')).toBeInTheDocument();
    });
  });

  describe('starting a run', () => {
    /** Only the calls that actually start a run, never the page's own runs listing. */
    const startCalls = () =>
      fetchMock.mock.calls.filter(([url]) => String(url).includes('/discovery/scopes/s1/runs'));

    it('asks before sending anything, naming the count and the rate', async () => {
      // The two numbers that decide how long this takes and how loud it is. An operator
      // who has mistyped a prefix length should find out here, not from the customer.
      renderPage();
      await screen.findByText('branch-edge');

      await userEvent.click(screen.getByRole('button', { name: 'Run' }));

      expect(screen.getByText(/Probe 126 addresses at up to 50\/s\?/)).toBeInTheDocument();
      // Narrowed to the start path: the page also polls `GET /discovery/runs`, and a
      // filter on `/runs` alone would match that and pass whatever the button did.
      expect(startCalls()).toHaveLength(0);
    });

    it('posts to the scope once confirmed', async () => {
      renderPage();
      await screen.findByText('branch-edge');

      await userEvent.click(screen.getByRole('button', { name: 'Run' }));
      await userEvent.click(screen.getByRole('button', { name: 'Start' }));

      await waitFor(() => {
        const [call] = startCalls();
        expect(call).toBeDefined();
        expect(call?.[1]).toMatchObject({ method: 'POST' });
      });
    });

    it('backs out without sending anything', async () => {
      renderPage();
      await screen.findByText('branch-edge');

      await userEvent.click(screen.getByRole('button', { name: 'Run' }));
      await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));

      expect(screen.getByRole('button', { name: 'Run' })).toBeInTheDocument();
      expect(startCalls()).toHaveLength(0);
    });

    it('offers no button to someone who may only read', async () => {
      // Sending packets to a customer's network is not a read. An Auditor may see what
      // discovery found and may not go looking for more.
      fetchMock.mockImplementation((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes('/auth/me')) {
          return Promise.resolve(
            jsonResponse({ ...ME, roles: ['auditor'], permissions: ['discovery:read'] }),
          );
        }
        if (url.includes('/discovery/scopes')) return Promise.resolve(jsonResponse([SCOPE]));
        if (url.includes('/discovery/runs')) return Promise.resolve(jsonResponse([]));
        if (url.includes('/discovery/pending')) {
          return Promise.resolve(jsonResponse({ data: [], meta: { count: 0, limit: 200 } }));
        }
        return Promise.resolve(jsonResponse({}, 404));
      });

      renderPage();
      await screen.findByText('branch-edge');

      expect(screen.queryByRole('button', { name: 'Run' })).toBeNull();
    });
  });

  describe('what a run could not do', () => {
    it('shows caveats beside the counters rather than instead of them', async () => {
      // "0 hosts found" and "0 hosts found, and no echo request could be sent" are
      // different answers. Showing only the numbers makes an undetectable estate read
      // exactly like a quiet one.
      fetchMock.mockImplementation((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes('/auth/me')) return Promise.resolve(jsonResponse(ME));
        if (url.includes('/discovery/scopes')) return Promise.resolve(jsonResponse([SCOPE]));
        if (url.includes('/discovery/runs')) {
          return Promise.resolve(
            jsonResponse([
              {
                id: 'r1',
                scope_id: 's1',
                status: 'succeeded',
                started_at: '2026-09-17T09:00:00Z',
                finished_at: '2026-09-17T09:04:00Z',
                addresses_probed: 126,
                hosts_found: 0,
                hosts_unidentified: 0,
                error_message: null,
                notes: ['No echo request could be sent.'],
              },
            ]),
          );
        }
        if (url.includes('/discovery/pending')) {
          return Promise.resolve(jsonResponse({ data: [], meta: { count: 0, limit: 200 } }));
        }
        return Promise.resolve(jsonResponse({}, 404));
      });

      renderPage();

      expect(await screen.findByText('No echo request could be sent.')).toBeInTheDocument();
    });
  });

  describe('the review queue', () => {
    it('opens with the least understood host', async () => {
      renderPage();
      await screen.findByText('198.51.100.11');

      // Scoped to the queue table: the scopes table above it also has rows.
      const queue = screen.getByText('198.51.100.11').closest('table') as HTMLElement;
      const addresses = within(queue)
        .getAllByRole('row')
        .slice(1)
        .map((row) => row.querySelector('td:nth-child(2)')?.textContent);

      // 15% first, 90% second — the entry that most needs a person is not on page two.
      expect(addresses).toEqual(['198.51.100.11', '198.51.100.10']);
    });

    it('says why a low score means attention rather than unimportance', async () => {
      renderPage();
      await screen.findByText('198.51.100.11');

      expect(screen.getByText(/could not tell what this is/i)).toBeInTheDocument();
    });

    it('labels an unidentified host as such', async () => {
      renderPage();
      await screen.findByText('198.51.100.11');

      const row = screen.getByText('198.51.100.11').closest('tr') as HTMLElement;
      expect(within(row).getByText('unidentified')).toBeInTheDocument();
    });

    it('shows the probe evidence behind a fingerprint', async () => {
      renderPage();
      await screen.findByText('198.51.100.10');

      const row = screen.getByText('198.51.100.10').closest('tr') as HTMLElement;
      await userEvent.click(within(row).getByRole('button', { name: /review/i }));

      expect(await screen.findByText('SSH banner')).toBeInTheDocument();
      expect(screen.getByText('SSH-2.0-Cisco-1.25')).toBeInTheDocument();
    });

    it('explains an empty fingerprint rather than showing a blank panel', async () => {
      renderPage();
      await screen.findByText('198.51.100.11');

      const row = screen.getByText('198.51.100.11').closest('tr') as HTMLElement;
      await userEvent.click(within(row).getByRole('button', { name: /review/i }));

      expect(await screen.findByText(/no identifying signal/i)).toBeInTheDocument();
    });

    it('offers the fingerprinter guess as an editable suggestion', async () => {
      renderPage();
      await screen.findByText('198.51.100.10');

      const row = screen.getByText('198.51.100.10').closest('tr') as HTMLElement;
      await userEvent.click(within(row).getByRole('button', { name: /review/i }));

      // Pre-filled from the fingerprint, and changeable: a wrong platform picks the
      // wrong collection profile and with it the wrong command allow-list.
      const platform = await screen.findByLabelText('Platform');
      expect(platform).toHaveValue('cisco_ios');
      expect(screen.getByText(/selects the collection profile/i)).toBeInTheDocument();
    });

    it('will not submit a rejection without a reason', async () => {
      renderPage();
      await screen.findByText('198.51.100.11');

      const row = screen.getByText('198.51.100.11').closest('tr') as HTMLElement;
      await userEvent.click(within(row).getByRole('button', { name: /review/i }));

      expect(await screen.findByRole('button', { name: /^reject$/i })).toBeDisabled();
    });

    it('enables the rejection once a reason is typed', async () => {
      renderPage();
      await screen.findByText('198.51.100.11');

      const row = screen.getByText('198.51.100.11').closest('tr') as HTMLElement;
      await userEvent.click(within(row).getByRole('button', { name: /review/i }));
      await userEvent.type(await screen.findByLabelText('Reason'), 'Site printer');

      expect(screen.getByRole('button', { name: /^reject$/i })).toBeEnabled();
    });

    it('posts the corrected platform when approving', async () => {
      renderPage();
      await screen.findByText('198.51.100.10');

      const row = screen.getByText('198.51.100.10').closest('tr') as HTMLElement;
      await userEvent.click(within(row).getByRole('button', { name: /review/i }));

      const platform = await screen.findByLabelText('Platform');
      await userEvent.clear(platform);
      await userEvent.type(platform, 'fortios');
      await userEvent.click(screen.getByRole('button', { name: /approve and onboard/i }));

      await waitFor(() => {
        const approve = fetchMock.mock.calls.find((call) => String(call[0]).includes('/approve'));
        expect(approve).toBeDefined();
        expect(String((approve?.[1] as RequestInit)?.body)).toContain('fortios');
      });
    });
  });

  describe('removing a scope', () => {
    it('asks first, because a scope is the permission itself', async () => {
      // Deleting one is how you stop probing a range that turned out not to be yours.
      // Doing it by accident removes the record of what was agreed.
      renderPage();
      const row = (await screen.findByText('branch-edge')).closest('tr') as HTMLElement;

      await userEvent.click(within(row).getByRole('button', { name: 'Remove' }));

      expect(
        fetchMock.mock.calls.find((call) => (call[1] as RequestInit)?.method === 'DELETE'),
      ).toBeUndefined();
      expect(within(row).getByRole('button', { name: /yes, remove/i })).toBeInTheDocument();
    });

    it('sends the delete once confirmed', async () => {
      renderPage();
      const row = (await screen.findByText('branch-edge')).closest('tr') as HTMLElement;

      await userEvent.click(within(row).getByRole('button', { name: 'Remove' }));
      await userEvent.click(within(row).getByRole('button', { name: /yes, remove/i }));

      await waitFor(() => {
        const call = fetchMock.mock.calls.find(
          (entry) => (entry[1] as RequestInit)?.method === 'DELETE',
        );
        expect(call).toBeDefined();
        expect(String(call?.[0])).toContain('/discovery/scopes/');
      });
    });

    it('offers no removal to someone who may only read', async () => {
      // Sending packets to a network is not a read, and neither is withdrawing the
      // permission to.
      fetchMock.mockImplementation((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes('/auth/me')) {
          return Promise.resolve(
            jsonResponse({ ...ME, roles: ['auditor'], permissions: ['discovery:read'] }),
          );
        }
        if (url.includes('/discovery/scopes')) return Promise.resolve(jsonResponse([SCOPE]));
        if (url.includes('/discovery/runs')) return Promise.resolve(jsonResponse([]));
        return Promise.resolve(jsonResponse({ data: [], meta: { count: 0, limit: 200 } }));
      });
      renderPage();
      await screen.findByText('branch-edge');

      expect(screen.queryByRole('button', { name: 'Remove' })).not.toBeInTheDocument();
    });
  });

  it('re-reads the host as the review panel opens', async () => {
    // The list is a snapshot of whenever it loaded, and this panel decides the device's
    // *platform* — which selects the collection profile and with it the command
    // allow-list. Worth one request to make the evidence current at the decision.
    renderPage();
    const row = (await screen.findByText('198.51.100.10')).closest('tr') as HTMLElement;

    await userEvent.click(within(row).getByRole('button', { name: /review/i }));

    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some((call) => /\/discovery\/pending\/[^/?]+$/.test(String(call[0]))),
      ).toBe(true),
    );
  });

  it('tells an operator nothing is probed without a scope', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/auth/me')) return Promise.resolve(jsonResponse(ME));
      if (url.includes('/discovery/scopes')) return Promise.resolve(jsonResponse([]));
      if (url.includes('/discovery/runs')) return Promise.resolve(jsonResponse([]));
      return Promise.resolve(jsonResponse({ data: [], meta: { count: 0, limit: 200 } }));
    });
    renderPage();

    expect(await screen.findByText(/nothing is probed without one/i)).toBeInTheDocument();
  });
});
