/** Component tests for the discovery view (FR-DISC-01, FR-DISC-04, TEST-05).
 *
 * Two properties are worth pinning, and both are the sort a redesign quietly reverses.
 *
 * **The queue opens with what is least understood.** Ascending confidence looks like a
 * mistake until you remember what the queue is for: a low score means the fingerprinter
 * could not tell, and those entries are the ones needing a person. The obvious fix —
 * "sort best matches first" — buries them.
 *
 * **There is no button that starts a run.** FR-DISC-05's rate limiting is unbuilt and
 * there is no run executor, so an unpaced run would be the port sweep SRS §1.2 forbids.
 * The page has to say that, or the feature reads as broken rather than deliberately
 * incomplete.
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

  describe('runs cannot be started yet', () => {
    it('explains why rather than offering a button', async () => {
      renderPage();

      expect(await screen.findByText(/cannot be started yet/i)).toBeInTheDocument();
      expect(screen.getByText(/port sweep this product refuses to do/i)).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /start|run now|scan/i })).toBeNull();
    });

    it('says an empty run list is the state of the subsystem, not a load failure', async () => {
      renderPage();

      expect(await screen.findByText(/state of the subsystem rather than a/i)).toBeInTheDocument();
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
