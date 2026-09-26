/** Component tests for path analysis (FR-TOPO-04, TEST-05).
 *
 * One property matters more than the rest and is the sort a redesign quietly reverses:
 * **the two verdicts are shown separately, and `partially-allowed` never reads as
 * success.** Merging them into one badge is the obvious simplification, and it forces the
 * UI to decide what "every firewall permits this, and I lost the path halfway" means —
 * which is exactly the decision that must stay with the operator, because someone opens a
 * firewall on the strength of these answers.
 *
 * The second is that a router with no rulebase renders differently from a firewall that
 * permitted. Both pass traffic; only one looked at it.
 */

import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { TopologyPage } from '../../app/TopologyPage';
import { AuthProvider } from '../auth/AuthProvider';
import { POLICY_LABELS, ROUTING_LABELS } from './types';

const ME = {
  id: 'u1',
  username: 'analyst',
  email: 'analyst@example.com',
  full_name: 'Analyst',
  roles: ['security_analyst'],
  permissions: ['snapshot:read', 'device:read'],
  must_change_password: false,
  mfa_enabled: false,
};

const SUMMARY = {
  devices: 3,
  devices_with_routes: 3,
  devices_without_route_data: 0,
  devices_with_rulebase: 2,
  routes: 12,
  unmanaged_next_hops: 1,
};

/** Traced end to end: a router that formed no opinion, then a firewall that permitted. */
const ROUTED_AND_ALLOWED = {
  source: '10.10.0.5',
  destination: '10.20.0.5',
  protocol: 'tcp',
  port: 443,
  routing: 'routed',
  policy: 'allowed',
  hops: [
    {
      device_id: 'd1',
      hostname: 'core-rtr',
      platform: 'cisco_ios',
      matched_route: '10.20.0.0/24 via 10.0.1.2',
      next_hop: '10.0.1.2',
      egress_interface: 'dmz',
      ingress_zone: null,
      egress_zone: null,
      action: null,
      rule_name: null,
      rule_order: null,
      limitations: [],
      translation: null,
    },
    {
      device_id: 'd2',
      hostname: 'dmz-fw',
      platform: 'cisco_asa',
      matched_route: 'connected',
      next_hop: null,
      egress_interface: null,
      ingress_zone: 'trust',
      egress_zone: 'dmz',
      action: 'allow',
      rule_name: 'permit-web',
      rule_order: 2,
      limitations: [],
      translation: null,
    },
  ],
  stopped_at_prefix: null,
  stopped_at_next_hop: null,
  stopped_at_device: null,
  // Returned by the API since the endpoint shipped. They were absent from this
  // fixture and from the TS type, so the NAT and equal-cost caveats never reached
  // the console at all.
  translated_at: [],
  translation_unknown_at: [],
  branched_at: [],
  notes: [],
};

/** Every firewall permits it, and the path left the estate before the destination. */
const LOST_THE_PATH = {
  ...ROUTED_AND_ALLOWED,
  destination: '8.8.8.8',
  routing: 'partially-routed',
  policy: 'partially-allowed',
  stopped_at_prefix: '0.0.0.0/0',
  stopped_at_next_hop: '203.0.113.1',
  stopped_at_device: 'edge-fw',
  notes: ['The path leaves the managed estate at edge-fw.'],
};

const MISSING = [
  {
    address: '203.0.113.1',
    referenced_by: ['edge-fw'],
    prefixes: ['0.0.0.0/0'],
    carries_default_route: true,
    score: 10,
    adjacent_to: '203.0.113.0/29',
    reason:
      '1 device(s) route through 203.0.113.1; covering 1 prefix(es); including a default route.',
  },
];

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
          <TopologyPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('TopologyPage', () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let pathResult: unknown;
  let summary: unknown;

  beforeEach(() => {
    pathResult = ROUTED_AND_ALLOWED;
    summary = SUMMARY;

    fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/auth/me')) return Promise.resolve(jsonResponse(ME));
      if (url.includes('/topology/summary')) return Promise.resolve(jsonResponse(summary));
      if (url.includes('/topology/missing-devices')) return Promise.resolve(jsonResponse(MISSING));
      if (url.includes('/topology/path')) return Promise.resolve(jsonResponse(pathResult));
      return Promise.resolve(jsonResponse({}, 404));
    });
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  async function trace() {
    await userEvent.type(screen.getByPlaceholderText('10.10.0.5'), '10.10.0.5');
    await userEvent.type(screen.getByPlaceholderText('10.20.0.5'), '10.20.0.5');
    await userEvent.click(screen.getByRole('button', { name: 'Trace' }));
  }

  describe('the two verdicts', () => {
    it('shows routing and policy as separate answers', async () => {
      renderPage();
      await trace();

      expect(await screen.findByText('Routing')).toBeInTheDocument();
      expect(screen.getByText('Policy')).toBeInTheDocument();
      expect(screen.getByText('Routed')).toBeInTheDocument();
      expect(screen.getByText('Allowed')).toBeInTheDocument();
    });

    it('never renders a permit on a lost path as allowed', async () => {
      // The assertion this file exists for. "Partially allowed" is the case an operator
      // most wants to read as yes, and the one a merged badge would let them.
      pathResult = LOST_THE_PATH;
      renderPage();
      await trace();

      expect(await screen.findByText('Partially allowed')).toBeInTheDocument();
      expect(screen.queryByText('Allowed')).toBeNull();
      expect(screen.getByText('Partially routed')).toBeInTheDocument();
    });

    it('does not colour a partial permit the same as a full one', () => {
      // Asserted on the mapping rather than the DOM, because that is where the mistake
      // is made. Labels alone are not enough: the severity palette renders `medium` and
      // `low` identically, so a plausible tone choice makes the two badges visually
      // identical while every text assertion in this file still passes.
      expect(POLICY_LABELS['partially-allowed'].tone).not.toEqual(POLICY_LABELS.allowed.tone);
      expect(ROUTING_LABELS['partially-routed'].tone).not.toEqual(ROUTING_LABELS.routed.tone);
    });

    it('reserves the success tone for definitive answers only', () => {
      const provisional = [
        POLICY_LABELS['partially-allowed'].tone,
        ROUTING_LABELS['partially-routed'].tone,
        ROUTING_LABELS.unknown.tone,
      ];

      expect(provisional).not.toContain('success');
    });

    it('spells out what partially allowed means, next to the badge', async () => {
      pathResult = LOST_THE_PATH;
      renderPage();
      await trace();

      expect(
        await screen.findByText(/not a statement that the traffic gets through/i),
      ).toBeInTheDocument();
    });

    it('names the device to onboard when the path leaves the estate', async () => {
      // A hedge that does not say what would resolve it is just a hedge.
      pathResult = LOST_THE_PATH;
      renderPage();
      await trace();

      // Scoped to the alert: the address also appears in the missing-device table
      // below, and an unscoped query matches both and proves neither.
      const alert = await screen.findByRole('note');
      expect(within(alert).getByText('203.0.113.1')).toBeInTheDocument();
      expect(within(alert).getByText(/Onboarding that device would extend/i)).toBeInTheDocument();
    });
  });

  describe('the hops', () => {
    it('distinguishes a router with no rulebase from a firewall that permitted', async () => {
      // Both pass traffic; only one of them looked at it. Rendering them alike counts a
      // device that inspected nothing as a control that was checked.
      renderPage();
      await trace();

      expect(await screen.findByText('no rulebase')).toBeInTheDocument();
      expect(screen.getByText('permitted')).toBeInTheDocument();
    });

    it('shows the route each device chose', async () => {
      renderPage();
      await trace();

      expect(await screen.findByText('10.20.0.0/24 via 10.0.1.2')).toBeInTheDocument();
    });

    it('shows the zones the rulebase was evaluated against', async () => {
      renderPage();
      await trace();

      // Scoped to the table: the diagram above it labels the same hop with the same
      // zones, which is deliberate duplication rather than a collision to design away.
      // This assertion is about the table, so it says so.
      const table = await screen.findByRole('table', { name: /Hops from/ });
      expect(within(table).getByText('trust → dmz')).toBeInTheDocument();
    });
  });

  describe('coverage', () => {
    it('warns when devices contribute no routes', async () => {
      // Otherwise a path stopping early looks arbitrary rather than explained.
      summary = { ...SUMMARY, devices_without_route_data: 2 };
      renderPage();

      expect(
        await screen.findByText(/collected\s+before forwarding tables were parsed/i),
      ).toBeInTheDocument();
    });

    it('stays quiet when every device has routes', async () => {
      renderPage();
      await screen.findByRole('button', { name: 'Trace' });

      expect(screen.queryByText(/before forwarding tables were parsed/i)).toBeNull();
    });
  });

  describe('the missing-device report', () => {
    it('ranks unmanaged next hops with the reason', async () => {
      renderPage();

      expect(await screen.findByText('default route')).toBeInTheDocument();
      expect(screen.getByText(/including a default route/i)).toBeInTheDocument();
    });

    it('frames them as evidence rather than a work queue', async () => {
      // An unmanaged next hop may be an ISP router or a virtual address no box owns.
      renderPage();

      expect(await screen.findByText(/evidence, not a work queue/i)).toBeInTheDocument();
    });
  });

  describe('input', () => {
    it('will not trace until both addresses are given', async () => {
      renderPage();
      await screen.findByRole('button', { name: 'Trace' });

      expect(screen.getByRole('button', { name: 'Trace' })).toBeDisabled();
    });

    it('surfaces a refusal rather than silently failing', async () => {
      fetchMock.mockImplementation((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes('/auth/me')) return Promise.resolve(jsonResponse(ME));
        if (url.includes('/topology/summary')) return Promise.resolve(jsonResponse(SUMMARY));
        if (url.includes('/topology/missing-devices')) return Promise.resolve(jsonResponse([]));
        return Promise.resolve(jsonResponse({ detail: "'server01' is not an IP address." }, 422));
      });

      renderPage();
      await trace();

      await waitFor(() => expect(screen.getByText(/is not an IP address/i)).toBeInTheDocument());
    });
  });
});
