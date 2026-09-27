/** Component tests for the network map (FR-TOPO-02, TEST-05).
 *
 * The properties here are the ones that make the picture honest rather than pretty:
 *
 * * a device the estate routes to and does not manage is on the map and labelled as
 *   unmanaged, because that boundary is the most actionable thing on it;
 * * a group's name says whether it was configured or inferred from hostnames;
 * * "no open findings" never renders as an all-clear, because a device nothing has
 *   checked produces exactly the same zero.
 */

import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { NetworkMapPage } from '../../app/NetworkMapPage';
import { AuthProvider } from '../auth/AuthProvider';

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

const MAP = {
  nodes: [
    {
      id: 'fw-1',
      kind: 'device',
      label: 'edge-fw',
      group: 'g0',
      tier: 0,
      platform: 'cisco_asa',
      vendor: 'cisco',
      device_class: 'firewall',
      criticality: 'critical',
      status: 'active',
      site: null,
      has_rulebase: true,
      inspects: true,
      routes: 4,
      routes_known: true,
      interfaces: [
        { name: 'outside', addresses: ['203.0.113.2/255.255.255.248'], zone: 'untrust' },
        { name: 'inside', addresses: ['10.0.0.1/30'], zone: 'trust' },
      ],
      interface_count: 6,
      findings: { high: 2, low: 1 },
      has_snapshot: true,
      referenced_by: [],
      carries_default_route: false,
    },
    {
      id: 'rtr-1',
      kind: 'device',
      label: 'core-rtr',
      group: 'g0',
      tier: 1,
      platform: 'cisco_nxos',
      vendor: 'cisco',
      device_class: 'router',
      criticality: 'high',
      status: 'active',
      site: null,
      has_rulebase: false,
      inspects: false,
      routes: 9,
      routes_known: true,
      interfaces: [{ name: 'up', addresses: ['10.0.0.2/30'], zone: null }],
      interface_count: 3,
      findings: {},
      has_snapshot: true,
      referenced_by: [],
      carries_default_route: false,
    },
    {
      id: 'unmanaged:203.0.113.1',
      kind: 'unmanaged',
      label: '203.0.113.1',
      group: 'g0',
      tier: -1,
      platform: null,
      vendor: null,
      device_class: null,
      criticality: null,
      status: null,
      site: null,
      has_rulebase: false,
      inspects: false,
      routes: 0,
      routes_known: true,
      interfaces: [],
      interface_count: 0,
      findings: {},
      has_snapshot: false,
      referenced_by: ['fw-1'],
      carries_default_route: true,
    },
  ],
  links: [
    {
      id: 'fw-1|rtr-1',
      source: 'fw-1',
      target: 'rtr-1',
      via: ['10.0.0.2'],
      prefixes: 3,
      carries_default: false,
      bidirectional: true,
      source_interface: 'inside',
      target_interface: 'up',
      crosses_firewall: true,
    },
    {
      id: 'fw-1|unmanaged:203.0.113.1',
      source: 'fw-1',
      target: 'unmanaged:203.0.113.1',
      via: ['203.0.113.1'],
      prefixes: 1,
      carries_default: true,
      bidirectional: false,
      source_interface: 'outside',
      target_interface: null,
      crosses_firewall: true,
    },
  ],
  groups: [
    {
      id: 'g0',
      label: 'edge',
      label_source: 'hostname',
      devices: 2,
      firewalls: 1,
      unmanaged: 1,
      links: 2,
      tiers: 3,
    },
  ],
  devices: 2,
  unmanaged: 1,
  devices_without_route_data: 0,
  isolated: 0,
  omitted_groups: [],
  omitted_devices: 0,
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
          <NetworkMapPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('NetworkMapPage', () => {
  let body: unknown;

  beforeEach(() => {
    body = MAP;
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes('/auth/me')) return Promise.resolve(jsonResponse(ME));
        if (url.includes('/topology/map')) return Promise.resolve(jsonResponse(body));
        return Promise.resolve(jsonResponse({}, 404));
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('draws every device and the boundary beyond them', async () => {
    renderPage();

    expect(await screen.findByText('edge-fw')).toBeInTheDocument();
    expect(screen.getByText('core-rtr')).toBeInTheDocument();
    // The ISP router is not in the inventory and is still on the picture: it names the
    // device somebody would onboard to learn more.
    expect(screen.getByText('203.0.113.1')).toBeInTheDocument();
    expect(screen.getByText('unmanaged · default route')).toBeInTheDocument();
  });

  it('says a group name was inferred from hostnames rather than configured', async () => {
    renderPage();
    await screen.findByText('edge-fw');

    expect(screen.getByText(/nothing configured says this is a site/i)).toBeInTheDocument();
  });

  it('has a text alternative for the picture', async () => {
    renderPage();
    await screen.findByText('edge-fw');

    // One image with a description, and the list beside it as the keyboard path —
    // rather than several hundred focusable boxes between the toolbar and the rest.
    const picture = screen.getByRole('img', { name: 'Network map' });
    expect(picture).toBeInTheDocument();
  });

  it('shows a device its interfaces and zones when it is selected', async () => {
    renderPage();
    await userEvent.click(await screen.findByText('edge-fw'));

    // Scoped to the interface table: `outside` is also the egress of a connection in
    // the table below it, which is the point — the same leg, named in both places.
    const interfaces = screen.getByRole('table', { name: /Addressed interfaces on edge-fw/i });
    expect(within(interfaces).getByText('outside')).toBeInTheDocument();
    expect(within(interfaces).getByText('untrust')).toBeInTheDocument();
    // A dotted mask and a prefix length are the same address written two ways, and one
    // list showing both reads as a defect.
    expect(within(interfaces).getByText('203.0.113.2/29')).toBeInTheDocument();
  });

  it('names the interface at each end of a connection', async () => {
    renderPage();
    await userEvent.click(await screen.findByText('edge-fw'));

    const panel = screen.getByRole('heading', { level: 2, name: 'edge-fw' }).closest('section')!;
    const row = within(panel).getByRole('button', { name: 'core-rtr' }).closest('tr')!;
    expect(within(row).getByText('inside')).toBeInTheDocument();
    expect(within(row).getByText('up')).toBeInTheDocument();
  });

  it('does not render "no findings" as an all-clear', async () => {
    renderPage();
    await userEvent.click(await screen.findByText('core-rtr'));

    const panel = screen.getByRole('heading', { level: 2, name: 'core-rtr' }).closest('section')!;
    // The device has an empty finding count, which means it passed everything that
    // applies *or* nothing has run. A bare "0" would assert the first.
    expect(within(panel).getByText(/the map cannot tell those apart/i)).toBeInTheDocument();
  });

  it('says how much of the estate is not drawn when the limit trimmed it', async () => {
    body = { ...MAP, omitted_groups: ['frankfurt', 'tokyo'], omitted_devices: 128 };
    renderPage();

    expect(
      await screen.findByText(/128 device\(s\) in 2 group\(s\) are not on this map/i),
    ).toBeInTheDocument();
  });

  it('reports a failure without implying the rest of the product is down', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) =>
        Promise.resolve(
          String(input).includes('/auth/me')
            ? jsonResponse(ME)
            : jsonResponse({ detail: 'boom' }, 500),
        ),
      ),
    );
    renderPage();

    expect(await screen.findByRole('alert')).toHaveTextContent(
      /Path analysis and the device inventory are unaffected/i,
    );
  });
});
