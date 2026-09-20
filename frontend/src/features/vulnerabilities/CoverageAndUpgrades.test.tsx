/** The two Vulnerabilities panels that were API-only (FR-VUL-02, FR-VUL-10).
 *
 * Both exist to stop a confident-looking screen being read as good news. The coverage
 * check says which platforms report zero CVEs because nothing could be matched rather
 * than because they are clean; the upgrade path refuses to count an undetermined CVE as
 * closed. So the tests are mostly about the distinctions surviving to the screen, since
 * collapsing any of them turns the panel into the reassurance it exists to prevent.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { VulnerabilitiesPage } from '../../app/VulnerabilitiesPage';
import { api } from '../../api/client';

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ can: () => true }),
}));

const SUMMARY = {
  total: 1,
  by_severity: { high: 1 },
  by_confidence: { confirmed: 1 },
  kev_count: 1,
  devices_affected: 1,
  devices_unassessed: 0,
};

const FINDING = {
  finding_id: 'f1',
  device_id: 'd1',
  device_hostname: 'edge-fw-01',
  cve_ids: ['CVE-2024-20353'],
  advisory_id: null,
  severity: 'high',
  installed_version: '9.18(2)',
  fixed_versions: ['9.18(4)'],
  confidence: 'confirmed',
  cvss: { base_score: 8.6 },
  epss: null,
  kev: true,
};

let coverage: unknown = null;
let upgrade: unknown = null;

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <VulnerabilitiesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('the coverage check', () => {
  beforeEach(() => {
    coverage = {
      advisories_examined: 120,
      products: [
        {
          platform: 'cisco_asa',
          vendor: 'cisco',
          product: 'adaptive_security_appliance_software',
          status: 'corroborated',
          vendor_products_seen: ['adaptive_security_appliance_software'],
          advisories_for_vendor: 40,
          closest_match: null,
        },
        {
          platform: 'checkpoint_gaia',
          vendor: 'checkpoint',
          product: 'checkpoint_mgmt',
          status: 'contradicted',
          vendor_products_seen: ['gaia_os', 'quantum_security_gateway'],
          advisories_for_vendor: 12,
          closest_match: 'gaia_os',
        },
        {
          platform: 'fortios',
          vendor: 'fortinet',
          product: 'fortios',
          status: 'no-evidence',
          vendor_products_seen: [],
          advisories_for_vendor: 0,
          closest_match: null,
        },
      ],
      limitations: ['1 platform(s) have no advisory in the corpus naming their product.'],
    };
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/vulnerabilities/cpe-coverage')) return coverage as never;
      if (path.startsWith('/vulnerabilities/summary')) return SUMMARY as never;
      if (path.startsWith('/vulnerabilities/feeds')) return [] as never;
      if (path.startsWith('/vulnerabilities?')) {
        return { data: [FINDING], meta: { total: 1 } } as never;
      }
      return { data: [], meta: { total: 0 } } as never;
    });
  });

  afterEach(() => vi.restoreAllMocks());

  /** The coverage panel, scoped — the findings table is on the same screen and shares
   *  both row roles and version strings with it. */
  async function openCoverage(): Promise<HTMLElement> {
    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: 'Coverage check' }));
    await screen.findByText('cisco_asa');
    return screen
      .getByRole('heading', { name: 'Can these platforms match anything?' })
      .closest('section')!;
  }

  it('warns that a contradicted platform may be matching nothing', async () => {
    // The whole point. A device on that platform reports zero vulnerabilities, which on
    // every other screen is indistinguishable from a device that has none.
    await openCoverage();

    expect(screen.getByRole('alert')).toHaveTextContent(/may be matching nothing/);
  });

  it('says what the name is probably meant to be', async () => {
    // `closest_match` exists for exactly this and was not even being serialised. "This
    // is wrong" costs somebody an afternoon; "you mean gaia_os" costs a minute.
    await openCoverage();

    const row = screen.getByText('checkpoint_gaia').closest('tr')!;
    expect(within(row).getByText('gaia_os')).toBeInTheDocument();
  });

  it('does not present "nothing to check against" as a fault', async () => {
    // A vendor with no imported advisories says nothing either way. Rendering it as a
    // problem sends people chasing a gap in the corpus as though it were a bug.
    await openCoverage();

    const row = screen.getByText('fortios').closest('tr')!;
    expect(within(row).getByText(/unconfirmed rather than wrong/)).toBeInTheDocument();
    expect(within(row).queryByText(/Probably wrong/)).not.toBeInTheDocument();
  });

  it('puts the contradictions first', async () => {
    // The only rows anybody has to act on, and by default they sort under a pile of
    // corroborated ones.
    const panel = await openCoverage();

    const platforms = within(panel)
      .getAllByRole('row')
      .slice(1)
      .map((row) => within(row).getAllByRole('cell')[0]?.textContent);
    expect(platforms[0]).toBe('checkpoint_gaia');
  });

  it('carries the service’s own limitations through', async () => {
    await openCoverage();

    expect(screen.getByText(/no advisory in the corpus/)).toBeInTheDocument();
  });

  it('says so plainly when nothing could be checked at all', async () => {
    coverage = {
      advisories_examined: 0,
      products: [
        {
          platform: 'cisco_asa',
          vendor: 'cisco',
          product: 'adaptive_security_appliance_software',
          status: 'no-evidence',
          vendor_products_seen: [],
          advisories_for_vendor: 0,
          closest_match: null,
        },
      ],
      limitations: ['No advisories have been imported, so nothing could be checked.'],
    };
    await openCoverage();

    expect(screen.getByText(/Nothing could be checked at all/)).toBeInTheDocument();
  });
});

describe('the upgrade path', () => {
  beforeEach(() => {
    upgrade = {
      device_id: 'd1',
      hostname: 'edge-fw-01',
      platform: 'cisco_asa',
      current_version: '9.18(2)',
      current_version_unparsed: false,
      total_open_cves: 11,
      candidates: [
        {
          version: '9.18(4)',
          eliminates: ['CVE-2024-20353', 'CVE-2024-20359'],
          remaining: ['CVE-2024-99001'],
          undetermined: ['CVE-2023-20269'],
          eliminates_count: 2,
          remaining_count: 1,
          undetermined_count: 1,
          kev_eliminated: 1,
          advisories_closed: 2,
        },
      ],
    };
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.includes('/upgrade-path')) return upgrade as never;
      if (path.startsWith('/vulnerabilities/summary')) return SUMMARY as never;
      if (path.startsWith('/vulnerabilities/feeds')) return [] as never;
      if (path.startsWith('/vulnerabilities?')) {
        return { data: [FINDING], meta: { total: 1 } } as never;
      }
      return { data: [], meta: { total: 0 } } as never;
    });
  });

  afterEach(() => vi.restoreAllMocks());

  /** The upgrade panel, scoped — `9.18(4)` is also the findings table's "Fixed in". */
  async function openUpgrades(): Promise<HTMLElement> {
    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: 'Upgrades' }));
    const heading = await screen.findByRole('heading', { name: /Upgrade path/ });
    return heading.closest('section')!;
  }

  it('shows what a release would close and what it would leave', async () => {
    const panel = await openUpgrades();

    const row = within(panel).getByText('9.18(4)').closest('tr')!;
    expect(within(row).getByText('CVE-2024-20353, CVE-2024-20359')).toBeInTheDocument();
  });

  it('keeps undetermined out of the closed count', async () => {
    // The rounding error that sends somebody to a release that does not fix their
    // problem: two Cisco trains have independent fix schedules, so neither is later.
    const panel = await openUpgrades();

    const row = within(panel).getByText('9.18(4)').closest('tr')!;
    const cells = within(row).getAllByRole('cell');
    expect(cells[1]).toHaveTextContent('2');
    expect(cells[4]).toHaveTextContent('1');
    expect(within(panel).getByText(/Undetermined is not closed/)).toBeInTheDocument();
  });

  it('surfaces the known-exploited count separately', async () => {
    // The ranking anybody actually uses: one window, and a release that closes fewer
    // CVEs but both of the exploited ones is usually the right choice.
    const panel = await openUpgrades();

    const row = within(panel).getByText('9.18(4)').closest('tr')!;
    expect(within(row).getAllByRole('cell')[2]).toHaveTextContent('1');
  });

  it('warns when the installed version could not be parsed', async () => {
    // Without it the list reads as "these are upgrades from where you are", which is
    // not what it is: nothing was filtered against the current version.
    upgrade = { ...(upgrade as object), current_version_unparsed: true };
    await openUpgrades();

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/could not be parsed/));
  });

  it('distinguishes no candidates from nothing to fix', async () => {
    upgrade = { ...(upgrade as object), candidates: [] };
    await openUpgrades();

    expect(screen.getByText(/gap in the advisories/)).toBeInTheDocument();
  });
});
