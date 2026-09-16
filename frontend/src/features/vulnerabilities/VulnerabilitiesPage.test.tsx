/** Component tests for the vulnerability view (FR-VUL-04, TEST-05).
 *
 * Almost every assertion here is about a null not rendering as a zero. The matcher goes
 * to real trouble to keep "we checked and it does not apply" apart from "we could not
 * check", and a UI is where that distinction dies quietly: `{kev && <Badge/>}` renders
 * nothing for both `false` and `null`, and an estate nobody has checked then looks
 * exactly like an estate that checked and is clean.
 */

import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { VulnerabilitiesPage } from '../../app/VulnerabilitiesPage';
import { AuthProvider } from '../auth/AuthProvider';

const ME = {
  id: 'u1',
  username: 'analyst',
  email: 'analyst@example.com',
  full_name: 'Analyst',
  roles: ['security_analyst'],
  permissions: ['vuln:read', 'vuln:write', 'finding:read'],
  must_change_password: false,
  mfa_enabled: false,
};

const KEV_ROW = {
  finding_id: 'v1',
  device_id: 'd1',
  device_hostname: 'sw-core-01',
  title: 'CVE-2024-20353',
  severity: 'critical',
  status: 'open',
  advisory_id: 'CVE-2024-20353',
  advisory_source: 'nvd',
  cve_ids: ['CVE-2024-20353'],
  cwe_ids: ['CWE-287'],
  cvss: { version: '3.1', base_score: 8.6, base_severity: 'HIGH', vector: 'AV:N/AC:L' },
  epss: 0.71,
  kev: true,
  kev_due_date: '2024-05-01',
  confidence: 'confirmed',
  reasoning: ['version 15.2(7)E3 is within the affected range'],
  installed_version: '15.2(7)E3',
  fixed_versions: ['15.2(7)E6'],
  remediations: ['Upgrade to 15.2(7)E6 or later.'],
  references: ['https://example.invalid/a'],
  published: '2024-04-24T00:00:00Z',
  modified: '2024-05-01T00:00:00Z',
  first_seen_at: '2026-09-01T10:00:00Z',
  last_seen_at: '2026-09-12T10:00:00Z',
};

/** Checked against the catalogue and not listed. Must not look like the row below. */
const CHECKED_NOT_LISTED = {
  ...KEV_ROW,
  finding_id: 'v2',
  device_hostname: 'sw-edge-02',
  title: 'CVE-2024-11111',
  severity: 'medium',
  cve_ids: ['CVE-2024-11111'],
  kev: false,
  kev_due_date: null,
  epss: 0.02,
  confidence: 'likely',
};

/** No KEV catalogue has ever been imported for this CVE. */
const NEVER_CHECKED = {
  ...KEV_ROW,
  finding_id: 'v3',
  device_hostname: 'sw-edge-03',
  title: 'CVE-2099-00001',
  severity: 'high',
  cve_ids: ['CVE-2099-00001'],
  kev: null,
  kev_due_date: null,
  epss: null,
  cvss: null,
  confidence: 'likely',
};

const SUMMARY = {
  total: 3,
  by_severity: { critical: 1, high: 1, medium: 1 },
  by_confidence: { confirmed: 1, likely: 2 },
  kev_count: 1,
  devices_affected: 3,
  devices_unassessed: 4,
};

const CVE_DETAIL = {
  cve_id: 'CVE-2024-20353',
  description: 'A test CVE.',
  cvss31: { version: '3.1', base_score: 8.6, base_severity: 'HIGH', vector: 'AV:N/AC:L' },
  cvss40: null,
  cwe_ids: ['CWE-287'],
  epss: 0.71,
  kev: true,
  kev_due_date: '2024-05-01',
  published: '2024-04-24T00:00:00Z',
  modified: '2024-05-01T00:00:00Z',
  advisories: [
    {
      source: 'nvd',
      advisory_id: 'CVE-2024-20353',
      title: 'A test CVE',
      fully_interpreted: false,
      unparsed_statements: ['all versions before 7.2.5'],
      references: [],
    },
  ],
  affected_devices: [
    {
      device_id: 'd1',
      hostname: 'sw-core-01',
      mgmt_ip: '10.0.0.1',
      platform: 'cisco_ios',
      installed_version: '15.2(7)E3',
      confidence: 'confirmed',
      fixed_versions: ['15.2(7)E6'],
      finding_status: 'open',
    },
  ],
  unevaluated_devices: [
    {
      device_id: 'd9',
      hostname: 'sw-mystery-09',
      mgmt_ip: '10.0.0.9',
      platform: 'cisco_ios',
      installed_version: null,
      confidence: 'not_evaluated',
      fixed_versions: [],
      finding_status: null,
    },
  ],
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
          <VulnerabilitiesPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('VulnerabilitiesPage', () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let rows: unknown[];
  let summary: typeof SUMMARY;

  beforeEach(() => {
    rows = [KEV_ROW, CHECKED_NOT_LISTED, NEVER_CHECKED];
    summary = { ...SUMMARY };

    fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/auth/me')) return Promise.resolve(jsonResponse(ME));
      if (url.includes('/vulnerabilities/summary')) return Promise.resolve(jsonResponse(summary));
      if (url.includes('/vulnerabilities/feeds')) return Promise.resolve(jsonResponse([]));
      if (url.includes('/vulnerabilities/CVE-')) return Promise.resolve(jsonResponse(CVE_DETAIL));
      if (url.includes('/vulnerabilities')) {
        return Promise.resolve(
          jsonResponse({ data: rows, meta: { total: rows.length, limit: 25, offset: 0 } }),
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

  it('lists vulnerabilities with the installed and fixed versions', async () => {
    renderPage();
    expect(await screen.findByText('sw-core-01')).toBeInTheDocument();

    // Scoped to the row: all three fixtures run the same installed version, which is
    // the realistic case — one release, many devices.
    const row = screen.getByText('sw-core-01').closest('tr') as HTMLElement;
    expect(within(row).getByText('15.2(7)E3')).toBeInTheDocument();
    expect(within(row).getByText('15.2(7)E6')).toBeInTheDocument();
  });

  describe('the three KEV states stay three', () => {
    it('shows a known-exploited CVE as KEV', async () => {
      renderPage();
      await screen.findByText('sw-core-01');

      // Scoped to the row: "KEV" is also the column header.
      const row = screen.getByText('sw-core-01').closest('tr') as HTMLElement;
      expect(within(row).getByText('KEV')).toHaveClass('pill--critical');
    });

    it('distinguishes "checked and not listed" from "never checked"', async () => {
      renderPage();
      await screen.findByText('sw-core-01');

      // Two different sentences, deliberately. Rendering nothing for both — the
      // natural `{kev && ...}` — makes an unchecked estate look clean.
      expect(screen.getByText('Not in KEV')).toBeInTheDocument();
      expect(screen.getByText('Unchecked')).toBeInTheDocument();
    });

    it('explains what unchecked means rather than only labelling it', async () => {
      renderPage();
      await screen.findByText('sw-core-01');

      expect(screen.getByText('Unchecked')).toHaveAttribute(
        'title',
        expect.stringContaining('has not been imported'),
      );
    });
  });

  describe('an unscored CVE is not a harmless one', () => {
    it('shows "Not scored" rather than 0% for a null EPSS', async () => {
      renderPage();
      await screen.findByText('sw-core-01');

      expect(screen.getByText('Not scored')).toBeInTheDocument();
      expect(screen.queryByText('0.0%')).not.toBeInTheDocument();
    });

    it('shows a dash rather than a zero for a missing CVSS', async () => {
      renderPage();
      await screen.findByText('sw-edge-03');

      const row = screen.getByText('sw-edge-03').closest('tr');
      expect(within(row as HTMLElement).getByText('—')).toBeInTheDocument();
    });
  });

  describe('never-assessed devices are stated, not omitted', () => {
    it('counts them beside the findings count', async () => {
      renderPage();
      await screen.findByText('devices never assessed');

      const stat = screen.getByText('devices never assessed').closest('div');
      expect(within(stat as HTMLElement).getByText('4')).toBeInTheDocument();
    });

    it('warns that their absence from the table is not an all-clear', async () => {
      renderPage();

      expect(await screen.findByText(/not a statement that they are clear/i)).toBeInTheDocument();
    });

    it('says so even when the table is empty', async () => {
      // The dangerous case: zero findings and four unassessed devices reads as a clean
      // estate unless the page says otherwise.
      rows = [];
      renderPage();

      expect(await screen.findByText(/some devices have never been assessed/i)).toBeInTheDocument();
    });

    it('does not warn when every device has been assessed', async () => {
      rows = [];
      summary = { ...SUMMARY, total: 0, devices_unassessed: 0, kev_count: 0, devices_affected: 0 };
      renderPage();

      expect(await screen.findByText(/matched nothing in the imported feeds/i)).toBeInTheDocument();
    });
  });

  describe('match confidence', () => {
    it('labels a likely match as a question rather than a weak confirmation', async () => {
      renderPage();
      await screen.findByText('sw-edge-02');

      // Scoped to the row: the confidence filter carries an <option>Likely</option>.
      const row = screen.getByText('sw-edge-02').closest('tr') as HTMLElement;
      expect(within(row).getByText('Likely')).toHaveAttribute(
        'title',
        expect.stringContaining('unanswered question'),
      );
    });
  });

  describe('the CVE panel', () => {
    it('keeps unevaluated devices in their own section', async () => {
      renderPage();
      await screen.findByText('sw-core-01');

      const row = screen.getByText('sw-core-01').closest('tr') as HTMLElement;
      await userEvent.click(within(row).getByRole('button', { name: /details/i }));

      // The device that could not be evaluated must not appear among the affected, and
      // must not be silently dropped either — it is neither affected nor clear.
      expect(await screen.findByText('Could not be evaluated')).toBeInTheDocument();
      expect(screen.getByText('sw-mystery-09')).toBeInTheDocument();
      expect(screen.getByText(/neither affected nor clear/i)).toBeInTheDocument();
    });

    it('flags an advisory that was only partly read', async () => {
      renderPage();
      await screen.findByText('sw-core-01');

      const row = screen.getByText('sw-core-01').closest('tr') as HTMLElement;
      await userEvent.click(within(row).getByRole('button', { name: /details/i }));

      expect(await screen.findByText('partly read')).toBeInTheDocument();
      expect(screen.getByText(/can never clear a device/i)).toBeInTheDocument();
    });
  });

  describe('feed status', () => {
    it('says why an empty estate may mean nothing has been compared', async () => {
      renderPage();
      await screen.findByText('sw-core-01');

      await userEvent.click(screen.getByRole('button', { name: /feed status/i }));

      expect(await screen.findByText(/No feed has ever been imported/i)).toBeInTheDocument();
      expect(screen.getByText(/not the same as being clear/i)).toBeInTheDocument();
    });
  });

  it('asks the API for known-exploited only when the filter is set', async () => {
    renderPage();
    await screen.findByText('sw-core-01');

    await userEvent.click(screen.getByLabelText(/known exploited only/i));

    await waitFor(() => {
      const called = fetchMock.mock.calls
        .map((call) => String(call[0]))
        .filter((url) => url.includes('/vulnerabilities?'));
      expect(called.some((url) => url.includes('kev_only=true'))).toBe(true);
    });
  });
});
