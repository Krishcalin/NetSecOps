/** Component tests for the report archive (FR-RPT-02, FR-RPT-03, TEST-05).
 *
 * The page's whole job is to present reports as dated evidence rather than as a live
 * view, and every property pinned here is one a well-meaning redesign reverses:
 *
 * - **A failed report offers no download.** "Let them export whatever we have" sounds
 *   helpful and puts a half-assembled document outside the product, where it reads as a
 *   finished assessment.
 * - **Templates that cannot be assembled are shown, disabled.** Hiding them makes the
 *   feature look smaller; enabling them produces an empty document, and an empty
 *   compliance report reads like a compliant estate.
 * - **A trend report asks for its comparison before it is generated**, rather than
 *   letting the failure teach the lesson.
 * - **The filename comes from the server.** The date in the name is the point, and a
 *   client that rebuilds it is a second place for that decision to drift.
 */

import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ReportsPage } from '../../app/ReportsPage';
import { AuthProvider } from '../auth/AuthProvider';

const ME = {
  id: 'u1',
  username: 'analyst',
  email: 'analyst@example.com',
  full_name: 'Analyst',
  roles: ['security_analyst'],
  permissions: ['report:read', 'report:generate'],
  must_change_password: false,
  mfa_enabled: false,
};

const TEMPLATES = [
  {
    id: 'executive_summary',
    title: 'Executive summary',
    audience: 'Leadership',
    description: 'Estate posture on one page.',
    implemented: true,
  },
  {
    id: 'exceptions_register',
    title: 'Exceptions register',
    audience: 'Auditor',
    description: 'Accepted risks with justification, approver and expiry.',
    implemented: true,
  },
  {
    id: 'trend',
    title: 'Trend report',
    audience: 'Leadership',
    description: 'This report against an earlier one.',
    implemented: true,
  },
  {
    id: 'group_compliance',
    title: 'Group compliance',
    audience: 'Auditor',
    description: 'Pass, fail and not-evaluated counts per framework control.',
    implemented: true,
  },
  {
    id: 'device_detail',
    title: 'Device detail',
    audience: 'Engineer',
    description: 'Every finding on one device, with the evidence behind it.',
    implemented: true,
  },
];

const DEVICES = {
  data: [
    { id: 'd-1', hostname: 'sw-bad', mgmt_ip: '10.0.1.1' },
    { id: 'd-2', hostname: null, mgmt_ip: '10.0.1.2' },
  ],
  meta: { total: 2 },
};

const GROUPS = [{ id: 'g-1', name: 'branch-sites' }];

/** Counts differ on purpose: 13 mapped checks and 103 support very different claims. */
const FRAMEWORKS = [
  { key: 'cis', checks: 67 },
  { key: 'cert_in', checks: 13 },
  { key: 'nist_800_53', checks: 103 },
];

const READY_REPORT = {
  id: 'r-ready',
  template: 'executive_summary',
  title: 'March position',
  status: 'ready',
  scope_device_id: null,
  scope_group_id: null,
  compare_to_id: null,
  content_hash: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
  generated_at: '2026-03-31T18:00:00Z',
  expires_at: null,
  retention_expired: false,
  error_message: null,
  created_at: '2026-03-31T18:00:00Z',
};

const FAILED_REPORT = {
  ...READY_REPORT,
  id: 'r-failed',
  template: 'trend',
  title: 'Trend report',
  status: 'failed',
  content_hash: null,
  generated_at: null,
  error_message: 'A trend report compares against an earlier report. Pass `compare_to_id`.',
  created_at: '2026-04-01T09:00:00Z',
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': status >= 400 ? 'application/problem+json' : 'application/json' },
  });
}

/** "Trend report" is also a template name in the generate dropdown, so archive lookups
 *  are scoped to the table rather than the page. */
async function failedRow(): Promise<HTMLElement> {
  const table = await screen.findByRole('table');
  return within(table).getByText('Trend report').closest('tr')!;
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AuthProvider>
          <ReportsPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('ReportsPage', () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let reports: unknown[];

  beforeEach(() => {
    reports = [FAILED_REPORT, READY_REPORT];

    fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/auth/me')) return Promise.resolve(jsonResponse(ME));
      if (url.includes('/reports/templates')) return Promise.resolve(jsonResponse(TEMPLATES));
      if (url.includes('/compliance/frameworks')) return Promise.resolve(jsonResponse(FRAMEWORKS));
      if (url.includes('/device-groups')) return Promise.resolve(jsonResponse(GROUPS));
      if (url.includes('/devices')) return Promise.resolve(jsonResponse(DEVICES));
      if (url.includes('/reports/r-ready/download')) {
        return Promise.resolve(
          new Response('# March position\nhostname,mgmt_ip\nsw-bad,10.0.1.1\n', {
            status: 200,
            headers: {
              'Content-Type': 'text/csv',
              'Content-Disposition':
                'attachment; filename="netsecops-executive-summary-20260331-r-ready.csv"',
            },
          }),
        );
      }
      if (url.includes('/reports/r-ready')) {
        return Promise.resolve(
          jsonResponse({
            ...READY_REPORT,
            parameters: {},
            content: { totals: { findings: 3, devices_without_findings: 1 } },
          }),
        );
      }
      if (url.includes('/reports')) {
        return Promise.resolve(
          jsonResponse({
            data: reports,
            meta: { total: reports.length, limit: 25, offset: 0 },
          }),
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

  describe('the archive reads as dated evidence', () => {
    it('frames reports by the moment they speak for, not the moment they are read', async () => {
      renderPage();
      await screen.findByText('March position');

      expect(screen.getByText(/what did you know on 31\s*March/i)).toBeInTheDocument();
      expect(screen.getByRole('columnheader', { name: /as of/i })).toBeInTheDocument();
    });

    it('shows the content hash so a recipient can verify the artefact', async () => {
      renderPage();
      await screen.findByText('March position');

      // Truncated in the table; the full value is in the detail panel and in the file.
      expect(screen.getByText('a1b2c3d4e5f6')).toBeInTheDocument();
    });
  });

  describe('a failed report is not a result', () => {
    it('offers no download for it', async () => {
      renderPage();
      const row = await failedRow();

      expect(within(row).queryByRole('button', { name: 'JSON' })).toBeNull();
      expect(within(row).queryByRole('button', { name: 'CSV' })).toBeNull();
    });

    it('says why it failed rather than showing it as empty', async () => {
      renderPage();
      const row = await failedRow();

      expect(within(row).getByText(/Pass `compare_to_id`/)).toBeInTheDocument();
      expect(within(row).getByText('failed')).toBeInTheDocument();
    });

    it('offers both formats for a report that did complete', async () => {
      renderPage();
      const row = (await screen.findByText('March position')).closest('tr')!;

      expect(within(row).getByRole('button', { name: 'JSON' })).toBeInTheDocument();
      expect(within(row).getByRole('button', { name: 'CSV' })).toBeInTheDocument();
    });
  });

  describe('formats', () => {
    it('offers all four for a report whose content is a table', async () => {
      renderPage();
      const row = (await screen.findByText('March position')).closest('tr')!;

      for (const format of ['PDF', 'XLSX', 'CSV', 'JSON']) {
        expect(within(row).getByRole('button', { name: format })).toBeInTheDocument();
      }
    });

    it('offers only PDF and JSON when the content is not a table', async () => {
      // A trend report is two sets of totals and the deltas between them. A blank
      // spreadsheet of that reads as "no findings", so it is not offered at all.
      reports = [{ ...READY_REPORT, id: 'r-trend', template: 'trend', title: 'Q1 trend' }];
      renderPage();
      const row = (await screen.findByText('Q1 trend')).closest('tr')!;

      expect(within(row).getByRole('button', { name: 'PDF' })).toBeInTheDocument();
      expect(within(row).getByRole('button', { name: 'JSON' })).toBeInTheDocument();
      expect(within(row).queryByRole('button', { name: 'CSV' })).toBeNull();
      expect(within(row).queryByRole('button', { name: 'XLSX' })).toBeNull();
    });
  });

  describe('retention', () => {
    it('flags an expired report and still lists it', async () => {
      // Nothing deletes a report. An auditor cannot be told a cron removed March.
      reports = [{ ...READY_REPORT, retention_expired: true, expires_at: '2026-04-01T00:00:00Z' }];
      renderPage();

      const row = (await screen.findByText('March position')).closest('tr')!;
      expect(within(row).getByText('retention expired')).toBeInTheDocument();
      expect(within(row).getByRole('button', { name: 'PDF' })).toBeInTheDocument();
    });

    it('does not flag a report with no expiry', async () => {
      renderPage();
      const row = (await screen.findByText('March position')).closest('tr')!;

      expect(within(row).queryByText('retention expired')).toBeNull();
    });
  });

  describe('templates that need a scope ask for it before generating', () => {
    it('will not generate a device report until a device is chosen', async () => {
      const user = userEvent.setup();
      renderPage();
      await screen.findByLabelText('Report template');

      await user.selectOptions(screen.getByLabelText('Report template'), 'device_detail');

      expect(screen.getByRole('button', { name: /generate/i })).toBeDisabled();
      expect(screen.getByText(/will not fall back to the estate/i)).toBeInTheDocument();
    });

    it('offers a device by hostname, falling back to its address', async () => {
      const user = userEvent.setup();
      renderPage();
      await screen.findByLabelText('Report template');

      await user.selectOptions(screen.getByLabelText('Report template'), 'device_detail');
      const picker = await screen.findByLabelText('Device');

      expect(within(picker).getByRole('option', { name: 'sw-bad' })).toBeInTheDocument();
      // A device with no hostname must still be selectable, not blank.
      expect(within(picker).getByRole('option', { name: '10.0.1.2' })).toBeInTheDocument();
    });

    it('enables generation once a device is picked', async () => {
      const user = userEvent.setup();
      renderPage();
      await screen.findByLabelText('Report template');

      await user.selectOptions(screen.getByLabelText('Report template'), 'device_detail');
      await user.selectOptions(await screen.findByLabelText('Device'), 'd-1');

      expect(screen.getByRole('button', { name: /generate/i })).toBeEnabled();
    });

    it('clears a scope when the template changes', async () => {
      const user = userEvent.setup();
      renderPage();
      await screen.findByLabelText('Report template');

      await user.selectOptions(screen.getByLabelText('Report template'), 'device_detail');
      await user.selectOptions(await screen.findByLabelText('Device'), 'd-1');
      await user.selectOptions(screen.getByLabelText('Report template'), 'group_compliance');

      // A device id carried into a group report is a scope the server would reject and
      // the operator never chose.
      expect(screen.queryByLabelText('Device')).toBeNull();
      expect(screen.getByRole('button', { name: /generate/i })).toBeDisabled();
    });
  });

  describe('a compliance report needs a group and a framework', () => {
    it('asks for both, and stays blocked with only one', async () => {
      const user = userEvent.setup();
      renderPage();
      await screen.findByLabelText('Report template');

      await user.selectOptions(screen.getByLabelText('Report template'), 'group_compliance');
      await user.selectOptions(await screen.findByLabelText('Device group'), 'g-1');

      expect(screen.getByRole('button', { name: /generate/i })).toBeDisabled();

      await user.selectOptions(await screen.findByLabelText('Framework'), 'cis');
      expect(screen.getByRole('button', { name: /generate/i })).toBeEnabled();
    });

    it('shows how many checks reach each framework', async () => {
      const user = userEvent.setup();
      renderPage();
      await screen.findByLabelText('Report template');

      await user.selectOptions(screen.getByLabelText('Report template'), 'group_compliance');
      const picker = await screen.findByLabelText('Framework');

      // 13 checks and 103 support very different claims about the same framework, so
      // the picker must not present them as equivalent.
      expect(
        within(picker).getByRole('option', { name: /cert_in \(13 checks\)/ }),
      ).toBeInTheDocument();
      expect(
        within(picker).getByRole('option', { name: /nist_800_53 \(103 checks\)/ }),
      ).toBeInTheDocument();
    });

    it('sources the framework list from the API rather than a hard-coded one', async () => {
      const user = userEvent.setup();
      renderPage();
      await screen.findByLabelText('Report template');

      await user.selectOptions(screen.getByLabelText('Report template'), 'group_compliance');
      await screen.findByLabelText('Framework');

      // The console hard-coded four and hid cert_in and cea for a whole phase.
      expect(
        fetchMock.mock.calls.some(([url]) => String(url).includes('/compliance/frameworks')),
      ).toBe(true);
    });
  });

  describe('a trend report asks for its comparison up front', () => {
    it('will not generate until one is chosen', async () => {
      const user = userEvent.setup();
      renderPage();
      await screen.findByLabelText('Report template');

      await user.selectOptions(screen.getByLabelText('Report template'), 'trend');

      expect(screen.getByRole('button', { name: /generate/i })).toBeDisabled();
    });

    it('offers only finished reports as the comparison', async () => {
      const user = userEvent.setup();
      renderPage();
      await screen.findByText('March position');

      await user.selectOptions(screen.getByLabelText('Report template'), 'trend');
      const picker = screen.getByLabelText('Report to compare against');

      expect(within(picker).getByRole('option', { name: /March position/ })).toBeInTheDocument();
      // The failed one is not a baseline anything can be measured against.
      expect(within(picker).queryByRole('option', { name: /Trend report/ })).toBeNull();
    });

    it('enables generation once a comparison is picked', async () => {
      const user = userEvent.setup();
      renderPage();
      await screen.findByText('March position');

      await user.selectOptions(screen.getByLabelText('Report template'), 'trend');
      await user.selectOptions(screen.getByLabelText('Report to compare against'), 'r-ready');

      expect(screen.getByRole('button', { name: /generate/i })).toBeEnabled();
    });
  });

  describe('downloading', () => {
    it('uses the filename the server chose, which carries the date', async () => {
      const user = userEvent.setup();
      const click = vi
        .spyOn(HTMLAnchorElement.prototype, 'click')
        .mockImplementation(() => undefined);
      // Defined as properties rather than by replacing the global: jsdom has no
      // createObjectURL, but swapping `URL` wholesale takes the constructor with it and
      // everything that parses a URL breaks somewhere unrelated.
      Object.defineProperty(URL, 'createObjectURL', {
        value: vi.fn(() => 'blob:report'),
        configurable: true,
      });
      Object.defineProperty(URL, 'revokeObjectURL', { value: vi.fn(), configurable: true });

      renderPage();
      const row = (await screen.findByText('March position')).closest('tr')!;
      await user.click(within(row).getByRole('button', { name: 'CSV' }));

      await waitFor(() => expect(click).toHaveBeenCalled());
      // `instances` is typed from the spied method's return type (void), so the cast
      // goes through unknown; at runtime these are the `this` values, i.e. the anchors.
      const anchor = click.mock.instances[0] as unknown as HTMLAnchorElement;
      expect(anchor.download).toBe('netsecops-executive-summary-20260331-r-ready.csv');
    });
  });

  describe('the detail panel', () => {
    it('says the content is frozen rather than current', async () => {
      const user = userEvent.setup();
      renderPage();

      await user.click(await screen.findByRole('button', { name: 'March position' }));

      expect(
        await screen.findByText(/not recalculated — a finding resolved since does not disappear/i),
      ).toBeInTheDocument();
    });

    it('shows the full hash next to what it identifies', async () => {
      const user = userEvent.setup();
      renderPage();

      await user.click(await screen.findByRole('button', { name: 'March position' }));

      expect(await screen.findByText(/sha256 a1b2c3d4/)).toBeInTheDocument();
    });
  });
});
