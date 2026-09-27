/** The segmentation matrix page (FR-TOPO-07, TEST-05).
 *
 * This is the page somebody prints and signs, so every test here is a version of one
 * question: **can a reader mistake something for a pass that was not checked?**
 *
 * The three that matter: `unverified` is never coloured or worded as success, it is
 * counted in the summary beside the violations rather than tucked away, and an empty
 * policy says so instead of rendering an unblemished page.
 */

import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { SegmentationPage } from '../../app/SegmentationPage';
import { AuthProvider } from '../auth/AuthProvider';
import type { Cell, IntentRule, Matrix, Zone } from './types';
import { STATUS_LABELS } from './types';

/** Permissions are the variable here: the page now carries policy authorship, and who
 *  may read the matrix is deliberately not who may change what it is judged against. */
function me(permissions: string[]) {
  return {
    id: 'u1',
    username: 'analyst',
    email: 'analyst@example.com',
    full_name: 'Analyst',
    roles: ['security_analyst'],
    permissions,
    must_change_password: false,
    mfa_enabled: false,
  };
}

const READER = ['policy:read', 'snapshot:read'];
const AUTHOR = [...READER, 'policy:write'];

function zone(id: string, name: string, prefixes: string[]): Zone {
  return { id, name, description: null, prefixes };
}

function intent(overrides: Partial<IntentRule> = {}): IntentRule {
  return {
    id: 'i-1',
    source_zone_id: 'z-prod',
    destination_zone_id: 'z-cde',
    expectation: 'denied',
    protocol: 'tcp',
    port: 443,
    justification: 'PCI DSS 1.2.1.',
    ...overrides,
  };
}

function cell(overrides: Partial<Cell> = {}): Cell {
  return {
    rule_id: `r-${Math.random()}`,
    source_zone: 'Production',
    destination_zone: 'Cardholder data',
    expectation: 'denied',
    protocol: 'tcp',
    port: 443,
    status: 'upheld',
    detail: 'Traffic is denied at edge-fw, as the policy requires.',
    justification: 'PCI DSS 1.2.1.',
    walked: ['10.10.0.0/24 → 10.20.0.0/24'],
    limitations: [],
    ...overrides,
  };
}

function matrix(overrides: Partial<Matrix> = {}): Matrix {
  return { cells: [], upheld: 0, violated: 0, unverified: 0, limitations: [], ...overrides };
}

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
          <SegmentationPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('SegmentationPage', () => {
  let payload: Matrix;
  let zones: Zone[];
  let rules: IntentRule[];
  let permissions: string[];
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    payload = matrix();
    zones = [];
    rules = [];
    permissions = AUTHOR;

    fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      if (url.includes('/auth/me')) return Promise.resolve(jsonResponse(me(permissions)));
      if (url.includes('/segmentation/matrix')) return Promise.resolve(jsonResponse(payload));
      if (url.includes('/segmentation/zones') && method === 'GET') {
        return Promise.resolve(jsonResponse(zones));
      }
      if (url.includes('/segmentation/rules') && method === 'GET') {
        return Promise.resolve(jsonResponse(rules));
      }
      if (method === 'POST' || method === 'DELETE') {
        return Promise.resolve(jsonResponse({}, method === 'POST' ? 201 : 204));
      }
      return Promise.resolve(jsonResponse({}, 404));
    });
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  describe('not verified is not a pass', () => {
    it('never gives an unverified cell the success tone', () => {
      // Asserted on the mapping rather than the DOM, because that is where the mistake
      // gets made. A plausible amber would keep every text assertion in this file
      // passing while making the cell read as "mostly fine".
      expect(STATUS_LABELS.unverified.tone).not.toBe(STATUS_LABELS.upheld.tone);
      expect(STATUS_LABELS.unverified.tone).not.toBe('success');
    });

    it('labels it in words, not by colour alone', async () => {
      payload = matrix({ cells: [cell({ status: 'unverified' })], unverified: 1 });
      renderPage();

      expect(await screen.findByText('Not verified')).toBeInTheDocument();
    });

    it('says outright that it is not a pass when the row is opened', async () => {
      payload = matrix({
        cells: [
          cell({
            status: 'unverified',
            detail: 'The path could not be traced far enough to say.',
          }),
        ],
        unverified: 1,
      });
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: /Production/ }));

      expect(screen.getByText(/This is not a pass/)).toBeInTheDocument();
    });

    it('counts it beside the violations rather than tucked under them', async () => {
      // A reader scanning for red takes the absence of it as a pass, and this is the
      // number that says otherwise.
      payload = matrix({ cells: [cell({ status: 'unverified' })], unverified: 3, upheld: 1 });
      renderPage();

      const stat = (await screen.findByText('not verified')).closest('.stat');
      expect(within(stat as HTMLElement).getByText('3')).toBeInTheDocument();
    });
  });

  describe('the list', () => {
    it('puts violations first, then unverified, then upheld', async () => {
      // The page is read top-down and the rows needing action should be where a
      // reader stops scrolling.
      payload = matrix({
        cells: [
          cell({ rule_id: 'a', source_zone: 'AAA', status: 'upheld' }),
          cell({ rule_id: 'b', source_zone: 'BBB', status: 'unverified' }),
          cell({ rule_id: 'c', source_zone: 'CCC', status: 'violated' }),
        ],
        upheld: 1,
        unverified: 1,
        violated: 1,
      });
      renderPage();

      const rows = await screen.findAllByRole('listitem');
      const zones = rows.map((row) => row.textContent?.match(/[A-Z]{3}/)?.[0]);
      expect(zones).toEqual(['CCC', 'BBB', 'AAA']);
    });

    it('shows what was actually walked, so upheld has a stated scope', async () => {
      payload = matrix({
        cells: [cell({ walked: ['10.10.0.0/24 → 10.20.0.0/24'] })],
        upheld: 1,
      });
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: /Production/ }));

      expect(screen.getByText('10.10.0.0/24 → 10.20.0.0/24')).toBeInTheDocument();
    });

    it('carries the justification, so a cell can be argued with', async () => {
      payload = matrix({ cells: [cell({ justification: 'Required by PCI DSS 1.2.1.' })] });
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: /Production/ }));

      expect(screen.getByText('Required by PCI DSS 1.2.1.')).toBeInTheDocument();
    });
  });

  describe('an empty policy', () => {
    it('says nothing has been declared rather than rendering a clean page', async () => {
      // Zero violations out of zero rules is the most misleading thing this page
      // could show, because it is indistinguishable from a compliant estate.
      payload = matrix({
        limitations: ['No segmentation policy has been declared, so there is nothing to check.'],
      });
      renderPage();

      expect(await screen.findByText(/An empty matrix is not a clean one/)).toBeInTheDocument();
    });

    it('repeats the limitations the server sent', async () => {
      payload = matrix({
        cells: [cell()],
        upheld: 1,
        limitations: ['2 of 3 cells could not be verified. Those are not passes.'],
      });
      renderPage();

      expect(await screen.findByText(/Those are not passes/)).toBeInTheDocument();
    });
  });

  describe('writing the policy', () => {
    it('declares a zone from the console', async () => {
      // The gap this closes: the page evaluated a policy that could only be written
      // through the API, so on a console-only deployment it was permanently empty.
      renderPage();
      await screen.findByRole('heading', { name: 'The policy' });

      await userEvent.type(screen.getByLabelText('Name'), 'Cardholder data');
      await userEvent.type(screen.getByLabelText('Address space'), '10.20.0.0/24');
      await userEvent.click(screen.getByRole('button', { name: 'Declare zone' }));

      const posted = fetchMock.mock.calls.find(
        ([url, init]) =>
          String(url).includes('/segmentation/zones') &&
          (init as RequestInit | undefined)?.method === 'POST',
      );
      expect(posted).toBeDefined();
      expect(JSON.parse(String((posted?.[1] as RequestInit).body))).toMatchObject({
        name: 'Cardholder data',
        prefixes: ['10.20.0.0/24'],
      });
    });

    it('takes CIDRs typed as a list, however they were separated', async () => {
      renderPage();
      await screen.findByRole('heading', { name: 'The policy' });

      await userEvent.type(screen.getByLabelText('Name'), 'Users');
      await userEvent.type(
        screen.getByLabelText('Address space'),
        '10.10.0.0/24, 10.11.0.0/24{enter}10.12.0.0/24',
      );
      await userEvent.click(screen.getByRole('button', { name: 'Declare zone' }));

      const posted = fetchMock.mock.calls.find(
        ([url, init]) =>
          String(url).includes('/segmentation/zones') &&
          (init as RequestInit | undefined)?.method === 'POST',
      );
      expect(JSON.parse(String((posted?.[1] as RequestInit).body)).prefixes).toEqual([
        '10.10.0.0/24',
        '10.11.0.0/24',
        '10.12.0.0/24',
      ]);
    });

    it('will not declare an intent without a justification', async () => {
      // Required by the API too. Said here so it is not discovered from a 422 after
      // the field has scrolled away — a cell nobody can explain is one nobody changes.
      zones = [
        zone('z-prod', 'Production', ['10.10.0.0/24']),
        zone('z-cde', 'CDE', ['10.20.0.0/24']),
      ];
      renderPage();
      await screen.findByRole('heading', { name: 'The policy' });

      await userEvent.selectOptions(screen.getByLabelText('From'), 'z-prod');
      await userEvent.selectOptions(screen.getByLabelText('To'), 'z-cde');

      expect(screen.getByRole('button', { name: 'Declare intent' })).toBeDisabled();

      await userEvent.type(
        screen.getByLabelText('Why this rule exists'),
        'PCI DSS 1.2.1 — the CDE is not reachable from production.',
      );
      expect(screen.getByRole('button', { name: 'Declare intent' })).toBeEnabled();
    });

    it('refuses a zone pair with itself before the request is made', async () => {
      zones = [
        zone('z-prod', 'Production', ['10.10.0.0/24']),
        zone('z-cde', 'CDE', ['10.20.0.0/24']),
      ];
      renderPage();
      await screen.findByRole('heading', { name: 'The policy' });

      await userEvent.selectOptions(screen.getByLabelText('From'), 'z-prod');
      await userEvent.selectOptions(screen.getByLabelText('To'), 'z-prod');
      await userEvent.type(
        screen.getByLabelText('Why this rule exists'),
        'Long enough to satisfy the minimum justification length.',
      );

      expect(screen.getByText(/cannot be segmented from itself/)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Declare intent' })).toBeDisabled();
    });

    it('will not offer to remove a zone an intent names', async () => {
      // The refusal exists server-side because both foreign keys cascade. Offering the
      // button and reporting the 409 afterwards would present a tidy-up that silently
      // withdraws requirements as an ordinary action that happened to fail.
      zones = [
        zone('z-prod', 'Production', ['10.10.0.0/24']),
        zone('z-cde', 'CDE', ['10.20.0.0/24']),
      ];
      rules = [intent()];
      renderPage();

      // Scoped to the zones table: "Production" is also a cell in the verdicts above,
      // which is the point of having both on one page.
      const table = await screen.findByRole('table', { name: /Declared zones/ });
      const row = within(table).getByText('Production').closest('tr')!;
      expect(within(row).getByRole('button', { name: 'Remove' })).toBeDisabled();
      expect(within(row).getByText('1 intent')).toBeInTheDocument();
    });

    it('offers to remove a zone nothing names', async () => {
      zones = [zone('z-spare', 'Spare', ['10.90.0.0/24'])];
      renderPage();

      const row = (await screen.findByText('Spare')).closest('tr')!;
      expect(within(row).getByRole('button', { name: 'Remove' })).toBeEnabled();
    });

    it('withdraws a statement from the verdict it is shown beside', async () => {
      payload = matrix({ cells: [cell({ rule_id: 'r-1', status: 'violated' })], violated: 1 });
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: /Production/ }));
      await userEvent.click(screen.getByRole('button', { name: /Withdraw this statement/ }));

      const deleted = fetchMock.mock.calls.find(
        ([, init]) => (init as RequestInit | undefined)?.method === 'DELETE',
      );
      expect(String(deleted?.[0])).toContain('/segmentation/rules/r-1');
    });

    it('says that withdrawing changes the requirement and not the traffic', async () => {
      // A violated cell is exactly where somebody is tempted to make the red go away.
      payload = matrix({ cells: [cell({ status: 'violated' })], violated: 1 });
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: /Production/ }));

      expect(screen.getByText(/Nothing about the estate changes/)).toBeInTheDocument();
    });

    it('re-evaluates the matrix after a change', async () => {
      // A new intent that did not appear in the verdicts above would read as a page
      // that had not saved it — and a withdrawn one still showing its old verdict is
      // worse, because the verdict is what somebody signs.
      zones = [
        zone('z-prod', 'Production', ['10.10.0.0/24']),
        zone('z-cde', 'CDE', ['10.20.0.0/24']),
      ];
      renderPage();
      await screen.findByRole('heading', { name: 'The policy' });

      const matrixCalls = () =>
        fetchMock.mock.calls.filter(([url]) => String(url).includes('/segmentation/matrix')).length;
      const before = matrixCalls();

      await userEvent.selectOptions(screen.getByLabelText('From'), 'z-prod');
      await userEvent.selectOptions(screen.getByLabelText('To'), 'z-cde');
      await userEvent.type(
        screen.getByLabelText('Why this rule exists'),
        'PCI DSS 1.2.1 — the CDE is not reachable from production.',
      );
      await userEvent.click(screen.getByRole('button', { name: 'Declare intent' }));

      await waitFor(() => expect(matrixCalls()).toBeGreaterThan(before));
    });

    it('surfaces the server refusal rather than failing silently', async () => {
      renderPage();
      await screen.findByRole('heading', { name: 'The policy' });
      fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.includes('/auth/me')) return Promise.resolve(jsonResponse(me(permissions)));
        if (url.includes('/segmentation/matrix')) return Promise.resolve(jsonResponse(payload));
        if ((init?.method ?? 'GET') === 'GET') return Promise.resolve(jsonResponse([]));
        return Promise.resolve(
          jsonResponse(
            { status: 409, title: 'Conflict', detail: "A zone called 'Prod' already exists." },
            409,
          ),
        );
      });

      await userEvent.type(screen.getByLabelText('Name'), 'Prod');
      await userEvent.type(screen.getByLabelText('Address space'), '10.10.0.0/24');
      await userEvent.click(screen.getByRole('button', { name: 'Declare zone' }));

      expect(await screen.findByRole('alert')).toHaveTextContent(/already exists/);
    });
  });

  describe('a reader who may not author policy', () => {
    beforeEach(() => {
      permissions = READER;
    });

    it('still sees the zones and the verdicts', async () => {
      zones = [zone('z-prod', 'Production', ['10.10.0.0/24'])];
      payload = matrix({ cells: [cell()], upheld: 1 });
      renderPage();

      const table = await screen.findByRole('table', { name: /Declared zones/ });
      expect(within(table).getByText('Production')).toBeInTheDocument();
      expect(within(table).getByText('10.10.0.0/24')).toBeInTheDocument();
    });

    it('is offered no way to change the policy, and told why', async () => {
      zones = [zone('z-spare', 'Spare', ['10.90.0.0/24'])];
      payload = matrix({ cells: [cell()], upheld: 1 });
      renderPage();

      await screen.findByRole('heading', { name: 'The policy' });
      expect(screen.queryByRole('button', { name: 'Declare zone' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Remove' })).not.toBeInTheDocument();
      expect(screen.getByText(/needs/)).toBeInTheDocument();

      await userEvent.click(screen.getByRole('button', { name: /Production/ }));
      expect(
        screen.queryByRole('button', { name: /Withdraw this statement/ }),
      ).not.toBeInTheDocument();
    });
  });
});
