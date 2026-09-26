/** Component tests for the findings view (FR-FIND-03, FR-FIND-04, TEST-05).
 *
 * The assertions worth having here are about what the UI *will not* let an operator
 * do, and about whether a finding arrives with enough substance to act on. A findings
 * list that looks right but shows a conclusion with no evidence behind it is the
 * failure mode that matters.
 */

import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { FindingsPage } from '../../app/FindingsPage';
import { AuthProvider } from '../auth/AuthProvider';

const ME = {
  id: 'u1',
  username: 'analyst',
  email: 'analyst@example.com',
  full_name: 'Analyst',
  roles: ['security_analyst'],
  permissions: ['finding:read', 'finding:write'],
  must_change_password: false,
  mfa_enabled: false,
};

const FINDING = {
  id: 'f1',
  device_id: 'd1',
  kind: 'config',
  check_id: 'telnet-disabled',
  cve_id: null,
  title: 'Telnet is disabled',
  description: 'management.services.telnet.enabled is True, but it should be False.',
  severity: 'critical',
  status: 'new',
  first_seen_at: '2026-09-01T10:00:00Z',
  last_seen_at: '2026-09-12T10:00:00Z',
  resolved_at: null,
  occurrences: 4,
  assignee_id: null,
  due_at: null,
  created_at: '2026-09-01T10:00:00Z',
};

const DETAIL = {
  ...FINDING,
  evidence: {
    observed: true,
    expected: 'management.services.telnet.enabled should be False',
    lines: [
      {
        path: 'management.services.telnet.enabled',
        line_start: 85,
        line_end: 85,
        excerpt: 'transport input all',
        command: 'show running-config',
      },
    ],
  },
  remediation: 'Set `transport input ssh` under every line vty block.',
  snapshot_id: 's1',
  rationale: 'Telnet carries credentials in clear text.',
  references: { cis: ['1.2.4'], nist_800_53: ['AC-17'], urls: [] },
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
          <FindingsPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('FindingsPage', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/auth/me')) return Promise.resolve(jsonResponse(ME));
      if (url.includes('/findings/f1')) return Promise.resolve(jsonResponse(DETAIL));
      if (url.includes('/findings')) {
        return Promise.resolve(
          jsonResponse({ data: [FINDING], meta: { total: 1, limit: 25, offset: 0 } }),
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

  it('lists findings with their severity', async () => {
    renderPage();
    expect(await screen.findByText('Telnet is disabled')).toBeInTheDocument();

    // Scoped to the table: the severity filter carries an <option>critical</option>
    // with the same text.
    const table = screen.getByRole('table');
    expect(within(table).getByText('critical')).toHaveClass('pill--critical');
  });

  it('defaults to open findings only', async () => {
    renderPage();
    await screen.findByText('Telnet is disabled');

    // The list answers "what should I do next", so resolved findings are out of the
    // way until asked for.
    expect(screen.getByLabelText(/open findings only/i)).toBeChecked();
    const called = fetchMock.mock.calls
      .map((c) => String(c[0]))
      .find((u) => u.includes('/findings?'));
    expect(called).toContain('active_only=true');
  });

  it('shows the configuration line behind the conclusion', async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText('Telnet is disabled');

    await user.click(screen.getByRole('button', { name: 'Details for Telnet is disabled' }));

    const panel = await screen.findByText('Evidence');
    const card = panel.closest('.card') as HTMLElement;

    // The line number and the operator's own text, which is what makes a finding
    // verifiable rather than merely assertive.
    expect(within(card).getByText('85')).toBeInTheDocument();
    expect(within(card).getByText('transport input all')).toBeInTheDocument();
  });

  it('explains why the check exists and how to fix it', async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText('Telnet is disabled');
    await user.click(screen.getByRole('button', { name: 'Details for Telnet is disabled' }));

    expect(await screen.findByText(/carries credentials in clear text/)).toBeInTheDocument();
    expect(screen.getByText(/transport input ssh/)).toBeInTheDocument();
  });

  it('shows the framework controls the check maps to', async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText('Telnet is disabled');
    await user.click(screen.getByRole('button', { name: 'Details for Telnet is disabled' }));

    expect(await screen.findByText('CIS')).toBeInTheDocument();
    expect(screen.getByText('NIST 800-53')).toBeInTheDocument();
  });

  it('offers no way to mark a finding resolved by hand', async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText('Telnet is disabled');
    await user.click(screen.getByRole('button', { name: 'Details for Telnet is disabled' }));
    await screen.findByText('Evidence');

    // Resolved means "the check passed on a later assessment". Offering it as a button
    // would turn a measurement into a claim, and let a real problem be clicked away.
    expect(screen.queryByRole('button', { name: /mark resolved/i })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /mark risk accepted/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /mark false positive/i })).toBeInTheDocument();
  });

  it('explains a check with no line-level evidence rather than showing a blank', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/auth/me')) return Promise.resolve(jsonResponse(ME));
      if (url.includes('/findings/f1')) {
        return Promise.resolve(
          jsonResponse({
            ...DETAIL,
            evidence: { observed: ['public'], expected: null, lines: [] },
          }),
        );
      }
      return Promise.resolve(
        jsonResponse({ data: [FINDING], meta: { total: 1, limit: 25, offset: 0 } }),
      );
    });

    const user = userEvent.setup();
    renderPage();
    await screen.findByText('Telnet is disabled');
    await user.click(screen.getByRole('button', { name: 'Details for Telnet is disabled' }));

    expect(await screen.findByText(/reasons over the parsed configuration/i)).toBeInTheDocument();
  });

  it('says so plainly when there are no findings', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/auth/me')) return Promise.resolve(jsonResponse(ME));
      return Promise.resolve(jsonResponse({ data: [], meta: { total: 0, limit: 25, offset: 0 } }));
    });

    renderPage();

    // "No findings" is ambiguous on its own — nothing assessed looks identical to
    // everything passing, and the two mean opposite things.
    expect(await screen.findByText(/nothing has been assessed yet/i)).toBeInTheDocument();
  });

  it('hides triage actions from a reader who cannot write findings', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/auth/me')) {
        return Promise.resolve(jsonResponse({ ...ME, permissions: ['finding:read'] }));
      }
      if (url.includes('/findings/f1')) return Promise.resolve(jsonResponse(DETAIL));
      return Promise.resolve(
        jsonResponse({ data: [FINDING], meta: { total: 1, limit: 25, offset: 0 } }),
      );
    });

    const user = userEvent.setup();
    renderPage();
    await screen.findByText('Telnet is disabled');
    await user.click(screen.getByRole('button', { name: 'Details for Telnet is disabled' }));
    await screen.findByText('Evidence');

    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /mark risk accepted/i })).not.toBeInTheDocument();
    });
  });

  describe('reviewing a finding with a keyboard and a screen reader', () => {
    // The detail panel renders *below* the table and below the button that opens it, and
    // its Close button unmounts itself. Without focus management, opening announces
    // nothing and closing drops focus to <body>, restarting the reader at the top.

    it('names each Details button for its own row', async () => {
      // Twenty-five buttons all called "Details" are indistinguishable in a screen
      // reader's element list (WCAG 2.4.4).
      renderPage();

      expect(
        await screen.findByRole('button', { name: 'Details for Telnet is disabled' }),
      ).toBeVisible();
    });

    it('moves focus into the panel when it opens', async () => {
      // This caught a real defect: the first version of the effect ran on mount, when
      // the panel is still a "Loading…" paragraph and the ref points at nothing, so it
      // silently did nothing while looking correct in the source.
      const user = userEvent.setup();
      renderPage();

      await user.click(
        await screen.findByRole('button', { name: 'Details for Telnet is disabled' }),
      );

      const panel = await screen.findByRole('region', { name: /Finding detail/ });
      await waitFor(() => expect(panel).toHaveFocus());
    });

    it('returns focus to the row that opened it when it closes', async () => {
      const user = userEvent.setup();
      renderPage();

      await user.click(
        await screen.findByRole('button', { name: 'Details for Telnet is disabled' }),
      );
      await screen.findByRole('region', { name: /Finding detail/ });

      await user.click(screen.getByRole('button', { name: 'Close' }));

      await waitFor(() =>
        expect(
          screen.getByRole('button', { name: 'Details for Telnet is disabled' }),
        ).toHaveFocus(),
      );
    });
  });
});
