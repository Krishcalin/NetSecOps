/** The exception register (FR-CHK-07).
 *
 * The register only works if it is legible at a glance: what was accepted, over how much
 * of the estate, by whom, and how long is left. Each of those, missing, turns an
 * accepted risk back into an unexplained one — which is the state this page exists to
 * end.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ExceptionsPage } from './ExceptionsPage';
import { api } from '../api/client';

let granted = new Set(['policy:read', 'exception:write']);

vi.mock('../features/auth/useAuth', () => ({
  useAuth: () => ({ can: (permission: string) => granted.has(permission) }),
}));

const CHECK = {
  id: 'ssh-version-2',
  title: 'SSH is restricted to version 2',
  severity: 'high',
  description: '',
  tags: [],
  logic_type: 'ncm',
  vendors: [],
  platforms: [],
  frameworks: {},
  enabled_by_default: true,
  is_custom: false,
};

const DEVICE = { id: 'd1', mgmt_ip: '10.0.0.1', hostname: 'core-sw-01' };
const GROUP = { id: 'g1', name: 'north', description: null, parent_id: null, path: 'a' };

function inDays(days: number): string {
  return new Date(Date.now() + days * 86_400_000).toISOString();
}

const EXCEPTION = {
  id: 'e1',
  check_id: 'ssh-version-2',
  scope: 'device',
  device_id: 'd1',
  device_group_id: null,
  justification: 'Vendor firmware does not support it until Q3.',
  approver: 'CISO',
  expires_at: inDays(90),
  status: 'active',
  created_at: '2026-09-01T00:00:00Z',
};

let exceptions: unknown[] = [];

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ExceptionsPage />
    </QueryClientProvider>,
  );
}

async function row(text: string): Promise<HTMLElement> {
  return (await screen.findByText(text)).closest('tr')!;
}

/** The check select renders before its options arrive, so waiting on the label alone
 *  races the library query. */
async function chooseCheck(): Promise<void> {
  await screen.findByRole('option', { name: /SSH is restricted to version 2/ });
  await userEvent.selectOptions(screen.getByLabelText('Check'), 'ssh-version-2');
}

describe('ExceptionsPage', () => {
  beforeEach(() => {
    granted = new Set(['policy:read', 'exception:write']);
    exceptions = [EXCEPTION];
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/exceptions')) return exceptions as never;
      if (path.startsWith('/checks')) return [CHECK] as never;
      if (path.startsWith('/devices')) return { data: [DEVICE], meta: { total: 1 } } as never;
      if (path.startsWith('/device-groups')) return [GROUP] as never;
      return [] as never;
    });
  });

  afterEach(() => vi.restoreAllMocks());

  describe('reading the register', () => {
    it('resolves the check and the device rather than showing ids', async () => {
      renderPage();

      const line = await row('SSH is restricted to version 2');
      await waitFor(() => expect(within(line).getByText('core-sw-01')).toBeInTheDocument());
    });

    it('says how long is left, not just the date', async () => {
      // The date alone makes "is this about to lapse" an arithmetic problem, so nobody
      // does it and the review happens after the finding reappears.
      renderPage();

      expect(await screen.findByText(/90 days left/)).toBeInTheDocument();
    });

    it('flags an exception nobody is named against', async () => {
      // The approver is optional on the API, and a waiver with no name on it is the one
      // thing the register cannot be allowed to record silently.
      exceptions = [{ ...EXCEPTION, approver: null }];
      renderPage();

      expect(await screen.findByText('nobody named')).toBeInTheDocument();
    });

    it('marks a lapsed exception as no longer in force', async () => {
      exceptions = [{ ...EXCEPTION, expires_at: inDays(-3) }];
      renderPage();

      expect(await screen.findByText('lapsed')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument();
    });

    it('marks a global exception as global', async () => {
      exceptions = [{ ...EXCEPTION, scope: 'global', device_id: null }];
      renderPage();

      expect(await screen.findByText('global')).toBeInTheDocument();
      expect(screen.getByText('the whole estate')).toBeInTheDocument();
    });

    it('says plainly when nothing is suppressed', async () => {
      // "No exceptions" is a meaningful state — it means every finding on the dashboard
      // is one nobody has accepted — and an empty table does not say it.
      exceptions = [];
      renderPage();

      expect(await screen.findByText(/one nobody has accepted/)).toBeInTheDocument();
    });
  });

  describe('filing one', () => {
    it('requires a justification and an end date', async () => {
      renderPage();

      await chooseCheck();
      await userEvent.selectOptions(screen.getByLabelText('Device'), 'd1');

      expect(screen.getByRole('button', { name: 'File the exception' })).toBeDisabled();
    });

    it('sends the device for a device-scoped exception and no group', async () => {
      const post = vi.spyOn(api, 'post').mockResolvedValue(EXCEPTION as never);
      renderPage();

      await chooseCheck();
      await userEvent.selectOptions(screen.getByLabelText('Device'), 'd1');
      await userEvent.type(screen.getByLabelText('Justification'), 'Waiting on firmware.');
      await userEvent.type(screen.getByLabelText('Expires'), '2027-01-31');
      await userEvent.click(screen.getByRole('button', { name: 'File the exception' }));

      await waitFor(() =>
        expect(post).toHaveBeenCalledWith(
          '/exceptions',
          expect.objectContaining({
            check_id: 'ssh-version-2',
            scope: 'device',
            device_id: 'd1',
            device_group_id: null,
          }),
        ),
      );
    });

    it('asks for a group instead when the scope is a group', async () => {
      renderPage();

      await userEvent.selectOptions(await screen.findByLabelText('Scope'), 'group');

      expect(screen.getByLabelText('Device group')).toBeInTheDocument();
      expect(screen.queryByLabelText('Device')).not.toBeInTheDocument();
    });

    it('warns what a global exception costs, and points at the alternative', async () => {
      renderPage();

      await userEvent.selectOptions(await screen.findByLabelText('Scope'), 'global');

      expect(screen.getByText(/disabling the check in the policy instead/)).toBeInTheDocument();
    });
  });

  describe('revoking', () => {
    it('calls the endpoint for an exception in force', async () => {
      const remove = vi.spyOn(api, 'delete').mockResolvedValue(EXCEPTION as never);
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Revoke' }));

      expect(remove).toHaveBeenCalledWith('/exceptions/e1');
    });

    it('is not offered without exception:write', async () => {
      granted = new Set(['policy:read']);
      renderPage();

      await screen.findByText('SSH is restricted to version 2');
      expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument();
      expect(screen.queryByLabelText('Justification')).not.toBeInTheDocument();
    });
  });
});
