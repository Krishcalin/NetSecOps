/** Policies — which checks apply where (FR-CHK-05, FR-CHK-06).
 *
 * The risk this page carries is not a broken call, it is a misunderstood one. Disabling a
 * check inside a policy and filing an exception look like the same act and are not: one
 * says the rule does not apply, the other says it applies and is knowingly unmet. Choose
 * wrong and you lose either the finding or the audit trail, so the distinction has to be
 * in front of the control rather than in documentation.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { PoliciesPage } from './PoliciesPage';
import { api } from '../api/client';

let granted = new Set(['policy:read', 'policy:write']);

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

const POLICY = {
  id: 'p1',
  name: 'Baseline',
  description: 'The shipped baseline',
  source: 'builtin',
  version: 1,
  enabled: true,
  is_default: false,
  frameworks: ['nist_800_53'],
  created_at: '2026-09-01T00:00:00Z',
};

let policies: unknown[] = [];
let detail: unknown = null;

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <PoliciesPage />
    </QueryClientProvider>,
  );
}

describe('PoliciesPage', () => {
  beforeEach(() => {
    granted = new Set(['policy:read', 'policy:write']);
    policies = [POLICY];
    detail = {
      ...POLICY,
      entries: [{ check_id: 'ssh-version-2', enabled: true, severity_override: null, notes: null }],
    };
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/policies/')) return detail as never;
      if (path.startsWith('/policies')) return policies as never;
      if (path.startsWith('/checks')) return [CHECK] as never;
      if (path.startsWith('/device-groups')) {
        return [
          { id: 'g1', name: 'north', description: null, parent_id: null, path: 'a' },
        ] as never;
      }
      return [] as never;
    });
  });

  afterEach(() => vi.restoreAllMocks());

  describe('the distinction that matters', () => {
    it('says what disabling a check means, beside the control that does it', async () => {
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Open' }));

      expect(await screen.findByText(/file an exception instead/)).toBeInTheDocument();
    });

    it('warns that changing the default changes every unassigned device', async () => {
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Open' }));

      expect(await screen.findByText(/every unassigned device/)).toBeInTheDocument();
    });

    it('does not offer to make the default policy the default again', async () => {
      policies = [{ ...POLICY, is_default: true }];
      detail = { ...POLICY, is_default: true, entries: [] };
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Open' }));

      await screen.findByText(/covers every device no assignment reaches/);
      expect(
        screen.queryByRole('button', { name: 'Make this the default' }),
      ).not.toBeInTheDocument();
    });
  });

  describe('editing the entries', () => {
    it('sends the enabled flag for the check that was toggled', async () => {
      const put = vi.spyOn(api, 'put').mockResolvedValue({} as never);
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Open' }));
      await userEvent.click(await screen.findByLabelText('ssh-version-2 enabled'));

      expect(put).toHaveBeenCalledWith(
        '/policies/p1/checks/ssh-version-2',
        expect.objectContaining({ enabled: false }),
      );
    });

    it('treats a blank severity as "as the check defines it", not as none', async () => {
      // A cleared override restores the check's own severity. Sending something that
      // reads as "no severity" would silently downgrade the finding.
      const put = vi.spyOn(api, 'put').mockResolvedValue({} as never);
      detail = {
        ...POLICY,
        entries: [
          { check_id: 'ssh-version-2', enabled: true, severity_override: 'low', notes: null },
        ],
      };
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Open' }));
      await userEvent.selectOptions(await screen.findByLabelText('ssh-version-2 severity'), '');

      expect(put).toHaveBeenCalledWith(
        '/policies/p1/checks/ssh-version-2',
        expect.objectContaining({ severity_override: null }),
      );
    });

    it('shows the entries read-only without policy:write', async () => {
      granted = new Set(['policy:read']);
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Open' }));

      expect(await screen.findByLabelText('ssh-version-2 enabled')).toBeDisabled();
      expect(screen.queryByRole('button', { name: 'Create policy' })).not.toBeInTheDocument();
    });
  });

  describe('assigning', () => {
    it('applies the policy to the chosen group', async () => {
      const post = vi.spyOn(api, 'post').mockResolvedValue(undefined as never);
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Open' }));
      await screen.findByRole('option', { name: 'north' });
      await userEvent.selectOptions(screen.getByLabelText('Apply to a device group'), 'g1');
      await userEvent.click(screen.getByRole('button', { name: 'Apply' }));

      expect(post).toHaveBeenCalledWith('/policies/p1/assignments', { device_group_id: 'g1' });
    });

    it('says the change takes effect at the next assessment', async () => {
      // A policy change that appears to apply immediately is a wrong expectation about
      // when findings will move.
      vi.spyOn(api, 'post').mockResolvedValue(undefined as never);
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Open' }));
      await screen.findByRole('option', { name: 'north' });
      await userEvent.selectOptions(screen.getByLabelText('Apply to a device group'), 'g1');
      await userEvent.click(screen.getByRole('button', { name: 'Apply' }));

      expect(await screen.findByText(/next assessment/)).toBeInTheDocument();
    });
  });

  describe('creating one', () => {
    it('will not create a policy that assesses nothing', async () => {
      renderPage();

      await userEvent.type(await screen.findByLabelText('Policy name'), 'Empty');

      expect(screen.getByRole('button', { name: 'Create policy' })).toBeDisabled();
    });

    it('sends the selected check ids', async () => {
      const post = vi.spyOn(api, 'post').mockResolvedValue(POLICY as never);
      renderPage();

      await userEvent.type(await screen.findByLabelText('Policy name'), 'Cisco only');
      await userEvent.click(await screen.findByLabelText('ssh-version-2'));
      await userEvent.click(screen.getByRole('button', { name: 'Create policy' }));

      await waitFor(() =>
        expect(post).toHaveBeenCalledWith(
          '/policies',
          expect.objectContaining({ name: 'Cisco only', check_ids: ['ssh-version-2'] }),
        ),
      );
    });
  });
});
