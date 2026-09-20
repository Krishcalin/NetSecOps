/** User administration (FR-AUTH-04, FR-AUTH-05).
 *
 * The first group is about the one thing this page can get dangerously wrong: reporting
 * a user's reach. A scope shown as a restriction when the role ignores it, or an empty
 * scope shown as "not restricted yet", both tell an administrator the opposite of the
 * truth — and they will act on it by leaving something alone.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { UsersPage } from './UsersPage';
import { api } from '../api/client';

let granted = new Set(['user:read', 'user:write']);
let selfRoles: string[] = ['super_admin'];

vi.mock('../features/auth/useAuth', () => ({
  useAuth: () => ({
    can: (permission: string) => granted.has(permission),
    user: { id: 'me', username: 'admin', roles: selfRoles },
  }),
}));

const ENGINEER = {
  id: 'u1',
  username: 'jo.engineer',
  email: 'jo@example.com',
  full_name: 'Jo Engineer',
  is_active: true,
  is_service_account: false,
  mfa_enabled: false,
  must_change_password: false,
  roles: ['network_engineer'],
  device_group_ids: ['g1'],
  last_login_at: '2026-09-18T08:00:00Z',
  created_at: '2026-09-01T08:00:00Z',
  updated_at: '2026-09-01T08:00:00Z',
};

const ROLE_CATALOGUE = [
  { role: 'super_admin', description: 'Everything', permissions: ['user:write', 'device:read'] },
  { role: 'security_analyst', description: 'Assessment', permissions: ['device:read'] },
  { role: 'network_engineer', description: 'Device work', permissions: ['device:read'] },
  { role: 'auditor', description: 'Read only', permissions: ['audit:read'] },
  { role: 'api_service', description: 'Token owner', permissions: [] },
];

const GROUPS = [
  { id: 'g1', name: 'north', description: null, parent_id: null, path: 'a', created_at: 'x' },
  { id: 'g2', name: 'south', description: null, parent_id: null, path: 'b', created_at: 'x' },
];

let users: unknown[] = [];

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <UsersPage />
    </QueryClientProvider>,
  );
}

describe('UsersPage', () => {
  beforeEach(() => {
    granted = new Set(['user:read', 'user:write']);
    selfRoles = ['super_admin'];
    users = [ENGINEER];
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/auth/roles')) return ROLE_CATALOGUE as never;
      if (path.startsWith('/device-groups')) return GROUPS as never;
      if (path.startsWith('/users')) {
        return { data: users, meta: { total: users.length } } as never;
      }
      return { data: [], meta: { total: 0 } } as never;
    });
  });

  afterEach(() => vi.restoreAllMocks());

  describe('what a scope actually means', () => {
    it('names the groups a group-scoped user is restricted to', async () => {
      renderPage();

      const row = await screen.findByText('Jo Engineer');
      expect(within(row.closest('tr')!).getByText('north')).toBeInTheDocument();
    });

    it('reports an unrestricted role as seeing everything, whatever is stored', async () => {
      // The assignment is real and the server keeps it; it just does not bind while the
      // user holds a role that lifts scoping. Rendering "north" here would say this
      // analyst is confined to one group, which is false.
      users = [{ ...ENGINEER, roles: ['security_analyst'], device_group_ids: ['g1'] }];
      renderPage();

      const row = (await screen.findByText('Jo Engineer')).closest('tr')!;
      expect(within(row).getByText('all devices')).toBeInTheDocument();
      expect(within(row).queryByText('north')).not.toBeInTheDocument();
    });

    it('reports an empty scope on a group-scoped role as seeing nothing', async () => {
      // The scope filter fails closed, so empty means no devices at all — not "no
      // restriction has been applied yet", which is how an empty cell reads.
      users = [{ ...ENGINEER, device_group_ids: [] }];
      renderPage();

      const row = (await screen.findByText('Jo Engineer')).closest('tr')!;
      expect(within(row).getByText('no devices')).toBeInTheDocument();
    });

    it('warns in the editor when a stored scope will not bind', async () => {
      users = [{ ...ENGINEER, roles: ['super_admin'] }];
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Manage' }));

      expect(screen.getByText(/stored and ignored/)).toBeInTheDocument();
    });
  });

  describe('the role picker', () => {
    it('is built from the server catalogue rather than a list in the browser', async () => {
      // A hard-coded list is a second copy of rbac.py, and the drift is invisible: the
      // picker keeps offering roles that still exist while missing the new one.
      renderPage();

      await waitFor(() => expect(screen.getByLabelText('Auditor')).toBeInTheDocument());
      expect(screen.getByText(/Device work/)).toBeInTheDocument();
    });

    it('sends the whole set, so unticking removes a role', async () => {
      const put = vi.spyOn(api, 'put').mockResolvedValue(ENGINEER as never);
      users = [{ ...ENGINEER, roles: ['network_engineer', 'auditor'] }];
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Manage' }));
      await userEvent.click(screen.getByLabelText('Auditor for jo.engineer'));
      await userEvent.click(screen.getByRole('button', { name: 'Save roles' }));

      expect(put).toHaveBeenCalledWith('/users/u1/roles', { roles: ['network_engineer'] });
    });

    it('does not offer to save roles that have not changed', async () => {
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Manage' }));

      expect(screen.getByRole('button', { name: 'Save roles' })).toBeDisabled();
    });
  });

  describe('scope editing', () => {
    it('starts from what the server says the scope is', async () => {
      // The reason `device_group_ids` was added to the user payload. Without it the
      // editor opens empty and saving would silently clear the scope.
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Manage' }));

      expect(screen.getByLabelText('north for jo.engineer')).toBeChecked();
      expect(screen.getByLabelText('south for jo.engineer')).not.toBeChecked();
    });

    it('sends the selected groups', async () => {
      const put = vi.spyOn(api, 'put').mockResolvedValue(ENGINEER as never);
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Manage' }));
      await userEvent.click(screen.getByLabelText('south for jo.engineer'));
      await userEvent.click(screen.getByRole('button', { name: 'Save scope' }));

      expect(put).toHaveBeenCalledWith('/users/u1/scope', { device_group_ids: ['g1', 'g2'] });
    });
  });

  describe('creating a user', () => {
    it('forces a password change at first sign-in', async () => {
      // The administrator typing it knows it. Leaving the flag off means two people hold
      // the password indefinitely.
      const post = vi.spyOn(api, 'post').mockResolvedValue(ENGINEER as never);
      renderPage();

      await userEvent.type(await screen.findByLabelText('Username'), 'new.person');
      await userEvent.type(screen.getByLabelText('Email'), 'new@example.com');
      await userEvent.type(screen.getByLabelText('Initial password'), 'Staple-Mountain-4!');
      await userEvent.click(screen.getByLabelText('Auditor'));
      await userEvent.click(screen.getByRole('button', { name: 'Create user' }));

      expect(post).toHaveBeenCalledWith(
        '/users',
        expect.objectContaining({ username: 'new.person', must_change_password: true }),
      );
    });

    it('surfaces the password policy violations the server returns', async () => {
      const { ApiError } = await import('../api/client');
      vi.spyOn(api, 'post').mockRejectedValue(
        new ApiError({
          type: 'password-policy',
          title: 'Weak password',
          status: 422,
          detail: 'Password rejected.',
          violations: ['must contain a digit', 'must be 12 characters'],
        }),
      );
      renderPage();

      await userEvent.type(await screen.findByLabelText('Username'), 'weak');
      await userEvent.type(screen.getByLabelText('Email'), 'weak@example.com');
      await userEvent.type(screen.getByLabelText('Initial password'), 'short');
      await userEvent.click(screen.getByRole('button', { name: 'Create user' }));

      expect(await screen.findByRole('alert')).toHaveTextContent('must contain a digit');
    });
  });

  describe('what it will not offer', () => {
    it('hides creation and deactivation without user:write', async () => {
      granted = new Set(['user:read']);
      renderPage();

      await screen.findByText('Jo Engineer');
      expect(screen.queryByRole('button', { name: 'Create user' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Deactivate' })).not.toBeInTheDocument();
    });

    it('hides roles, scope, reset and delete from a non Super Admin', async () => {
      // These are Super Admin only on the server. Rendering them for everyone would mean
      // offering four buttons whose only outcome is a 403.
      selfRoles = ['security_analyst'];
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Manage' }));

      expect(screen.queryByRole('button', { name: 'Save roles' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Save scope' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Delete user' })).not.toBeInTheDocument();
    });

    it('asks before deleting, and offers deactivation as the reversible option', async () => {
      const remove = vi.spyOn(api, 'delete').mockResolvedValue(undefined as never);
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Manage' }));
      await userEvent.click(screen.getByRole('button', { name: 'Delete user' }));

      expect(remove).not.toHaveBeenCalled();
      expect(screen.getByText(/Delete jo.engineer permanently\?/)).toBeInTheDocument();

      await userEvent.click(screen.getByRole('button', { name: 'Yes, delete' }));
      expect(remove).toHaveBeenCalledWith('/users/u1');
    });
  });

  describe('deactivation', () => {
    it('sends the flag rather than deleting', async () => {
      const patch = vi.spyOn(api, 'patch').mockResolvedValue(ENGINEER as never);
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Deactivate' }));

      expect(patch).toHaveBeenCalledWith('/users/u1', { is_active: false });
    });

    it('offers to reactivate an account that is already off', async () => {
      users = [{ ...ENGINEER, is_active: false }];
      const patch = vi.spyOn(api, 'patch').mockResolvedValue(ENGINEER as never);
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Reactivate' }));

      expect(patch).toHaveBeenCalledWith('/users/u1', { is_active: true });
    });
  });
});
