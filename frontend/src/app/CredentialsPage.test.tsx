/** The credential vault page (FR-CRED-01 … FR-CRED-05).
 *
 * The first group is what the page must never do. A vault UI that leaks a secret is
 * worse than no vault UI, and the guarantee rests on two separate things: the API
 * returns no secret field, and the page has nowhere to put one. Only the second is
 * testable here, so it is tested directly.
 *
 * The rest is the first-run path this page exists to unblock — store a credential,
 * assign it, and find out whether it works before a job tries it against five hundred
 * devices at once.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { CredentialsPage } from './CredentialsPage';
import { api } from '../api/client';

let granted = new Set(['credential:read', 'credential:write']);

vi.mock('../features/auth/useAuth', () => ({
  useAuth: () => ({ can: (permission: string) => granted.has(permission) }),
}));

const CREDENTIAL = {
  id: 'c1',
  name: 'core-ro',
  description: 'read-only account',
  credential_type: 'ssh_password',
  metadata: { username: 'netsecops-ro' },
  key_id: 'k1',
  last_used_at: null,
  last_tested_at: null,
  last_test_succeeded: null,
  created_at: '2026-09-19T09:00:00Z',
};

const DEVICE = {
  id: 'd1',
  mgmt_ip: '10.0.0.1',
  hostname: 'core-sw-01',
  vendor: 'cisco',
  platform: 'cisco_ios',
};

const GROUP = { id: 'g1', name: 'core-switches', description: null, parent_id: null, path: '/' };

let credentials: unknown[] = [];
let assignments: unknown[] = [];

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <CredentialsPage />
    </QueryClientProvider>,
  );
}

describe('CredentialsPage', () => {
  beforeEach(() => {
    granted = new Set(['credential:read', 'credential:write']);
    credentials = [CREDENTIAL];
    assignments = [];
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.includes('/assignments')) return assignments as never;
      if (path.startsWith('/credentials')) {
        return { data: credentials, meta: { total: credentials.length } } as never;
      }
      if (path.startsWith('/devices')) {
        return { data: [DEVICE], meta: { total: 1 } } as never;
      }
      if (path.startsWith('/device-groups')) return [GROUP] as never;
      return { data: [], meta: { total: 0 } } as never;
    });
  });

  afterEach(() => vi.restoreAllMocks());

  describe('what it must never do', () => {
    it('does not render metadata it was not asked to show', async () => {
      // `metadata` is the public half by construction, so the API cannot put a secret
      // here. This pins the page's half of the guarantee anyway: it reads the one field
      // it means to show rather than dumping the object, so a field appearing there
      // later — by a schema change, or a vendor adapter storing more than it should —
      // does not reach the screen on its own.
      credentials = [{ ...CREDENTIAL, metadata: { username: 'netsecops-ro', token: 'leaked' } }];
      renderPage();

      await waitFor(() => expect(screen.getByText('netsecops-ro')).toBeInTheDocument());
      expect(document.body.textContent).not.toContain('leaked');
    });

    it('masks every secret field on the form', async () => {
      renderPage();

      await waitFor(() => expect(screen.getByLabelText('Password')).toBeInTheDocument());
      expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password');
      expect(screen.getByLabelText('Username')).toHaveAttribute('type', 'text');
    });

    it('does not offer to store or delete without credential:write', async () => {
      granted = new Set(['credential:read']);
      renderPage();

      await waitFor(() => expect(screen.getByText('core-ro')).toBeInTheDocument());
      expect(screen.queryByText('Store credential')).not.toBeInTheDocument();
      expect(screen.queryByText('Delete')).not.toBeInTheDocument();
    });
  });

  describe('storing one', () => {
    it('sends only the fields that were filled in', async () => {
      // An empty passphrase is not the same as no passphrase, and the service stores
      // what it is given.
      const post = vi.spyOn(api, 'post').mockResolvedValue(CREDENTIAL as never);
      renderPage();

      await waitFor(() => expect(screen.getByLabelText('Name')).toBeInTheDocument());
      await userEvent.type(screen.getByLabelText('Name'), 'edge-ro');
      await userEvent.type(screen.getByLabelText('Username'), 'ro');
      await userEvent.type(screen.getByLabelText('Password'), 'hunter2');
      await userEvent.click(screen.getByText('Store credential'));

      await waitFor(() => expect(post).toHaveBeenCalled());
      const [, body] = post.mock.calls[0]!;
      expect(body).toMatchObject({
        name: 'edge-ro',
        credential_type: 'ssh_password',
        secret_data: { username: 'ro', password: 'hunter2' },
      });
    });

    it('clears the secret from the form once it is sealed', async () => {
      // Holding a password in component state after the vault has it serves nobody.
      vi.spyOn(api, 'post').mockResolvedValue(CREDENTIAL as never);
      renderPage();

      await waitFor(() => expect(screen.getByLabelText('Name')).toBeInTheDocument());
      await userEvent.type(screen.getByLabelText('Name'), 'edge-ro');
      await userEvent.type(screen.getByLabelText('Password'), 'hunter2');
      await userEvent.click(screen.getByText('Store credential'));

      await waitFor(() => expect(screen.getByLabelText('Password')).toHaveValue(''));
    });

    it('shows the fields the chosen type actually uses', async () => {
      renderPage();

      await waitFor(() => expect(screen.getByLabelText('Password')).toBeInTheDocument());
      await userEvent.selectOptions(screen.getByLabelText('Type'), 'snmp_v2c');

      expect(screen.getByLabelText('Community')).toBeInTheDocument();
      expect(screen.queryByLabelText('Password')).not.toBeInTheDocument();
    });

    it('discards typed values when the type changes', async () => {
      // Fields differ per type. Carrying them across would submit a password under
      // whatever the next type happens to call its first field.
      const post = vi.spyOn(api, 'post').mockResolvedValue(CREDENTIAL as never);
      renderPage();

      await waitFor(() => expect(screen.getByLabelText('Password')).toBeInTheDocument());
      await userEvent.type(screen.getByLabelText('Password'), 'hunter2');
      await userEvent.selectOptions(screen.getByLabelText('Type'), 'snmp_v2c');
      await userEvent.type(screen.getByLabelText('Name'), 'snmp');
      await userEvent.type(screen.getByLabelText('Community'), 'public');
      await userEvent.click(screen.getByText('Store credential'));

      await waitFor(() => expect(post).toHaveBeenCalled());
      expect(post.mock.calls[0]![1]).toMatchObject({
        secret_data: { community: 'public' },
      });
      expect(JSON.stringify(post.mock.calls[0]![1])).not.toContain('hunter2');
    });

    it('surfaces a refusal from the vault', async () => {
      vi.spyOn(api, 'post').mockRejectedValue(new Error('Unknown field: passwrd'));
      renderPage();

      await waitFor(() => expect(screen.getByLabelText('Name')).toBeInTheDocument());
      await userEvent.type(screen.getByLabelText('Name'), 'bad');
      await userEvent.click(screen.getByText('Store credential'));

      await waitFor(() =>
        expect(screen.getByRole('alert')).toHaveTextContent('Unknown field: passwrd'),
      );
    });
  });

  describe('assignments', () => {
    it('says plainly that an unassigned credential is never used', async () => {
      // This is the state every credential is in immediately after being stored, and
      // the reason a first collection fails.
      renderPage();

      await waitFor(() => expect(screen.getByText('Details')).toBeInTheDocument());
      await userEvent.click(screen.getByText('Details'));

      await waitFor(() => expect(screen.getByText(/no job will ever use it/)).toBeInTheDocument());
    });

    it('binds to a device', async () => {
      const post = vi.spyOn(api, 'post').mockResolvedValue({} as never);
      renderPage();

      await waitFor(() => expect(screen.getByText('Details')).toBeInTheDocument());
      await userEvent.click(screen.getByText('Details'));
      await waitFor(() => expect(screen.getByLabelText('Assign to')).toBeInTheDocument());

      await userEvent.selectOptions(screen.getByLabelText('Assign to'), 'device:d1');
      await userEvent.click(screen.getByText('Assign'));

      expect(post).toHaveBeenCalledWith('/credentials/c1/assignments', {
        device_id: 'd1',
        group_id: null,
        priority: 100,
      });
    });

    it('binds to a group as a group, not as a device', async () => {
      // The two are different columns and the resolver treats them differently —
      // device bindings win, group ones are inherited.
      const post = vi.spyOn(api, 'post').mockResolvedValue({} as never);
      renderPage();

      await waitFor(() => expect(screen.getByText('Details')).toBeInTheDocument());
      await userEvent.click(screen.getByText('Details'));
      await waitFor(() => expect(screen.getByLabelText('Assign to')).toBeInTheDocument());

      await userEvent.selectOptions(screen.getByLabelText('Assign to'), 'group:g1');
      await userEvent.click(screen.getByText('Assign'));

      expect(post).toHaveBeenCalledWith('/credentials/c1/assignments', {
        device_id: null,
        group_id: 'g1',
        priority: 100,
      });
    });

    it('can revoke a binding', async () => {
      // The reason the read endpoint was added: an assignment that cannot be
      // enumerated cannot be withdrawn.
      assignments = [
        { id: 'a1', credential_id: 'c1', device_id: 'd1', group_id: null, priority: 100 },
      ];
      const del = vi.spyOn(api, 'delete').mockResolvedValue(undefined as never);
      renderPage();

      await waitFor(() => expect(screen.getByText('Details')).toBeInTheDocument());
      await userEvent.click(screen.getByText('Details'));
      await waitFor(() => expect(screen.getByText('Remove')).toBeInTheDocument());

      await userEvent.click(screen.getByText('Remove'));

      expect(del).toHaveBeenCalledWith('/credentials/assignments/a1');
    });

    it('names the device rather than showing a bare id', async () => {
      // An operator auditing a credential needs to recognise what it reaches. A
      // truncated uuid answers nothing.
      assignments = [
        { id: 'a1', credential_id: 'c1', device_id: 'd1', group_id: null, priority: 50 },
      ];
      renderPage();

      await waitFor(() => expect(screen.getByText('Details')).toBeInTheDocument());
      await userEvent.click(screen.getByText('Details'));
      await waitFor(() => expect(screen.getByRole('list')).toBeInTheDocument());

      // Scoped to the list: the device also appears in both picker dropdowns.
      const bindings = within(screen.getByRole('list'));
      expect(bindings.getByText('core-sw-01')).toBeInTheDocument();
      expect(bindings.getByText(/priority 50/)).toBeInTheDocument();
      expect(bindings.queryByText(/^d1/)).not.toBeInTheDocument();
    });
  });

  describe('testing one', () => {
    it('will not test until a device is chosen', async () => {
      renderPage();

      await waitFor(() => expect(screen.getByText('Details')).toBeInTheDocument());
      await userEvent.click(screen.getByText('Details'));

      await waitFor(() => expect(screen.getByText('Test')).toBeDisabled());
    });

    it('reports the command it issued, so read-only is checkable', async () => {
      vi.spyOn(api, 'post').mockResolvedValue({
        succeeded: true,
        device_id: 'd1',
        detail: null,
        command: 'show clock',
        host_key_fingerprint: 'SHA256:abc',
      } as never);

      renderPage();
      await waitFor(() => expect(screen.getByText('Details')).toBeInTheDocument());
      await userEvent.click(screen.getByText('Details'));
      await waitFor(() =>
        expect(screen.getByLabelText('Device to test against')).toBeInTheDocument(),
      );

      await userEvent.selectOptions(screen.getByLabelText('Device to test against'), 'd1');
      await userEvent.click(screen.getByText('Test'));

      const status = await screen.findByRole('status');
      expect(within(status).getByText(/show clock/)).toBeInTheDocument();
      expect(status).toHaveTextContent('The credential worked.');
    });

    it('reports a failed login as a result, not as an error', async () => {
      // A wrong password is an answer to the question asked, and finding out here is
      // the entire point — the alternative is a burst of failed logins across the
      // estate during a collection.
      vi.spyOn(api, 'post').mockResolvedValue({
        succeeded: false,
        device_id: 'd1',
        detail: 'Authentication failed.',
        command: null,
        host_key_fingerprint: null,
      } as never);

      renderPage();
      await waitFor(() => expect(screen.getByText('Details')).toBeInTheDocument());
      await userEvent.click(screen.getByText('Details'));
      await waitFor(() =>
        expect(screen.getByLabelText('Device to test against')).toBeInTheDocument(),
      );

      await userEvent.selectOptions(screen.getByLabelText('Device to test against'), 'd1');
      await userEvent.click(screen.getByText('Test'));

      await waitFor(() =>
        expect(screen.getByRole('status')).toHaveTextContent('The credential failed.'),
      );
    });
  });
});
