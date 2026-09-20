/** Self-service account page — API tokens and MFA reset (FR-AUTH-03, FR-AUTH-07).
 *
 * The plaintext of a token exists in exactly one place for a few seconds: this page. If
 * it is not shown, or is shown somewhere a reload clears before anybody copies it, the
 * token is dead on arrival and the only recourse is to issue another. So the tests that
 * matter most here are about that one moment.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';

import { ProfilePage } from './ProfilePage';
import { api } from '../api/client';

let currentUser = {
  id: 'me',
  username: 'admin',
  email: 'admin@example.com',
  full_name: 'Admin',
  mfa_enabled: false,
  roles: ['super_admin'],
  permissions: ['device:read', 'user:write'],
};

const refreshUser = vi.fn();

vi.mock('../features/auth/useAuth', () => ({
  useAuth: () => ({ user: currentUser, refreshUser, logout: vi.fn() }),
}));

const TOKEN = {
  id: 't1',
  name: 'ci-runner',
  prefix: 'nso_abcd',
  scopes: ['device:read'],
  owner_id: 'me',
  expires_at: null,
  revoked_at: null,
  last_used_at: null,
  created_at: '2026-09-01T00:00:00Z',
};

let tokens: unknown[] = [];

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ProfilePage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('ProfilePage', () => {
  beforeEach(() => {
    currentUser = { ...currentUser, mfa_enabled: false };
    tokens = [TOKEN];
    refreshUser.mockReset();
    vi.spyOn(api, 'get').mockImplementation(async () => tokens as never);
  });

  afterEach(() => vi.restoreAllMocks());

  describe('issuing a token', () => {
    it('shows the plaintext, because there is no second chance', async () => {
      vi.spyOn(api, 'post').mockResolvedValue({ ...TOKEN, token: 'nso_secret_value' } as never);
      renderPage();

      await userEvent.type(await screen.findByLabelText('Token name'), 'ci');
      await userEvent.click(screen.getByLabelText('device:read'));
      await userEvent.click(screen.getByRole('button', { name: 'Issue token' }));

      expect(await screen.findByText('nso_secret_value')).toBeInTheDocument();
    });

    it('offers only the permissions the signed-in user holds', async () => {
      // The server refuses scopes beyond the owner — a token that outranked its owner
      // would be a way around RBAC. Offering one anyway is a picker whose options are
      // sometimes lies.
      renderPage();

      await waitFor(() => expect(screen.getByLabelText('device:read')).toBeInTheDocument());
      expect(screen.getByLabelText('user:write')).toBeInTheDocument();
      expect(screen.queryByLabelText('credential:write')).not.toBeInTheDocument();
    });

    it('will not issue a token with no scopes', async () => {
      // A scopeless token authenticates and can do nothing, which reads at the call site
      // as a permissions bug rather than as a token that was never finished.
      renderPage();

      await userEvent.type(await screen.findByLabelText('Token name'), 'empty');

      expect(screen.getByRole('button', { name: 'Issue token' })).toBeDisabled();
    });

    it('sends no expiry when the field is left empty', async () => {
      const post = vi.spyOn(api, 'post').mockResolvedValue({ ...TOKEN, token: 'x' } as never);
      renderPage();

      await userEvent.type(await screen.findByLabelText('Token name'), 'forever');
      await userEvent.click(screen.getByLabelText('device:read'));
      await userEvent.click(screen.getByRole('button', { name: 'Issue token' }));

      expect(post).toHaveBeenCalledWith(
        '/api-tokens',
        expect.objectContaining({ expires_at: null, scopes: ['device:read'] }),
      );
    });

    it('says a token with no expiry never expires', async () => {
      renderPage();

      expect(await screen.findByText(/no expiry/)).toBeInTheDocument();
    });
  });

  describe('revoking', () => {
    it('keeps the row and marks it, rather than removing it', async () => {
      // "When was this withdrawn" is a question people ask during an incident, and a row
      // that vanished cannot answer it.
      tokens = [{ ...TOKEN, revoked_at: '2026-09-15T00:00:00Z' }];
      renderPage();

      expect(await screen.findByText(/revoked/)).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument();
    });

    it('calls the endpoint for a live token', async () => {
      const remove = vi.spyOn(api, 'delete').mockResolvedValue(undefined as never);
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Revoke' }));

      expect(remove).toHaveBeenCalledWith('/api-tokens/t1');
    });
  });

  describe('turning MFA off', () => {
    it('asks first, because it lowers the account back to a password alone', async () => {
      currentUser = { ...currentUser, mfa_enabled: true };
      const remove = vi.spyOn(api, 'delete').mockResolvedValue(undefined as never);
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Turn off MFA' }));
      expect(remove).not.toHaveBeenCalled();

      await userEvent.click(screen.getByRole('button', { name: 'Yes, turn it off' }));
      expect(remove).toHaveBeenCalledWith('/auth/mfa');
    });

    it('is not offered when MFA is already off', async () => {
      renderPage();

      await waitFor(() => expect(screen.getByText(/not enabled/)).toBeInTheDocument());
      expect(screen.queryByRole('button', { name: 'Turn off MFA' })).not.toBeInTheDocument();
    });
  });
});
