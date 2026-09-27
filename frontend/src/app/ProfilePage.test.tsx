/** Self-service account page — API tokens and MFA reset (FR-AUTH-03, FR-AUTH-07).
 *
 * The plaintext of a token exists in exactly one place for a few seconds: this page. If
 * it is not shown, or is shown somewhere a reload clears before anybody copies it, the
 * token is dead on arrival and the only recourse is to issue another. So the tests that
 * matter most here are about that one moment.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
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
    it('re-proves both factors rather than asking for a confirmation click', async () => {
      // A session says somebody signed in once; it does not say who is at the keyboard
      // now. Removing the second factor from a borrowed unlocked browser was one
      // click, and it is the single change that weakens every future sign-in.
      currentUser = { ...currentUser, mfa_enabled: true };
      const remove = vi.spyOn(api, 'delete').mockResolvedValue(undefined as never);
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Turn off MFA' }));
      expect(remove).not.toHaveBeenCalled();

      // Scoped to the two-factor card: the password-change form above it has its own
      // `Current password` field, so an unscoped query matches two.
      const card = screen.getByRole('heading', { name: 'Two-factor authentication' })
        .closest('.card') as HTMLElement;
      await userEvent.type(within(card).getByLabelText('Current password'), 'Correct-Horse-9!');
      await userEvent.type(within(card).getByLabelText('Code from your app'), '123456');
      await userEvent.click(within(card).getByRole('button', { name: 'Turn off two-factor' }));

      expect(remove).toHaveBeenCalledWith('/auth/mfa', {
        password: 'Correct-Horse-9!',
        code: '123456',
      });
    });

    it('will not submit with only one of the two', async () => {
      // Asserted through the disabled button rather than through `required`, which
      // jsdom does not enforce — a test written against the attribute passes here and
      // proves nothing about the code.
      currentUser = { ...currentUser, mfa_enabled: true };
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Turn off MFA' }));
      const card = screen.getByRole('heading', { name: 'Two-factor authentication' })
        .closest('.card') as HTMLElement;
      const submit = within(card).getByRole('button', { name: 'Turn off two-factor' });

      expect(submit).toBeDisabled();

      await userEvent.type(within(card).getByLabelText('Current password'), 'Correct-Horse-9!');
      expect(submit).toBeDisabled();

      await userEvent.type(within(card).getByLabelText('Code from your app'), '123456');
      expect(submit).toBeEnabled();
    });

    it('warns when the recovery codes have run out', async () => {
      // They cannot be redisplayed, only reissued. Nought left is a lockout waiting
      // for a lost phone, and it was not visible anywhere before.
      currentUser = { ...currentUser, mfa_enabled: true };
      vi.spyOn(api, 'get').mockImplementation(async (path: string) =>
        (path === '/auth/mfa'
          ? { enabled: true, recovery_codes_left: 0 }
          : tokens) as never,
      );
      renderPage();

      expect(await screen.findByText(/none left/)).toBeInTheDocument();
    });

    it('is not offered when MFA is already off', async () => {
      renderPage();

      await waitFor(() => expect(screen.getByText(/not enabled/)).toBeInTheDocument());
      expect(screen.queryByRole('button', { name: 'Turn off MFA' })).not.toBeInTheDocument();
    });
  });

  describe('enrolling', () => {
    /** Three ways to get one secret into an authenticator, because one is never enough
     *  in practice. The screen offered exactly one — a bare base32 string under the
     *  words "scan this" — for three phases, while `qrcode` sat in the dependency list
     *  unimported. */

    const ENROLMENT = {
      secret: 'JBSWY3DPEHPK3PXP',
      formatted_secret: 'JBSW Y3DP EHPK 3PXP',
      provisioning_uri: 'otpauth://totp/NetSecOps:admin@example.com?secret=JBSWY3DPEHPK3PXP',
      qr_svg: '<svg viewBox="0 0 41 41"><path d="M2,2H3V3H2z"/></svg>',
      recovery_codes: ['aaaa1111-bbbb2222', 'cccc3333-dddd4444'],
    };

    async function startEnrolment() {
      vi.spyOn(api, 'post').mockResolvedValue(ENROLMENT as never);
      renderPage();
      await userEvent.click(await screen.findByRole('button', { name: /Set up|Enable MFA/ }));
    }

    it('gives something to scan', async () => {
      await startEnrolment();

      const card = screen.getByRole('heading', { name: 'Two-factor authentication' })
        .closest('.card') as HTMLElement;
      expect(card.querySelector('.mfa-qr svg')).not.toBeNull();
    });

    it('offers a tap-through for somebody reading this on the phone', async () => {
      // There is nothing to scan when the screen holding the QR is the phone itself.
      await startEnrolment();

      const link = await screen.findByRole('link', { name: /Open in your authenticator/ });
      expect(link).toHaveAttribute('href', ENROLMENT.provisioning_uri);
    });

    it('shows the key grouped, for typing in by hand', async () => {
      // For a shared screen, or a machine with no camera. An unbroken 32-character
      // base32 string is transcribed wrongly often enough that every authenticator
      // app groups it.
      await startEnrolment();

      expect(await screen.findByText('JBSW Y3DP EHPK 3PXP')).toBeInTheDocument();
    });

    it('shows the recovery codes rather than folding them away', async () => {
      // They are displayed exactly once and can never be redisplayed. A disclosure
      // somebody does not open is a set of codes they do not have when the phone goes.
      await startEnrolment();

      expect(await screen.findByText('aaaa1111-bbbb2222')).toBeVisible();
      expect(screen.getByText('cccc3333-dddd4444')).toBeVisible();
      expect(screen.getByText(/one time they can be shown/)).toBeInTheDocument();
    });
  });
});
