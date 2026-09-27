/** Component tests for the sign-in flow (TEST-05). */

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AuthProvider } from './AuthProvider';
import { LoginPage } from './LoginPage';

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': status >= 400 ? 'application/problem+json' : 'application/json' },
  });
}

const UNAUTHENTICATED = jsonResponse(401, {
  type: 'https://netsecops.invalid/problems/authentication-failed',
  title: 'Authentication failed',
  status: 401,
  detail: 'Not authenticated.',
});

/** Renders the router's current query string, so a test can assert on it. */
function LocationProbe() {
  const { search } = useLocation();
  return <span data-testid="search">{search || '(empty)'}</span>;
}

function renderLogin(initialEntry = '/login') {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe('LoginPage', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    // The provider probes /auth/me on mount; unauthenticated is the default.
    fetchMock.mockResolvedValue(UNAUTHENTICATED.clone());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('renders the password form', async () => {
    renderLogin();

    expect(await screen.findByLabelText(/username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
  });

  it('keeps sign-in disabled until both fields are filled', async () => {
    const user = userEvent.setup();
    renderLogin();

    const submit = await screen.findByRole('button', { name: /sign in/i });
    expect(submit).toBeDisabled();

    await user.type(screen.getByLabelText(/username/i), 'analyst');
    expect(submit).toBeDisabled();

    await user.type(screen.getByLabelText(/password/i), 'Correct-Horse-9!');
    expect(submit).toBeEnabled();
  });

  it('shows the server message when credentials are rejected', async () => {
    const user = userEvent.setup();
    renderLogin();
    await screen.findByLabelText(/username/i);

    fetchMock.mockResolvedValueOnce(
      jsonResponse(401, {
        type: 'https://netsecops.invalid/problems/authentication-failed',
        title: 'Authentication failed',
        status: 401,
        detail: 'Invalid username or password.',
      }),
    );

    await user.type(screen.getByLabelText(/username/i), 'analyst');
    await user.type(screen.getByLabelText(/password/i), 'wrong-password');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid username or password.');
  });

  it('explains a lockout rather than showing a bare error (FR-AUTH-06)', async () => {
    const user = userEvent.setup();
    renderLogin();
    await screen.findByLabelText(/username/i);

    fetchMock.mockResolvedValueOnce(
      jsonResponse(423, {
        type: 'https://netsecops.invalid/problems/account-locked',
        title: 'Account locked',
        status: 423,
        detail: 'Account is temporarily locked.',
      }),
    );

    await user.type(screen.getByLabelText(/username/i), 'analyst');
    await user.type(screen.getByLabelText(/password/i), 'wrong-password');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/temporarily locked/i);
  });

  it('switches to the code step when MFA is required (FR-AUTH-03)', async () => {
    const user = userEvent.setup();
    renderLogin();
    await screen.findByLabelText(/username/i);

    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, {
        mfa_required: true,
        mfa_token: 'pending-token',
        expires_at: new Date(Date.now() + 300_000).toISOString(),
      }),
    );

    await user.type(screen.getByLabelText(/username/i), 'analyst');
    await user.type(screen.getByLabelText(/password/i), 'Correct-Horse-9!');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByLabelText(/verification code/i)).toBeInTheDocument();
    });
    expect(screen.queryByLabelText(/^password$/i)).not.toBeInTheDocument();
  });

  describe('single sign-on (FR-AUTH-04)', () => {
    /** Route by URL: these tests care what the SSO endpoints answer, and the provider
     *  is also probing /auth/me on mount. */
    function routes(handlers: Record<string, () => Response>) {
      fetchMock.mockImplementation((input: RequestInfo | URL) => {
        const url = String(input);
        for (const [fragment, respond] of Object.entries(handlers)) {
          if (url.includes(fragment)) return Promise.resolve(respond());
        }
        return Promise.resolve(UNAUTHENTICATED.clone());
      });
    }

    it('offers no button when the deployment has no identity provider', async () => {
      // A button that leads to a 401 is worse than no button, and most deployments
      // will never configure one.
      routes({ '/auth/sso/status': () => jsonResponse(200, { enabled: false, button_label: null }) });
      renderLogin();

      await screen.findByLabelText(/username/i);
      await waitFor(() => {
        expect(screen.queryByRole('button', { name: /single sign-on/i })).not.toBeInTheDocument();
      });
    });

    it('labels the button with the provider the server names', async () => {
      // "Sign in with Entra ID" tells somebody which credentials to reach for.
      routes({
        '/auth/sso/status': () =>
          jsonResponse(200, { enabled: true, button_label: 'Sign in with Entra ID' }),
      });
      renderLogin();

      expect(
        await screen.findByRole('button', { name: 'Sign in with Entra ID' }),
      ).toBeInTheDocument();
    });

    it('sends the browser to the URL the server returns', async () => {
      // The flow is a redirect, not a fetch: the provider has to receive a top-level
      // navigation or there is no sign-in screen for the user to use.
      const assign = vi.fn();
      vi.stubGlobal('location', { ...window.location, assign });
      routes({
        '/auth/sso/status': () => jsonResponse(200, { enabled: true, button_label: 'SSO' }),
        '/auth/sso/start': () =>
          jsonResponse(200, { authorization_url: 'https://idp.test/authorize?state=abc' }),
      });
      renderLogin();

      await userEvent.click(await screen.findByRole('button', { name: 'SSO' }));

      await waitFor(() => {
        expect(assign).toHaveBeenCalledWith('https://idp.test/authorize?state=abc');
      });
    });

    it('explains a failed sign-in that came back in the URL', async () => {
      // The user is at the end of a round trip through another website and cannot read
      // a JSON body, so the callback redirects here with a reason.
      renderLogin('/login?sso_error=denied');

      expect(await screen.findByRole('alert')).toHaveTextContent(/No NetSecOps account matches/i);
    });

    it('falls back to a general message for a reason it does not recognise', async () => {
      renderLogin('/login?sso_error=something_new');

      expect(await screen.findByRole('alert')).toHaveTextContent(/did not complete/i);
    });

    it('still asks for the second factor after single sign-on', async () => {
      // The decision this deployment made: the provider replaces the password, not the
      // authenticator. The pending token arrives in the query string because a redirect
      // is the only channel available.
      renderLogin('/login?mfa_token=pending-from-sso');

      expect(await screen.findByLabelText(/verification code/i)).toBeInTheDocument();
    });

    it('clears the pending token out of the address bar', async () => {
      // It is a credential. Left in the URL it goes into history, into a bookmark, and
      // into the referrer of anything this page loads.
      //
      // Asserted through the router rather than `window.location`, which MemoryRouter
      // never writes to — reading that would pass whether or not the URL was cleared.
      render(
        <MemoryRouter initialEntries={['/login?mfa_token=pending-from-sso']}>
          <AuthProvider>
            <LoginPage />
            <LocationProbe />
          </AuthProvider>
        </MemoryRouter>,
      );

      await screen.findByLabelText(/verification code/i);
      await waitFor(() => {
        expect(screen.getByTestId('search')).toHaveTextContent('(empty)');
      });
    });
  });

  it('keeps the typed password masked and out of rendered text', async () => {
    const user = userEvent.setup();
    const { container } = renderLogin();
    await screen.findByLabelText(/username/i);

    await user.type(screen.getByLabelText(/password/i), 'Correct-Horse-9!');

    // The field itself must be masked...
    expect(screen.getByLabelText(/password/i)).toHaveAttribute('type', 'password');
    // ...and the value must not have leaked into any rendered text node.
    // textContent excludes input values, so a hit here means a genuine leak.
    expect(container.textContent).not.toContain('Correct-Horse-9!');
  });
});
