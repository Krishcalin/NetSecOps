/** Component tests for the sign-in flow (TEST-05). */

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
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

function renderLogin() {
  return render(
    <MemoryRouter>
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
