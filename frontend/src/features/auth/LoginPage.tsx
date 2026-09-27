/** Sign-in screen: password step, then the TOTP step when MFA is enabled.
 *
 * Single sign-on joins this screen at two points rather than replacing it. The button
 * is offered only when the server says SSO is configured, because a button that leads
 * to a 401 is worse than no button. And the return leg lands *here*, not on a page of
 * its own: the identity provider redirects a browser, so whatever happened arrives as
 * a query parameter — either a reason it failed, or a pending MFA token, since the
 * second factor is still this system's to ask for.
 */

import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';

import { ApiError, api } from '../../api/client';
import { useAuth } from './useAuth';
import type { SSOStatus } from './types';

/** Why a sign-in came back unfinished. The callback sends a short code rather than the
 *  provider's own message, which quotes back whatever it was handed. */
const SSO_ERRORS: Record<string, string> = {
  provider_denied: 'Your identity provider did not complete the sign-in.',
  incomplete: 'The sign-in came back incomplete. Please try again.',
  denied:
    'No NetSecOps account matches that sign-in, or the account cannot be used. Contact an administrator.',
  locked: 'This account is temporarily locked after repeated failed sign-in attempts.',
  provider_unreachable: 'NetSecOps could not reach the identity provider. Try again shortly.',
};

export function LoginPage() {
  const { login, verifyMfa, resumeMfa, mfaToken, cancelMfa } = useAuth();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [sso, setSso] = useState<SSOStatus | null>(null);

  useEffect(() => {
    // A deployment without SSO must not be told about it, so a failure here is silence
    // rather than an error on the sign-in screen.
    api
      .get<SSOStatus>('/auth/sso/status')
      .then(setSso)
      .catch(() => setSso({ enabled: false, button_label: null }));
  }, []);

  useEffect(() => {
    const failure = params.get('sso_error');
    const pending = params.get('mfa_token');
    if (!failure && !pending) return;

    if (failure) {
      setError(SSO_ERRORS[failure] ?? 'The single sign-on attempt did not complete.');
    }
    if (pending) {
      resumeMfa(pending);
    }
    // Cleared from the address bar once read: the pending token is a credential, and
    // leaving it in the URL puts it in history, in a bookmark, and in the referrer of
    // anything this page loads.
    setParams({}, { replace: true });
  }, [params, resumeMfa, setParams]);

  async function startSso() {
    setError(null);
    setBusy(true);
    try {
      const { authorization_url } = await api.post<{ authorization_url: string }>(
        '/auth/sso/start',
        {},
      );
      window.location.assign(authorization_url);
    } catch (err) {
      setError(describe(err));
      setBusy(false);
    }
  }

  async function handlePasswordStep(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);

    try {
      const result = await login(username, password);
      if (!result.mfa_required) {
        navigate('/', { replace: true });
      }
    } catch (err) {
      setError(describe(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleMfaStep(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);

    try {
      await verifyMfa(code);
      navigate('/', { replace: true });
    } catch (err) {
      setError(describe(err));
      setCode('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <header className="auth-card__header">
          <h1 className="auth-card__title">
            {mfaToken ? 'Two-factor authentication' : 'Sign in'}
          </h1>
          <p className="auth-card__tagline">Network configuration &amp; vulnerability assessment</p>
        </header>

        {error && (
          <div className="alert alert--error" role="alert">
            {error}
          </div>
        )}

        {mfaToken ? (
          <form onSubmit={handleMfaStep} noValidate>
            <p className="auth-card__hint">
              Enter the 6-digit code from your authenticator app, or one of your recovery codes.
            </p>

            <label className="field">
              <span className="field__label">Verification code</span>
              <input
                className="field__input"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                autoComplete="one-time-code"
                inputMode="numeric"
                autoFocus
                required
              />
            </label>

            <button className="button button--primary" type="submit" disabled={busy || !code}>
              {busy ? 'Verifying…' : 'Verify'}
            </button>
            <button
              className="button button--ghost"
              type="button"
              onClick={() => {
                cancelMfa();
                setCode('');
                setError(null);
              }}
            >
              Back
            </button>
          </form>
        ) : (
          <form onSubmit={handlePasswordStep} noValidate>
            <label className="field">
              <span className="field__label">Username</span>
              <input
                className="field__input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                autoFocus
                required
              />
            </label>

            <label className="field">
              <span className="field__label">Password</span>
              <input
                className="field__input"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </label>

            <button
              className="button button--primary"
              type="submit"
              disabled={busy || !username || !password}
            >
              {busy ? 'Signing in…' : 'Sign in'}
            </button>

            {sso?.enabled && (
              <>
                <p className="auth-card__divider">
                  <span>or</span>
                </p>
                <button
                  className="button button--ghost button--block"
                  type="button"
                  onClick={() => void startSso()}
                  disabled={busy}
                >
                  {sso.button_label ?? 'Single sign-on'}
                </button>
              </>
            )}
          </form>
        )}

        <footer className="auth-card__footer">
          NetSecOps performs read-only assessment. It never modifies a target device.
        </footer>
      </div>

      {/* The brand, beside the form rather than above it. Second in the DOM and first
          on screen below 820px, so a narrow window identifies the product before it
          asks for a password — a bare username box with no branding above it is what
          a phishing page looks like. */}
      <div className="auth-brand">
        {/* Intrinsic size so nothing reflows once the image lands. `alt` carries the
            product name because this image is the only place it appears. */}
        <img
          className="auth-brand__mark brand-panel"
          src="/brand/netsecops-lockup.png"
          alt="NetSecOps"
          width={560}
          height={522}
        />
      </div>
    </div>
  );
}

function describe(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.isLocked) {
      return 'This account is temporarily locked after repeated failed sign-in attempts. Try again later.';
    }
    if (error.isRateLimited) {
      return 'Too many attempts. Please wait a moment before trying again.';
    }
    return error.problem.detail;
  }
  return 'Unable to reach the server. Check your connection and try again.';
}
