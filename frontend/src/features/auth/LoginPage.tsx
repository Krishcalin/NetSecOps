/** Sign-in screen: password step, then the TOTP step when MFA is enabled. */

import { useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';

import { ApiError } from '../../api/client';
import { useAuth } from './useAuth';

export function LoginPage() {
  const { login, verifyMfa, mfaToken, cancelMfa } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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
          {/* Intrinsic size given so the card does not reflow once the image lands —
              the asset is 560x522 and renders at half that. `alt` carries the product
              name because this image *is* the `h1`. */}
          <h1 className="brand-panel">
            <img src="/brand/netsecops-lockup.png" alt="NetSecOps" width={280} height={261} />
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
          </form>
        )}

        <footer className="auth-card__footer">
          NetSecOps performs read-only assessment. It never modifies a target device.
        </footer>
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
