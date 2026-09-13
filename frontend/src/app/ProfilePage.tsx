/** Self-service account page: password change and MFA enrolment (FR-AUTH-01, FR-AUTH-03). */

import { useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';

import { ApiError, api } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import type { MFAEnrolment } from '../features/auth/types';

export function ProfilePage() {
  const { user, refreshUser, logout } = useAuth();
  const navigate = useNavigate();

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordError, setPasswordError] = useState<string | null>(null);

  const [enrolment, setEnrolment] = useState<MFAEnrolment | null>(null);
  const [mfaCode, setMfaCode] = useState('');
  const [mfaError, setMfaError] = useState<string | null>(null);
  const [mfaDone, setMfaDone] = useState(false);

  async function changePassword(event: FormEvent) {
    event.preventDefault();
    setPasswordError(null);

    if (newPassword !== confirmPassword) {
      setPasswordError('The two new passwords do not match.');
      return;
    }

    try {
      await api.post('/auth/password', {
        current_password: currentPassword,
        new_password: newPassword,
      });
      // Changing a password revokes every session (FR-AUTH-02), so sign in again.
      await logout();
      navigate('/login', { replace: true });
    } catch (err) {
      setPasswordError(describePasswordError(err));
    }
  }

  async function beginEnrolment() {
    setMfaError(null);
    try {
      setEnrolment(await api.post<MFAEnrolment>('/auth/mfa/enroll'));
    } catch (err) {
      setMfaError(err instanceof ApiError ? err.problem.detail : 'Could not start enrolment.');
    }
  }

  async function confirmEnrolment(event: FormEvent) {
    event.preventDefault();
    setMfaError(null);
    try {
      await api.post('/auth/mfa/confirm', { code: mfaCode });
      setMfaDone(true);
      setEnrolment(null);
      setMfaCode('');
      await refreshUser();
    } catch (err) {
      setMfaError(err instanceof ApiError ? err.problem.detail : 'Could not confirm the code.');
      setMfaCode('');
    }
  }

  return (
    <div className="page">
      <header className="page__header">
        <h1>Your profile</h1>
        <p className="page__subtitle">{user?.email}</p>
      </header>

      <div className="card-grid">
        <section className="card">
          <h2 className="card__title">Change password</h2>
          {passwordError && (
            <div className="alert alert--error" role="alert">
              {passwordError}
            </div>
          )}
          <form onSubmit={changePassword} noValidate>
            <label className="field">
              <span className="field__label">Current password</span>
              <input
                className="field__input"
                type="password"
                autoComplete="current-password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                required
              />
            </label>
            <label className="field">
              <span className="field__label">New password</span>
              <input
                className="field__input"
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
              />
            </label>
            <label className="field">
              <span className="field__label">Confirm new password</span>
              <input
                className="field__input"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
            </label>
            <p className="field__help">
              At least 12 characters, with upper and lower case, a digit and a symbol. It must not
              match your last 5 passwords. Changing it signs out every session.
            </p>
            <button className="button button--primary" type="submit">
              Change password
            </button>
          </form>
        </section>

        <section className="card">
          <h2 className="card__title">Two-factor authentication</h2>

          {mfaError && (
            <div className="alert alert--error" role="alert">
              {mfaError}
            </div>
          )}
          {mfaDone && (
            <div className="alert alert--ok" role="status">
              MFA is now enabled on your account.
            </div>
          )}

          {user?.mfa_enabled && !enrolment ? (
            <p>
              MFA is <strong>enabled</strong>. You will be asked for a code from your authenticator
              app at each sign-in.
            </p>
          ) : enrolment ? (
            <>
              <p className="field__help">
                Scan this into your authenticator app, or enter the secret manually, then confirm
                with a generated code.
              </p>
              <p className="mono secret-block">{enrolment.secret}</p>

              <details className="recovery">
                <summary>Recovery codes ({enrolment.recovery_codes.length})</summary>
                <p className="field__help">
                  Store these somewhere safe. Each works once, and they are shown only now.
                </p>
                <ul className="recovery__list mono">
                  {enrolment.recovery_codes.map((code) => (
                    <li key={code}>{code}</li>
                  ))}
                </ul>
              </details>

              <form onSubmit={confirmEnrolment} noValidate>
                <label className="field">
                  <span className="field__label">Code from your app</span>
                  <input
                    className="field__input"
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value)}
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    required
                  />
                </label>
                <button className="button button--primary" type="submit" disabled={!mfaCode}>
                  Confirm and enable
                </button>
              </form>
            </>
          ) : (
            <>
              <p>
                MFA is <strong>not enabled</strong>. Enabling it adds a time-based code to each
                sign-in.
              </p>
              <button className="button button--primary" onClick={beginEnrolment}>
                Set up MFA
              </button>
            </>
          )}
        </section>
      </div>
    </div>
  );
}

function describePasswordError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.problem.violations?.length) {
      return `Password ${error.problem.violations.join(', ')}.`;
    }
    return error.problem.detail;
  }
  return 'Could not change the password.';
}
