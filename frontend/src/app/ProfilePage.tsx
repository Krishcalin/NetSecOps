/** Self-service account page: password, MFA and API tokens (FR-AUTH-01, FR-AUTH-03,
 *  FR-AUTH-07).
 *
 * API tokens live here rather than on an administration page because that is what they
 * are: the server classes them as self-service, `GET /api-tokens` defaults to your own,
 * and a token carries a subset of *your* permissions. Putting them under Users would
 * suggest an administrator issues them on someone's behalf, which is the exception — it
 * takes a Super Admin and an explicit owner.
 */

import { useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { ApiError, api } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import type { MFAEnrolment, MFAStatus } from '../features/auth/types';
import type { ApiToken, IssuedApiToken } from '../features/users/types';
import { PageHeader } from '../components/PageHeader';

/** FR-AUTH-07 — issue and revoke tokens for your own account.
 *
 * The scope picker offers exactly the permissions the signed-in user holds, because the
 * server refuses anything more: a token can never grant beyond its owner, or it becomes a
 * way around RBAC. Offering a permission that is certain to be rejected would be a
 * picker that teaches people to ignore it.
 */
function ApiTokens({ permissions }: { permissions: string[] }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<string[]>([]);
  const [expiresAt, setExpiresAt] = useState('');
  const [issued, setIssued] = useState<IssuedApiToken | null>(null);
  const [error, setError] = useState<string | null>(null);

  const tokens = useQuery({
    // No `mine_only` parameter: it defaults to true, and spelling it out would imply
    // the other setting is a normal thing to ask for here.
    queryKey: ['api-tokens'],
    queryFn: () => api.get<ApiToken[]>('/api-tokens'),
  });

  const refresh = () => void queryClient.invalidateQueries({ queryKey: ['api-tokens'] });

  const create = useMutation({
    mutationFn: () =>
      api.post<IssuedApiToken>('/api-tokens', {
        name: name.trim(),
        scopes,
        // A datetime-local value has no zone. Sent as the browser's local time so the
        // expiry means what the person typing it meant.
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
      }),
    onSuccess: (token) => {
      setError(null);
      setIssued(token);
      setName('');
      setScopes([]);
      setExpiresAt('');
      refresh();
    },
    onError: (err) =>
      setError(err instanceof ApiError ? err.problem.detail : 'The token could not be issued.'),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api.delete<void>(`/api-tokens/${id}`),
    onSuccess: refresh,
    onError: (err) =>
      setError(err instanceof ApiError ? err.problem.detail : 'The token could not be revoked.'),
  });

  const toggle = (permission: string) =>
    setScopes(
      scopes.includes(permission)
        ? scopes.filter((s) => s !== permission)
        : [...scopes, permission],
    );

  const rows = tokens.data ?? [];

  return (
    <section className="card">
      <h2 className="card__title">API tokens</h2>
      <p className="field__help">
        A token acts as you, limited to the permissions you tick. It is the only way to reach the
        API without a browser session.
      </p>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      {issued && (
        <div className="alert alert--ok" role="status">
          <strong>Copy this now. It is not stored and cannot be shown again.</strong>
          <p className="mono secret-block">{issued.token}</p>
          <button className="button button--ghost button--small" onClick={() => setIssued(null)}>
            I have copied it
          </button>
        </div>
      )}

      {rows.length === 0 ? (
        <p className="empty">You have no API tokens.</p>
      ) : (
        <ul className="device-list">
          {rows.map((token) => (
            <li key={token.id} className={token.revoked_at ? 'row--muted' : undefined}>
              <span className="mono">{token.prefix}…</span> {token.name}
              <div className="muted">
                {token.scopes.length} scope{token.scopes.length === 1 ? '' : 's'}
                {token.expires_at
                  ? ` · expires ${new Date(token.expires_at).toLocaleDateString()}`
                  : ' · no expiry'}
                {token.last_used_at
                  ? ` · last used ${new Date(token.last_used_at).toLocaleDateString()}`
                  : ' · never used'}
              </div>
              {token.revoked_at ? (
                // Kept on the list rather than removed: "when was this withdrawn" is a
                // question people ask, and a vanished row cannot answer it.
                <span className="pill pill--failure">
                  revoked {new Date(token.revoked_at).toLocaleDateString()}
                </span>
              ) : (
                <button
                  className="button button--ghost button--small"
                  disabled={revoke.isPending}
                  onClick={() => revoke.mutate(token.id)}
                >
                  Revoke
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      <div className="stack">
        <h3 className="finding__heading">Issue a token</h3>

        <label className="field">
          <span className="field__label">Name</span>
          <input
            className="field__input"
            value={name}
            aria-label="Token name"
            onChange={(event) => setName(event.target.value)}
          />
          <span className="field__help">
            What it is for. It appears in the audit log beside everything the token does.
          </span>
        </label>

        <label className="field">
          <span className="field__label">Expires</span>
          <input
            className="field__input"
            type="datetime-local"
            value={expiresAt}
            aria-label="Token expiry"
            onChange={(event) => setExpiresAt(event.target.value)}
          />
          <span className="field__help">
            Leave empty for a token that never expires — a permanent credential, so prefer a date.
          </span>
        </label>

        <fieldset className="field">
          <legend className="field__label">Scopes</legend>
          <div className="checkbox-grid">
            {permissions.map((permission) => (
              <label className="checkbox" key={permission}>
                <input
                  type="checkbox"
                  checked={scopes.includes(permission)}
                  aria-label={permission}
                  onChange={() => toggle(permission)}
                />
                <span className="mono">{permission}</span>
              </label>
            ))}
          </div>
        </fieldset>

        <div className="toolbar">
          <button
            className="button button--primary"
            disabled={!name.trim() || scopes.length === 0 || create.isPending}
            onClick={() => create.mutate()}
          >
            Issue token
          </button>
        </div>
      </div>
    </section>
  );
}

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
  const [confirmDisable, setConfirmDisable] = useState(false);
  const [disablePassword, setDisablePassword] = useState('');

  // How many single-use codes are left. They can never be redisplayed, only reissued
  // by turning the factor off and on — so nought is a lockout waiting for a lost
  // phone, and until this endpoint existed the only way to find out was to run out.
  const mfa = useQuery({
    queryKey: ['mfa-status'],
    queryFn: () => api.get<MFAStatus>('/auth/mfa'),
  });

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

  async function disableMfa(event: FormEvent) {
    event.preventDefault();
    setMfaError(null);
    try {
      // Both factors, not a confirmation click. A session says somebody signed in
      // once; it does not say who is at the keyboard now, and this is the one change
      // that weakens every future sign-in.
      await api.delete('/auth/mfa', { password: disablePassword, code: mfaCode });
      setMfaDone(false);
      setConfirmDisable(false);
      setDisablePassword('');
      setMfaCode('');
      await refreshUser();
      await mfa.refetch();
    } catch (err) {
      setMfaError(err instanceof ApiError ? err.problem.detail : 'Could not turn MFA off.');
      setMfaCode('');
    }
  }

  return (
    <div className="page">
      <PageHeader icon="users" title="Your profile" subtitle={user?.email} />

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
            <>
              <p>
                MFA is <strong>enabled</strong>. You will be asked for a code from your
                authenticator app at each sign-in.
              </p>

              {mfa.data && (
                <p className={mfa.data.recovery_codes_left === 0 ? 'text-error' : 'field__help'}>
                  Recovery codes remaining: <strong>{mfa.data.recovery_codes_left}</strong>
                  {mfa.data.recovery_codes_left === 0 &&
                    ' — none left. They cannot be redisplayed, only reissued: turn two-factor off and on again for a new set.'}
                </p>
              )}

              {confirmDisable ? (
                <form onSubmit={disableMfa} noValidate>
                  {/* Both factors, not a confirmation click. Removing the second
                      factor from a borrowed unlocked browser was one click, and it is
                      the single change that weakens every future sign-in. */}
                  <p className="field__help">
                    Turning it off re-proves both factors. A recovery code works here too, which is
                    what they are for when the phone is gone.
                  </p>
                  <label className="field">
                    <span className="field__label">Current password</span>
                    <input
                      className="field__input"
                      type="password"
                      autoComplete="current-password"
                      value={disablePassword}
                      onChange={(e) => setDisablePassword(e.target.value)}
                      required
                    />
                  </label>
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
                  <div className="toolbar">
                    {/* Disabled until both are present rather than relying on
                        `required`, which stops a person typing into the form and does
                        nothing for a submit that arrives any other way. */}
                    <button
                      className="button button--ghost button--small"
                      type="submit"
                      disabled={!disablePassword || !mfaCode}
                    >
                      Turn off two-factor
                    </button>
                    <button
                      className="button button--ghost button--small"
                      type="button"
                      onClick={() => {
                        setConfirmDisable(false);
                        setDisablePassword('');
                        setMfaCode('');
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              ) : (
                <button
                  className="button button--ghost button--small"
                  onClick={() => setConfirmDisable(true)}
                >
                  Turn off MFA
                </button>
              )}
            </>
          ) : enrolment ? (
            <>
              {/* Three ways in, because one is never enough: the camera, the tap if
                  you are reading this on the phone, and the typed key when the camera
                  is unavailable or the screen is shared. All three carry one secret. */}
              <p className="field__help">
                Scan this with Microsoft Authenticator, Google Authenticator, Authy, 1Password —
                anything that speaks the standard.
              </p>

              <div
                className="mfa-qr"
                /* Safe: the encoder emits one <path> of numeric coordinates, so no
                   part of the URI — which carries the secret — reaches the markup. */
                dangerouslySetInnerHTML={{ __html: enrolment.qr_svg }}
              />

              <p className="field__help">
                On the phone already? <a href={enrolment.provisioning_uri}>Open in your
                authenticator app</a>
              </p>

              <p className="field__help">Or type this setup key in by hand:</p>
              <p className="mono secret-block">{enrolment.formatted_secret}</p>

              {/* Shown, not folded into a <details>. They are displayed exactly once
                  and can never be redisplayed — a disclosure somebody does not open is
                  a set of codes they do not have when the phone goes. */}
              <div className="alert alert--warning" role="status">
                <strong>Save these recovery codes now.</strong> Only fingerprints are stored, so
                this is the one time they can be shown. Each works once, and they are the way back
                in if the phone is lost.
                <ul className="recovery__list mono">
                  {enrolment.recovery_codes.map((code) => (
                    <li key={code}>{code}</li>
                  ))}
                </ul>
              </div>

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

      <ApiTokens permissions={user?.permissions ?? []} />
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
