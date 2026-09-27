/** Auth context object and its value type.
 *
 * Kept in a module of its own, with no component export, so React Fast Refresh can
 * hot-reload the provider component without discarding session state.
 */

import { createContext } from 'react';

import type { CurrentUser, LoginResponse } from './types';

export interface AuthState {
  user: CurrentUser | null;
  loading: boolean;
  /** Set while a password has been accepted but TOTP is still outstanding. */
  mfaToken: string | null;
}

export interface AuthContextValue extends AuthState {
  login: (username: string, password: string) => Promise<LoginResponse>;
  verifyMfa: (code: string) => Promise<void>;
  /**
   * Pick up a challenge that began somewhere other than the password form.
   *
   * After single sign-on the identity provider returns the browser to a URL, not to
   * a `fetch` — so the pending token arrives in the query string rather than as a
   * response this app was waiting for, and the TOTP step has to be resumed from it.
   */
  resumeMfa: (mfaToken: string) => void;
  logout: (allSessions?: boolean) => Promise<void>;
  refreshUser: () => Promise<void>;
  cancelMfa: () => void;
  can: (permission: string) => boolean;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
