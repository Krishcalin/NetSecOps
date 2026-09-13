/**
 * Authentication state for the SPA.
 *
 * There is deliberately no token in this provider. Tokens live in HttpOnly cookies
 * (FR-AUTH-02) that JavaScript cannot read, so "am I signed in?" is answered by asking
 * the server (`GET /auth/me`) rather than by inspecting local state that could be stale
 * or forged.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

import { ApiError, api } from '../../api/client';
import { AuthContext } from './context';
import type { AuthContextValue, AuthState } from './context';
import type { CurrentUser, LoginResponse } from './types';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ user: null, loading: true, mfaToken: null });

  const refreshUser = useCallback(async () => {
    try {
      const user = await api.get<CurrentUser>('/auth/me');
      setState((s) => ({ ...s, user, loading: false }));
    } catch (error) {
      // A 401 here is the normal "not signed in" case, not a failure worth surfacing.
      if (!(error instanceof ApiError) || error.status !== 401) {
        console.error('Failed to load the current user', error);
      }
      setState((s) => ({ ...s, user: null, loading: false }));
    }
  }, []);

  // Establish session state once on mount.
  useEffect(() => {
    void refreshUser();
  }, [refreshUser]);

  const login = useCallback(
    async (username: string, password: string): Promise<LoginResponse> => {
      const result = await api.post<LoginResponse>('/auth/login', { username, password });

      if (result.mfa_required) {
        setState((s) => ({ ...s, mfaToken: result.mfa_token }));
        return result;
      }

      setState((s) => ({ ...s, mfaToken: null }));
      await refreshUser();
      return result;
    },
    [refreshUser],
  );

  const verifyMfa = useCallback(
    async (code: string) => {
      if (!state.mfaToken) {
        throw new Error('No MFA challenge is in progress.');
      }
      await api.post('/auth/mfa/verify', { mfa_token: state.mfaToken, code });
      setState((s) => ({ ...s, mfaToken: null }));
      await refreshUser();
    },
    [state.mfaToken, refreshUser],
  );

  const logout = useCallback(async (allSessions = false) => {
    try {
      await api.post(`/auth/logout${allSessions ? '?all_sessions=true' : ''}`);
    } finally {
      // Clear local state even if the call failed: the user asked to be signed out.
      setState({ user: null, loading: false, mfaToken: null });
    }
  }, []);

  const cancelMfa = useCallback(() => {
    setState((s) => ({ ...s, mfaToken: null }));
  }, []);

  const can = useCallback(
    (permission: string) => state.user?.permissions.includes(permission) ?? false,
    [state.user],
  );

  const value = useMemo<AuthContextValue>(
    () => ({ ...state, login, verifyMfa, logout, refreshUser, cancelMfa, can }),
    [state, login, verifyMfa, logout, refreshUser, cancelMfa, can],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
