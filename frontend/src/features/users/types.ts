/** User administration and API tokens (FR-AUTH-05, FR-AUTH-07).
 *
 * Mirrors `schemas/auth.py`. `Role` and `ROLE_LABELS` live in `../auth/types` and are
 * re-used rather than restated — a second copy of the role list would drift the first
 * time one is added.
 */

import type { Role } from '../auth/types';

export interface User {
  id: string;
  username: string;
  email: string;
  full_name: string | null;
  is_active: boolean;
  is_service_account: boolean;
  mfa_enabled: boolean;
  must_change_password: boolean;
  roles: Role[];
  /** The Device Groups *assigned* to this user, which an unrestricted role ignores. */
  device_group_ids: string[];
  last_login_at: string | null;
  created_at: string;
  updated_at: string;
}

/** `GET /auth/roles` — the permission model, served rather than hard-coded here. */
export interface RoleInfo {
  role: Role;
  description: string;
  permissions: string[];
}

export interface ApiToken {
  id: string;
  name: string;
  /** The visible head of the token. All that is ever shown after creation. */
  prefix: string;
  scopes: string[];
  owner_id: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

/** The creation response, and the only time the plaintext exists outside the client. */
export interface IssuedApiToken extends ApiToken {
  token: string;
}
