/** Auth types mirroring the backend Pydantic schemas.
 *
 * These are hand-written for Phase 0. From Phase 1 they are generated from the
 * published OpenAPI document (`npm run gen:api`), so the two cannot drift.
 */

export type Role =
  'super_admin' | 'security_analyst' | 'network_engineer' | 'auditor' | 'api_service';

export interface TokenResponse {
  mfa_required: false;
  token_type: 'bearer';
  access_token: string;
  expires_at: string;
  refresh_expires_at: string;
}

export interface MFAChallengeResponse {
  mfa_required: true;
  mfa_token: string;
  expires_at: string;
}

export type LoginResponse = TokenResponse | MFAChallengeResponse;

export interface CurrentUser {
  id: string;
  username: string;
  email: string;
  full_name: string | null;
  is_active: boolean;
  is_service_account: boolean;
  mfa_enabled: boolean;
  must_change_password: boolean;
  roles: Role[];
  last_login_at: string | null;
  created_at: string;
  updated_at: string;
  permissions: string[];
  device_group_ids: string[];
  unrestricted_scope: boolean;
}

export interface MFAEnrolment {
  secret: string;
  provisioning_uri: string;
  recovery_codes: string[];
}

export const ROLE_LABELS: Record<Role, string> = {
  super_admin: 'Super Admin',
  security_analyst: 'Security Analyst',
  network_engineer: 'Network Engineer',
  auditor: 'Auditor',
  api_service: 'API Service Account',
};
