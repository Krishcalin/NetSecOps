/** User administration (FR-AUTH-04, FR-AUTH-05).
 *
 * Eight endpoints shipped in Phase 0 with no surface, which means the only account a
 * NetSecOps deployment has ever had is the one the installer seeded: a second operator
 * could not be added, a role could not be changed, and a locked-out person could not
 * have their password reset — except with a REST client and a session cookie.
 *
 * Three decisions worth stating, because each one shows on the page:
 *
 * **Roles come from the server.** `GET /auth/roles` returns the catalogue and what each
 * role grants, and the picker is built from it. A hard-coded list in the browser would be
 * a second copy of `rbac.py` that drifts the first time a permission is added, and the
 * drift would be invisible — the picker would keep offering roles that still exist.
 *
 * **Scope is shown next to the role, not on its own.** Device Group scope only binds a
 * group-scoped role; on a Super Admin or an Analyst the assignment is stored and ignored.
 * Showing a scope without the role beside it would read as a restriction that is in force
 * when it is not.
 *
 * **Deactivate sits before delete, and delete asks.** Deactivation is reversible and
 * keeps the audit trail attributable; deletion is not, and the audit log then references
 * a user id that resolves to nothing.
 */

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { ApiError, api } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import { ROLE_LABELS } from '../features/auth/types';
import type { Role } from '../features/auth/types';
import type { RoleInfo, User } from '../features/users/types';
import type { DeviceGroup, Paginated } from '../features/inventory/types';

/** Roles whose visibility is not narrowed by Device Group scope.
 *
 * Mirrors `AuthService._scope_for`, which lifts scoping for any unrestricted role. Used
 * only to decide whether to *warn* that a stored scope is inert — never to decide access,
 * which is the server's alone. */
const UNRESTRICTED_ROLES: Role[] = ['super_admin', 'security_analyst'];

function message(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    return err.problem.violations?.length
      ? `${err.problem.detail} ${err.problem.violations.join(', ')}.`
      : err.problem.detail;
  }
  return err instanceof Error ? err.message : fallback;
}

function scopeApplies(roles: Role[]): boolean {
  return roles.length > 0 && !roles.some((role) => UNRESTRICTED_ROLES.includes(role));
}

// ─────────────────────────────── create ──────────────────────────────────────

function CreateUser({ roles, onCreated }: { roles: RoleInfo[]; onCreated: () => void }) {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [password, setPassword] = useState('');
  const [selected, setSelected] = useState<Role[]>([]);
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () =>
      api.post<User>('/users', {
        username: username.trim(),
        email: email.trim(),
        password,
        full_name: fullName.trim() || null,
        roles: selected,
        // The administrator setting this knows the password, so leaving it in place
        // would mean two people hold it indefinitely.
        must_change_password: true,
      }),
    onSuccess: () => {
      setError(null);
      setUsername('');
      setEmail('');
      setFullName('');
      setPassword('');
      setSelected([]);
      onCreated();
    },
    onError: (err) => setError(message(err, 'The user could not be created.')),
  });

  const toggle = (role: Role) =>
    setSelected(selected.includes(role) ? selected.filter((r) => r !== role) : [...selected, role]);

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">Add a user</h2>
      </div>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      <div className="form-grid">
        <label className="field">
          <span className="field__label">Username</span>
          <input
            className="field__input"
            value={username}
            aria-label="Username"
            autoComplete="off"
            onChange={(event) => setUsername(event.target.value)}
          />
        </label>
        <label className="field">
          <span className="field__label">Email</span>
          <input
            className="field__input"
            type="email"
            value={email}
            aria-label="Email"
            autoComplete="off"
            onChange={(event) => setEmail(event.target.value)}
          />
        </label>
        <label className="field">
          <span className="field__label">Full name</span>
          <input
            className="field__input"
            value={fullName}
            aria-label="Full name"
            onChange={(event) => setFullName(event.target.value)}
          />
        </label>
        <label className="field">
          <span className="field__label">Initial password</span>
          <input
            className="field__input"
            type="password"
            value={password}
            aria-label="Initial password"
            autoComplete="new-password"
            onChange={(event) => setPassword(event.target.value)}
          />
          <span className="field__help">
            At least 12 characters. They must change it at first sign-in.
          </span>
        </label>
      </div>

      <fieldset className="field">
        <legend className="field__label">Roles</legend>
        {roles.length === 0 ? (
          <p className="field__help">Loading the role catalogue…</p>
        ) : (
          <div className="checkbox-grid">
            {roles.map((info) => (
              <label className="checkbox" key={info.role}>
                <input
                  type="checkbox"
                  checked={selected.includes(info.role)}
                  aria-label={ROLE_LABELS[info.role]}
                  onChange={() => toggle(info.role)}
                />
                <span>
                  <strong>{ROLE_LABELS[info.role]}</strong>
                  <span className="muted"> — {info.description}</span>
                </span>
              </label>
            ))}
          </div>
        )}
        {selected.length === 0 && (
          <span className="field__help">
            A user with no role can sign in and see nothing. That is a valid state, not an oversight
            — but it is rarely what was meant.
          </span>
        )}
      </fieldset>

      <div className="toolbar">
        <button
          className="button button--small"
          disabled={!username.trim() || !email.trim() || !password || create.isPending}
          onClick={() => create.mutate()}
        >
          Create user
        </button>
      </div>
    </section>
  );
}

// ─────────────────────────────── roles ───────────────────────────────────────

function RoleEditor({ user, roles }: { user: User; roles: RoleInfo[] }) {
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<Role[]>(user.roles);
  const [error, setError] = useState<string | null>(null);

  const save = useMutation({
    // PUT, not PATCH: the whole set is sent, so unticking a box removes that role.
    mutationFn: () => api.put<User>(`/users/${user.id}/roles`, { roles: selected }),
    onSuccess: () => {
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ['users'] });
    },
    onError: (err) => setError(message(err, 'The roles could not be changed.')),
  });

  const toggle = (role: Role) =>
    setSelected(selected.includes(role) ? selected.filter((r) => r !== role) : [...selected, role]);

  const changed =
    selected.length !== user.roles.length || selected.some((r) => !user.roles.includes(r));

  return (
    <div className="stack">
      <h3 className="finding__heading">Roles</h3>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      <div className="checkbox-grid">
        {roles.map((info) => (
          <label className="checkbox" key={info.role}>
            <input
              type="checkbox"
              checked={selected.includes(info.role)}
              aria-label={`${ROLE_LABELS[info.role]} for ${user.username}`}
              onChange={() => toggle(info.role)}
            />
            <span>
              <strong>{ROLE_LABELS[info.role]}</strong>
              <span className="muted"> — {info.permissions.length} permissions</span>
            </span>
          </label>
        ))}
      </div>

      <div className="toolbar">
        <button
          className="button button--ghost button--small"
          disabled={!changed || save.isPending}
          onClick={() => save.mutate()}
        >
          Save roles
        </button>
      </div>
    </div>
  );
}

// ─────────────────────────────── scope ───────────────────────────────────────

/** FR-AUTH-05 — which Device Groups a group-scoped role may see. */
function ScopeEditor({ user, groups }: { user: User; groups: DeviceGroup[] }) {
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<string[]>(user.device_group_ids);
  const [error, setError] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: () => api.put<User>(`/users/${user.id}/scope`, { device_group_ids: selected }),
    onSuccess: () => {
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ['users'] });
    },
    onError: (err) => setError(message(err, 'The scope could not be set.')),
  });

  const toggle = (id: string) =>
    setSelected(selected.includes(id) ? selected.filter((g) => g !== id) : [...selected, id]);

  const binding = scopeApplies(user.roles);

  return (
    <div className="stack">
      <h3 className="finding__heading">Device Group scope</h3>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      {!binding && (
        <p className="field__help">
          This user holds a role whose visibility is not narrowed by scope, so anything set here is
          stored and ignored. It takes effect if they are later given only group-scoped roles.
        </p>
      )}

      {binding && selected.length === 0 && (
        // Failing closed is right, and surprising. Said out loud so nobody reads an
        // empty list as "not restricted yet".
        <p className="field__help">
          No group is selected, so this user sees no devices at all. An empty scope is not an unset
          one.
        </p>
      )}

      {groups.length === 0 ? (
        <p className="empty">No Device Groups exist yet, so there is nothing to scope to.</p>
      ) : (
        <div className="checkbox-grid">
          {groups.map((group) => (
            <label className="checkbox" key={group.id}>
              <input
                type="checkbox"
                checked={selected.includes(group.id)}
                aria-label={`${group.name} for ${user.username}`}
                onChange={() => toggle(group.id)}
              />
              <span>{group.name}</span>
            </label>
          ))}
        </div>
      )}

      <div className="toolbar">
        <button
          className="button button--ghost button--small"
          disabled={save.isPending}
          onClick={() => save.mutate()}
        >
          Save scope
        </button>
      </div>
    </div>
  );
}

// ────────────────────────────── password ─────────────────────────────────────

function PasswordReset({ user }: { user: User }) {
  const [password, setPassword] = useState('');
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reset = useMutation({
    mutationFn: () =>
      api.post<void>(`/users/${user.id}/password`, {
        new_password: password,
        must_change_password: true,
      }),
    onSuccess: () => {
      setError(null);
      // Cleared rather than left in the box: the administrator has to hand it over by
      // some other channel, and it should not sit in the DOM while they do.
      setPassword('');
      setDone(true);
    },
    onError: (err) => {
      setDone(false);
      setError(message(err, 'The password could not be reset.'));
    },
  });

  return (
    <div className="stack">
      <h3 className="finding__heading">Reset password</h3>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}
      {done && (
        <div className="alert alert--ok" role="status">
          The password was reset. {user.username} must change it at their next sign-in, and every
          session they had is now closed.
        </div>
      )}

      <div className="toolbar">
        <input
          className="field__input field__input--small"
          type="password"
          value={password}
          aria-label={`New password for ${user.username}`}
          autoComplete="new-password"
          onChange={(event) => {
            setPassword(event.target.value);
            setDone(false);
          }}
        />
        <button
          className="button button--ghost button--small"
          disabled={!password || reset.isPending}
          onClick={() => reset.mutate()}
        >
          Reset
        </button>
      </div>
      <span className="field__help">
        At least 12 characters, and not one of their last 5. It cannot be the password already in
        force.
      </span>
    </div>
  );
}

// ─────────────────────────────── page ────────────────────────────────────────

export function UsersPage() {
  const { can, user: self } = useAuth();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canWrite = can('user:write');
  // Roles, scope, password reset and deletion are Super Admin only on the server. The
  // UI hides them rather than offering buttons that return 403.
  const isSuperAdmin = self?.roles.includes('super_admin') ?? false;

  const users = useQuery({
    queryKey: ['users', search],
    queryFn: () =>
      api.get<Paginated<User>>(
        `/users?limit=200${search.trim() ? `&search=${encodeURIComponent(search.trim())}` : ''}`,
      ),
  });

  const roles = useQuery({
    queryKey: ['role-catalogue'],
    queryFn: () => api.get<RoleInfo[]>('/auth/roles'),
    // The permission model changes when the server is upgraded, not while a page is open.
    staleTime: Infinity,
  });

  const groups = useQuery({
    queryKey: ['user-scope-groups'],
    queryFn: () => api.get<DeviceGroup[]>('/device-groups'),
  });

  const refresh = () => {
    setError(null);
    void queryClient.invalidateQueries({ queryKey: ['users'] });
  };

  const setActive = useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) =>
      api.patch<User>(`/users/${id}`, { is_active: active }),
    onSuccess: refresh,
    onError: (err) => setError(message(err, 'The account could not be changed.')),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.delete<void>(`/users/${id}`),
    onSuccess: () => {
      setConfirmDelete(null);
      refresh();
    },
    onError: (err) => setError(message(err, 'The user could not be deleted.')),
  });

  const rows = users.data?.data ?? [];
  const roleRows = roles.data ?? [];
  const groupRows = groups.data ?? [];
  const groupName = (id: string) => groupRows.find((g) => g.id === id)?.name ?? id.slice(0, 8);
  const selected = rows.find((u) => u.id === expanded);

  return (
    <div className="page">
      <header className="page__header">
        <h1>Users</h1>
        <p className="page__subtitle">
          Who can sign in, what their role lets them do, and which devices they can see.
        </p>
      </header>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      {canWrite && <CreateUser roles={roleRows} onCreated={refresh} />}

      <div className="toolbar">
        <input
          className="field__input field__input--small"
          value={search}
          aria-label="Search users"
          placeholder="Search by name, username or email"
          onChange={(event) => setSearch(event.target.value)}
        />
      </div>

      {users.isLoading ? (
        <p className="page-loading">Loading…</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>User</th>
                <th>Roles</th>
                <th>Scope</th>
                <th>MFA</th>
                <th>Last sign-in</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((user) => (
                <tr key={user.id} className={user.is_active ? undefined : 'row--muted'}>
                  <td>
                    {user.full_name || user.username}
                    <div className="muted">{user.email}</div>
                    {!user.is_active && <span className="pill pill--failure">deactivated</span>}
                    {user.is_service_account && <span className="pill">service account</span>}
                  </td>
                  <td>
                    {user.roles.length === 0 ? (
                      <span className="muted">no role</span>
                    ) : (
                      user.roles.map((role) => ROLE_LABELS[role]).join(', ')
                    )}
                  </td>
                  <td>
                    {/* Read beside the role: an assignment on an unrestricted role is
                        stored and does nothing, and reporting it as a restriction would
                        be a lie about what this user can see. */}
                    {!scopeApplies(user.roles) ? (
                      <span className="muted">all devices</span>
                    ) : user.device_group_ids.length === 0 ? (
                      <span className="pill pill--failure">no devices</span>
                    ) : (
                      user.device_group_ids.map(groupName).join(', ')
                    )}
                  </td>
                  <td>
                    {user.mfa_enabled ? (
                      <span className="pill pill--success">on</span>
                    ) : (
                      <span className="muted">off</span>
                    )}
                  </td>
                  <td className="mono">
                    {user.last_login_at
                      ? new Date(user.last_login_at).toLocaleString()
                      : 'never signed in'}
                  </td>
                  <td className="table__actions">
                    <button
                      className="button button--ghost button--small"
                      onClick={() => setExpanded(expanded === user.id ? null : user.id)}
                    >
                      {expanded === user.id ? 'Hide' : 'Manage'}
                    </button>
                    {canWrite && (
                      <button
                        className="button button--ghost button--small"
                        disabled={setActive.isPending}
                        onClick={() => setActive.mutate({ id: user.id, active: !user.is_active })}
                      >
                        {user.is_active ? 'Deactivate' : 'Reactivate'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="table__empty">
                    No user matches that search.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {selected && (
        <section className="card">
          <div className="card__header">
            <h2 className="card__title">{selected.full_name || selected.username}</h2>
          </div>

          {isSuperAdmin ? (
            <>
              <RoleEditor key={`roles-${selected.id}`} user={selected} roles={roleRows} />
              <ScopeEditor key={`scope-${selected.id}`} user={selected} groups={groupRows} />
              <PasswordReset key={`password-${selected.id}`} user={selected} />

              <div className="stack">
                <h3 className="finding__heading">Delete</h3>
                <p className="field__help">
                  Deactivating keeps the account and the audit trail that points at it. Deleting
                  leaves audit entries naming a user who no longer resolves — so unless this account
                  was created in error, deactivate instead.
                </p>
                {confirmDelete === selected.id ? (
                  <div className="toolbar">
                    <span>Delete {selected.username} permanently?</span>
                    <button
                      className="button button--ghost button--small"
                      disabled={remove.isPending}
                      onClick={() => remove.mutate(selected.id)}
                    >
                      Yes, delete
                    </button>
                    <button
                      className="button button--ghost button--small"
                      onClick={() => setConfirmDelete(null)}
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <div className="toolbar">
                    <button
                      className="button button--ghost button--small"
                      onClick={() => setConfirmDelete(selected.id)}
                    >
                      Delete user
                    </button>
                  </div>
                )}
              </div>
            </>
          ) : (
            <p className="field__help">
              Roles, scope, password resets and deletion are Super Admin only. You can see this
              account and change whether it is active.
            </p>
          )}
        </section>
      )}
    </div>
  );
}
