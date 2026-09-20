/** Sites, Device Groups and tags — how the estate is divided up (FR-INV-03, FR-AUTH-05).
 *
 * Reference data, and easy to dismiss as such, except that Device Groups are what
 * object-level scoping is expressed in: the Users page can only confine somebody to a
 * group that exists, and until a group existed the only available answers were "the whole
 * estate" or "nothing". Groups are also what a policy is assigned to, and what a schedule
 * covers. Three pages depend on this one and none of them could create what they depend
 * on.
 *
 * **Moving a group rewrites its subtree.** `PUT /device-groups/{id}/parent` is not a
 * cosmetic reorganisation: every descendant's materialised path changes, so every scoped
 * user's visibility and every policy assignment that resolves through those paths follows
 * the move. The page says so at the control rather than in a tooltip.
 *
 * **A group cannot be deleted here, because the API has no such endpoint**, and that is
 * arguably right — deleting a group with scopes and assignments pointing at it is not a
 * decision to take from a list. Stated rather than hidden, so nobody hunts for the button.
 *
 * Tags are read-only for the same reason they are elsewhere: they are created by applying
 * them to a device, not in the abstract.
 */

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';

import { ApiError, api } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import type { DeviceGroup, Site } from '../features/inventory/types';

interface Tag {
  id: string;
  name: string;
  colour: string | null;
}

function message(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.problem.detail : fallback;
}

/** How deep a group sits, from its materialised ltree path. Used only to indent the
 *  list — the server's path is authoritative about ancestry. */
function depth(group: DeviceGroup): number {
  return Math.max(0, group.path.split('.').length - 1);
}

// ────────────────────────────── device groups ────────────────────────────────

function Groups({ canWrite }: { canWrite: boolean }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [parentId, setParentId] = useState('');
  const [moving, setMoving] = useState<string | null>(null);
  const [moveTo, setMoveTo] = useState('');
  const [error, setError] = useState<string | null>(null);

  const groups = useQuery({
    queryKey: ['device-groups'],
    queryFn: () => api.get<DeviceGroup[]>('/device-groups'),
  });

  const refresh = () => {
    setError(null);
    void queryClient.invalidateQueries({ queryKey: ['device-groups'] });
  };

  const create = useMutation({
    mutationFn: () =>
      api.post<DeviceGroup>('/device-groups', {
        name: name.trim(),
        parent_id: parentId || null,
      }),
    onSuccess: () => {
      setName('');
      refresh();
    },
    onError: (err) => setError(message(err, 'The group could not be created.')),
  });

  const move = useMutation({
    mutationFn: (groupId: string) =>
      api.put<DeviceGroup>(`/device-groups/${groupId}/parent`, { parent_id: moveTo || null }),
    onSuccess: () => {
      setMoving(null);
      setMoveTo('');
      refresh();
    },
    onError: (err) => setError(message(err, 'The group could not be moved.')),
  });

  const rows = [...(groups.data ?? [])].sort((a, b) => a.path.localeCompare(b.path));

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">Device Groups</h2>
      </div>
      <p className="field__help">
        What a user's visibility is confined to, what a policy is assigned to, and what a schedule
        covers. Nested: a scope on a parent reaches everything beneath it.
      </p>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      {groups.isLoading ? (
        <p className="page-loading">Loading…</p>
      ) : rows.length === 0 ? (
        <p className="empty">
          No group exists, so every scoped user sees nothing and every policy is estate-wide.
        </p>
      ) : (
        <ul className="device-list">
          {rows.map((group) => (
            <li key={group.id} style={{ paddingLeft: `${depth(group) * 18}px` }}>
              {group.name}
              {group.description && <span className="muted"> — {group.description}</span>}
              {canWrite &&
                (moving === group.id ? (
                  <span className="toolbar">
                    <select
                      className="field__input field__input--small"
                      value={moveTo}
                      aria-label={`New parent for ${group.name}`}
                      onChange={(event) => setMoveTo(event.target.value)}
                    >
                      <option value="">No parent (top level)</option>
                      {rows
                        // A group cannot be its own parent, and the server rejects a move
                        // into its own subtree — offering either would be an option whose
                        // only outcome is an error.
                        .filter((other) => !other.path.startsWith(group.path))
                        .map((other) => (
                          <option key={other.id} value={other.id}>
                            {other.name}
                          </option>
                        ))}
                    </select>
                    <button
                      className="button button--ghost button--small"
                      disabled={move.isPending}
                      onClick={() => move.mutate(group.id)}
                    >
                      Move
                    </button>
                    <button
                      className="button button--ghost button--small"
                      onClick={() => setMoving(null)}
                    >
                      Cancel
                    </button>
                  </span>
                ) : (
                  <button
                    className="button button--ghost button--small"
                    onClick={() => {
                      setMoving(group.id);
                      setMoveTo(group.parent_id ?? '');
                    }}
                  >
                    Move
                  </button>
                ))}
            </li>
          ))}
        </ul>
      )}

      {canWrite && (
        <>
          <p className="field__help">
            Moving a group rewrites every path beneath it, so every scoped user's visibility and
            every policy assignment that resolves through those paths moves with it.
          </p>
          <div className="toolbar">
            <input
              className="field__input field__input--small"
              value={name}
              aria-label="New group name"
              placeholder="New group"
              onChange={(event) => setName(event.target.value)}
            />
            <select
              className="field__input field__input--small"
              value={parentId}
              aria-label="Parent group"
              onChange={(event) => setParentId(event.target.value)}
            >
              <option value="">No parent (top level)</option>
              {rows.map((group) => (
                <option key={group.id} value={group.id}>
                  {group.name}
                </option>
              ))}
            </select>
            <button
              className="button button--small"
              disabled={!name.trim() || create.isPending}
              onClick={() => create.mutate()}
            >
              Create group
            </button>
          </div>
          <p className="field__help">
            Groups cannot be deleted from here — the API has no endpoint for it, deliberately: user
            scopes and policy assignments point at them, and unpicking that is not a decision to
            take from a list.
          </p>
        </>
      )}
    </section>
  );
}

// ───────────────────────────────── sites ─────────────────────────────────────

function Sites({ canWrite }: { canWrite: boolean }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [location, setLocation] = useState('');
  const [error, setError] = useState<string | null>(null);

  const sites = useQuery({
    queryKey: ['sites'],
    queryFn: () => api.get<Site[]>('/sites'),
  });

  const create = useMutation({
    mutationFn: () =>
      api.post<Site>('/sites', {
        name: name.trim(),
        location: location.trim() || null,
      }),
    onSuccess: () => {
      setError(null);
      setName('');
      setLocation('');
      void queryClient.invalidateQueries({ queryKey: ['sites'] });
    },
    onError: (err) => setError(message(err, 'The site could not be created.')),
  });

  const rows = sites.data ?? [];

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">Sites</h2>
      </div>
      <p className="field__help">
        Where a device physically is. Descriptive rather than structural — scoping and policy use
        Device Groups, not sites.
      </p>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      {rows.length === 0 ? (
        <p className="empty">No site is defined.</p>
      ) : (
        <ul className="device-list">
          {rows.map((site) => (
            <li key={site.id}>
              {site.name}
              {site.location && <span className="muted"> — {site.location}</span>}
            </li>
          ))}
        </ul>
      )}

      {canWrite && (
        <div className="toolbar">
          <input
            className="field__input field__input--small"
            value={name}
            aria-label="New site name"
            placeholder="New site"
            onChange={(event) => setName(event.target.value)}
          />
          <input
            className="field__input field__input--small"
            value={location}
            aria-label="Site location"
            placeholder="Location"
            onChange={(event) => setLocation(event.target.value)}
          />
          <button
            className="button button--small"
            disabled={!name.trim() || create.isPending}
            onClick={() => create.mutate()}
          >
            Create site
          </button>
        </div>
      )}
    </section>
  );
}

// ────────────────────────────────── tags ─────────────────────────────────────

function Tags() {
  const tags = useQuery({
    queryKey: ['tags'],
    queryFn: () => api.get<Tag[]>('/tags'),
  });

  const rows = tags.data ?? [];

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">Tags</h2>
      </div>
      <p className="field__help">
        Every tag in use, which is the set a job scope or a filter can name. Tags come into
        existence by being applied to a device, so there is nothing to create here.
      </p>

      {rows.length === 0 ? (
        <p className="empty">No device carries a tag.</p>
      ) : (
        <div className="toolbar">
          {rows.map((tag) => (
            <span className="pill" key={tag.id}>
              {tag.name}
            </span>
          ))}
        </div>
      )}
    </section>
  );
}

// ─────────────────────────────── page ────────────────────────────────────────

export function OrganisationPage() {
  const { can } = useAuth();
  const canWrite = can('device:write');

  return (
    <div className="page">
      <header className="page__header">
        <h1>Sites, groups and tags</h1>
        <p className="page__subtitle">
          How the estate is divided up. Device Groups are what user scope, policy assignment and
          schedules are all expressed in. <Link to="/inventory">Back to inventory</Link>
        </p>
      </header>

      <Groups canWrite={canWrite} />
      <Sites canWrite={canWrite} />
      <Tags />
    </div>
  );
}
