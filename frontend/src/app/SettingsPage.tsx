/** Notification channels, subscriptions, deliveries and platform settings.
 *
 * FR-ADM-01 and the management half of FR-INT-01. Two things this page deliberately
 * does *not* do:
 *
 * It never shows a channel's secret, because the API never returns one — a Slack
 * incoming-webhook URL is a bearer credential, and a page that displayed it would turn
 * everyone who can read the settings screen into someone who can post as NetSecOps. The
 * form writes a secret and the table reports only whether one is stored.
 *
 * It shows deliveries that *succeeded* as well as those that failed. "Was anybody
 * actually told?" is asked after an incident, and a list holding only failures cannot
 * answer it.
 */

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { api, ApiError } from '../api/client';
import type {
  ChannelKind,
  NotificationChannel,
  NotificationDelivery,
  NotificationSubscription,
  PlatformSetting,
} from '../features/settings/types';
import {
  CHANNEL_LABELS,
  EVENT_LABELS,
  SECRET_HINTS,
  STATUS_TONE,
} from '../features/settings/types';
import type { Role, SSORoleMap, SSORoleMapping } from '../features/auth/types';
import { ROLE_LABELS } from '../features/auth/types';
import { PageHeader } from '../components/PageHeader';

const CHANNELS = '/notifications/channels';
const DELIVERIES = '/notifications/deliveries';
const SUBSCRIPTIONS = '/notifications/subscriptions';
const SETTINGS = '/settings';
const ROLE_MAP = '/auth/sso/role-map';

function describe(error: unknown): string {
  return error instanceof ApiError
    ? error.problem.detail
    : 'Unable to reach the server. Check your connection and try again.';
}

function ChannelHealth({ channel }: { channel: NotificationChannel }) {
  if (channel.last_error) {
    return (
      <span className="badge badge--error" title={channel.last_error}>
        failing
      </span>
    );
  }
  if (channel.last_success_at) {
    return <span className="badge badge--success">delivering</span>;
  }
  return <span className="badge">not used yet</span>;
}

/** Which events reach which channel (FR-INT-01).
 *
 * A channel with no subscription is wired up, healthy, tested — and silent. That is
 * the state this panel exists to make visible: until now the subscription endpoints
 * had no surface at all, so on a console-only deployment every channel was in it and
 * the page above said nothing about why nothing arrived.
 *
 * **The severity floor is a floor, not a filter.** `min_severity: medium` means
 * medium and worse, so a subscription to `finding.opened` at that level will not
 * carry an informational one. The form says so rather than leaving somebody to
 * discover it from an alert that never came.
 */
function SubscriptionsPanel({
  channels,
  onError,
}: {
  channels: NotificationChannel[];
  onError: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const [channelId, setChannelId] = useState('');
  const [kinds, setKinds] = useState<string[]>([]);
  const [floor, setFloor] = useState('medium');

  const subscriptions = useQuery({
    queryKey: [SUBSCRIPTIONS],
    queryFn: () => api.get<NotificationSubscription[]>(SUBSCRIPTIONS),
  });

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: [SUBSCRIPTIONS] });
  };

  const subscribe = useMutation({
    mutationFn: () =>
      api.post<NotificationSubscription>(SUBSCRIPTIONS, {
        channel_id: channelId,
        event_kinds: kinds,
        min_severity: floor,
      }),
    onSuccess: () => {
      setKinds([]);
      refresh();
    },
    onError: (err) => onError(describe(err)),
  });

  const unsubscribe = useMutation({
    mutationFn: (id: string) => api.delete<void>(`${SUBSCRIPTIONS}/${id}`),
    onSuccess: refresh,
    onError: (err) => onError(describe(err)),
  });

  const named = (id: string) => channels.find((c) => c.id === id)?.name ?? id;
  const rows = subscriptions.data ?? [];
  const subscribed = new Set(rows.map((row) => row.channel_id));
  const silent = channels.filter((channel) => channel.enabled && !subscribed.has(channel.id));

  return (
    <section className="card">
      <h2>What each channel is told</h2>
      <p className="card__hint">
        A channel with no subscription is configured and silent. Leave the event list empty to
        subscribe to everything — the severity floor still applies, so that is not the same as every
        message.
      </p>

      {/* The finding this panel makes visible. A healthy channel nobody subscribed
          anything to looks identical, in the table above, to one that is working. */}
      {silent.length > 0 && (
        <div className="alert alert--warning" role="status">
          {silent.length} enabled channel{silent.length === 1 ? '' : 's'} (
          {silent.map((c) => c.name).join(', ')}) {silent.length === 1 ? 'has' : 'have'} no
          subscription, so nothing is sent to {silent.length === 1 ? 'it' : 'them'}.
        </div>
      )}

      <table className="table">
        <caption className="visually-hidden">Event subscriptions by channel</caption>
        <thead>
          <tr>
            <th>Channel</th>
            <th>Events</th>
            <th>From severity</th>
            <th>State</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>{named(row.channel_id)}</td>
              <td>
                {row.event_kinds.length === 0 ? (
                  <em>every kind</em>
                ) : (
                  row.event_kinds.map((kind) => EVENT_LABELS[kind] ?? kind).join(', ')
                )}
              </td>
              <td>
                <span className={`pill pill--${row.min_severity}`}>{row.min_severity}</span> and
                worse
              </td>
              <td>{row.enabled ? 'active' : <span className="pill pill--unknown">paused</span>}</td>
              <td>
                <button
                  className="button button--ghost button--small"
                  onClick={() => unsubscribe.mutate(row.id)}
                  disabled={unsubscribe.isPending}
                >
                  Remove
                </button>
              </td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={5}>
                Nothing is subscribed, so no channel is told anything. Events are still recorded and
                still visible in the console.
              </td>
            </tr>
          )}
        </tbody>
      </table>

      <form
        className="form-row"
        onSubmit={(event) => {
          event.preventDefault();
          subscribe.mutate();
        }}
      >
        <label className="field">
          <span className="field__label">Channel</span>
          <select
            className="field__input"
            value={channelId}
            onChange={(e) => setChannelId(e.target.value)}
            required
          >
            <option value="">Choose a channel</option>
            {channels.map((channel) => (
              <option key={channel.id} value={channel.id}>
                {channel.name}
              </option>
            ))}
          </select>
        </label>

        <fieldset className="field">
          <legend className="field__label">Events</legend>
          <div className="checkbox-grid">
            {Object.entries(EVENT_LABELS).map(([value, label]) => (
              <label key={value} className="checkbox">
                <input
                  type="checkbox"
                  checked={kinds.includes(value)}
                  onChange={(e) =>
                    setKinds((current) =>
                      e.target.checked
                        ? [...current, value]
                        : current.filter((kind) => kind !== value),
                    )
                  }
                />
                {label}
              </label>
            ))}
          </div>
          <span className="field__help">
            {kinds.length === 0 ? 'None ticked — every kind of event.' : `${kinds.length} chosen.`}
          </span>
        </fieldset>

        <label className="field">
          <span className="field__label">From severity</span>
          <select className="field__input" value={floor} onChange={(e) => setFloor(e.target.value)}>
            {['critical', 'high', 'medium', 'low', 'info'].map((value) => (
              <option key={value} value={value}>
                {value} and worse
              </option>
            ))}
          </select>
        </label>

        <button
          className="button button--primary"
          type="submit"
          disabled={subscribe.isPending || !channelId}
        >
          Subscribe
        </button>
      </form>
    </section>
  );
}

function SSORoleMapPanel({ onError }: { onError: (message: string | null) => void }) {
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<SSORoleMapping[] | null>(null);
  const [saved, setSaved] = useState(false);

  const map = useQuery({
    queryKey: [ROLE_MAP],
    queryFn: () => api.get<SSORoleMap>(ROLE_MAP),
  });

  const rows = draft ?? map.data?.mappings ?? [];
  const roles = map.data?.mappable_roles ?? [];
  const defaultRole: Role | undefined = roles[0];

  const save = useMutation({
    mutationFn: () => api.put<SSORoleMap>(ROLE_MAP, { mappings: rows }),
    onSuccess: () => {
      setDraft(null);
      setSaved(true);
      onError(null);
      void queryClient.invalidateQueries({ queryKey: [ROLE_MAP] });
    },
    onError: (err) => {
      setSaved(false);
      onError(describe(err));
    },
  });

  function edit(next: SSORoleMapping[]) {
    setDraft(next);
    setSaved(false);
  }

  if (map.isError) {
    // Reading this is reading the authorization policy, so it is Super Admin only.
    // Saying nothing would look like a mapping that is empty.
    return null;
  }

  return (
    <section className="card">
      <h2>Single sign-on roles</h2>
      <p className="card__hint">
        Which identity-provider group carries which NetSecOps role. Applied at every sign-in:
        joining a group grants the role, leaving it takes the role away. Roles that appear in no
        mapping are left alone, so a grant made by hand here is not undone by somebody signing in.
      </p>
      <p className="card__hint">
        Signing in never <em>creates</em> an account — an unknown user is refused — and Super Admin
        cannot be mapped, because it is the role that can rewrite this page.
      </p>

      {saved && (
        <div className="alert alert--ok" role="status">
          Saved. It takes effect at each user&rsquo;s next sign-in.
        </div>
      )}

      <table className="table">
        <thead>
          <tr>
            <th>Identity-provider group</th>
            <th>NetSecOps role</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>
              <td>
                <input
                  className="field__input field__input--small"
                  value={row.group}
                  aria-label={`Group ${index + 1}`}
                  placeholder="net-admins"
                  onChange={(event) =>
                    edit(
                      rows.map((r, i) => (i === index ? { ...r, group: event.target.value } : r)),
                    )
                  }
                />
              </td>
              <td>
                <select
                  className="field__input field__input--small"
                  value={row.role}
                  aria-label={`Role ${index + 1}`}
                  onChange={(event) =>
                    edit(
                      rows.map((r, i) =>
                        i === index ? { ...r, role: event.target.value as Role } : r,
                      ),
                    )
                  }
                >
                  {roles.map((role) => (
                    <option key={role} value={role}>
                      {ROLE_LABELS[role]}
                    </option>
                  ))}
                </select>
              </td>
              <td>
                <button
                  className="button button--ghost"
                  type="button"
                  onClick={() => edit(rows.filter((_, i) => i !== index))}
                >
                  Remove
                </button>
              </td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={3}>
                No groups are mapped, so signing in changes nobody&rsquo;s roles — each account
                keeps whatever an administrator granted it.
              </td>
            </tr>
          )}
        </tbody>
      </table>

      <div className="toolbar">
        <button
          className="button button--ghost"
          type="button"
          // Disabled until the server has said which roles may be mapped, rather than
          // defaulting to one the save would then refuse.
          disabled={defaultRole === undefined}
          onClick={() => defaultRole && edit([...rows, { group: '', role: defaultRole }])}
        >
          Add mapping
        </button>
        <button
          className="button button--primary"
          type="button"
          disabled={draft === null || save.isPending}
          onClick={() => save.mutate()}
        >
          {save.isPending ? 'Saving…' : 'Save mapping'}
        </button>
        {draft !== null && (
          <button
            className="button button--ghost"
            type="button"
            onClick={() => {
              setDraft(null);
              onError(null);
            }}
          >
            Discard changes
          </button>
        )}
      </div>
    </section>
  );
}

export function SettingsPage() {
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [kind, setKind] = useState<ChannelKind>('slack');
  const [secret, setSecret] = useState('');

  const channels = useQuery({
    queryKey: [CHANNELS],
    queryFn: () => api.get<NotificationChannel[]>(CHANNELS),
  });
  const deliveries = useQuery({
    queryKey: [DELIVERIES],
    queryFn: () => api.get<NotificationDelivery[]>(`${DELIVERIES}?limit=50`),
  });
  const settings = useQuery({
    queryKey: [SETTINGS],
    queryFn: () => api.get<PlatformSetting[]>(SETTINGS),
  });

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: [CHANNELS] });
    void queryClient.invalidateQueries({ queryKey: [DELIVERIES] });
  };

  const createChannel = useMutation({
    mutationFn: () =>
      api.post<NotificationChannel>(CHANNELS, {
        name,
        channel_type: kind,
        // The key the backend expects differs by transport: an e-mail channel seals a
        // password, a webhook a signing key, Slack and Teams the URL itself.
        secret:
          kind === 'email'
            ? { password: secret }
            : kind === 'webhook'
              ? { secret }
              : { url: secret },
      }),
    onSuccess: () => {
      setName('');
      setSecret('');
      setError(null);
      refresh();
    },
    onError: (err) => setError(describe(err)),
  });

  const sendTest = useMutation({
    mutationFn: (id: string) => api.post(`${CHANNELS}/${id}/test`),
    onSuccess: refresh,
    onError: (err) => setError(describe(err)),
  });

  const setChannel = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: Record<string, unknown> }) =>
      api.patch<NotificationChannel>(`${CHANNELS}/${id}`, patch),
    onSuccess: refresh,
    onError: (err) => setError(describe(err)),
  });

  const removeChannel = useMutation({
    mutationFn: (id: string) => api.delete<void>(`${CHANNELS}/${id}`),
    onSuccess: refresh,
    onError: (err) => setError(describe(err)),
  });

  const requeue = useMutation({
    mutationFn: (id: string) => api.post(`${DELIVERIES}/${id}/requeue`),
    onSuccess: refresh,
    onError: (err) => setError(describe(err)),
  });

  const dead = (deliveries.data ?? []).filter((d) => d.status === 'dead');

  return (
    <div className="page">
      <PageHeader
        icon="settings"
        title="Settings"
        subtitle="Where notifications go, and the platform values that are neither environment configuration nor per-device state."
      />

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      {dead.length > 0 && (
        <div className="alert alert--warning" role="status">
          {dead.length} notification{dead.length === 1 ? '' : 's'} gave up after repeated failures
          and never arrived. They are listed below and can be tried again.
        </div>
      )}

      <section className="card">
        <h2>Notification channels</h2>
        <p className="card__hint">
          A channel&rsquo;s secret is sealed in the credential vault and is never shown again — the
          API has no field for it. Replace it by saving a new one.
        </p>

        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Secret</th>
              <th>State</th>
              <th>Health</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(channels.data ?? []).map((channel) => (
              <tr key={channel.id}>
                <td>{channel.name}</td>
                <td>{CHANNEL_LABELS[channel.channel_type]}</td>
                <td>{channel.has_secret ? 'stored' : <em>none</em>}</td>
                {/* A disabled channel is not a broken one, and the health column
                    cannot say so — it reports the last delivery, which for something
                    switched off yesterday still reads as a success. */}
                <td>
                  {channel.enabled ? (
                    'enabled'
                  ) : (
                    <span className="pill pill--unknown">disabled</span>
                  )}
                </td>
                <td>
                  <ChannelHealth channel={channel} />
                </td>
                <td className="table__actions">
                  <button
                    className="button button--ghost button--small"
                    onClick={() => sendTest.mutate(channel.id)}
                    disabled={sendTest.isPending}
                  >
                    Send test
                  </button>
                  {/* Disabling is the reversible half of removing, and it is what
                      somebody silencing a noisy channel for an afternoon actually
                      wants. Offering only delete makes that a destructive act. */}
                  <button
                    className="button button--ghost button--small"
                    onClick={() =>
                      setChannel.mutate({ id: channel.id, patch: { enabled: !channel.enabled } })
                    }
                    disabled={setChannel.isPending}
                  >
                    {channel.enabled ? 'Disable' : 'Enable'}
                  </button>
                  <button
                    className="button button--ghost button--small"
                    onClick={() => removeChannel.mutate(channel.id)}
                    disabled={removeChannel.isPending}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
            {channels.data?.length === 0 && (
              <tr>
                <td colSpan={6}>
                  No channels yet, so nothing is notified. Findings and jobs are still recorded —
                  they are just not pushed anywhere.
                </td>
              </tr>
            )}
          </tbody>
        </table>

        <form
          className="form-row"
          onSubmit={(event) => {
            event.preventDefault();
            createChannel.mutate();
          }}
        >
          <label className="field">
            <span className="field__label">Name</span>
            <input
              className="field__input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </label>

          <label className="field">
            <span className="field__label">Type</span>
            <select
              className="field__input"
              value={kind}
              onChange={(e) => setKind(e.target.value as ChannelKind)}
            >
              {Object.entries(CHANNEL_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            <span className="field__label">Secret</span>
            <input
              className="field__input"
              type="password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              autoComplete="new-password"
              required
            />
            <span className="field__hint">{SECRET_HINTS[kind]}</span>
          </label>

          <button
            className="button button--primary"
            type="submit"
            disabled={createChannel.isPending || !name || !secret}
          >
            Add channel
          </button>
        </form>
      </section>

      <SubscriptionsPanel channels={channels.data ?? []} onError={setError} />

      <SSORoleMapPanel onError={setError} />

      <section className="card">
        <h2>Recent deliveries</h2>
        <p className="card__hint">
          Successes as well as failures: &ldquo;was anybody told?&rdquo; is asked after an incident,
          and a list of failures alone cannot answer it.
        </p>

        <table className="table">
          <thead>
            <tr>
              <th>Event</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Attempts</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(deliveries.data ?? []).map((delivery) => (
              <tr key={delivery.id}>
                <td title={delivery.last_error ?? undefined}>{delivery.title}</td>
                <td>{delivery.severity}</td>
                <td>
                  <span className={`badge badge--${STATUS_TONE[delivery.status]}`}>
                    {delivery.status}
                  </span>
                </td>
                <td>{delivery.attempts}</td>
                <td>
                  {delivery.status === 'dead' && (
                    <button
                      className="button button--ghost button--small"
                      onClick={() => requeue.mutate(delivery.id)}
                      disabled={requeue.isPending}
                    >
                      Try again
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {deliveries.data?.length === 0 && (
              <tr>
                <td colSpan={6}>Nothing has been sent yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h2>Platform settings</h2>
        <p className="card__hint">
          Values marked <em>managed</em> are maintained by NetSecOps and cannot be edited: they
          record how far forwarding has reached, and changing one by hand would silently skip or
          repeat part of the stream.
        </p>

        <table className="table">
          <thead>
            <tr>
              <th>Key</th>
              <th>Value</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {(settings.data ?? []).map((setting) => (
              <tr key={setting.key}>
                <td className="mono">
                  {/* The key is its own element rather than a bare text node beside the
                      badge, so it stays one selectable string for anything reading the
                      table — a test, a screen reader, or a copy-paste. */}
                  <span>{setting.key}</span>
                  {setting.managed && <span className="badge">managed</span>}
                </td>
                <td className="mono">{JSON.stringify(setting.value)}</td>
                <td>{setting.description}</td>
              </tr>
            ))}
            {settings.data?.length === 0 && (
              <tr>
                <td colSpan={3}>No settings stored; the built-in defaults apply.</td>
              </tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
