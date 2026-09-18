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
  PlatformSetting,
} from '../features/settings/types';
import { CHANNEL_LABELS, SECRET_HINTS, STATUS_TONE } from '../features/settings/types';

const CHANNELS = '/notifications/channels';
const DELIVERIES = '/notifications/deliveries';
const SETTINGS = '/settings';

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

  const requeue = useMutation({
    mutationFn: (id: string) => api.post(`${DELIVERIES}/${id}/requeue`),
    onSuccess: refresh,
    onError: (err) => setError(describe(err)),
  });

  const dead = (deliveries.data ?? []).filter((d) => d.status === 'dead');

  return (
    <div className="page">
      <header className="page__header">
        <h1>Settings</h1>
        <p className="page__subtitle">
          Where notifications go, and the platform values that are neither environment configuration
          nor per-device state.
        </p>
      </header>

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
                <td>
                  <ChannelHealth channel={channel} />
                </td>
                <td>
                  <button
                    className="button button--ghost button--small"
                    onClick={() => sendTest.mutate(channel.id)}
                    disabled={sendTest.isPending}
                  >
                    Send test
                  </button>
                </td>
              </tr>
            ))}
            {channels.data?.length === 0 && (
              <tr>
                <td colSpan={5}>
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
                <td colSpan={5}>Nothing has been sent yet.</td>
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
