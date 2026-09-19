/** The credential vault (FR-CRED-01 … FR-CRED-05).
 *
 * Every one of these endpoints shipped with Phase 1 and none had a surface, which made
 * this the one gap that stopped NetSecOps being pointed at a real estate at all: a
 * credential could not be stored without a REST client, and a device with no credential
 * fails its job with "no credential is assigned" before a single command is sent.
 *
 * Three things this page will not do:
 *
 * **It never shows secret material, because it is never sent any.** `CredentialRead`
 * carries a `metadata` object that is the *public* half by construction — usernames,
 * SNMPv3 protocol names, key comments — and the API has no field that could carry the
 * other half. So there is nowhere on this page a secret could be rendered even by
 * mistake, and the secret inputs below are write-only: they are cleared on success and
 * never repopulated from a response.
 *
 * **It does not validate the type-specific fields itself.** The field table below
 * mirrors the service's, but the service is authoritative: it rejects unknown field
 * names so a secret cannot land in searchable metadata, and a second copy of that rule
 * in a browser would eventually disagree with it. This shows the right boxes; the API
 * decides whether they are right.
 *
 * **It does not test on save.** Testing opens a session against a real device, so it is
 * a deliberate action against a device you choose — see `CredentialTest`.
 */

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { api } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import type {
  Credential,
  CredentialTestResult,
  Device,
  DeviceGroup,
  Paginated,
} from '../features/inventory/types';

/** One field on the create form. `secret: true` means the service seals it. */
interface Field {
  name: string;
  label: string;
  secret?: boolean;
  required?: boolean;
}

/** Mirrors `SECRET_FIELDS` / `PUBLIC_FIELDS` / `REQUIRED_FIELDS` in the credential
 *  service. The service is authoritative — this exists to show the right boxes, not to
 *  decide what is valid. */
const TYPES: { value: string; label: string; fields: Field[] }[] = [
  {
    value: 'ssh_password',
    label: 'SSH password',
    fields: [
      { name: 'username', label: 'Username', required: true },
      { name: 'password', label: 'Password', secret: true, required: true },
    ],
  },
  {
    value: 'ssh_key',
    label: 'SSH key',
    fields: [
      { name: 'username', label: 'Username', required: true },
      { name: 'private_key', label: 'Private key', secret: true, required: true },
      { name: 'passphrase', label: 'Passphrase', secret: true },
      { name: 'key_comment', label: 'Key comment' },
    ],
  },
  {
    value: 'enable_secret',
    label: 'Enable secret',
    fields: [{ name: 'secret', label: 'Secret', secret: true, required: true }],
  },
  {
    value: 'api_key',
    label: 'API key',
    fields: [
      { name: 'api_key', label: 'API key', secret: true, required: true },
      { name: 'header_name', label: 'Header name' },
    ],
  },
  {
    value: 'api_username_password',
    label: 'API username and password',
    fields: [
      { name: 'username', label: 'Username', required: true },
      { name: 'password', label: 'Password', secret: true, required: true },
    ],
  },
  {
    value: 'snmp_v2c',
    label: 'SNMP v2c community',
    fields: [{ name: 'community', label: 'Community', secret: true, required: true }],
  },
  {
    value: 'snmp_v3',
    label: 'SNMP v3',
    fields: [
      { name: 'username', label: 'Username', required: true },
      { name: 'security_level', label: 'Security level', required: true },
      { name: 'auth_protocol', label: 'Auth protocol' },
      { name: 'priv_protocol', label: 'Privacy protocol' },
      { name: 'auth_key', label: 'Auth key', secret: true },
      { name: 'priv_key', label: 'Privacy key', secret: true },
    ],
  },
  {
    value: 'checkpoint_api',
    label: 'Check Point API',
    fields: [
      { name: 'username', label: 'Username', required: true },
      { name: 'password', label: 'Password', secret: true, required: true },
      { name: 'domain', label: 'Domain' },
    ],
  },
  {
    value: 'jump_host',
    label: 'Jump host',
    fields: [
      { name: 'username', label: 'Username', required: true },
      { name: 'host', label: 'Host', required: true },
      { name: 'port', label: 'Port' },
      { name: 'password', label: 'Password', secret: true },
      { name: 'private_key', label: 'Private key', secret: true },
      { name: 'passphrase', label: 'Passphrase', secret: true },
    ],
  },
];

const TYPE_LABELS: Record<string, string> = Object.fromEntries(
  TYPES.map((t) => [t.value, t.label]),
);

interface Assignment {
  id: string;
  credential_id: string;
  device_id: string | null;
  group_id: string | null;
  priority: number;
}

function message(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

// ─────────────────────────────── create ──────────────────────────────────────

function CreateCredential({ onCreated }: { onCreated: () => void }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [type, setType] = useState(TYPES[0]!.value);
  const [values, setValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  const definition = TYPES.find((t) => t.value === type)!;

  const create = useMutation({
    mutationFn: () =>
      api.post<Credential>('/credentials', {
        name,
        credential_type: type,
        description: description.trim() || null,
        // Blank optional fields are dropped rather than sent empty: the service stores
        // what it is given, and an empty passphrase is not the same as no passphrase.
        secret_data: Object.fromEntries(
          Object.entries(values).filter(([, value]) => value.trim() !== ''),
        ),
      }),
    onSuccess: () => {
      setError(null);
      setName('');
      setDescription('');
      // Cleared rather than kept for convenience. Holding a password in component state
      // after it has been sealed serves nobody and outlives the reason it existed.
      setValues({});
      onCreated();
    },
    onError: (err) => setError(message(err, 'The credential could not be stored.')),
  });

  const set = (field: string, value: string) => setValues({ ...values, [field]: value });

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">Store a credential</h2>
      </div>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      <div className="form-grid">
        <label className="field">
          <span className="field__label">Name</span>
          <input
            className="field__input"
            value={name}
            aria-label="Name"
            onChange={(event) => setName(event.target.value)}
          />
        </label>
        <label className="field">
          <span className="field__label">Type</span>
          <select
            className="field__input"
            value={type}
            aria-label="Type"
            onChange={(event) => {
              setType(event.target.value);
              // Fields differ per type, so carrying values across would submit a
              // password under whatever the next type happens to call its first field.
              setValues({});
            }}
          >
            {TYPES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span className="field__label">Description</span>
          <input
            className="field__input"
            value={description}
            aria-label="Description"
            onChange={(event) => setDescription(event.target.value)}
          />
        </label>
      </div>

      <div className="form-grid">
        {definition.fields.map((field) => (
          <label className="field" key={field.name}>
            <span className="field__label">
              {field.label}
              {field.required ? ' *' : ''}
            </span>
            <input
              className="field__input"
              type={field.secret ? 'password' : 'text'}
              value={values[field.name] ?? ''}
              aria-label={field.label}
              autoComplete="off"
              onChange={(event) => set(field.name, event.target.value)}
            />
            {field.secret && (
              <span className="field__help">Sealed on save; never shown again.</span>
            )}
          </label>
        ))}
      </div>

      <div className="toolbar">
        <button
          className="button button--small"
          disabled={!name.trim() || create.isPending}
          onClick={() => create.mutate()}
        >
          Store credential
        </button>
      </div>
    </section>
  );
}

// ─────────────────────────────── test ────────────────────────────────────────

/** FR-CRED-05 — a login and one trivial read, against a device you name.
 *
 * Offered because the alternative is finding out during a collection: a wrong password
 * tried across an estate is a burst of failed logins against every device at once, which
 * on TACACS- or RADIUS-backed gear is how an account gets locked.
 */
function CredentialTest({ credential, devices }: { credential: Credential; devices: Device[] }) {
  const [deviceId, setDeviceId] = useState('');
  const [result, setResult] = useState<CredentialTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const test = useMutation({
    mutationFn: () =>
      api.post<CredentialTestResult>(`/credentials/${credential.id}/test`, {
        device_id: deviceId,
      }),
    onSuccess: (outcome) => {
      setError(null);
      setResult(outcome);
    },
    onError: (err) => {
      setResult(null);
      setError(message(err, 'The test could not be run.'));
    },
  });

  return (
    <div className="stack">
      <h3 className="finding__heading">Test against a device</h3>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      <div className="toolbar">
        <select
          className="field__input field__input--small"
          value={deviceId}
          aria-label="Device to test against"
          onChange={(event) => setDeviceId(event.target.value)}
        >
          <option value="">Choose a device…</option>
          {devices.map((device) => (
            <option key={device.id} value={device.id}>
              {device.hostname ?? device.mgmt_ip}
            </option>
          ))}
        </select>
        <button
          className="button button--ghost button--small"
          disabled={!deviceId || test.isPending}
          onClick={() => test.mutate()}
        >
          Test
        </button>
      </div>

      {result && (
        <div className="alert" role="status">
          <strong>{result.succeeded ? 'The credential worked.' : 'The credential failed.'}</strong>
          {result.detail ? ` ${result.detail}` : ''}
          {/* Shown so nobody has to take on trust that a "test" is read-only. */}
          {result.command && <div className="mono">Command issued: {result.command}</div>}
          {result.host_key_fingerprint && (
            <div className="mono">Host key: {result.host_key_fingerprint}</div>
          )}
        </div>
      )}
    </div>
  );
}

// ──────────────────────────── assignments ────────────────────────────────────

/** FR-CRED-04 — which devices this credential reaches.
 *
 * Device bindings are listed before inherited group ones because that is the order the
 * resolver tries them, so the list reads as the fallback order it governs.
 */
function Assignments({
  credential,
  devices,
  groups,
  canWrite,
}: {
  credential: Credential;
  devices: Device[];
  groups: DeviceGroup[];
  canWrite: boolean;
}) {
  const queryClient = useQueryClient();
  const [target, setTarget] = useState('');
  const [priority, setPriority] = useState('100');
  const [error, setError] = useState<string | null>(null);

  const key = ['credential-assignments', credential.id];

  const assignments = useQuery({
    queryKey: key,
    queryFn: () => api.get<Assignment[]>(`/credentials/${credential.id}/assignments`),
  });

  const refresh = () => {
    setError(null);
    void queryClient.invalidateQueries({ queryKey: key });
  };

  const assign = useMutation({
    mutationFn: () => {
      const [kind, id] = target.split(':');
      return api.post<Assignment>(`/credentials/${credential.id}/assignments`, {
        device_id: kind === 'device' ? id : null,
        group_id: kind === 'group' ? id : null,
        priority: Number(priority) || 100,
      });
    },
    onSuccess: () => {
      setTarget('');
      refresh();
    },
    onError: (err) => setError(message(err, 'The assignment failed.')),
  });

  const unassign = useMutation({
    mutationFn: (id: string) => api.delete<void>(`/credentials/assignments/${id}`),
    onSuccess: refresh,
    onError: (err) => setError(message(err, 'The assignment could not be removed.')),
  });

  const deviceName = (id: string) => {
    const device = devices.find((d) => d.id === id);
    return device ? (device.hostname ?? device.mgmt_ip) : id.slice(0, 8);
  };
  const groupName = (id: string) => groups.find((g) => g.id === id)?.name ?? id.slice(0, 8);

  const rows = assignments.data ?? [];

  return (
    <div className="stack">
      <h3 className="finding__heading">Assigned to</h3>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      {rows.length === 0 ? (
        <p className="empty">
          Not assigned to anything, so no job will ever use it. A device with no credential fails
          with "no credential is assigned" before any command is sent.
        </p>
      ) : (
        <ul className="device-list">
          {rows.map((row) => (
            <li key={row.id}>
              <span className="mono">
                {row.device_id ? deviceName(row.device_id) : `${groupName(row.group_id!)} (group)`}
              </span>
              <span className="muted"> priority {row.priority}</span>
              {canWrite && (
                <button
                  className="button button--ghost button--small"
                  disabled={unassign.isPending}
                  onClick={() => unassign.mutate(row.id)}
                >
                  Remove
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      {canWrite && (
        <div className="toolbar">
          <select
            className="field__input field__input--small"
            value={target}
            aria-label="Assign to"
            onChange={(event) => setTarget(event.target.value)}
          >
            <option value="">Assign to…</option>
            {devices.map((device) => (
              <option key={device.id} value={`device:${device.id}`}>
                {device.hostname ?? device.mgmt_ip}
              </option>
            ))}
            {groups.map((group) => (
              <option key={group.id} value={`group:${group.id}`}>
                {group.name} (group)
              </option>
            ))}
          </select>
          <input
            className="field__input field__input--small"
            value={priority}
            aria-label="Priority"
            onChange={(event) => setPriority(event.target.value)}
          />
          <button
            className="button button--ghost button--small"
            disabled={!target || assign.isPending}
            onClick={() => assign.mutate()}
          >
            Assign
          </button>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────── page ────────────────────────────────────────

export function CredentialsPage() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canWrite = can('credential:write');

  const credentials = useQuery({
    queryKey: ['credentials'],
    queryFn: () => api.get<Paginated<Credential>>('/credentials?limit=200'),
  });

  const devices = useQuery({
    queryKey: ['credential-devices'],
    queryFn: () => api.get<Paginated<Device>>('/devices?limit=200'),
  });

  const groups = useQuery({
    queryKey: ['credential-groups'],
    queryFn: () => api.get<DeviceGroup[]>('/device-groups'),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.delete<void>(`/credentials/${id}`),
    onSuccess: () => {
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ['credentials'] });
    },
    onError: (err) => setError(message(err, 'The credential could not be deleted.')),
  });

  const rows = credentials.data?.data ?? [];
  const deviceRows = devices.data?.data ?? [];
  const groupRows = groups.data ?? [];

  return (
    <div className="page">
      <header className="page__header">
        <h1>Credentials</h1>
        <p className="page__subtitle">
          Secrets are sealed in the vault and never returned — this page can store one and say where
          it is used, and cannot show you one.
        </p>
      </header>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      {canWrite && (
        <CreateCredential
          onCreated={() => void queryClient.invalidateQueries({ queryKey: ['credentials'] })}
        />
      )}

      {credentials.isLoading ? (
        <p className="page-loading">Loading…</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Identity</th>
                <th>Last used</th>
                <th>Last test</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((credential) => (
                <tr key={credential.id}>
                  <td>
                    {credential.name}
                    {credential.description && (
                      <div className="muted">{credential.description}</div>
                    )}
                  </td>
                  <td className="mono">
                    {TYPE_LABELS[credential.credential_type] ?? credential.credential_type}
                  </td>
                  {/* The public half only. There is no field here that could carry a secret. */}
                  <td className="mono">{String(credential.metadata.username ?? '—')}</td>
                  <td className="mono">
                    {credential.last_used_at
                      ? new Date(credential.last_used_at).toLocaleString()
                      : 'never'}
                  </td>
                  <td>
                    {credential.last_tested_at === null ? (
                      <span className="muted">never tested</span>
                    ) : (
                      <span
                        className={`pill pill--${credential.last_test_succeeded ? 'success' : 'failure'}`}
                      >
                        {credential.last_test_succeeded ? 'worked' : 'failed'}
                      </span>
                    )}
                  </td>
                  <td className="table__actions">
                    <button
                      className="button button--ghost button--small"
                      onClick={() => setExpanded(expanded === credential.id ? null : credential.id)}
                    >
                      {expanded === credential.id ? 'Hide' : 'Details'}
                    </button>
                    {canWrite && (
                      <button
                        className="button button--ghost button--small"
                        disabled={remove.isPending}
                        onClick={() => remove.mutate(credential.id)}
                      >
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="table__empty">
                    No credential has been stored. Until one is, every collection fails before it
                    sends a command.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {expanded && (
        <section className="card">
          <div className="card__header">
            <h2 className="card__title">{rows.find((c) => c.id === expanded)?.name}</h2>
          </div>
          <Assignments
            credential={rows.find((c) => c.id === expanded)!}
            devices={deviceRows}
            groups={groupRows}
            canWrite={canWrite}
          />
          {canWrite && (
            <CredentialTest
              credential={rows.find((c) => c.id === expanded)!}
              devices={deviceRows}
            />
          )}
        </section>
      )}
    </div>
  );
}
