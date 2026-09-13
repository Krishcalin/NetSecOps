/** Phase 0 dashboard.
 *
 * FR-RPT-01's real widgets need devices, findings and vulnerabilities, none of which
 * exist yet. Until then this shows what Phase 0 can honestly report: who you are, what
 * you may do, and whether the platform itself is healthy.
 */

import { useQuery } from '@tanstack/react-query';

import { api } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import { ROLE_LABELS } from '../features/auth/types';

interface Health {
  status: string;
  version: string;
  environment: string;
}

export function DashboardPage() {
  const { user } = useAuth();

  const health = useQuery({
    queryKey: ['health'],
    queryFn: () => fetch('/healthz').then((r) => r.json() as Promise<Health>),
    refetchInterval: 60_000,
  });

  const chain = useQuery({
    queryKey: ['audit-chain'],
    queryFn: () => api.get<{ total: number; valid: boolean }>('/audit-log/verify'),
    enabled: user?.permissions.includes('audit:read') ?? false,
  });

  return (
    <div className="page">
      <header className="page__header">
        <h1>Dashboard</h1>
        <p className="page__subtitle">
          Signed in as {user?.username} &middot;{' '}
          {user?.roles.map((r) => ROLE_LABELS[r]).join(', ') || 'no role assigned'}
        </p>
      </header>

      <div className="card-grid">
        <section className="card">
          <h2 className="card__title">Platform</h2>
          <dl className="kv">
            <dt>Status</dt>
            <dd>{health.isLoading ? '…' : (health.data?.status ?? 'unreachable')}</dd>
            <dt>Version</dt>
            <dd>{health.data?.version ?? '—'}</dd>
            <dt>Environment</dt>
            <dd>{health.data?.environment ?? '—'}</dd>
          </dl>
        </section>

        <section className="card">
          <h2 className="card__title">Your access</h2>
          <dl className="kv">
            <dt>MFA</dt>
            <dd>{user?.mfa_enabled ? 'Enabled' : 'Not enabled'}</dd>
            <dt>Scope</dt>
            <dd>
              {user?.unrestricted_scope
                ? 'All device groups'
                : `${user?.device_group_ids.length ?? 0} device group(s)`}
            </dd>
            <dt>Permissions</dt>
            <dd>{user?.permissions.length ?? 0}</dd>
          </dl>
        </section>

        {chain.data && (
          <section className="card">
            <h2 className="card__title">Audit chain</h2>
            <dl className="kv">
              <dt>Records</dt>
              <dd>{chain.data.total.toLocaleString()}</dd>
              <dt>Integrity</dt>
              <dd className={chain.data.valid ? 'status--ok' : 'status--bad'}>
                {chain.data.valid ? 'Verified' : 'BROKEN'}
              </dd>
            </dl>
          </section>
        )}
      </div>

      <section className="card card--muted">
        <h2 className="card__title">What is not here yet</h2>
        <p>
          Phase 0 delivers the platform foundation: authentication, roles, the credential vault and
          the tamper-evident audit log. Device inventory and collection arrive in Phase 1, the check
          engine in Phase 3, and vulnerability matching in Phase 6.
        </p>
      </section>
    </div>
  );
}
