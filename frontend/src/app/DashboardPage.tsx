/** The front door (FR-RPT-01).
 *
 * This replaced a Phase-0 placeholder that rendered a card headed "What is not here
 * yet" long after the things it named had shipped. The landing page of a working
 * product told every visitor it was unfinished.
 *
 * Two rules hold the design together:
 *
 * **Every tile is a link to the list it counts, already filtered.** A number you cannot
 * click is a number you have to go and re-derive by hand, and the filter it dropped you
 * into has to be the same filter that produced it — which is why the target pages keep
 * their filters in the URL. A tile whose destination cannot reproduce its own count is
 * worse than no tile.
 *
 * **An empty estate gets instructions, not zeroes.** Six tiles reading nought tell a
 * new operator nothing about what to do next, and read as a broken install rather than
 * an empty one. Below, the same page becomes an ordered checklist whose steps tick
 * themselves off from real counts — never from a guess about what the user has done.
 */

import { useQuery } from '@tanstack/react-query';
import { NavLink } from 'react-router-dom';

import { api } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import { ROLE_LABELS } from '../features/auth/types';
import type { VulnerabilitySummary } from '../features/vulnerabilities/types';

interface Health {
  status: string;
  version: string;
  environment: string;
}

/** Only `meta.total` is wanted, so every count asks for a single row. */
interface CountOnly {
  meta: { total: number };
}

const countOf = (path: string) => () => api.get<CountOnly>(path).then((r) => r.meta.total);

interface TileProps {
  label: string;
  value: number | undefined;
  to: string;
  hint: string;
  tone?: 'plain' | 'alert' | 'warn';
}

function Tile({ label, value, to, hint, tone = 'plain' }: TileProps) {
  // A tile with nothing in it is still a link, and still says so — "0 critical
  // findings" is a real answer and a reassuring one. Only an unloaded tile is blank.
  const shown = value === undefined ? '—' : value.toLocaleString();
  return (
    <NavLink className={`tile tile--${tone}`} to={to}>
      <span className="tile__value">{shown}</span>
      <span className="tile__label">{label}</span>
      <span className="tile__hint">{hint}</span>
    </NavLink>
  );
}

interface StepProps {
  n: number;
  done: boolean | undefined;
  title: string;
  body: string;
  to: string;
  cta: string;
}

function Step({ n, done, title, body, to, cta }: StepProps) {
  return (
    <li className={done ? 'step step--done' : 'step'}>
      <span className="step__n" aria-hidden="true">
        {n}
      </span>
      <div className="step__body">
        <h3 className="step__title">
          {title}
          {/* The word, not only the tick — a state carried by a glyph alone is a state
              a screen reader does not report. */}
          {done ? <span className="step__state"> · done</span> : null}
        </h3>
        <p className="step__text">{body}</p>
        <NavLink className="button button--ghost button--small" to={to}>
          {cta}
        </NavLink>
      </div>
    </li>
  );
}

export function DashboardPage() {
  const { user } = useAuth();
  const may = (permission: string) => user?.permissions.includes(permission) ?? false;

  const health = useQuery({
    queryKey: ['health'],
    queryFn: () => fetch('/healthz').then((r) => r.json() as Promise<Health>),
    refetchInterval: 60_000,
  });

  const chain = useQuery({
    queryKey: ['audit-chain'],
    queryFn: () => api.get<{ total: number; valid: boolean }>('/audit-log/verify'),
    enabled: may('audit:read'),
  });

  const devices = useQuery({
    queryKey: ['count', 'devices'],
    queryFn: countOf('/devices?limit=1'),
    enabled: may('device:read'),
  });

  const credentials = useQuery({
    queryKey: ['count', 'credentials'],
    queryFn: countOf('/credentials?limit=1'),
    enabled: may('credential:read'),
  });

  const jobs = useQuery({
    queryKey: ['count', 'jobs'],
    queryFn: countOf('/jobs?limit=1'),
    enabled: may('job:read'),
  });

  const critical = useQuery({
    queryKey: ['count', 'findings', 'critical'],
    queryFn: countOf('/findings?severity=critical&limit=1'),
    enabled: may('finding:read'),
  });

  const high = useQuery({
    queryKey: ['count', 'findings', 'high'],
    queryFn: countOf('/findings?severity=high&limit=1'),
    enabled: may('finding:read'),
  });

  const findings = useQuery({
    queryKey: ['count', 'findings', 'all'],
    queryFn: countOf('/findings?limit=1'),
    enabled: may('finding:read'),
  });

  // One request covers the KEV count, the confidence split and the unassessed-device
  // count, so the vulnerability tiles cost a single round trip between them.
  const vulns = useQuery({
    queryKey: ['vuln-summary'],
    queryFn: () => api.get<VulnerabilitySummary>('/vulnerabilities/summary'),
    enabled: may('vuln:read'),
  });

  const subtitle = `Signed in as ${user?.username ?? '—'} · ${
    user?.roles.map((r) => ROLE_LABELS[r]).join(', ') || 'no role assigned'
  }`;

  // Only an operator who can see the inventory can be told the estate is empty. For
  // anyone else an empty device list means "none visible to you", which is a different
  // sentence and not a reason to show a setup checklist.
  const estateEmpty = may('device:read') && devices.isSuccess && devices.data === 0;

  return (
    <div className="page">
      <header className="page__header">
        <h1>Dashboard</h1>
        <p className="page__subtitle">{subtitle}</p>
      </header>

      {estateEmpty ? (
        <section className="card">
          <h2 className="card__title">Start here</h2>
          <p>
            Nothing has been collected yet. These four steps take a device from unknown to assessed,
            and each one ticks itself off when it is genuinely done.
          </p>
          <ol className="steps">
            <Step
              n={1}
              done={credentials.data !== undefined && credentials.data > 0}
              title="Add a credential"
              body="A read-only account on the device. Nothing is ever written back, so it needs no more than that."
              to="/credentials"
              cta="Go to Credentials"
            />
            <Step
              n={2}
              done={devices.data !== undefined && devices.data > 0}
              title="Add a device"
              body="One address and a platform. Import a CSV, or let discovery find candidates for you to approve."
              to="/inventory"
              cta="Go to Inventory"
            />
            <Step
              n={3}
              done={jobs.data !== undefined && jobs.data > 0}
              title="Run an assessment"
              body="Collects the configuration, parses it, and runs the check library against what came back."
              to="/jobs"
              cta="Go to Assessments"
            />
            <Step
              n={4}
              done={findings.data !== undefined && findings.data > 0}
              title="Read the findings"
              body="Worst first, each one carrying the configuration line it came from."
              to="/findings"
              cta="Go to Findings"
            />
          </ol>
        </section>
      ) : (
        <div className="tiles">
          {may('finding:read') && (
            <>
              <Tile
                label="Critical findings"
                value={critical.data}
                to="/findings?severity=critical"
                hint="Open, worst first"
                tone={critical.data ? 'alert' : 'plain'}
              />
              <Tile
                label="High findings"
                value={high.data}
                to="/findings?severity=high"
                hint="Open"
                tone={high.data ? 'warn' : 'plain'}
              />
            </>
          )}

          {may('vuln:read') && (
            <>
              <Tile
                label="Known exploited"
                value={vulns.data?.kev_count}
                to="/vulnerabilities?kev=true"
                hint="In the CISA KEV catalogue"
                tone={vulns.data?.kev_count ? 'alert' : 'plain'}
              />
              <Tile
                label="Confirmed matches"
                value={vulns.data?.by_confidence?.confirmed}
                to="/vulnerabilities?confidence=confirmed"
                hint="Version and conditions both matched"
                tone={vulns.data?.by_confidence?.confirmed ? 'warn' : 'plain'}
              />
              {/* Beside the counts rather than under them: an empty vulnerability
                  table and a fleet nobody assessed look identical from here. */}
              <Tile
                label="Never assessed"
                value={vulns.data?.devices_unassessed}
                to="/vulnerabilities"
                hint="Devices with no assessment on record"
                tone={vulns.data?.devices_unassessed ? 'warn' : 'plain'}
              />
            </>
          )}

          {may('device:read') && (
            <Tile label="Devices" value={devices.data} to="/inventory" hint="In inventory" />
          )}
        </div>
      )}

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

        {/* Kept on the front page deliberately. No competitor in this category can show
            it, and a tamper-evident log nobody ever looks at is only half a control. */}
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
    </div>
  );
}
