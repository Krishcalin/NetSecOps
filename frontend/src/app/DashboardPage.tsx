/** The front door (FR-RPT-01).
 *
 * Two rules the first version was built on, and neither is negotiable when the page
 * gets a redesign:
 *
 * **Every tile is a link to the list it counts, already filtered.** A number you
 * cannot click is a number you go and re-derive by hand, and the filter it drops you
 * into has to be the filter that produced it. A tile whose destination cannot
 * reproduce its own count is worse than no tile.
 *
 * **An empty estate gets instructions, not zeroes.** Six tiles reading nought tell a
 * new operator nothing and read as a broken install rather than an empty one.
 *
 * Three more that the graphics brought with them:
 *
 * **The dial draws compliance, which is the only real score this product has.** It is
 * a percentage of what was actually *decided* — not-applicable and not-evaluated
 * checks are in neither half. Inventing a "posture score" out of a weighted blend of
 * finding counts would look more impressive and would be a number with no referent,
 * which on a page somebody screenshots for a board pack is the worst thing here.
 *
 * **Nothing is coloured without also being counted.** Every tone on this page sits
 * beside the figure it describes, so the page survives greyscale and colour-blindness
 * (WCAG 1.4.1) and a reader never estimates a value off an arc.
 *
 * **A figure that could not be computed shows a dash.** Zero is an answer — "no
 * critical findings" is a real and reassuring one — so it is reserved for when it is
 * true, and an unloaded or unevaluated figure never borrows it.
 */

import { useQuery } from '@tanstack/react-query';
import { NavLink } from 'react-router-dom';

import { api } from '../api/client';
import { Icon } from '../components/Icon';
import { Dial, Panel, Readout, StackBar, StatTile } from '../components/Graphics';
import { useAuth } from '../features/auth/useAuth';
import { ROLE_LABELS } from '../features/auth/types';
import type { TopologySummary } from '../features/topology/types';
import type { Matrix } from '../features/segmentation/types';
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

interface Compliance {
  framework: string;
  device_count: number;
  compliance_percent: number | null;
}

interface JobRow {
  id: string;
  kind: string;
  status: string;
  created_at: string;
  device_count?: number;
}

const countOf = (path: string) => () => api.get<CountOnly>(path).then((r) => r.meta.total);

const SEVERITY_TONES: Record<string, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  info: 'var(--sev-info)',
};

/** Compliance banding. Deliberately coarse — three steps, not a gradient — because a
 *  percentage of decided checks does not support finer judgement than that. */
function complianceTone(percent: number | null): string {
  if (percent === null) return 'var(--text-faint)';
  if (percent >= 90) return 'var(--sev-low)';
  if (percent >= 70) return 'var(--sev-medium)';
  return 'var(--sev-critical)';
}

function jobTone(status: string): string {
  if (status === 'succeeded' || status === 'completed') return 'var(--sev-low)';
  if (status === 'failed') return 'var(--sev-critical)';
  if (status === 'running' || status === 'queued') return 'var(--sev-info)';
  return 'var(--sev-none)';
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
        {done ? <Icon name="tick" size={16} /> : n}
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

  const jobCount = useQuery({
    queryKey: ['count', 'jobs'],
    queryFn: countOf('/jobs?limit=1'),
    enabled: may('job:read'),
  });

  const recentJobs = useQuery({
    queryKey: ['jobs', 'recent'],
    queryFn: () => api.get<{ items: JobRow[] }>('/jobs?limit=5').then((r) => r.items),
    enabled: may('job:read'),
    refetchInterval: 30_000,
  });

  // One request per severity, which is five for the whole distribution. The findings
  // API has no facet endpoint and inventing one for a dashboard would be the tail
  // wagging the dog; each of these is a `limit=1` count, not a page of rows.
  const severities = ['critical', 'high', 'medium', 'low', 'info'] as const;
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
  const medium = useQuery({
    queryKey: ['count', 'findings', 'medium'],
    queryFn: countOf('/findings?severity=medium&limit=1'),
    enabled: may('finding:read'),
  });
  const low = useQuery({
    queryKey: ['count', 'findings', 'low'],
    queryFn: countOf('/findings?severity=low&limit=1'),
    enabled: may('finding:read'),
  });
  const info = useQuery({
    queryKey: ['count', 'findings', 'info'],
    queryFn: countOf('/findings?severity=info&limit=1'),
    enabled: may('finding:read'),
  });
  const bySeverity: Record<string, number | undefined> = {
    critical: critical.data,
    high: high.data,
    medium: medium.data,
    low: low.data,
    info: info.data,
  };
  const findingsTotal = severities.reduce((sum, key) => sum + (bySeverity[key] ?? 0), 0);

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

  const compliance = useQuery({
    queryKey: ['compliance', 'cis'],
    queryFn: () => api.get<Compliance>('/compliance/cis'),
    enabled: may('report:read'),
    retry: false,
  });

  const topology = useQuery({
    queryKey: ['topology-summary'],
    queryFn: () => api.get<TopologySummary>('/topology/summary'),
    enabled: may('snapshot:read'),
  });

  const segmentation = useQuery({
    queryKey: ['segmentation-matrix'],
    queryFn: () => api.get<Matrix>('/segmentation/matrix'),
    enabled: may('policy:read') && may('snapshot:read'),
    retry: false,
  });

  const subtitle = `Signed in as ${user?.username ?? '—'} · ${
    user?.roles.map((r) => ROLE_LABELS[r]).join(', ') || 'no role assigned'
  }`;

  // Only an operator who can see the inventory can be told the estate is empty. For
  // anyone else an empty device list means "none visible to you", which is a different
  // sentence and not a reason to show a setup checklist.
  const estateEmpty = may('device:read') && devices.isSuccess && devices.data === 0;

  if (estateEmpty) {
    return (
      <div className="page">
        <header className="page__header">
          <h1>Dashboard</h1>
          <p className="page__subtitle">{subtitle}</p>
        </header>

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
              done={jobCount.data !== undefined && jobCount.data > 0}
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
      </div>
    );
  }

  return (
    <div className="page">
      <header className="page__header">
        <h1>Dashboard</h1>
        <p className="page__subtitle">{subtitle}</p>
      </header>

      {/* ── the hero: one honest score, and the shape of the findings ───────── */}
      <div className="hero">
        {may('report:read') && (
          <section className="hero__score">
            <Dial
              value={compliance.data?.compliance_percent ?? null}
              label="CIS"
              tone={complianceTone(compliance.data?.compliance_percent ?? null)}
              caption={
                compliance.data?.compliance_percent === null
                  ? 'No CIS check has been evaluated yet.'
                  : `${compliance.data?.compliance_percent ?? 0} per cent of decided CIS checks pass.`
              }
            />
            <div className="hero__score-text">
              <span className="hero__eyebrow">Compliance</span>
              <h2 className="hero__heading">CIS Benchmarks</h2>
              {/* The caveat travels with the number, not in a footnote. A percentage
                  that counted unevaluated checks as passes would make a device whose
                  collection half-failed score better than one fully assessed. */}
              <p className="hero__note">
                Of the checks that were actually decided across {compliance.data?.device_count ?? 0}{' '}
                device(s). Not-applicable and not-evaluated checks are in neither half.
              </p>
              <NavLink className="button button--ghost button--small" to="/compliance">
                Open compliance
              </NavLink>
            </div>
          </section>
        )}

        {may('finding:read') && (
          <section className="hero__spread">
            <div className="hero__spread-head">
              <span className="hero__eyebrow">Open findings by severity</span>
              <strong className="hero__total">{findingsTotal.toLocaleString()}</strong>
            </div>
            <StackBar
              parts={severities.map((key) => ({
                label: key,
                value: bySeverity[key] ?? 0,
                tone: SEVERITY_TONES[key]!,
              }))}
            />
          </section>
        )}
      </div>

      {/* ── the counts, each a link to the list that produced it ────────────── */}
      <div className="tiles">
        {may('finding:read') && (
          <>
            <StatTile
              icon="alert"
              label="Critical findings"
              value={critical.data}
              to="/findings?severity=critical"
              hint="Open, worst first"
              tone="var(--sev-critical)"
            />
            <StatTile
              icon="finding"
              label="High findings"
              value={high.data}
              to="/findings?severity=high"
              hint="Open"
              tone="var(--sev-high)"
            />
          </>
        )}

        {may('vuln:read') && (
          <>
            <StatTile
              icon="vulnerability"
              label="Known exploited"
              value={vulns.data?.kev_count}
              to="/vulnerabilities?kev=true"
              hint="In the CISA KEV catalogue"
              tone="var(--sev-critical)"
            />
            <StatTile
              icon="shield"
              label="Confirmed matches"
              value={vulns.data?.by_confidence?.confirmed}
              to="/vulnerabilities?confidence=confirmed"
              hint="Version and conditions both matched"
              tone="var(--sev-high)"
            />
            {/* Beside the counts rather than under them: an empty vulnerability
                table and a fleet nobody assessed look identical from here. */}
            <StatTile
              icon="clock"
              label="Never assessed"
              value={vulns.data?.devices_unassessed}
              to="/vulnerabilities"
              hint="Devices with no assessment on record"
              tone="var(--sev-medium)"
            />
          </>
        )}

        {may('device:read') && (
          <StatTile
            icon="device"
            label="Devices"
            value={devices.data}
            to="/inventory"
            hint="In inventory"
          />
        )}
      </div>

      {/* ── the panels: what the estate looks like, and what just happened ──── */}
      <div className="panels">
        {may('snapshot:read') && (
          <Panel icon="map" title="The estate" to="/topology/map" cta="Open map">
            <Readout
              label="Devices in the graph"
              value={topology.data?.devices?.toLocaleString() ?? '—'}
            />
            <Readout
              label="Carrying a rulebase"
              value={topology.data?.devices_with_rulebase?.toLocaleString() ?? '—'}
            />
            <Readout label="Routes read" value={topology.data?.routes?.toLocaleString() ?? '—'} />
            {/* Called out rather than listed flat: it is the number that says how far
                any path answer can be trusted. */}
            <Readout
              label="Unmanaged next hops"
              value={topology.data?.unmanaged_next_hops?.toLocaleString() ?? '—'}
              tone={topology.data?.unmanaged_next_hops ? 'var(--sev-medium)' : undefined}
              note="Addresses the estate routes to and no inventoried device answers for"
            />
            {topology.data && topology.data.devices_without_route_data > 0 && (
              <Readout
                label="No route data"
                value={topology.data.devices_without_route_data.toLocaleString()}
                tone="var(--sev-medium)"
                note="Collected before forwarding tables were parsed, so they join nothing"
              />
            )}
          </Panel>
        )}

        {may('policy:read') && may('snapshot:read') && (
          <Panel icon="segmentation" title="Segmentation" to="/segmentation" cta="Open matrix">
            {segmentation.data && segmentation.data.cells.length > 0 ? (
              <>
                <StackBar
                  parts={[
                    {
                      label: 'violated',
                      value: segmentation.data.violated,
                      tone: 'var(--sev-critical)',
                    },
                    {
                      label: 'not verified',
                      value: segmentation.data.unverified,
                      tone: 'var(--sev-none)',
                    },
                    { label: 'upheld', value: segmentation.data.upheld, tone: 'var(--sev-low)' },
                  ]}
                />
                {/* Said here as well as on the page itself. A dashboard reader scanning
                    for red takes the absence of it as a pass, and this is the number
                    that says otherwise. */}
                {segmentation.data.unverified > 0 && (
                  <p className="panel__note">
                    {segmentation.data.unverified} pair(s) could not be traced far enough to say.
                    That is not a pass.
                  </p>
                )}
              </>
            ) : (
              <p className="panel__note">
                No segmentation policy has been declared, so there is nothing to check. An empty
                matrix is not a clean one.
              </p>
            )}
          </Panel>
        )}

        {may('job:read') && (
          <Panel icon="assessment" title="Recent assessments" to="/jobs" cta="All runs">
            {(recentJobs.data ?? []).length === 0 ? (
              <p className="panel__note">Nothing has run yet.</p>
            ) : (
              <ul className="runlist">
                {(recentJobs.data ?? []).map((job) => (
                  <li key={job.id} className="runlist__row">
                    {/* The status word, with the dot as reinforcement rather than as
                        the carrier — six statuses cannot be told apart by hue. */}
                    <span
                      className="runlist__dot"
                      style={{ background: jobTone(job.status) }}
                      aria-hidden="true"
                    />
                    <span className="runlist__kind">{job.kind}</span>
                    <span className="runlist__status" style={{ color: jobTone(job.status) }}>
                      {job.status}
                    </span>
                    <span className="runlist__when">
                      {new Date(job.created_at).toLocaleString()}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        )}

        <Panel icon="settings" title="Platform" tone="var(--sev-none)">
          <Readout
            label="Status"
            value={health.isLoading ? '…' : (health.data?.status ?? 'unreachable')}
            tone={health.data?.status === 'ok' ? 'var(--sev-low)' : 'var(--sev-critical)'}
          />
          <Readout label="Version" value={health.data?.version ?? '—'} />
          <Readout label="Environment" value={health.data?.environment ?? '—'} />
        </Panel>

        <Panel icon="users" title="Your access" tone="var(--sev-none)">
          <Readout
            label="MFA"
            value={user?.mfa_enabled ? 'Enabled' : 'Not enabled'}
            tone={user?.mfa_enabled ? 'var(--sev-low)' : 'var(--sev-medium)'}
          />
          <Readout
            label="Scope"
            value={
              user?.unrestricted_scope
                ? 'All device groups'
                : `${user?.device_group_ids.length ?? 0} device group(s)`
            }
          />
          <Readout label="Permissions" value={user?.permissions.length ?? 0} />
        </Panel>

        {/* Kept on the front page deliberately. No competitor in this category can show
            it, and a tamper-evident log nobody ever looks at is only half a control. */}
        {chain.data && (
          <Panel icon="audit" title="Audit chain" to="/audit" cta="Open log" tone="var(--sev-none)">
            <Readout label="Records" value={chain.data.total.toLocaleString()} />
            <Readout
              label="Integrity"
              value={chain.data.valid ? 'Verified' : 'BROKEN'}
              tone={chain.data.valid ? 'var(--sev-low)' : 'var(--sev-critical)'}
            />
          </Panel>
        )}
      </div>
    </div>
  );
}
