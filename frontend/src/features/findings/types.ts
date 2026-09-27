/** Check, finding and policy types, mirroring netsecops/schemas/checks.py. */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Outcome = 'pass' | 'fail' | 'warning' | 'not_applicable' | 'not_evaluated' | 'error';

export type FindingStatus =
  'new' | 'open' | 'reopened' | 'resolved' | 'risk_accepted' | 'false_positive';

export interface EvidenceLine {
  path: string;
  line_start: number | null;
  line_end: number | null;
  excerpt: string | null;
  command: string | null;
}

export interface Evidence {
  observed: unknown;
  expected: string | null;
  lines: EvidenceLine[];
}

/** Counts by facet, from `GET /findings/summary`.
 *
 *  Scoped and filtered exactly as the list is, so a strip drawn from this and a table
 *  drawn from the list are counting the same population. `by_severity` always carries
 *  a key for every severity, including the empty ones, so a five-band bar needs no
 *  knowledge of the vocabulary to render. */
export interface FindingSummary {
  total: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  /** Devices carrying at least one — not the size of the estate. */
  devices_affected: number;
}

export interface TrendDay {
  day: string;
  /** Findings first seen on this day. Exact for all time. */
  first_seen: number;
  /** Resolutions that still stand — a fix later undone is not here. `reopened_now`
   *  on the parent says how much that is. */
  resolved: number;
  first_seen_by_severity: Record<string, number>;
}

/** Whether the estate is getting better (FR-FIND-05).
 *
 * Deliberately carries no open-count per day: reopening a finding clears its
 * `resolved_at`, so a retrospective curve would show every fixed-and-returned problem
 * as open throughout. `open_by_severity` is today's count, which is a fact.
 */
export interface FindingTrend {
  days: number;
  since: string;
  points: TrendDay[];
  open_by_severity: Record<string, number>;
  reopened_now: number;
  median_days_to_resolve: number | null;
  mean_days_to_resolve: number | null;
  resolved_in_window: number;
  total_first_seen: number;
  total_resolved: number;
}

export interface RiskPoint {
  at: string;
  score: number;
  checks_evaluated: number;
}

export interface RiskTrend {
  device_id: string;
  points: RiskPoint[];
  /** Named by the server so a report and the console cannot disagree about the same
   *  two numbers. Risk counts down, so a falling score is `improving`. */
  direction: 'improving' | 'worsening' | 'steady' | 'unknown';
}

export interface DeviceRisk {
  device_id: string;
  score: number | null;
  compliance_percent: number | null;
  coverage_percent: number | null;
  checks_evaluated: number;
  checks_passed: number;
  checks_failed: number;
  checks_not_evaluated: number;
  components: Record<string, unknown>;
  assessed_at: string | null;
}

export interface Finding {
  id: string;
  device_id: string;
  kind: string;
  check_id: string | null;
  cve_id: string | null;
  title: string;
  description: string | null;
  severity: Severity;
  status: FindingStatus;
  first_seen_at: string | null;
  last_seen_at: string | null;
  resolved_at: string | null;
  occurrences: number;
  assignee_id: string | null;
  due_at: string | null;
  created_at: string;
}

export interface FindingDetail extends Finding {
  evidence: Evidence;
  remediation: string | null;
  snapshot_id: string | null;
  /** Why the check matters. The first question anyone asks of a failure. */
  rationale: string | null;
  references: Record<string, string[]>;
}

export interface CheckSummary {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  tags: string[];
  logic_type: 'ncm' | 'regex' | 'python' | 'golden';
  vendors: string[];
  platforms: string[];
  frameworks: Record<string, string[]>;
  enabled_by_default: boolean;
  is_custom: boolean;
}

export interface CheckResult {
  id: string;
  device_id: string;
  snapshot_id: string | null;
  check_id: string;
  check_version: number;
  outcome: Outcome;
  severity: Severity;
  message: string;
  reason: string | null;
  evidence: Evidence;
  duration_ms: number;
  suppressed_by_id: string | null;
  created_at: string;
}

export interface Policy {
  id: string;
  name: string;
  description: string | null;
  source: string;
  version: number;
  enabled: boolean;
  is_default: boolean;
  frameworks: string[];
  created_at: string;
}

export interface Risk {
  device_id: string;
  score: number | null;
  /** Passes as a share of what was decided. Not Applicable and Not Evaluated are in
   *  neither half — counting them as passes would reward a failed collection. */
  compliance_percent: number | null;
  /** How much of the policy produced a verdict at all. */
  coverage_percent: number | null;
  checks_evaluated: number;
  checks_passed: number;
  checks_failed: number;
  checks_not_evaluated: number;
  components: Record<string, unknown>;
  assessed_at: string | null;
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const STATUS_LABELS: Record<FindingStatus, string> = {
  new: 'New',
  open: 'Open',
  reopened: 'Reopened',
  resolved: 'Resolved',
  risk_accepted: 'Risk accepted',
  false_positive: 'False positive',
};

export const OUTCOME_LABELS: Record<Outcome, string> = {
  pass: 'Pass',
  fail: 'Fail',
  warning: 'Warning',
  not_applicable: 'Not applicable',
  not_evaluated: 'Not evaluated',
  error: 'Error',
};

/** Statuses an operator may set. `resolved` is deliberately absent: a finding is
 *  resolved by its check passing on a later assessment, never by hand. */
export const SETTABLE_STATUSES: FindingStatus[] = ['open', 'risk_accepted', 'false_positive'];
